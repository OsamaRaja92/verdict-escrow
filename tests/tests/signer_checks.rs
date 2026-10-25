//! Who has to sign, and whose money their signature is allowed to move.
//!
//! A missing signer check is the shape of most drained programs: every account
//! passed in looks plausible, the arithmetic is right, and the one thing
//! nobody checked is whether the owner of the money agreed to any of it. The
//! class is worth testing instruction by instruction, because the answer is
//! not the same for all three here.
//!
//! `settle` deliberately has no privileged signer at all — the authority is
//! the Ed25519 verdict, not the sender — and `time_and_caller.rs` covers both
//! that and `reclaim`'s single signature. What is left is `create_escrow`,
//! the one instruction that spends tokens the program does not control, and a
//! standing guard that none of the three instructions quietly gains or loses
//! a `Signer` later.
//!
//! The last question the class raises is delegation, since an SPL delegate is
//! the one way the owner of a token account can lend out the right to spend
//! from it. It is asked here in both directions: a delegate on the buyer's
//! account, and a stranger trying to become the delegate of the vault.

use anchor_lang::error::ErrorCode as AnchorError;
use anchor_lang::prelude::Pubkey;
use anchor_lang::{InstructionData, ToAccountMetas};
use escrow_harness::*;
use litesvm::types::TransactionResult;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use verdict_escrow::verdict::Verdict;

/// `TokenError::OwnerMismatch`. It is the fifth variant of the error enum both
/// token programs share, so both surface it as `Custom(4)`.
const TOKEN_ERROR_OWNER_MISMATCH: u32 = 4;

/// Enough lamports for a stranger to pay fees and rent, so that no test here
/// can pass merely because the attacker was broke.
const STRANGER_FUNDS: u64 = 1_000_000_000;

/// `create_escrow` built by hand, so a test can name an account the harness
/// never would. The escrow address and the source token account are the two
/// the attacks below bend; everything else is the honest derivation for
/// `buyer`, and the terms are the harness defaults.
fn create_escrow_ix(
    h: &Harness,
    buyer: &Pubkey,
    escrow: Pubkey,
    buyer_token_account: Pubkey,
    escrow_id: u64,
) -> Instruction {
    Instruction {
        program_id: verdict_escrow::ID,
        accounts: verdict_escrow::accounts::CreateEscrow {
            buyer: *buyer,
            mint: h.mint,
            escrow,
            vault: ata_for(&escrow, &h.mint, &h.token_program),
            buyer_token_account,
            token_program: h.token_program,
            associated_token_program: ASSOCIATED_TOKEN_PROGRAM_ID,
            system_program: SYSTEM_PROGRAM_ID,
        }
        .to_account_metas(None),
        data: verdict_escrow::instruction::CreateEscrow {
            escrow_id,
            amount: ESCROW_AMOUNT,
            deadline: h.now() + HOUR,
            seller: h.seller.pubkey(),
            verdict_signer: h.verdict_signer.pubkey(),
        }
        .data(),
    }
}

/// The addresses a transaction's account metas are marked as signing, in the
/// order Anchor emits them.
fn required_signers(metas: &[AccountMeta]) -> Vec<Pubkey> {
    metas
        .iter()
        .filter(|meta| meta.is_signer)
        .map(|meta| meta.pubkey)
        .collect()
}

/// The delegate recorded on a token account: a `COption<Pubkey>` at offset 72,
/// a four-byte tag and then the key. The offsets are the same under both token
/// programs, since Token-2022 only appends its extensions after this base.
fn delegate_of(h: &Harness, token_account: &Pubkey) -> Option<Pubkey> {
    let account = h
        .svm
        .get_account(token_account)
        .expect("token account exists");
    match u32::from_le_bytes(account.data[72..76].try_into().unwrap()) {
        0 => None,
        _ => Some(Pubkey::new_from_array(
            account.data[76..108].try_into().unwrap(),
        )),
    }
}

/// `Approve`: instruction 4, then the amount. The accounts are the source, the
/// delegate, and the source's owner, who signs. The owner is passed separately
/// from the source on purpose: the token program checking that the two agree is
/// the subject of one of the tests below.
fn approve_ix(
    h: &Harness,
    source: &Pubkey,
    delegate: &Pubkey,
    owner: &Pubkey,
    amount: u64,
) -> Instruction {
    let mut data = vec![4u8];
    data.extend_from_slice(&amount.to_le_bytes());
    Instruction {
        program_id: h.token_program,
        accounts: vec![
            AccountMeta::new(*source, false),
            AccountMeta::new_readonly(*delegate, false),
            AccountMeta::new_readonly(*owner, true),
        ],
        data,
    }
}

/// `TransferChecked`: instruction 12, then the amount and the decimals. The
/// accounts are the source, the mint, the destination, and the authority,
/// which the token program will accept as either the owner or the delegate.
fn transfer_checked_ix(
    h: &Harness,
    source: &Pubkey,
    destination: &Pubkey,
    authority: &Pubkey,
    amount: u64,
) -> Instruction {
    let mut data = vec![12u8];
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(DECIMALS);
    Instruction {
        program_id: h.token_program,
        accounts: vec![
            AccountMeta::new(*source, false),
            AccountMeta::new_readonly(h.mint, false),
            AccountMeta::new(*destination, false),
            AccountMeta::new_readonly(*authority, true),
        ],
        data,
    }
}

#[track_caller]
fn assert_owner_mismatch(result: &TransactionResult) {
    assert_eq!(
        custom_error_code(result),
        Some(TOKEN_ERROR_OWNER_MISMATCH),
        "expected the token program's OwnerMismatch, got {:?}",
        result.as_ref().err().map(|failure| &failure.err)
    );
}

/// The buyer's own account, in the right place, with the signer bit cleared,
/// sent by a stranger who pays the fee. Nothing else about the instruction is
/// wrong: the escrow address, the vault and the source token account are all
/// the buyer's own, and the terms are the ones the buyer would have chosen.
/// Anchor's `Signer` type is the only thing between a stranger and 250 of the
/// buyer's tokens.
#[test]
fn creating_an_escrow_without_the_buyers_signature_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let buyer = h.buyer.pubkey();
        let escrow = h.escrow_pda(&buyer, 1);

        let mut ix = create_escrow_ix(&h, &buyer, escrow, h.ata(&buyer), 1);
        let buyer_meta = ix
            .accounts
            .iter_mut()
            .find(|meta| meta.pubkey == buyer)
            .expect("the buyer is one of the accounts");
        assert!(buyer_meta.is_signer, "it should have been a signer");
        buyer_meta.is_signer = false;

        let stranger = Keypair::new();
        h.svm.airdrop(&stranger.pubkey(), STRANGER_FUNDS).unwrap();
        let result = h.send(&[ix], &[&stranger]);

        assert_error(&result, AnchorError::AccountNotSigner);
        assert_eq!(h.token_balance(&h.ata(&buyer)), BUYER_START);
        assert!(!h.account_exists(&escrow));
    });
}

/// The same instruction with the signer bit left alone, sent and paid for by
/// the same stranger. It succeeds, which is what makes the test above an
/// assertion about the missing signature rather than about who paid the fee:
/// `create_escrow` asks for the buyer's consent, not for the buyer's lamports.
#[test]
fn a_stranger_may_pay_the_fee_when_the_buyer_signs() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let buyer = h.buyer.pubkey();
        let escrow = h.escrow_pda(&buyer, 1);
        let ix = create_escrow_ix(&h, &buyer, escrow, h.ata(&buyer), 1);

        let stranger = Keypair::new();
        h.svm.airdrop(&stranger.pubkey(), STRANGER_FUNDS).unwrap();
        // The first signer pays, so the stranger is the fee payer here and the
        // buyer is only a signer.
        let signer = h.buyer.insecure_clone();
        let result = h.send(&[ix], &[&stranger, &signer]);

        assert_ok(&result);
        assert_eq!(h.escrow_state(&escrow).buyer, buyer);
        assert_eq!(
            h.token_balance(&ata_for(&escrow, &h.mint, &h.token_program)),
            ESCROW_AMOUNT
        );
    });
}

/// The question the class is really about: can anyone other than the buyer
/// cause the buyer's tokens to be spent.
///
/// A stranger opens an escrow of their own — their key as the buyer, their
/// escrow address, their signature — and names the buyer's token account as
/// the source. Anchor refuses it, and the token program never sees the
/// transfer. `buyer_token_account` carries `associated_token::authority =
/// buyer`, and `buyer` resolves to whoever signed, so the owner recorded in
/// the account passed in has to be that same signer.
#[test]
fn a_stranger_cannot_name_the_buyers_token_account_as_the_source() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let buyer_ata = h.ata(&h.buyer.pubkey());

        let stranger = Keypair::new();
        h.svm.airdrop(&stranger.pubkey(), STRANGER_FUNDS).unwrap();
        h.create_ata(&stranger.pubkey());

        let escrow = h.escrow_pda(&stranger.pubkey(), 1);
        let ix = create_escrow_ix(&h, &stranger.pubkey(), escrow, buyer_ata, 1);
        let result = h.send(&[ix], &[&stranger]);

        assert_error(&result, AnchorError::ConstraintTokenOwner);
        assert_eq!(h.token_balance(&buyer_ata), BUYER_START);
        assert!(!h.account_exists(&escrow));
    });
}

/// What stands behind Anchor's constraint, shown directly because the program
/// cannot be made to reach it: a bare `transfer_checked` out of the buyer's
/// token account with a stranger as the authority. The token program compares
/// the authority against the owner recorded in the account and refuses.
///
/// The two checks cannot be made to disagree in the dangerous direction:
/// `create_escrow` always passes the signing buyer as the transfer authority,
/// and Anchor has already required that same key to be the owner recorded in
/// the source account, so anything Anchor lets through the token program also
/// accepts. They are not equally strict, though, and the asymmetry runs the
/// safe way: the token program would also accept an approved delegate as the
/// authority, and Anchor's constraint would not, which is what the delegate
/// test below turns on.
#[test]
fn the_token_program_refuses_a_transfer_authorised_by_a_stranger() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let buyer_ata = h.ata(&h.buyer.pubkey());

        let stranger = Keypair::new();
        h.svm.airdrop(&stranger.pubkey(), STRANGER_FUNDS).unwrap();
        let stranger_ata = h.create_ata(&stranger.pubkey());

        let ix = transfer_checked_ix(
            &h,
            &buyer_ata,
            &stranger_ata,
            &stranger.pubkey(),
            ESCROW_AMOUNT,
        );
        let result = h.send(&[ix], &[&stranger]);

        assert_owner_mismatch(&result);
        assert_eq!(h.token_balance(&stranger_ata), 0);
        assert_eq!(h.token_balance(&buyer_ata), BUYER_START);
    });
}

/// The address side of the same question. A stranger signs for themselves, but
/// passes the escrow PDA that belongs to the buyer's `(buyer, escrow_id)`
/// pair. The seeds constraint re-derives the address from the signing buyer,
/// so the address passed in and the address derived do not agree.
///
/// This gets its own test because the damage would not be a theft. The program
/// writes `escrow.buyer` from the signer, while both exits re-derive the PDA
/// from `escrow.buyer`, so an escrow stored at an address its own state does
/// not derive could never be settled or reclaimed. For the price of the rent a
/// stranger would be locking the buyer's `(buyer, escrow_id)` pair shut, with
/// the stranger's own deposit stranded inside it.
#[test]
fn a_stranger_cannot_open_an_escrow_at_the_buyers_address() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let buyers_escrow = h.escrow_pda(&h.buyer.pubkey(), 1);

        let stranger = Keypair::new();
        h.svm.airdrop(&stranger.pubkey(), STRANGER_FUNDS).unwrap();
        let stranger_ata = h.create_ata(&stranger.pubkey());

        let ix = create_escrow_ix(&h, &stranger.pubkey(), buyers_escrow, stranger_ata, 1);
        let result = h.send(&[ix], &[&stranger]);

        assert_error(&result, AnchorError::ConstraintSeeds);
        assert!(!h.account_exists(&buyers_escrow));

        // And the buyer's own escrow at that address still opens afterwards.
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        assert_eq!(escrow, buyers_escrow);
    });
}

/// A delegate is the one way a token account's owner can let somebody else
/// spend from it, so it is the obvious route around the constraint above.
///
/// It leads nowhere. The program never passes a delegate as the transfer
/// authority: the authority is always the signing buyer, and the source is
/// always that same signer's associated token account. A delegate naming the
/// buyer's account is refused by the same owner constraint as any other
/// stranger, with the approval sitting right there on the account, unused.
#[test]
fn a_delegate_on_the_buyers_token_account_cannot_open_an_escrow_with_it() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let buyer = h.buyer.pubkey();
        let buyer_ata = h.ata(&buyer);

        let delegate = Keypair::new();
        h.svm.airdrop(&delegate.pubkey(), STRANGER_FUNDS).unwrap();
        let delegate_ata = h.create_ata(&delegate.pubkey());

        // The buyer hands the delegate authority over the whole balance.
        let signer = h.buyer.insecure_clone();
        let approve = approve_ix(&h, &buyer_ata, &delegate.pubkey(), &buyer, BUYER_START);
        assert_ok(&h.send(&[approve], &[&signer]));
        assert_eq!(delegate_of(&h, &buyer_ata), Some(delegate.pubkey()));

        // The delegate opens an escrow of their own and tries to fund it from
        // the account they have been approved for.
        let escrow = h.escrow_pda(&delegate.pubkey(), 1);
        let ix = create_escrow_ix(&h, &delegate.pubkey(), escrow, buyer_ata, 1);
        let result = h.send(&[ix], &[&delegate]);

        assert_error(&result, AnchorError::ConstraintTokenOwner);
        assert_eq!(h.token_balance(&buyer_ata), BUYER_START);
        assert!(!h.account_exists(&escrow));

        // The approval really was live: the delegate can move the same tokens
        // through the token program directly. The escrow program simply offers
        // no instruction that would carry a delegate's authority.
        let direct = transfer_checked_ix(&h, &buyer_ata, &delegate_ata, &delegate.pubkey(), 1);
        assert_ok(&h.send(&[direct], &[&delegate]));
        assert_eq!(h.token_balance(&delegate_ata), 1);
    });
}

/// The same idea pointed at the vault instead of the buyer.
///
/// The vault's address follows from the escrow and the mint, so anyone can
/// create it before the escrow exists, which `creation.rs` relies on. The
/// attack that would make that dangerous is approving yourself as its delegate
/// while it is still empty, then waiting for the buyer's deposit to land in an
/// account you can spend from. The vault's owner is the escrow PDA, and only
/// this program can sign for that, so the token program refuses the approval
/// outright. Whoever paid the rent for the account is immaterial.
#[test]
fn a_stranger_cannot_make_themselves_the_vaults_delegate() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let buyer = h.buyer.pubkey();
        let escrow = h.escrow_pda(&buyer, 1);

        // The vault, created before the escrow it will belong to.
        let vault = h.create_ata(&escrow);

        let stranger = Keypair::new();
        h.svm.airdrop(&stranger.pubkey(), STRANGER_FUNDS).unwrap();
        let approve = approve_ix(
            &h,
            &vault,
            &stranger.pubkey(),
            &stranger.pubkey(),
            ESCROW_AMOUNT,
        );
        let result = h.send(&[approve], &[&stranger]);

        assert_owner_mismatch(&result);
        assert_eq!(delegate_of(&h, &vault), None);

        // The buyer funds it, and it is still nobody's to spend but the
        // program's: the money leaves only where a verdict sends it.
        let (opened, result) = h.create_escrow(1);
        assert_ok(&result);
        assert_eq!(opened, escrow);
        assert_eq!(delegate_of(&h, &vault), None);
        assert_eq!(h.token_balance(&vault), ESCROW_AMOUNT);

        let expires_at = h.now() + 600;
        assert_ok(&h.settle(escrow, Verdict::Release, expires_at));
        assert_eq!(h.token_balance(&h.ata(&h.seller.pubkey())), ESCROW_AMOUNT);
    });
}

// The three tests below are not attacks. They read the account metas Anchor
// generates for each instruction and pin the set of signatures it demands, so
// that a `Signer` added to or removed from one of the three account structs
// later fails here rather than in production. They need no ledger: the metas
// come from the same `#[derive(Accounts)]` the program runs on, and the
// addresses in them are arbitrary.

/// `settle` must keep demanding nothing. A privileged signer added here would
/// not be a vulnerability, but it would quietly end the relayer model the
/// instruction is built around: the verdict is the authority, and anyone may
/// carry it.
#[test]
fn settle_demands_no_signature_at_all() {
    let metas = verdict_escrow::accounts::Settle {
        escrow: Pubkey::new_unique(),
        buyer: Pubkey::new_unique(),
        mint: Pubkey::new_unique(),
        vault: Pubkey::new_unique(),
        seller_token_account: Pubkey::new_unique(),
        buyer_token_account: Pubkey::new_unique(),
        instructions_sysvar: INSTRUCTIONS_SYSVAR_ID,
        token_program: TOKEN_PROGRAM_ID,
    }
    .to_account_metas(None);

    assert!(
        !metas.is_empty(),
        "an empty account list would make this assertion vacuous"
    );
    assert_eq!(required_signers(&metas), Vec::<Pubkey>::new());
}

/// `create_escrow` must keep demanding exactly one signature, the buyer's. It
/// is the instruction that spends tokens the program does not own, so the
/// buyer's signature is the whole of its authorisation.
#[test]
fn create_escrow_demands_exactly_one_signature_the_buyers() {
    let buyer = Pubkey::new_unique();
    let metas = verdict_escrow::accounts::CreateEscrow {
        buyer,
        mint: Pubkey::new_unique(),
        escrow: Pubkey::new_unique(),
        vault: Pubkey::new_unique(),
        buyer_token_account: Pubkey::new_unique(),
        token_program: TOKEN_PROGRAM_ID,
        associated_token_program: ASSOCIATED_TOKEN_PROGRAM_ID,
        system_program: SYSTEM_PROGRAM_ID,
    }
    .to_account_metas(None);

    assert_eq!(required_signers(&metas), vec![buyer]);
}

/// `reclaim` must keep demanding exactly one signature, the buyer's. Dropping
/// it would leave `has_one = buyer` naming which key the account must be, with
/// nothing requiring that key to have agreed — the gap
/// `reclaim_without_the_buyers_signature_is_refused` exists to catch.
#[test]
fn reclaim_demands_exactly_one_signature_the_buyers() {
    let buyer = Pubkey::new_unique();
    let metas = verdict_escrow::accounts::Reclaim {
        escrow: Pubkey::new_unique(),
        buyer,
        mint: Pubkey::new_unique(),
        vault: Pubkey::new_unique(),
        buyer_token_account: Pubkey::new_unique(),
        token_program: TOKEN_PROGRAM_ID,
    }
    .to_account_metas(None);

    assert_eq!(required_signers(&metas), vec![buyer]);
}
