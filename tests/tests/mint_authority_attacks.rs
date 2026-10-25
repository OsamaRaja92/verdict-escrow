//! What the holder of a mint's authorities can do to a live escrow.
//!
//! An escrow over an arbitrary mint inherits whatever powers that mint's
//! authorities hold. The freeze authority can freeze any account of its mint,
//! the vault included; the mint authority can create tokens out of nothing.
//! Neither is a party to the deal, neither signs anything this program checks,
//! and neither can be removed by the buyer. So the question a reviewer needs
//! answered is exactly where that reach stops.
//!
//! It stops at availability. A freeze can stall a payout, in one direction or
//! in every direction at once, and that is a real property of any escrow over
//! a freezable mint rather than a bug in this program — which is why it is
//! written down here either way. What neither authority can do is redirect a
//! payout, take tokens out of the vault, or make a frozen escrow
//! unrecoverable: `reclaim` has no upper time bound, so the buyer's escape
//! route does not expire and reopens the moment the account is thawed.
//!
//! The one mint-side power that would empty a vault outright is Token-2022's
//! permanent delegate, which may move tokens out of any account of its mint
//! without the owner's signature. It arrives as a mint extension, and the
//! 82-byte rule in `create_escrow` refuses every mint that carries one. The
//! last test is the proof, and the same rule is what keeps out a pausable
//! mint, a default-frozen one and a transfer hook.
//!
//! The vault's own authorities are a separate question, and the answer is
//! shorter: the vault's owner is the escrow PDA, nobody can sign for a PDA,
//! and this program never issues `Approve` or `SetAuthority` to anyone.

use anchor_lang::prelude::Pubkey;
use escrow_harness::*;
use litesvm::types::TransactionResult;
use litesvm_token::CreateMint;
use solana_instruction::{AccountMeta, Instruction};
use solana_instruction_error::InstructionError;
use solana_keypair::Keypair;
use solana_transaction_error::TransactionError;
use verdict_escrow::errors::EscrowError;
use verdict_escrow::verdict::Verdict;

/// Enough lamports for any of the strangers below to pay their own fees.
const FEE_MONEY: u64 = 1_000_000_000;
/// A year, for the thaw that arrives long after the deadline.
const YEAR: i64 = 365 * 24 * HOUR;

// --- (a) the freeze authority, pointed at a payout destination -------------

/// The premise of everything below: a freeze authority is a field of the base
/// mint, not an extension, so a freezable mint is still the bare 82 bytes that
/// `create_escrow` insists on. The program cannot filter these out by length,
/// and does not try to.
#[test]
fn a_mint_with_a_freeze_authority_is_accepted_at_the_base_length() {
    for_each_token_program(|kind| {
        let (mut h, _freezer) = freezable(kind);
        let mint_len = h.svm.get_account(&h.mint).expect("mint exists").data.len();
        assert_eq!(mint_len, 82, "a freezable mint is still a bare mint");

        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        assert_eq!(
            h.token_balance(&ata_for(&escrow, &h.mint, &h.token_program)),
            ESCROW_AMOUNT
        );
    });
}

/// The seller's account is frozen after the escrow is funded. A release pays
/// that account, so the token program refuses the transfer and the whole
/// settle reverts: the escrow and the vault are exactly as they were.
#[test]
fn a_frozen_seller_account_blocks_a_release() {
    for_each_token_program(|kind| {
        let (mut h, freezer) = freezable(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let vault = ata_for(&escrow, &h.mint, &h.token_program);

        let seller_ata = h.ata(&h.seller.pubkey());
        freeze(&mut h, &freezer, seller_ata);

        let expires_at = h.now() + 600;
        let result = h.settle(escrow, Verdict::Release, expires_at);
        assert_error(&result, TokenError::AccountFrozen);

        assert_eq!(h.token_balance(&vault), ESCROW_AMOUNT);
        assert!(h.account_exists(&escrow), "nothing was closed");
        assert_eq!(h.escrow_state(&escrow).amount, ESCROW_AMOUNT);
    });
}

/// The first escape route. A refund pays the buyer, so a frozen seller does
/// not touch it: the verdict signer can still unwind the deal.
#[test]
fn a_frozen_seller_account_does_not_block_a_refund() {
    for_each_token_program(|kind| {
        let (mut h, freezer) = freezable(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let vault = ata_for(&escrow, &h.mint, &h.token_program);

        let seller_ata = h.ata(&h.seller.pubkey());
        freeze(&mut h, &freezer, seller_ata);

        let expires_at = h.now() + 600;
        assert_ok(&h.settle(escrow, Verdict::Refund, expires_at));

        assert_eq!(h.token_balance(&h.ata(&h.buyer.pubkey())), BUYER_START);
        assert!(!h.account_exists(&vault));
        assert!(!h.account_exists(&escrow));
    });
}

/// The second escape route, and the one that needs nobody's cooperation. Once
/// the deadline passes the buyer takes the money back, and a frozen seller is
/// irrelevant because the seller's account is not part of `reclaim`.
#[test]
fn a_frozen_seller_account_does_not_block_reclaim() {
    for_each_token_program(|kind| {
        let (mut h, freezer) = freezable(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let seller_ata = h.ata(&h.seller.pubkey());
        freeze(&mut h, &freezer, seller_ata);

        let deadline = h.escrow_state(&escrow).deadline;
        h.set_time(deadline);
        assert_ok(&h.reclaim(escrow));

        assert_eq!(h.token_balance(&h.ata(&h.buyer.pubkey())), BUYER_START);
        assert!(!h.account_exists(&escrow));
    });
}

/// The worst the freeze authority can do from outside the vault: freeze both
/// payout destinations, so neither verdict and not even `reclaim` can land.
///
/// This is not reported as a finding, for two reasons. The money is not lost,
/// only parked: `reclaim` has no upper time bound, so the buyer's exit is
/// still there a year later and works the moment the account is thawed. And
/// the authority gains nothing by it — the same signature freezes those tokens
/// in the buyer's own wallet with no escrow involved. The mitigation belongs
/// to the buyer, not to the program: check the mint's freeze authority before
/// funding anything.
#[test]
fn freezing_both_sides_parks_the_money_until_a_thaw() {
    for_each_token_program(|kind| {
        let (mut h, freezer) = freezable(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let vault = ata_for(&escrow, &h.mint, &h.token_program);
        let buyer_ata = h.ata(&h.buyer.pubkey());
        let seller_ata = h.ata(&h.seller.pubkey());

        freeze(&mut h, &freezer, seller_ata);
        freeze(&mut h, &freezer, buyer_ata);

        let expires_at = h.now() + 600;
        assert_error(
            &h.settle(escrow, Verdict::Release, expires_at),
            TokenError::AccountFrozen,
        );
        assert_error(
            &h.settle(escrow, Verdict::Refund, expires_at),
            TokenError::AccountFrozen,
        );

        let deadline = h.escrow_state(&escrow).deadline;
        h.set_time(deadline);
        assert_error(&h.reclaim(escrow), TokenError::AccountFrozen);
        assert_eq!(h.token_balance(&vault), ESCROW_AMOUNT);

        // A year late, the thaw arrives. The escrow is still there and the
        // buyer still gets everything back.
        h.set_time(deadline + YEAR);
        thaw(&mut h, &freezer, buyer_ata);
        assert_ok(&h.reclaim(escrow));
        assert_eq!(h.token_balance(&buyer_ata), BUYER_START);
        assert!(!h.account_exists(&vault));
        assert!(!h.account_exists(&escrow));
    });
}

// --- (b) the freeze authority, pointed at the vault ------------------------

/// Freezing the vault itself. The vault is an ordinary token account for the
/// mint, so the freeze authority reaches it even though a program owns it, and
/// a frozen account cannot be transferred *from*. That blocks both verdicts
/// and `reclaim` alike, because every exit moves the vault's balance first.
///
/// The same reasoning as above applies: nothing is closed, nothing is lost,
/// and the thaw reopens every exit. The one thing worth noticing is that this
/// freeze is strictly weaker than it looks — it cannot take the tokens, and
/// it cannot stop `reclaim` from working later.
#[test]
fn a_frozen_vault_blocks_every_exit_until_it_is_thawed() {
    for_each_token_program(|kind| {
        let (mut h, freezer) = freezable(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let vault = ata_for(&escrow, &h.mint, &h.token_program);
        let buyer_ata = h.ata(&h.buyer.pubkey());

        freeze(&mut h, &freezer, vault);

        let expires_at = h.now() + 600;
        assert_error(
            &h.settle(escrow, Verdict::Release, expires_at),
            TokenError::AccountFrozen,
        );
        assert_error(
            &h.settle(escrow, Verdict::Refund, expires_at),
            TokenError::AccountFrozen,
        );

        let deadline = h.escrow_state(&escrow).deadline;
        h.set_time(deadline);
        assert_error(&h.reclaim(escrow), TokenError::AccountFrozen);
        assert_eq!(h.token_balance(&vault), ESCROW_AMOUNT);
        assert_eq!(h.token_balance(&buyer_ata), BUYER_START - ESCROW_AMOUNT);

        thaw(&mut h, &freezer, vault);
        assert_ok(&h.reclaim(escrow));
        assert_eq!(h.token_balance(&buyer_ata), BUYER_START);
        assert!(!h.account_exists(&vault));
        assert!(!h.account_exists(&escrow));
    });
}

// --- (c) frozen before the escrow exists -----------------------------------

/// The buyer's account is frozen before `create_escrow`. The deposit is a
/// transfer *from* that account, so the escrow never opens. Nothing is left
/// behind: the escrow PDA and the vault are both created inside the same
/// transaction that then fails, so both disappear with it.
#[test]
fn a_frozen_buyer_account_cannot_fund_an_escrow() {
    for_each_token_program(|kind| {
        let (mut h, freezer) = freezable(kind);
        let buyer_ata = h.ata(&h.buyer.pubkey());
        freeze(&mut h, &freezer, buyer_ata);

        let (escrow, result) = h.create_escrow(1);
        assert_error(&result, TokenError::AccountFrozen);

        assert!(!h.account_exists(&escrow), "no escrow was opened");
        assert!(!h.account_exists(&ata_for(&escrow, &h.mint, &h.token_program)));
        assert_eq!(h.token_balance(&buyer_ata), BUYER_START);
    });
}

/// The vault can exist before the escrow does — anyone may create an
/// associated token account for any owner, which `create_escrow` allows for
/// deliberately — and a vault that exists can be frozen. Then the deposit is a
/// transfer *into* a frozen account and creation fails.
///
/// This is the limit of the squatting note in `lib.rs`, and it does not
/// contradict it. A squatter alone cannot block creation; a squatter plus the
/// mint's freeze authority can, and so can the freeze authority on its own
/// once the escrow is live. It costs the buyer a transaction fee and no
/// tokens.
#[test]
fn a_vault_frozen_before_creation_blocks_the_escrow() {
    for_each_token_program(|kind| {
        let (mut h, freezer) = freezable(kind);
        let buyer = h.buyer.pubkey();
        let escrow = h.escrow_pda(&buyer, 1);

        let vault = h.create_ata(&escrow);
        freeze(&mut h, &freezer, vault);

        let (_, result) = h.create_escrow(1);
        assert_error(&result, TokenError::AccountFrozen);

        assert!(!h.account_exists(&escrow), "no escrow was opened");
        assert_eq!(h.token_balance(&h.ata(&buyer)), BUYER_START);
        assert_eq!(h.token_balance(&vault), 0);
    });
}

// --- (d) the vault's own authorities ---------------------------------------

/// A delegate on the vault would be a standing right to move the escrowed
/// tokens out from under the program, so it is worth proving nobody can grant
/// one.
///
/// `Approve` is checked against the token account's recorded owner, which is
/// the escrow PDA. An attacker has two moves and both fail: name himself as
/// the authority, and the recorded owner does not match; or name the escrow
/// PDA, which has no private key and so cannot sign a transaction, leaving the
/// account unsigned. There is no third move through the program either — no
/// instruction here issues `Approve`, so the escrow's signature is never
/// available for one.
#[test]
fn a_delegate_on_the_vault_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let vault = ata_for(&escrow, &h.mint, &h.token_program);
        let token_program = h.token_program;

        let thief = Keypair::new();
        h.svm.airdrop(&thief.pubkey(), FEE_MONEY).expect("airdrop");

        let ix = approve_ix(
            token_program,
            vault,
            thief.pubkey(),
            Authority::signed(thief.pubkey()),
            ESCROW_AMOUNT,
        );
        assert_error(&h.send(&[ix], &[&thief]), TokenError::OwnerMismatch);

        let ix = approve_ix(
            token_program,
            vault,
            thief.pubkey(),
            Authority::unsigned(escrow),
            ESCROW_AMOUNT,
        );
        assert_instruction_error(
            &h.send(&[ix], &[&thief]),
            InstructionError::MissingRequiredSignature,
        );

        assert!(!delegate_is_set(&h, &vault), "the vault has no delegate");

        // And the escrow settles as normal afterwards.
        let expires_at = h.now() + 600;
        assert_ok(&h.settle(escrow, Verdict::Release, expires_at));
        assert_eq!(h.token_balance(&h.ata(&h.seller.pubkey())), ESCROW_AMOUNT);
    });
}

/// The same question for `SetAuthority`: taking the vault outright
/// (`AccountOwner`) or taking the right to close it (`CloseAccount`). Both are
/// checked against the same recorded owner, and both fail the same two ways.
#[test]
fn a_new_owner_or_close_authority_on_the_vault_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let vault = ata_for(&escrow, &h.mint, &h.token_program);
        let token_program = h.token_program;

        let thief = Keypair::new();
        h.svm.airdrop(&thief.pubkey(), FEE_MONEY).expect("airdrop");

        for authority_type in [AUTHORITY_ACCOUNT_OWNER, AUTHORITY_CLOSE_ACCOUNT] {
            let ix = set_authority_ix(
                token_program,
                vault,
                Authority::signed(thief.pubkey()),
                authority_type,
                thief.pubkey(),
            );
            assert_error(&h.send(&[ix], &[&thief]), TokenError::OwnerMismatch);

            let ix = set_authority_ix(
                token_program,
                vault,
                Authority::unsigned(escrow),
                authority_type,
                thief.pubkey(),
            );
            assert_instruction_error(
                &h.send(&[ix], &[&thief]),
                InstructionError::MissingRequiredSignature,
            );
        }

        assert!(
            !close_authority_is_set(&h, &vault),
            "the vault has no close authority"
        );
        assert_eq!(vault_owner(&h, &vault), escrow, "the escrow still owns it");

        let expires_at = h.now() + 600;
        assert_ok(&h.settle(escrow, Verdict::Release, expires_at));
    });
}

// --- (e) the mint authority ------------------------------------------------

/// The mint authority inflates the supply in the middle of a live escrow,
/// straight into the payout destination. It changes nothing about the escrow:
/// the recorded amount is what the buyer deposited, the signed verdict covers
/// that recorded amount and no supply figure, and the payout is the vault's
/// balance. The seller ends up ahead by the escrowed amount and not a unit
/// more.
///
/// The verdict here is signed before the inflation and submitted after it,
/// which is the point: nothing the mint authority does invalidates a verdict,
/// and nothing it does enlarges one.
#[test]
fn minting_new_supply_does_not_change_what_the_escrow_pays() {
    for_each_token_program(|kind| {
        // The harness mint has no freeze authority, and the buyer holds the
        // mint authority — the inflation below is as hostile as it gets.
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let seller_ata = h.ata(&h.seller.pubkey());

        let expires_at = h.now() + 600;
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let accounts = h.settle_accounts(escrow);

        const INFLATION: u64 = 900_000_000_000;
        let minter = h.buyer.insecure_clone();
        let ix = mint_to_ix(
            h.token_program,
            h.mint,
            seller_ata,
            minter.pubkey(),
            INFLATION,
        );
        assert_ok(&h.send(&[ix], &[&minter]));
        assert_eq!(supply(&h, &h.mint), BUYER_START + INFLATION);
        assert_eq!(h.escrow_state(&escrow).amount, ESCROW_AMOUNT);

        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_ok(&result);
        assert_eq!(h.token_balance(&seller_ata), INFLATION + ESCROW_AMOUNT);
    });
}

/// Minting straight into the vault. The payout is the vault's whole balance,
/// so the injected tokens leave with it — to whichever side the verdict names,
/// not to whichever side the minter wanted. The recorded amount stays as it
/// was, and the verdict signed over that recorded amount still verifies.
///
/// A refund is the interesting direction: the mint authority can add to the
/// pot and can choose the moment, but it cannot aim the addition, and it
/// cannot take anything out.
#[test]
fn tokens_minted_into_the_vault_follow_the_verdict() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let vault = ata_for(&escrow, &h.mint, &h.token_program);
        let buyer_ata = h.ata(&h.buyer.pubkey());

        const INJECTION: u64 = 5_000_000;
        let minter = h.buyer.insecure_clone();
        let ix = mint_to_ix(h.token_program, h.mint, vault, minter.pubkey(), INJECTION);
        assert_ok(&h.send(&[ix], &[&minter]));
        assert_eq!(h.token_balance(&vault), ESCROW_AMOUNT + INJECTION);
        assert_eq!(h.escrow_state(&escrow).amount, ESCROW_AMOUNT);

        let expires_at = h.now() + 600;
        assert_ok(&h.settle(escrow, Verdict::Refund, expires_at));
        assert_eq!(h.token_balance(&buyer_ata), BUYER_START + INJECTION);
        assert_eq!(h.token_balance(&h.ata(&h.seller.pubkey())), 0);
        assert!(!h.account_exists(&vault));
    });
}

/// An overflow on the payout would strand the vault for good, which would be
/// the one way inflation could cost anyone money. It is unreachable rather
/// than merely unlikely: the vault's own balance counts towards the same u64
/// supply the minter is capped by, so no destination can be inflated past the
/// point where the vault's balance still fits in it.
///
/// This test mints every token that can still exist into the payout
/// destination and settles anyway.
#[test]
fn inflating_a_destination_cannot_overflow_the_payout() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let seller_ata = h.ata(&h.seller.pubkey());

        let headroom = u64::MAX - supply(&h, &h.mint);
        let minter = h.buyer.insecure_clone();
        let ix = mint_to_ix(
            h.token_program,
            h.mint,
            seller_ata,
            minter.pubkey(),
            headroom,
        );
        assert_ok(&h.send(&[ix], &[&minter]));
        assert_eq!(supply(&h, &h.mint), u64::MAX, "the supply is now maximal");

        let expires_at = h.now() + 600;
        assert_ok(&h.settle(escrow, Verdict::Release, expires_at));
        assert_eq!(h.token_balance(&seller_ata), headroom + ESCROW_AMOUNT);
    });
}

// --- what the buyer can rule out in advance --------------------------------

/// A mint created without a freeze authority can never gain one: `SetAuthority`
/// replaces an authority that exists and has nothing to replace here. So the
/// whole of section (a) and (b) above is something a buyer can rule out before
/// funding an escrow, by reading one field of the mint.
#[test]
fn a_mint_with_no_freeze_authority_cannot_gain_one() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        // The harness mint's authority, trying to give itself the freeze
        // authority it did not ask for at creation.
        let minter = h.buyer.insecure_clone();
        let ix = set_authority_ix(
            h.token_program,
            h.mint,
            Authority::signed(minter.pubkey()),
            AUTHORITY_FREEZE_ACCOUNT,
            minter.pubkey(),
        );
        assert_error(&h.send(&[ix], &[&minter]), TokenError::MintCannotFreeze);

        let expires_at = h.now() + 600;
        assert_ok(&h.settle(escrow, Verdict::Release, expires_at));
        assert_eq!(h.token_balance(&h.ata(&h.seller.pubkey())), ESCROW_AMOUNT);
    });
}

/// The mint-side power that would actually drain a vault: a Token-2022
/// permanent delegate may transfer out of any account of its mint without the
/// owner's signature, so it would empty this vault whenever it liked and the
/// program would have no say in it. The test demonstrates that on an ordinary
/// account first, because the refusal below only matters if the threat is
/// real.
///
/// A permanent delegate cannot be attached to a bare mint, only to one that
/// reserves room for the extension, which makes the mint longer than 82 bytes
/// — and that is the rule `create_escrow` enforces. No escrow is ever opened
/// on such a mint, so there is nothing for the delegate to drain. The same
/// length rule is what keeps out a pausable mint, a default-frozen one and a
/// transfer hook.
///
/// Token-2022 only: classic SPL Token has no extensions at all.
#[test]
fn a_mint_with_a_permanent_delegate_is_refused() {
    let mut h = Harness::new(TokenKind::Token2022);

    let mint = Keypair::new();
    let buyer = h.buyer.insecure_clone();
    let authority = buyer.pubkey();
    let delegate = Keypair::new();
    h.svm
        .airdrop(&delegate.pubkey(), FEE_MONEY)
        .expect("airdrop to the permanent delegate");

    // Base mint (82) padded to 165, the account-type byte, then one TLV entry
    // for PermanentDelegate (4 byte header + 32 bytes).
    const DELEGATED_MINT_LEN: usize = 166 + 4 + 32;
    let lamports = h.svm.minimum_balance_for_rent_exemption(DELEGATED_MINT_LEN);

    let mut create_data = Vec::new();
    create_data.extend_from_slice(&0u32.to_le_bytes()); // SystemInstruction::CreateAccount
    create_data.extend_from_slice(&lamports.to_le_bytes());
    create_data.extend_from_slice(&(DELEGATED_MINT_LEN as u64).to_le_bytes());
    create_data.extend_from_slice(&TOKEN_2022_PROGRAM_ID.to_bytes());
    let create_account = Instruction {
        program_id: SYSTEM_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(authority, true),
            AccountMeta::new(mint.pubkey(), true),
        ],
        data: create_data,
    };

    // InitializePermanentDelegate (35), then InitializeMint2 (20): mint
    // extensions have to be in place before the mint itself is initialised.
    let mut delegate_data = vec![35u8];
    delegate_data.extend_from_slice(&delegate.pubkey().to_bytes());
    let init_permanent_delegate = Instruction {
        program_id: TOKEN_2022_PROGRAM_ID,
        accounts: vec![AccountMeta::new(mint.pubkey(), false)],
        data: delegate_data,
    };

    let mut init_data = vec![20u8, DECIMALS];
    init_data.extend_from_slice(&authority.to_bytes());
    init_data.push(0); // no freeze authority
    let init_mint = Instruction {
        program_id: TOKEN_2022_PROGRAM_ID,
        accounts: vec![AccountMeta::new(mint.pubkey(), false)],
        data: init_data,
    };

    let result = h.send(
        &[create_account, init_permanent_delegate, init_mint],
        &[&buyer, &mint],
    );
    assert_ok(&result);
    let mint_data = h.svm.get_account(&mint.pubkey()).expect("mint exists").data;
    assert!(
        mint_data.len() > 82,
        "a permanent delegate cannot fit in a bare mint"
    );
    // The TLV entry that follows the padded base: type 12 is PermanentDelegate,
    // so this is the extension claimed and not merely a longer mint.
    assert_eq!(
        u16::from_le_bytes(mint_data[166..168].try_into().unwrap()),
        12,
        "the extension should be a permanent delegate"
    );

    h.mint = mint.pubkey();
    let buyer_ata = h.create_ata(&authority);
    let delegate_ata = h.create_ata(&delegate.pubkey());
    let ix = mint_to_ix(
        TOKEN_2022_PROGRAM_ID,
        mint.pubkey(),
        buyer_ata,
        authority,
        BUYER_START,
    );
    assert_ok(&h.send(&[ix], &[&buyer]));

    // What the extension buys its holder: a transfer out of an account it
    // neither owns nor has been approved on, signed by nobody else. A vault
    // would be no different, which is the reason for the length rule.
    let ix = transfer_checked_ix(
        TOKEN_2022_PROGRAM_ID,
        buyer_ata,
        mint.pubkey(),
        delegate_ata,
        Authority::signed(delegate.pubkey()),
        BUYER_START,
    );
    assert_ok(&h.send(&[ix], &[&delegate]));
    assert_eq!(h.token_balance(&delegate_ata), BUYER_START);
    assert_eq!(h.token_balance(&buyer_ata), 0);

    // And the escrow that would have been drained is never opened. The buyer
    // has no balance left by now, which does not matter: the length check runs
    // before the deposit.
    let (escrow, result) = h.create_escrow(1);
    assert_error(&result, EscrowError::UnsupportedMintExtensions);
    assert!(!h.account_exists(&escrow), "no escrow was opened");
}

// --- the token programs, by hand -------------------------------------------
//
// The builder crate only freezes and approves accounts the signing authority
// itself owns, which is the opposite of every test above, so these
// instructions are assembled from their documented layouts. Both token
// programs share the layouts and the error numbers.

/// Instruction tags, identical in both programs.
const APPROVE: u8 = 4;
const SET_AUTHORITY: u8 = 6;
const MINT_TO: u8 = 7;
const FREEZE_ACCOUNT: u8 = 10;
const THAW_ACCOUNT: u8 = 11;
const TRANSFER_CHECKED: u8 = 12;

/// `AuthorityType`, as `SetAuthority` encodes it.
const AUTHORITY_FREEZE_ACCOUNT: u8 = 1;
const AUTHORITY_ACCOUNT_OWNER: u8 = 2;
const AUTHORITY_CLOSE_ACCOUNT: u8 = 3;

/// The token programs' numbered errors, as a client sees them. The numbers are
/// positional in SPL's own enum and the same in both programs.
#[derive(Clone, Copy, Debug)]
#[repr(u32)]
enum TokenError {
    OwnerMismatch = 4,
    MintCannotFreeze = 16,
    AccountFrozen = 17,
}

impl From<TokenError> for u32 {
    fn from(error: TokenError) -> Self {
        error as u32
    }
}

/// The authority an instruction names, and whether it signed.
///
/// Whether it signed is a dial because half of section (d) is about what the
/// token program does when the authority named is one nobody can sign for.
#[derive(Clone, Copy, Debug)]
struct Authority {
    key: Pubkey,
    signed: bool,
}

impl Authority {
    fn signed(key: Pubkey) -> Self {
        Self { key, signed: true }
    }

    fn unsigned(key: Pubkey) -> Self {
        Self { key, signed: false }
    }

    fn meta(self) -> AccountMeta {
        AccountMeta {
            pubkey: self.key,
            is_signer: self.signed,
            is_writable: false,
        }
    }
}

fn freeze_ix(token_program: Pubkey, account: Pubkey, mint: Pubkey, freezer: Pubkey) -> Instruction {
    Instruction {
        program_id: token_program,
        accounts: vec![
            AccountMeta::new(account, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new_readonly(freezer, true),
        ],
        data: vec![FREEZE_ACCOUNT],
    }
}

fn thaw_ix(token_program: Pubkey, account: Pubkey, mint: Pubkey, freezer: Pubkey) -> Instruction {
    Instruction {
        program_id: token_program,
        accounts: vec![
            AccountMeta::new(account, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new_readonly(freezer, true),
        ],
        data: vec![THAW_ACCOUNT],
    }
}

fn approve_ix(
    token_program: Pubkey,
    source: Pubkey,
    delegate: Pubkey,
    authority: Authority,
    amount: u64,
) -> Instruction {
    let mut data = vec![APPROVE];
    data.extend_from_slice(&amount.to_le_bytes());
    Instruction {
        program_id: token_program,
        accounts: vec![
            AccountMeta::new(source, false),
            AccountMeta::new_readonly(delegate, false),
            authority.meta(),
        ],
        data,
    }
}

fn set_authority_ix(
    token_program: Pubkey,
    account: Pubkey,
    authority: Authority,
    authority_type: u8,
    new_authority: Pubkey,
) -> Instruction {
    let mut data = vec![SET_AUTHORITY, authority_type, 1];
    data.extend_from_slice(&new_authority.to_bytes());
    Instruction {
        program_id: token_program,
        accounts: vec![AccountMeta::new(account, false), authority.meta()],
        data,
    }
}

fn transfer_checked_ix(
    token_program: Pubkey,
    source: Pubkey,
    mint: Pubkey,
    destination: Pubkey,
    authority: Authority,
    amount: u64,
) -> Instruction {
    let mut data = vec![TRANSFER_CHECKED];
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(DECIMALS);
    Instruction {
        program_id: token_program,
        accounts: vec![
            AccountMeta::new(source, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new(destination, false),
            authority.meta(),
        ],
        data,
    }
}

fn mint_to_ix(
    token_program: Pubkey,
    mint: Pubkey,
    destination: Pubkey,
    mint_authority: Pubkey,
    amount: u64,
) -> Instruction {
    let mut data = vec![MINT_TO];
    data.extend_from_slice(&amount.to_le_bytes());
    Instruction {
        program_id: token_program,
        accounts: vec![
            AccountMeta::new(mint, false),
            AccountMeta::new(destination, false),
            AccountMeta::new_readonly(mint_authority, true),
        ],
        data,
    }
}

// --- harness extras --------------------------------------------------------

/// A harness whose mint has a freeze authority, and the key that holds it.
///
/// `Harness::new` builds a mint without one, so this replaces the mint and
/// rebuilds the accounts that hang off it. The mint authority stays with the
/// buyer; the freeze authority is a stranger to the deal, which is the point.
fn freezable(kind: TokenKind) -> (Harness, Keypair) {
    let mut h = Harness::new(kind);
    let freezer = Keypair::new();
    h.svm
        .airdrop(&freezer.pubkey(), FEE_MONEY)
        .expect("airdrop to the freeze authority");

    let payer = h.buyer.insecure_clone();
    let authority = payer.pubkey();
    let freeze_authority = freezer.pubkey();
    let token_program = h.token_program;
    let mint = CreateMint::new(&mut h.svm, &payer)
        .token_program_id(&token_program)
        .decimals(DECIMALS)
        .authority(&authority)
        .freeze_authority(&freeze_authority)
        .send()
        .expect("create a freezable mint");

    h.mint = mint;
    let buyer_ata = h.create_ata(&authority);
    h.create_ata(&h.seller.pubkey());
    let ix = mint_to_ix(token_program, mint, buyer_ata, authority, BUYER_START);
    assert_ok(&h.send(&[ix], &[&payer]));

    (h, freezer)
}

/// Freeze one account, and confirm it is the account that ended up frozen. A
/// helper that silently froze the wrong thing would make every test below
/// pass for the wrong reason.
fn freeze(h: &mut Harness, freezer: &Keypair, account: Pubkey) {
    let ix = freeze_ix(h.token_program, account, h.mint, freezer.pubkey());
    assert_ok(&h.send(&[ix], &[freezer]));
    assert!(is_frozen(h, &account), "the account should now be frozen");
}

fn thaw(h: &mut Harness, freezer: &Keypair, account: Pubkey) {
    let ix = thaw_ix(h.token_program, account, h.mint, freezer.pubkey());
    assert_ok(&h.send(&[ix], &[freezer]));
    assert!(!is_frozen(h, &account), "the account should now be thawed");
}

/// Total supply, from the mint account. Offsets 36..44 of the base mint, which
/// Token-2022 keeps unchanged and appends its extensions after.
fn supply(h: &Harness, mint: &Pubkey) -> u64 {
    let account = h.svm.get_account(mint).expect("mint exists");
    u64::from_le_bytes(account.data[36..44].try_into().unwrap())
}

fn token_account_data(h: &Harness, account: &Pubkey) -> Vec<u8> {
    h.svm
        .get_account(account)
        .expect("token account exists")
        .data
}

/// The account state byte sits at offset 108 of the base layout, and 2 is
/// `Frozen`.
fn is_frozen(h: &Harness, account: &Pubkey) -> bool {
    token_account_data(h, account)[108] == 2
}

/// The token account's owner: offsets 32..64 of the base layout.
fn vault_owner(h: &Harness, account: &Pubkey) -> Pubkey {
    let data = token_account_data(h, account);
    Pubkey::try_from(&data[32..64]).expect("32 bytes")
}

/// The delegate is a `COption<Pubkey>` at offset 72, so a non-zero tag means
/// one is set.
fn delegate_is_set(h: &Harness, account: &Pubkey) -> bool {
    let data = token_account_data(h, account);
    u32::from_le_bytes(data[72..76].try_into().unwrap()) != 0
}

/// The close authority is the last `COption<Pubkey>` of the base layout, at
/// offset 129.
fn close_authority_is_set(h: &Harness, account: &Pubkey) -> bool {
    let data = token_account_data(h, account);
    u32::from_le_bytes(data[129..133].try_into().unwrap()) != 0
}

// --- assertions ------------------------------------------------------------

/// Not every refusal is a numbered program error: some the runtime raises
/// itself, and `assert_error` cannot see those. This names the exact
/// `InstructionError` instead.
#[track_caller]
fn assert_instruction_error(result: &TransactionResult, expected: InstructionError) {
    let failure = result
        .as_ref()
        .err()
        .unwrap_or_else(|| panic!("expected {expected:?}, got success"));
    match &failure.err {
        TransactionError::InstructionError(_, actual) => assert_eq!(
            *actual, expected,
            "wrong instruction error\n{:?}",
            failure.meta.logs
        ),
        other => panic!("expected {expected:?}, got {other:?}"),
    }
}
