//! Authority confusion on the money accounts: passing a different account
//! where the program expected the vault, or the payee.
//!
//! The vault is the escrow PDA's associated token account, and the escrow PDA
//! is its only authority. The program signs for it with the seeds
//! `["escrow", buyer, escrow_id, bump]`, rebuilt from the escrow's own stored
//! state on every call. Two independent things have to hold for that to be
//! safe: the account passed as the vault must be the one those seeds can sign
//! for, and the stored state the seeds are built from must belong to the
//! address it was read from. The tests below break one of those at a time, and
//! then do the same to the two payout accounts.
//!
//! This is the class that drains programs because the owner field looks like
//! enough and is not. A token account records an authority, so a check that
//! only reads that field accepts any account that happens to name the right
//! authority — and a program whose PDA can be pointed at an account it did not
//! derive is a program whose PDA can be pointed at the wrong one. The damage
//! does not have to be theft. `settle` takes no privileged signer, so anyone
//! who sees a published verdict can send it; if the vault were pinned by its
//! recorded authority alone, that sender could name an empty token account the
//! escrow also owns, pay out nothing, close the decoy, close the escrow, and
//! leave the real deposit in a vault whose only possible signer no longer
//! exists. Nobody profits and the buyer loses everything.
//!
//! One case of the payout pair is left to another file. When the two payout
//! accounts are a single account — a buyer who named itself the seller, which
//! `create_escrow` allows — Anchor's duplicate-mutable-account check refuses
//! the account list before any constraint tested here is reached, so the case
//! belongs to the duplicate class rather than to authority confusion. It is
//! covered, for both verdicts and with the reclaim that recovers the money, by
//! `a_self_dealing_escrow_can_be_created_but_can_never_be_settled` in
//! `duplicate_and_extra_accounts.rs`.

use anchor_lang::error::ErrorCode as AnchorError;
use anchor_lang::prelude::Pubkey;
use anchor_lang::AccountSerialize;
use escrow_harness::*;
use litesvm_token::{CreateAccount, CreateAssociatedTokenAccount, CreateMint, MintTo};
use solana_account::Account;
use solana_keypair::Keypair;
use verdict_escrow::state::Escrow;
use verdict_escrow::verdict::Verdict;

/// A token account for the escrowed mint whose authority is `owner`, created
/// with a plain keypair and `initialize_account3`.
///
/// This is the account the whole file turns on: its recorded authority is
/// whatever is asked for, and its address is a random keypair's rather than a
/// derived one. Anything that accepts it has checked the owner field and not
/// the address.
fn plain_token_account(h: &mut Harness, owner: &Pubkey) -> Pubkey {
    let payer = h.buyer.insecure_clone();
    let mint = h.mint;
    let token_program = h.token_program;
    CreateAccount::new(&mut h.svm, &payer, &mint)
        .owner(owner)
        .token_program_id(&token_program)
        .send()
        .expect("create a plain token account")
}

/// A second mint, and `owner`'s associated token account for it. Both the
/// authority and the token program are right; only the mint is wrong, so the
/// address comes out different.
fn ata_for_another_mint(h: &mut Harness, owner: &Pubkey) -> Pubkey {
    let payer = h.buyer.insecure_clone();
    let token_program = h.token_program;
    let other_mint = CreateMint::new(&mut h.svm, &payer)
        .token_program_id(&token_program)
        .decimals(DECIMALS)
        .send()
        .expect("second mint");
    CreateAssociatedTokenAccount::new(&mut h.svm, &payer, &other_mint)
        .owner(owner)
        .token_program_id(&token_program)
        .send()
        .expect("associated token account for the second mint")
}

/// Overwrite an escrow account in place with state of the test's choosing,
/// keeping its lamports, its owner and its length.
///
/// No attacker can do this: the program is the only writer of its own
/// accounts. It is in the file because it is the only way to show what the
/// address-to-state check is actually for. Everything these tests then send is
/// an ordinary transaction.
fn replant_escrow(h: &mut Harness, address: Pubkey, state: &Escrow) {
    let existing = h
        .svm
        .get_account(&address)
        .expect("the escrow account exists");
    let mut data = Vec::with_capacity(existing.data.len());
    state
        .try_serialize(&mut data)
        .expect("serialise the escrow");
    assert_eq!(
        data.len(),
        existing.data.len(),
        "the planted account must be the same length as the real one"
    );
    h.svm
        .set_account(address, Account { data, ..existing })
        .expect("plant the escrow account");
}

/// Mint `amount` of the escrowed mint to `account`, under the harness mint
/// authority.
fn mint_to(h: &mut Harness, account: &Pubkey, amount: u64) {
    let payer = h.buyer.insecure_clone();
    let mint = h.mint;
    let token_program = h.token_program;
    MintTo::new(&mut h.svm, &payer, &mint, account, amount)
        .token_program_id(&token_program)
        .send()
        .expect("mint to an account");
}

// --- owned by the escrow, but not derived from it -------------------------

/// The test that proves the derivation is doing work the owner field cannot.
///
/// The decoy really is the escrow's: its recorded authority is the escrow PDA,
/// so the `associated_token::authority` half of the constraint is satisfied,
/// and the program could sign for it. Only its address is wrong. An attacker
/// relaying someone else's valid verdict with this account in the vault slot
/// would pay out the decoy's zero balance and close the escrow, stranding the
/// deposit in the real vault for good.
#[test]
fn a_token_account_the_escrow_owns_but_did_not_derive_is_refused_by_settle() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let real_vault = ata_for(&escrow, &h.mint, &h.token_program);

        let decoy = plain_token_account(&mut h, &escrow);

        let expires_at = h.now() + 600;
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let mut accounts = h.settle_accounts(escrow);
        accounts.vault = decoy;

        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        // The owner check passes and the address check refuses it.
        assert_error(&result, AnchorError::ConstraintAssociated);
        assert_eq!(h.token_balance(&real_vault), ESCROW_AMOUNT);
        assert!(h.account_exists(&escrow), "the escrow is still open");
    });
}

/// The same decoy on the other exit. `reclaim` is the buyer's own instruction,
/// so the attacker here is whatever built the transaction the buyer signed: a
/// compromised client that strands the buyer's deposit while showing them a
/// successful reclaim.
#[test]
fn a_token_account_the_escrow_owns_but_did_not_derive_is_refused_by_reclaim() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let real_vault = ata_for(&escrow, &h.mint, &h.token_program);
        let deadline = h.escrow_state(&escrow).deadline;

        let decoy = plain_token_account(&mut h, &escrow);
        h.set_time(deadline);

        let mut ix = h.reclaim_ix(escrow);
        let meta = ix
            .accounts
            .iter_mut()
            .find(|meta| meta.pubkey == real_vault)
            .expect("the vault is one of the accounts");
        meta.pubkey = decoy;

        let buyer = h.buyer.insecure_clone();
        let result = h.send(&[ix], &[&buyer]);
        assert_error(&result, AnchorError::ConstraintAssociated);
        assert_eq!(h.token_balance(&real_vault), ESCROW_AMOUNT);
        assert!(h.account_exists(&escrow), "the escrow is still open");
    });
}

/// The same substitution at funding time, where the vault is `init_if_needed`
/// rather than a plain constraint. Anchor's init path has its own address
/// check with its own error code, so the assertion differs from the two above
/// even though the mistake is identical.
///
/// Had it passed, the deposit would have gone into an account neither exit can
/// name — both derive the vault — and the money would be unreachable from the
/// first instruction onwards.
#[test]
fn a_token_account_the_escrow_owns_but_did_not_derive_is_refused_at_creation() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let buyer = h.buyer.pubkey();

        // The escrow's address is derivable before the escrow exists, so the
        // decoy can name it as its authority in advance.
        let escrow = h.escrow_pda(&buyer, 1);
        let decoy = plain_token_account(&mut h, &escrow);
        let real_vault = ata_for(&escrow, &h.mint, &h.token_program);

        let deadline = h.now() + HOUR;
        let mut ix = h.create_escrow_ix(
            &buyer,
            1,
            ESCROW_AMOUNT,
            deadline,
            h.seller.pubkey(),
            h.verdict_signer.pubkey(),
        );
        let meta = ix
            .accounts
            .iter_mut()
            .find(|meta| meta.pubkey == real_vault)
            .expect("the vault is one of the accounts");
        meta.pubkey = decoy;

        let signer = h.buyer.insecure_clone();
        let result = h.send(&[ix], &[&signer]);
        assert_error(&result, AnchorError::AccountNotAssociatedTokenAccount);
        assert_eq!(h.token_balance(&decoy), 0);
        assert_eq!(h.token_balance(&h.ata(&buyer)), BUYER_START);
        assert!(!h.account_exists(&escrow), "no escrow was opened");
    });
}

// --- another escrow's vault -----------------------------------------------

/// `destinations.rs` sends another escrow's vault to `settle`; this is the same
/// attack on `reclaim`, which that file does not cover.
///
/// A buyer with two escrows open is the ordinary case for this. If it worked,
/// the first escrow to reach its deadline would drain the other one as well,
/// before any verdict on it had been given.
#[test]
fn another_escrows_vault_is_refused_by_reclaim() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let (other_escrow, result) = h.create_escrow(2);
        assert_ok(&result);

        let other_vault = ata_for(&other_escrow, &h.mint, &h.token_program);
        let own_vault = ata_for(&escrow, &h.mint, &h.token_program);
        let deadline = h.escrow_state(&escrow).deadline;
        h.set_time(deadline);

        let mut ix = h.reclaim_ix(escrow);
        let meta = ix
            .accounts
            .iter_mut()
            .find(|meta| meta.pubkey == own_vault)
            .expect("the vault is one of the accounts");
        meta.pubkey = other_vault;

        let buyer = h.buyer.insecure_clone();
        let result = h.send(&[ix], &[&buyer]);
        // The other vault's recorded authority is the other escrow, so the
        // owner check fires before the address check gets a say.
        assert_error(&result, AnchorError::ConstraintTokenOwner);
        assert_eq!(h.token_balance(&other_vault), ESCROW_AMOUNT);
        assert_eq!(h.token_balance(&own_vault), ESCROW_AMOUNT);
    });
}

// --- a token account the attacker owns ------------------------------------

/// The crude version: the right mint, the wrong authority. Nothing about this
/// account belongs to the escrow, and the owner check is what says so.
#[test]
fn a_token_account_the_attacker_owns_is_refused_as_the_vault_by_settle() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let real_vault = ata_for(&escrow, &h.mint, &h.token_program);

        let attacker = Keypair::new();
        let attacker_account = plain_token_account(&mut h, &attacker.pubkey());

        let expires_at = h.now() + 600;
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let mut accounts = h.settle_accounts(escrow);
        accounts.vault = attacker_account;

        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_error(&result, AnchorError::ConstraintTokenOwner);
        assert_eq!(h.token_balance(&real_vault), ESCROW_AMOUNT);
    });
}

/// The same account at funding time, which is where it would actually pay.
///
/// `create_escrow` moves the buyer's tokens with the buyer's own signature, so
/// a client that substitutes the vault here is asking the buyer to sign a
/// transfer straight into the attacker's account while an escrow appears to
/// open. The buyer sees one instruction and cannot read the derivation.
#[test]
fn a_token_account_the_attacker_owns_is_refused_as_the_vault_at_creation() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let buyer = h.buyer.pubkey();
        let escrow = h.escrow_pda(&buyer, 1);
        let real_vault = ata_for(&escrow, &h.mint, &h.token_program);

        let attacker = Keypair::new();
        let attacker_ata = h.create_ata(&attacker.pubkey());

        let deadline = h.now() + HOUR;
        let mut ix = h.create_escrow_ix(
            &buyer,
            1,
            ESCROW_AMOUNT,
            deadline,
            h.seller.pubkey(),
            h.verdict_signer.pubkey(),
        );
        let meta = ix
            .accounts
            .iter_mut()
            .find(|meta| meta.pubkey == real_vault)
            .expect("the vault is one of the accounts");
        meta.pubkey = attacker_ata;

        let signer = h.buyer.insecure_clone();
        let result = h.send(&[ix], &[&signer]);
        assert_error(&result, AnchorError::ConstraintTokenOwner);
        assert_eq!(h.token_balance(&attacker_ata), 0);
        assert_eq!(h.token_balance(&h.ata(&buyer)), BUYER_START);
        assert!(!h.account_exists(&escrow), "no escrow was opened");
    });
}

// --- can the escrow PDA sign for anything else? ---------------------------

/// The question this file exists to answer: can the escrow PDA be made to sign
/// for an account other than its own vault?
///
/// Both exits build the signer seeds from `escrow.buyer`, `escrow.escrow_id`
/// and `escrow.bump` — stored state, never an argument. If they took an
/// argument instead, a caller could hand over the seeds of any escrow and have
/// the program sign as it. Stored state is only as good as the guarantee that
/// it belongs to the account it was read from, and that guarantee is the
/// `seeds = [..., escrow.buyer, escrow.escrow_id]` constraint, which re-derives
/// the address from the state and compares.
///
/// So the lever is an escrow whose stored id does not match the address it sits
/// at. Note what the escrow id is not: it is not a field of the signed verdict
/// message, because the doc comment in `verdict.rs` reasons that the address
/// pins it. Changing it leaves a perfectly valid signature. The address check
/// is the only thing standing here, and it holds.
#[test]
fn an_escrow_whose_stored_id_does_not_match_its_address_cannot_settle() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let vault = ata_for(&escrow, &h.mint, &h.token_program);

        let expires_at = h.now() + 600;
        let mut state = h.escrow_state(&escrow);
        state.escrow_id = 999;
        replant_escrow(&mut h, escrow, &state);

        // Signed after the change, over the escrow's live state, by the real
        // verdict signer: the signature is not what fails.
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let accounts = h.settle_accounts(escrow);
        assert_eq!(accounts.vault, vault, "the vault is still the derived one");

        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_error(&result, AnchorError::ConstraintSeeds);
        assert_eq!(h.token_balance(&vault), ESCROW_AMOUNT);
        assert_eq!(h.token_balance(&h.ata(&h.seller.pubkey())), 0);
    });
}

#[test]
fn an_escrow_whose_stored_id_does_not_match_its_address_cannot_be_reclaimed() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let vault = ata_for(&escrow, &h.mint, &h.token_program);
        let deadline = h.escrow_state(&escrow).deadline;

        let mut state = h.escrow_state(&escrow);
        state.escrow_id = 999;
        replant_escrow(&mut h, escrow, &state);
        h.set_time(deadline);

        let result = h.reclaim(escrow);
        assert_error(&result, AnchorError::ConstraintSeeds);
        assert_eq!(h.token_balance(&vault), ESCROW_AMOUNT);
    });
}

/// The other seed, and the order the checks run in.
///
/// Here the stored buyer is replaced by an attacker and the attacker is passed
/// as the buyer, so `has_one = buyer` is satisfied and the attacker's signature
/// is real. The address no longer follows from the state, and the seeds check
/// runs before `has_one`, so that is what refuses it. A reader should take the
/// general point from this: satisfying every field-level check on an escrow
/// account is not the same as that account being this program's escrow.
#[test]
fn an_escrow_repointed_at_an_attacker_as_buyer_cannot_be_reclaimed() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let vault = ata_for(&escrow, &h.mint, &h.token_program);
        let deadline = h.escrow_state(&escrow).deadline;

        let attacker = Keypair::new();
        h.svm.airdrop(&attacker.pubkey(), 1_000_000_000).unwrap();
        let attacker_ata = h.create_ata(&attacker.pubkey());

        let mut state = h.escrow_state(&escrow);
        state.buyer = attacker.pubkey();
        replant_escrow(&mut h, escrow, &state);
        h.set_time(deadline);

        // `reclaim_ix` reads the stored state, so this names the attacker as
        // the buyer and the attacker's account as the destination.
        let ix = h.reclaim_ix(escrow);
        let result = h.send(&[ix], &[&attacker]);
        assert_error(&result, AnchorError::ConstraintSeeds);
        assert_eq!(h.token_balance(&attacker_ata), 0);
        assert_eq!(h.token_balance(&vault), ESCROW_AMOUNT);
    });
}

/// The same question with no planting at all, which is the version that
/// matters.
///
/// The attacker opens a real escrow of their own, for one base unit, naming
/// themselves as the verdict signer. They can therefore produce a verdict the
/// program accepts for that escrow, and the escrow's state is entirely theirs:
/// their buyer, their id, their bump. Then they point its `settle` at the
/// victim's vault.
///
/// Every check on the escrow account passes, and the attack still gets nowhere,
/// because the vault is constrained to the associated token account of the
/// escrow that was passed. The signer seeds and the vault address come from the
/// same place, so an escrow can only ever sign for its own vault — which is
/// what makes the seeds safe to build from stored state in the first place.
#[test]
fn an_escrow_the_attacker_owns_outright_cannot_sign_for_another_escrows_vault() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (victim, result) = h.create_escrow(1);
        assert_ok(&result);
        let victim_vault = ata_for(&victim, &h.mint, &h.token_program);

        // An ordinary buyer, who happens to be the attacker: funded, with an
        // account for the mint, and an accomplice to be paid.
        let attacker = Keypair::new();
        let accomplice = Keypair::new();
        h.svm.airdrop(&attacker.pubkey(), 1_000_000_000).unwrap();
        let attacker_ata = h.create_ata(&attacker.pubkey());
        let accomplice_ata = h.create_ata(&accomplice.pubkey());
        mint_to(&mut h, &attacker_ata, 1);

        let deadline = h.now() + HOUR;
        let ix = h.create_escrow_ix(
            &attacker.pubkey(),
            7,
            1,
            deadline,
            accomplice.pubkey(),
            attacker.pubkey(),
        );
        assert_ok(&h.send(&[ix], &[&attacker]));
        let attacker_escrow = h.escrow_pda(&attacker.pubkey(), 7);

        // A verdict for the attacker's own escrow, signed by the key that
        // escrow names. It verifies.
        let expires_at = h.now() + 600;
        let message = h.verdict_message(attacker_escrow, Verdict::Release, expires_at);
        let verdict_ix = Ed25519Ix::sign(&attacker, &message);

        let mut accounts = h.settle_accounts(attacker_escrow);
        accounts.vault = victim_vault;

        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_error(&result, AnchorError::ConstraintTokenOwner);
        assert_eq!(h.token_balance(&victim_vault), ESCROW_AMOUNT);
        assert_eq!(h.token_balance(&accomplice_ata), 0);

        // The same transaction with the attacker's own vault is accepted, so
        // the refusal above is about the account and nothing else.
        let accounts = h.settle_accounts(attacker_escrow);
        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_ok(&result);
        assert_eq!(h.token_balance(&accomplice_ata), 1);
        assert_eq!(h.token_balance(&victim_vault), ESCROW_AMOUNT);
    });
}

/// The last step of the same argument: state that is an escrow byte for byte,
/// at the address its own seeds derive, in an account this program does not
/// own.
///
/// `Account<'info, Escrow>` checks the owner before it reads a field, so the
/// forgery never reaches a constraint. That check is what makes stored state
/// trustworthy at all: without it an attacker could write any buyer, any id
/// and any bump into an account of their own and hand it over as the escrow,
/// and the signer seeds would be theirs to choose.
#[test]
fn a_real_escrows_state_in_a_foreign_owned_account_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let vault = ata_for(&escrow, &h.mint, &h.token_program);

        let expires_at = h.now() + 600;
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let accounts = h.settle_accounts(escrow);

        // Everything about the account stays as the program left it except
        // the one field that says who may write to it.
        let existing = h
            .svm
            .get_account(&escrow)
            .expect("the escrow account exists");
        h.svm
            .set_account(
                escrow,
                Account {
                    owner: MEMO_PROGRAM_ID,
                    ..existing
                },
            )
            .expect("plant an escrow another program owns");

        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_error(&result, AnchorError::AccountOwnedByWrongProgram);
        assert_eq!(h.token_balance(&vault), ESCROW_AMOUNT);
    });
}

// --- the payout accounts --------------------------------------------------

/// The right wallet, the wrong mint.
///
/// Worth reading the constraint for: `associated_token::mint = mint` does not
/// check the mint the token account itself records. It goes into the address
/// derivation, and the derived address is what catches this. The token
/// program's own `transfer_checked` would refuse the transfer a moment later,
/// so the mint is pinned twice over here; the assertion fixes which check
/// fires, so a later change that drops one of the two is visible.
#[test]
fn a_seller_account_for_another_mint_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let vault = ata_for(&escrow, &h.mint, &h.token_program);

        let seller = h.seller.pubkey();
        let wrong_mint_ata = ata_for_another_mint(&mut h, &seller);

        let expires_at = h.now() + 600;
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let mut accounts = h.settle_accounts(escrow);
        accounts.seller_token_account = wrong_mint_ata;

        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_error(&result, AnchorError::ConstraintAssociated);
        assert_eq!(h.token_balance(&vault), ESCROW_AMOUNT);
    });
}

#[test]
fn a_buyer_account_for_another_mint_is_refused_by_reclaim() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let vault = ata_for(&escrow, &h.mint, &h.token_program);
        let deadline = h.escrow_state(&escrow).deadline;

        let buyer = h.buyer.pubkey();
        let wrong_mint_ata = ata_for_another_mint(&mut h, &buyer);
        h.set_time(deadline);

        let mut ix = h.reclaim_ix(escrow);
        let right_ata = h.ata(&buyer);
        let meta = ix
            .accounts
            .iter_mut()
            .find(|meta| meta.pubkey == right_ata)
            .expect("the buyer's token account is one of the accounts");
        meta.pubkey = wrong_mint_ata;

        let signer = h.buyer.insecure_clone();
        let result = h.send(&[ix], &[&signer]);
        assert_error(&result, AnchorError::ConstraintAssociated);
        assert_eq!(h.token_balance(&vault), ESCROW_AMOUNT);
    });
}

/// The right mint, the wrong wallet, on the exit `destinations.rs` does not
/// reach. The buyer signs `reclaim`, so this is again the compromised-client
/// case: a reclaim that looks like a reclaim and pays a stranger.
#[test]
fn a_strangers_account_for_the_right_mint_is_refused_by_reclaim() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let vault = ata_for(&escrow, &h.mint, &h.token_program);
        let deadline = h.escrow_state(&escrow).deadline;

        let stranger = Keypair::new();
        let stranger_ata = h.create_ata(&stranger.pubkey());
        h.set_time(deadline);

        let mut ix = h.reclaim_ix(escrow);
        let right_ata = h.ata(&h.buyer.pubkey());
        let meta = ix
            .accounts
            .iter_mut()
            .find(|meta| meta.pubkey == right_ata)
            .expect("the buyer's token account is one of the accounts");
        meta.pubkey = stranger_ata;

        let signer = h.buyer.insecure_clone();
        let result = h.send(&[ix], &[&signer]);
        assert_error(&result, AnchorError::ConstraintTokenOwner);
        assert_eq!(h.token_balance(&stranger_ata), 0);
        assert_eq!(h.token_balance(&vault), ESCROW_AMOUNT);
    });
}
