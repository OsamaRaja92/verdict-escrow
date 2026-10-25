//! Where the money is allowed to go.
//!
//! No instruction argument names a destination. Both payout accounts are the
//! stored buyer's and seller's associated token accounts for the stored mint,
//! and the vault is the escrow's own. Point any of them somewhere else and the
//! instruction does not run.

use anchor_lang::error::ErrorCode as AnchorError;
use escrow_harness::*;
use litesvm_token::CreateMint;
use solana_keypair::Keypair;
use verdict_escrow::verdict::Verdict;

#[test]
fn a_substitute_seller_account_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        // A token account for the same mint, owned by someone else.
        let thief = Keypair::new();
        let thief_ata = h.create_ata(&thief.pubkey());

        let expires_at = h.now() + 600;
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let mut accounts = h.settle_accounts(escrow);
        accounts.seller_token_account = thief_ata;

        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        // Anchor checks the token account's recorded owner before it checks
        // the derived address, so this is the constraint that fires first.
        assert_error(&result, AnchorError::ConstraintTokenOwner);
        assert_eq!(h.token_balance(&thief_ata), 0);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
    });
}

#[test]
fn a_substitute_buyer_account_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let thief = Keypair::new();
        let thief_ata = h.create_ata(&thief.pubkey());

        let expires_at = h.now() + 600;
        let verdict_ix = h.verdict_ix(escrow, Verdict::Refund, expires_at);
        let mut accounts = h.settle_accounts(escrow);
        accounts.buyer_token_account = thief_ata;

        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Refund, expires_at);
        assert_error(&result, AnchorError::ConstraintTokenOwner);
        assert_eq!(h.token_balance(&thief_ata), 0);
    });
}

#[test]
fn a_substitute_vault_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let (other_escrow, result) = h.create_escrow(2);
        assert_ok(&result);

        // The second escrow's vault, holding its own money, passed to the
        // first escrow's settle.
        let expires_at = h.now() + 600;
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let mut accounts = h.settle_accounts(escrow);
        accounts.vault = ata_for(&other_escrow, &h.mint, &h.token_program);

        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_error(&result, AnchorError::ConstraintTokenOwner);
        assert_eq!(
            h.token_balance(&ata_for(&other_escrow, &h.mint, &h.token_program)),
            ESCROW_AMOUNT
        );
    });
}

#[test]
fn a_different_mint_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let payer = h.buyer.insecure_clone();
        let token_program = h.token_program;
        let other_mint = CreateMint::new(&mut h.svm, &payer)
            .token_program_id(&token_program)
            .decimals(DECIMALS)
            .send()
            .expect("second mint");

        let expires_at = h.now() + 600;
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let mut accounts = h.settle_accounts(escrow);
        accounts.mint = other_mint;

        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        // The escrow stores its mint; the account passed in must be that one.
        assert_error(&result, AnchorError::ConstraintHasOne);
    });
}

#[test]
fn the_other_token_program_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let expires_at = h.now() + 600;
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let mut accounts = h.settle_accounts(escrow);
        accounts.token_program = kind.other_program_id();

        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        // The mint is owned by one token program; naming the other one is
        // caught before any transfer is attempted.
        assert_error(&result, AnchorError::ConstraintMintTokenProgram);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
    });
}

#[test]
fn a_substitute_escrow_account_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        // Not a PDA of this program at all.
        let expires_at = h.now() + 600;
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let mut accounts = h.settle_accounts(escrow);
        accounts.escrow = Keypair::new().pubkey();

        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_error(&result, AnchorError::AccountNotInitialized);
    });
}
