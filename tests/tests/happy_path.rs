//! The three ways an escrow can end, under both token programs.
//!
//! Each one checks the same three things: the tokens landed where the rule
//! says, the escrow and its vault are gone, and the rent came back to the
//! buyer.

use escrow_harness::*;
use verdict_escrow::verdict::Verdict;

/// One signature at the standard fee. The buyer pays this once, on create.
const SIGNATURE_FEE: u64 = 5_000;

#[test]
fn release_verdict_pays_the_seller() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let buyer = h.buyer.pubkey();
        let buyer_ata = h.ata(&buyer);
        let seller_ata = h.ata(&h.seller.pubkey());
        let buyer_lamports_before = h.lamports(&buyer);

        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let vault = ata_for(&escrow, &h.mint, &h.token_program);
        assert_eq!(h.token_balance(&buyer_ata), BUYER_START - ESCROW_AMOUNT);
        assert_eq!(h.token_balance(&vault), ESCROW_AMOUNT);

        let expires_at = h.now() + 600;
        let result = h.settle(escrow, Verdict::Release, expires_at);
        assert_ok(&result);

        assert_eq!(h.token_balance(&seller_ata), ESCROW_AMOUNT);
        assert_eq!(h.token_balance(&buyer_ata), BUYER_START - ESCROW_AMOUNT);
        assert!(
            !h.account_exists(&escrow),
            "escrow account should be closed"
        );
        assert!(!h.account_exists(&vault), "vault should be closed");
        // The relayer paid the settle fee, so the buyer is out exactly the one
        // signature it paid for on create. All rent came back.
        assert_eq!(h.lamports(&buyer), buyer_lamports_before - SIGNATURE_FEE);
    });
}

#[test]
fn refund_verdict_pays_the_buyer() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let buyer = h.buyer.pubkey();
        let buyer_ata = h.ata(&buyer);
        let seller_ata = h.ata(&h.seller.pubkey());
        let buyer_lamports_before = h.lamports(&buyer);

        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let vault = ata_for(&escrow, &h.mint, &h.token_program);

        let expires_at = h.now() + 600;
        let result = h.settle(escrow, Verdict::Refund, expires_at);
        assert_ok(&result);

        assert_eq!(h.token_balance(&buyer_ata), BUYER_START);
        assert_eq!(h.token_balance(&seller_ata), 0);
        assert!(!h.account_exists(&escrow));
        assert!(!h.account_exists(&vault));
        assert_eq!(h.lamports(&buyer), buyer_lamports_before - SIGNATURE_FEE);
    });
}

#[test]
fn reclaim_after_the_deadline_pays_the_buyer() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let buyer = h.buyer.pubkey();
        let buyer_ata = h.ata(&buyer);
        let seller_ata = h.ata(&h.seller.pubkey());
        let buyer_lamports_before = h.lamports(&buyer);

        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let vault = ata_for(&escrow, &h.mint, &h.token_program);
        let deadline = h.escrow_state(&escrow).deadline;

        h.set_time(deadline);
        let result = h.reclaim(escrow);
        assert_ok(&result);

        assert_eq!(h.token_balance(&buyer_ata), BUYER_START);
        assert_eq!(h.token_balance(&seller_ata), 0);
        assert!(!h.account_exists(&escrow));
        assert!(!h.account_exists(&vault));
        // Two signature fees this time: the buyer sent both transactions.
        assert_eq!(
            h.lamports(&buyer),
            buyer_lamports_before - 2 * SIGNATURE_FEE
        );
    });
}

#[test]
fn create_escrow_records_what_the_verdict_will_be_checked_against() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let slot_at_creation = h.clock().slot;
        let deadline = h.now() + HOUR;

        let (escrow, result) = h.create_escrow_with(7, ESCROW_AMOUNT, deadline);
        assert_ok(&result);

        let state = h.escrow_state(&escrow);
        assert_eq!(state.buyer, h.buyer.pubkey());
        assert_eq!(state.seller, h.seller.pubkey());
        assert_eq!(state.mint, h.mint);
        assert_eq!(state.verdict_signer, h.verdict_signer.pubkey());
        assert_eq!(state.amount, ESCROW_AMOUNT);
        assert_eq!(state.deadline, deadline);
        assert_eq!(state.created_slot, slot_at_creation);
        assert_eq!(state.escrow_id, 7);
        assert_eq!(escrow, h.escrow_pda(&h.buyer.pubkey(), 7));
    });
}

#[test]
fn two_escrows_from_one_buyer_live_side_by_side() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (first, result) = h.create_escrow(1);
        assert_ok(&result);
        let (second, result) = h.create_escrow(2);
        assert_ok(&result);
        assert_ne!(first, second);

        let expires_at = h.now() + 600;
        assert_ok(&h.settle(first, Verdict::Release, expires_at));

        // Settling one leaves the other untouched.
        assert!(h.account_exists(&second));
        assert_eq!(h.escrow_state(&second).escrow_id, 2);
        assert_eq!(
            h.token_balance(&ata_for(&second, &h.mint, &h.token_program)),
            ESCROW_AMOUNT
        );
    });
}
