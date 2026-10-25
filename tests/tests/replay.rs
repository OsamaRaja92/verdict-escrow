//! Using the same verdict, or the same escrow, twice.
//!
//! Both exits close the escrow and its vault, so a second call finds nothing
//! to act on. The gap that leaves is a *new* escrow at the same address: the
//! creation slot is inside the signed message, so an old verdict does not fit
//! the new escrow.
//!
//! The other half of a stateless verdict is that it cannot be taken back. The
//! signed message carries no nonce and no sequence number, the program keeps no
//! record of what it has been shown, and `settle` is permissionless, so a
//! verdict is a bearer instrument: a signer that issues a refund and then
//! changes its mind and issues a release has put two live claims on one escrow,
//! and whoever submits first spends it. `expires_at` is the only invalidation
//! there is, and therefore the only mitigation — sign a short expiry and
//! reissue, because nothing revokes what is already signed.

use anchor_lang::error::ErrorCode as AnchorError;
use escrow_harness::*;
use solana_keypair::Keypair;
use verdict_escrow::errors::EscrowError;
use verdict_escrow::verdict::Verdict;

#[test]
fn settling_twice_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let expires_at = h.now() + 600;
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let accounts = h.settle_accounts(escrow);

        assert_ok(&h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at));
        assert_eq!(h.token_balance(&h.ata(&h.seller.pubkey())), ESCROW_AMOUNT);

        // The same verdict, sent again. There is no escrow left to read.
        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_error(&result, AnchorError::AccountNotInitialized);
        assert_eq!(h.token_balance(&h.ata(&h.seller.pubkey())), ESCROW_AMOUNT);
    });
}

#[test]
fn reclaiming_after_a_settlement_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let deadline = h.escrow_state(&escrow).deadline;

        let reclaim_ix = h.reclaim_ix(escrow);
        assert_ok(&h.settle(escrow, Verdict::Release, h.now() + 600));

        h.set_time(deadline);
        let buyer = h.buyer.insecure_clone();
        let result = h.send(&[reclaim_ix], &[&buyer]);
        assert_error(&result, AnchorError::AccountNotInitialized);
        assert_eq!(h.token_balance(&h.ata(&h.seller.pubkey())), ESCROW_AMOUNT);
    });
}

#[test]
fn settling_after_a_reclaim_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let deadline = h.escrow_state(&escrow).deadline;

        // Take the verdict out before the escrow is gone, then try to use it.
        let expires_at = deadline + 600;
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let accounts = h.settle_accounts(escrow);

        h.set_time(deadline);
        assert_ok(&h.reclaim(escrow));
        assert_eq!(h.token_balance(&h.ata(&h.buyer.pubkey())), BUYER_START);

        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_error(&result, AnchorError::AccountNotInitialized);
        assert_eq!(h.token_balance(&h.ata(&h.seller.pubkey())), 0);
    });
}

/// The replay this design exists to stop.
///
/// The buyer reuses an escrow id, so the second escrow has the same address as
/// the first. An old verdict for the first one is still perfectly signed — but
/// it carries the first escrow's creation slot, and the second escrow was
/// created later.
#[test]
fn a_used_verdict_does_not_fit_a_new_escrow_at_the_same_address() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let expires_at = h.now() + 6_000;
        let old_verdict = h.verdict_ix(escrow, Verdict::Release, expires_at);
        assert_ok(&h.settle(escrow, Verdict::Release, expires_at));

        // A later slot, and the same id again.
        h.advance_slots(1);
        let (reborn, result) = h.create_escrow(1);
        assert_ok(&result);
        assert_eq!(reborn, escrow, "same id, same address");

        let accounts = h.settle_accounts(reborn);
        let result = h.send_settle(&accounts, &old_verdict, Verdict::Release, expires_at);
        assert_error(&result, EscrowError::VerdictMessageMismatch);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
    });
}

/// The limit of that protection, stated plainly so the README can repeat it.
///
/// Two escrows created in the *same* slot at the same address share a creation
/// slot, and nothing else in the message distinguishes them. A buyer who
/// settles and immediately re-creates the same id within one slot can have the
/// old verdict applied to the new escrow. A fresh id each time avoids it.
#[test]
fn a_used_verdict_still_fits_a_same_slot_rebuild() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let expires_at = h.now() + 6_000;
        let old_verdict = h.verdict_ix(escrow, Verdict::Release, expires_at);
        assert_ok(&h.settle(escrow, Verdict::Release, expires_at));

        // Same slot, same id, same amount: an identical escrow.
        let (reborn, result) = h.create_escrow(1);
        assert_ok(&result);

        let accounts = h.settle_accounts(reborn);
        let result = h.send_settle(&accounts, &old_verdict, Verdict::Release, expires_at);
        assert_ok(&result);
        assert_eq!(
            h.token_balance(&h.ata(&h.seller.pubkey())),
            2 * ESCROW_AMOUNT,
            "documented gap: the same-slot rebuild accepts the old verdict"
        );
    });
}

#[test]
fn an_escrow_id_cannot_be_reused_while_it_is_open() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (_, result) = h.create_escrow(1);
        assert_ok(&result);

        // The address is already taken. The `init` constraint asks the system
        // program to create it, and the system program's "account already in
        // use" comes back as custom error 0.
        let (escrow, result) = h.create_escrow(1);
        assert_eq!(custom_error_code(&result), Some(0));
        assert_eq!(h.escrow_state(&escrow).escrow_id, 1);
        assert_eq!(
            h.token_balance(&ata_for(&escrow, &h.mint, &h.token_program)),
            ESCROW_AMOUNT,
            "the open escrow keeps its money"
        );
    });
}

/// The reason the seller is inside the signed message.
///
/// Settling and re-creating the same `escrow_id` is a single transaction a
/// buyer can always build — Anchor's `close` leaves the account empty and
/// system-owned, so a later instruction in the same transaction can re-create
/// it at the identical `created_slot`. If the signed bytes named only the
/// escrow, the buyer could point the rebuilt escrow at a payee of their
/// choosing and the old verdict would still fit it. The verdict signer would
/// have no record of who it actually paid.
#[test]
fn a_used_verdict_does_not_fit_a_rebuild_that_names_another_seller() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let buyer = h.buyer.pubkey();
        let deadline = h.now() + HOUR;

        let first = {
            let ix = h.create_escrow_ix(
                &buyer,
                1,
                ESCROW_AMOUNT,
                deadline,
                h.seller.pubkey(),
                h.verdict_signer.pubkey(),
            );
            let signer = h.buyer.insecure_clone();
            assert_ok(&h.send(&[ix], &[&signer]));
            h.escrow_pda(&buyer, 1)
        };

        let expires_at = h.now() + 6_000;
        let old_verdict = h.verdict_ix(first, Verdict::Release, expires_at);
        assert_ok(&h.settle(first, Verdict::Release, expires_at));
        assert_eq!(h.token_balance(&h.ata(&h.seller.pubkey())), ESCROW_AMOUNT);

        // Same slot, same id, same amount, same deadline — different payee.
        let accomplice = Keypair::new();
        let accomplice_ata = h.create_ata(&accomplice.pubkey());
        let ix = h.create_escrow_ix(
            &buyer,
            1,
            ESCROW_AMOUNT,
            deadline,
            accomplice.pubkey(),
            h.verdict_signer.pubkey(),
        );
        let signer = h.buyer.insecure_clone();
        assert_ok(&h.send(&[ix], &[&signer]));

        let rebuilt = h.escrow_pda(&buyer, 1);
        assert_eq!(h.escrow_state(&rebuilt).created_slot, h.clock().slot);

        let accounts = h.settle_accounts(rebuilt);
        let result = h.send_settle(&accounts, &old_verdict, Verdict::Release, expires_at);
        assert_error(&result, EscrowError::VerdictMessageMismatch);
        assert_eq!(h.token_balance(&accomplice_ata), 0);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
    });
}

/// A verdict cannot be revoked, only outrun.
///
/// The signer issues a refund and then changes its mind and issues a release
/// over the same escrow, with the same expiry, so nothing separates the two but
/// the order they are submitted in. Both are valid signatures over bytes the
/// program rebuilds from its own state, both are inside their expiry, and
/// `settle` has no privileged signer to ask which one is current — so both are
/// live, the one submitted first closes the escrow, and the other finds nothing
/// to act on.
///
/// There is no attack to stop here: the signer signed both, and the money goes
/// to a party the signer named. It is a property an integrator has to design
/// around, and the only lever is a short `expires_at`.
#[test]
fn two_verdicts_for_one_escrow_are_both_live_and_the_first_submitted_wins() {
    for_each_token_program(|kind| {
        // The signer refunds, then reverses itself. The refund was submitted,
        // so the release is worthless.
        first_submitted_wins(kind, Verdict::Refund);

        // And the mirror, which is the expensive direction for the buyer: the
        // release lands and the refund the signer issued afterwards is dead.
        first_submitted_wins(kind, Verdict::Release);
    });
}

/// Sign both verdicts for one escrow, submit `first`, and show that the other
/// one is already spent.
fn first_submitted_wins(kind: TokenKind, first: Verdict) {
    let second = match first {
        Verdict::Release => Verdict::Refund,
        Verdict::Refund => Verdict::Release,
    };

    let mut h = Harness::new(kind);
    let (escrow, result) = h.create_escrow(1);
    assert_ok(&result);
    let seller_ata = h.ata(&h.seller.pubkey());
    let buyer_ata = h.ata(&h.buyer.pubkey());

    // Identical expiries, so neither verdict is the fresher one by any measure
    // the program can take.
    let expires_at = h.now() + 600;
    let accounts = h.settle_accounts(escrow);
    let first_ix = h.verdict_ix(escrow, first, expires_at);
    let second_ix = h.verdict_ix(escrow, second, expires_at);

    assert_ok(&h.send_settle(&accounts, &first_ix, first, expires_at));
    assert!(
        !h.account_exists(&escrow),
        "the {first:?} closed the escrow"
    );
    assert!(!h.account_exists(&accounts.vault));

    let result = h.send_settle(&accounts, &second_ix, second, expires_at);
    assert_error(&result, AnchorError::AccountNotInitialized);

    let (seller, buyer) = match first {
        Verdict::Release => (ESCROW_AMOUNT, BUYER_START - ESCROW_AMOUNT),
        Verdict::Refund => (0, BUYER_START),
    };
    assert_eq!(
        h.token_balance(&seller_ata),
        seller,
        "the {first:?} paid out and the {second:?} did not"
    );
    assert_eq!(h.token_balance(&buyer_ata), buyer);
}
