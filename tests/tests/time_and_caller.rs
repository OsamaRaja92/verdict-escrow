//! The deadline, and who is allowed to act on either side of it.
//!
//! Before the deadline only a verdict can move the money; at or after it, only
//! the buyer. The two windows do not overlap, so `settle` and `reclaim` cannot
//! race for the same vault.

use anchor_lang::error::ErrorCode as AnchorError;
use escrow_harness::*;
use solana_keypair::Keypair;
use verdict_escrow::errors::EscrowError;
use verdict_escrow::verdict::Verdict;

#[test]
fn settle_at_the_deadline_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let deadline = h.escrow_state(&escrow).deadline;

        // The deadline second itself belongs to the buyer, not the verdict.
        h.set_time(deadline);
        let result = h.settle(escrow, Verdict::Release, deadline + 600);
        assert_error(&result, EscrowError::DeadlinePassed);
        assert_eq!(
            h.token_balance(&ata_for(&escrow, &h.mint, &h.token_program)),
            ESCROW_AMOUNT
        );
    });
}

#[test]
fn settle_after_the_deadline_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let deadline = h.escrow_state(&escrow).deadline;

        h.set_time(deadline + 3_600);
        let result = h.settle(escrow, Verdict::Release, deadline + 7_200);
        assert_error(&result, EscrowError::DeadlinePassed);
    });
}

#[test]
fn settle_one_second_before_the_deadline_still_works() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let deadline = h.escrow_state(&escrow).deadline;

        h.set_time(deadline - 1);
        let result = h.settle(escrow, Verdict::Release, deadline);
        assert_ok(&result);
        assert_eq!(h.token_balance(&h.ata(&h.seller.pubkey())), ESCROW_AMOUNT);
    });
}

#[test]
fn reclaim_before_the_deadline_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let deadline = h.escrow_state(&escrow).deadline;

        h.set_time(deadline - 1);
        let result = h.reclaim(escrow);
        assert_error(&result, EscrowError::DeadlineNotReached);
        assert_eq!(
            h.token_balance(&ata_for(&escrow, &h.mint, &h.token_program)),
            ESCROW_AMOUNT
        );
    });
}

#[test]
fn reclaim_by_anyone_other_than_the_buyer_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let deadline = h.escrow_state(&escrow).deadline;
        h.set_time(deadline);

        // A stranger, signing for themselves, pointing at someone else's
        // escrow and their own token account.
        let stranger = Keypair::new();
        h.svm.airdrop(&stranger.pubkey(), 1_000_000_000).unwrap();
        h.create_ata(&stranger.pubkey());

        let state = h.escrow_state(&escrow);
        let ix = solana_instruction::Instruction {
            program_id: verdict_escrow::ID,
            accounts: anchor_lang::ToAccountMetas::to_account_metas(
                &verdict_escrow::accounts::Reclaim {
                    escrow,
                    buyer: stranger.pubkey(),
                    mint: state.mint,
                    vault: ata_for(&escrow, &state.mint, &h.token_program),
                    buyer_token_account: ata_for(&stranger.pubkey(), &state.mint, &h.token_program),
                    token_program: h.token_program,
                },
                None,
            ),
            data: anchor_lang::InstructionData::data(&verdict_escrow::instruction::Reclaim {}),
        };
        let result = h.send(&[ix], &[&stranger]);

        // The escrow records its buyer; the account passed in has to be that
        // same key, and it has to have signed.
        assert_error(&result, AnchorError::ConstraintHasOne);
        assert_eq!(
            h.token_balance(&ata_for(&escrow, &h.mint, &h.token_program)),
            ESCROW_AMOUNT
        );
    });
}

#[test]
fn settle_needs_no_privileged_signer() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        // A stranger who has never touched this escrow pays the fee and sends
        // the verdict. The signature is the authority, not the sender.
        let stranger = Keypair::new();
        h.svm.airdrop(&stranger.pubkey(), 1_000_000_000).unwrap();

        let expires_at = h.now() + 600;
        let accounts = h.settle_accounts(escrow);
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let settle_ix = accounts.instruction(Verdict::Release, expires_at);
        let result = h.send(&[verdict_ix.instruction(), settle_ix], &[&stranger]);

        assert_ok(&result);
        assert_eq!(h.token_balance(&h.ata(&h.seller.pubkey())), ESCROW_AMOUNT);
    });
}

/// `has_one` pins *which* key the buyer must be. This is the other half: that
/// key must also have signed. Anchor's `Signer` type enforces it, and nothing
/// else in the instruction would.
#[test]
fn reclaim_without_the_buyers_signature_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let deadline = h.escrow_state(&escrow).deadline;
        h.set_time(deadline);

        // The real buyer's address, in the right place, but not marked as a
        // signer — so the runtime never asks for its signature.
        let mut ix = h.reclaim_ix(escrow);
        let buyer = h.buyer.pubkey();
        let buyer_meta = ix
            .accounts
            .iter_mut()
            .find(|meta| meta.pubkey == buyer)
            .expect("the buyer is one of the accounts");
        assert!(buyer_meta.is_signer, "it should have been a signer");
        buyer_meta.is_signer = false;

        let stranger = Keypair::new();
        h.svm.airdrop(&stranger.pubkey(), 1_000_000_000).unwrap();
        let result = h.send(&[ix], &[&stranger]);

        assert_error(&result, AnchorError::AccountNotSigner);
        assert_eq!(
            h.token_balance(&ata_for(&escrow, &h.mint, &h.token_program)),
            ESCROW_AMOUNT
        );
    });
}
