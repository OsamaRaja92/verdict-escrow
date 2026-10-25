//! Whether the payout destination is there to be paid.
//!
//! Both exits transfer into a token account the program does not create. The
//! address is derived, so nobody can point it elsewhere — `destinations.rs`
//! covers that — but a derived address still has to hold a live account whose
//! recorded owner is the one the constraint expects. `Harness::new` creates the
//! seller's and the buyer's accounts up front, so no other test in the suite
//! ever sees one that is missing, closed or re-owned. These do.
//!
//! There are three ways a destination stops being usable, and the owner of the
//! account controls all three: never create it, close it once it is empty, or
//! hand its owner field to somebody else with `SetAuthority`. The first two
//! read as "not initialized" to Anchor, the third as a token-owner mismatch,
//! and under Token-2022 the third is not available at all — every associated
//! token account that program creates carries the `ImmutableOwner` extension.
//!
//! What that adds up to is worth stating plainly, because it is a property of
//! the design rather than a bug in it. A seller can refuse payment at will. A
//! release is not self-executing: the signed verdict says who should be paid,
//! and the seller decides whether a destination exists to pay. The deadline is
//! what stops that refusal becoming a lockup — `reclaim` does not touch the
//! seller's account at all, so the buyer's money comes home at the deadline no
//! matter what the seller has done to their own account.
//!
//! The same lever points the other way, and further. `Settle` takes both payout
//! accounts whichever way the verdict goes, so a buyer who closes their own
//! token account blocks the release they are not the payee of, and then
//! reclaims once the deadline passes. A release verdict therefore binds the
//! buyer only as long as the buyer cannot stall it past the deadline, which is
//! an argument for short deadlines rather than for a different program: no
//! money moves anywhere it should not, and the buyer who stalls gets back only
//! what they put in.
//!
//! A frozen destination stalls a payout the same way without the owner's
//! cooperation; that is the mint authority's reach, and it lives in
//! `mint_authority_attacks.rs`.

use anchor_lang::error::ErrorCode as AnchorError;
use anchor_lang::prelude::Pubkey;
use escrow_harness::*;
use litesvm::types::TransactionResult;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use verdict_escrow::verdict::Verdict;

/// A bare token account under either program: the 165-byte base layout.
const BASE_TOKEN_ACCOUNT_LEN: usize = 165;
/// What Token-2022's associated token accounts measure instead: the same base,
/// then the account-type byte, then `ImmutableOwner`'s four-byte header and no
/// payload.
const IMMUTABLE_OWNER_ACCOUNT_LEN: usize = BASE_TOKEN_ACCOUNT_LEN + 1 + 4;

/// Assert the error code *and* which account Anchor rejected.
///
/// Every test in this file is about one named destination, and the codes here
/// do not say which: `AccountNotInitialized` is the same number for a missing
/// escrow as for a missing seller account, and the buyer's slot is validated
/// on a release as well as on a refund. Anchor prints the account it refused
/// in the log line beside the code, so that line is part of the claim.
#[track_caller]
fn assert_error_on_account(
    result: &TransactionResult,
    expected: impl Into<u32> + Copy + std::fmt::Debug,
    account: &str,
) {
    assert_error(result, expected);
    let failure = result
        .as_ref()
        .err()
        .unwrap_or_else(|| panic!("assert_error already proved this one failed"));
    let logs = &failure.meta.logs;
    let line = format!("AnchorError caused by account: {account}.");
    assert!(
        logs.iter().any(|logged| logged.contains(&line)),
        "expected {expected:?} on {account}, and the logs name another account: {logs:?}"
    );
}

// --- the seller's side -----------------------------------------------------

/// The escrow names a seller who has never held this mint, so the release
/// destination does not exist. Nothing is wrong with the verdict; there is
/// simply no account to deserialize, and Anchor stops before any transfer.
///
/// The second half is the resolution path a real deployment would use.
/// Creating an associated token account needs nobody's permission and the
/// relayer is already paying the fee, so the relayer creates the seller's
/// account and settles in one transaction — with the verdict still immediately
/// before `settle`, which is all the program asks of the ordering.
#[test]
fn a_release_to_a_seller_with_no_token_account_is_refused_until_someone_creates_it() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let buyer = h.buyer.pubkey();

        // Deliberately not `h.seller`, whose account the harness creates.
        let seller = Keypair::new().pubkey();
        let deadline = h.now() + HOUR;
        let ix = h.create_escrow_ix(
            &buyer,
            1,
            ESCROW_AMOUNT,
            deadline,
            seller,
            h.verdict_signer.pubkey(),
        );
        let signer = h.buyer.insecure_clone();
        assert_ok(&h.send(&[ix], &[&signer]));

        let escrow = h.escrow_pda(&buyer, 1);
        let vault = ata_for(&escrow, &h.mint, &h.token_program);
        let seller_ata = ata_for(&seller, &h.mint, &h.token_program);
        assert!(
            !h.account_exists(&seller_ata),
            "the seller has no token account for this mint"
        );

        let expires_at = h.now() + 600;
        let result = h.settle(escrow, Verdict::Release, expires_at);
        assert_error_on_account(
            &result,
            AnchorError::AccountNotInitialized,
            "seller_token_account",
        );
        assert_eq!(h.token_balance(&vault), ESCROW_AMOUNT);
        assert!(h.account_exists(&escrow), "nothing was closed");

        let accounts = h.settle_accounts(escrow);
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let settle_ix = accounts.instruction(Verdict::Release, expires_at);
        let relayer = h.relayer.insecure_clone();
        let create_ix = create_ata_ix(&relayer.pubkey(), &seller, &h.mint, &h.token_program);
        assert_ok(&h.send(
            &[create_ix, verdict_ix.instruction(), settle_ix],
            &[&relayer],
        ));

        assert_eq!(h.token_balance(&seller_ata), ESCROW_AMOUNT);
        assert!(!h.account_exists(&escrow));
        assert!(!h.account_exists(&vault));
    });
}

/// The seller closes the account the release would pay, after the escrow is
/// funded. An empty token account is the owner's to close, and the seller's is
/// empty until it is paid, so this costs the seller one transaction and takes
/// nobody's cooperation. The address stops existing and the release has nowhere
/// to land.
///
/// It blocks the release and nothing else: the escrow, the vault and the
/// recorded amount are untouched, and the same verdict lands once the account
/// is back. Recreating it needs no signature from the seller either.
#[test]
fn a_seller_who_closes_their_token_account_blocks_a_release_until_it_is_recreated() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let vault = ata_for(&escrow, &h.mint, &h.token_program);
        let seller_ata = h.ata(&h.seller.pubkey());

        let seller = h.seller.insecure_clone();
        let ix = close_account_ix(
            &h.token_program,
            &seller_ata,
            &seller.pubkey(),
            &seller.pubkey(),
        );
        assert_ok(&h.send(&[ix], &[&seller]));
        assert!(
            !h.account_exists(&seller_ata),
            "closing an empty token account frees the address"
        );

        let expires_at = h.now() + 600;
        let result = h.settle(escrow, Verdict::Release, expires_at);
        assert_error_on_account(
            &result,
            AnchorError::AccountNotInitialized,
            "seller_token_account",
        );
        assert_eq!(h.token_balance(&vault), ESCROW_AMOUNT);
        assert_eq!(h.escrow_state(&escrow).amount, ESCROW_AMOUNT);

        h.create_ata(&seller.pubkey());
        assert_ok(&h.settle(escrow, Verdict::Release, expires_at));
        assert_eq!(h.token_balance(&seller_ata), ESCROW_AMOUNT);
        assert!(!h.account_exists(&vault));
    });
}

/// The limit of that refusal. `reclaim` pays the buyer and names no account of
/// the seller's, so a seller who has closed their own account cannot keep the
/// buyer's money parked past the deadline. This is the escape that makes the
/// refusal above a seller's own loss rather than a hostage situation.
#[test]
fn a_seller_who_closes_their_token_account_cannot_block_the_buyers_reclaim() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let vault = ata_for(&escrow, &h.mint, &h.token_program);
        let buyer_ata = h.ata(&h.buyer.pubkey());

        let seller = h.seller.insecure_clone();
        let seller_ata = h.ata(&seller.pubkey());
        let ix = close_account_ix(
            &h.token_program,
            &seller_ata,
            &seller.pubkey(),
            &seller.pubkey(),
        );
        assert_ok(&h.send(&[ix], &[&seller]));

        let deadline = h.escrow_state(&escrow).deadline;
        h.set_time(deadline);
        assert_ok(&h.reclaim(escrow));

        assert_eq!(h.token_balance(&buyer_ata), BUYER_START);
        assert!(!h.account_exists(&vault));
        assert!(!h.account_exists(&escrow));
    });
}

/// The third way out of being paid: keep the account and give away its owner
/// field. `SetAuthority` with `AccountOwner` is the account owner's own
/// instruction, so the seller needs nobody's agreement for it.
///
/// What it buys depends on the token program, and the answer is not the same on
/// both, so both are asserted here. Under the classic program the owner field
/// is the seller's to hand over: the address still derives correctly, but
/// Anchor's destination pin is on the recorded owner, so the release is refused
/// with a token-owner mismatch and the buyer's reclaim is again the escape.
/// Under Token-2022 the associated token program gives every account it creates
/// the `ImmutableOwner` extension, so there is no owner to hand over — the
/// re-own is refused by the token program itself and the release is unaffected.
#[test]
fn re_owning_the_seller_token_account_blocks_a_release_under_classic_token_only() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let vault = ata_for(&escrow, &h.mint, &h.token_program);
        let seller = h.seller.insecure_clone();
        let seller_ata = h.ata(&seller.pubkey());

        let stranger = Keypair::new().pubkey();
        let ix = set_account_owner_ix(&h.token_program, &seller_ata, &seller.pubkey(), &stranger);
        let re_own = h.send(&[ix], &[&seller]);

        let expires_at = h.now() + 600;
        let account_len = h
            .svm
            .get_account(&seller_ata)
            .expect("the seller's token account exists")
            .data
            .len();

        match kind {
            TokenKind::Classic => {
                assert_eq!(account_len, BASE_TOKEN_ACCOUNT_LEN, "no extensions");
                assert_ok(&re_own);

                let result = h.settle(escrow, Verdict::Release, expires_at);
                assert_error_on_account(
                    &result,
                    AnchorError::ConstraintTokenOwner,
                    "seller_token_account",
                );
                assert_eq!(h.token_balance(&vault), ESCROW_AMOUNT);

                let deadline = h.escrow_state(&escrow).deadline;
                h.set_time(deadline);
                assert_ok(&h.reclaim(escrow));
                assert_eq!(h.token_balance(&h.ata(&h.buyer.pubkey())), BUYER_START);
            }
            TokenKind::Token2022 => {
                assert_eq!(
                    account_len, IMMUTABLE_OWNER_ACCOUNT_LEN,
                    "the associated token program added ImmutableOwner"
                );
                assert_error(&re_own, TokenError::ImmutableOwner);

                assert_ok(&h.settle(escrow, Verdict::Release, expires_at));
                assert_eq!(h.token_balance(&seller_ata), ESCROW_AMOUNT);
            }
        }
    });
}

// --- the buyer's side ------------------------------------------------------

/// The refund destination, missing. The buyer's token account has to exist to
/// fund the escrow in the first place, so the only way for it to be gone by the
/// time a refund arrives is for the buyer to close it afterwards — which needs
/// the account empty, so the buyer escrows the whole balance here.
///
/// The same resolution path works, for the same reason: the relayer creates the
/// buyer's account and settles in one transaction.
#[test]
fn a_refund_to_a_buyer_with_no_token_account_is_refused_until_someone_creates_it() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let deadline = h.now() + HOUR;
        let (escrow, result) = h.create_escrow_with(1, BUYER_START, deadline);
        assert_ok(&result);
        let vault = ata_for(&escrow, &h.mint, &h.token_program);
        let buyer = h.buyer.insecure_clone();
        let buyer_ata = h.ata(&buyer.pubkey());
        assert_eq!(h.token_balance(&buyer_ata), 0, "the buyer escrowed it all");

        let ix = close_account_ix(
            &h.token_program,
            &buyer_ata,
            &buyer.pubkey(),
            &buyer.pubkey(),
        );
        assert_ok(&h.send(&[ix], &[&buyer]));
        assert!(!h.account_exists(&buyer_ata));

        let expires_at = h.now() + 600;
        let result = h.settle(escrow, Verdict::Refund, expires_at);
        assert_error_on_account(
            &result,
            AnchorError::AccountNotInitialized,
            "buyer_token_account",
        );
        assert_eq!(h.token_balance(&vault), BUYER_START);

        let accounts = h.settle_accounts(escrow);
        let verdict_ix = h.verdict_ix(escrow, Verdict::Refund, expires_at);
        let settle_ix = accounts.instruction(Verdict::Refund, expires_at);
        let relayer = h.relayer.insecure_clone();
        let create_ix = create_ata_ix(
            &relayer.pubkey(),
            &buyer.pubkey(),
            &h.mint,
            &h.token_program,
        );
        assert_ok(&h.send(
            &[create_ix, verdict_ix.instruction(), settle_ix],
            &[&relayer],
        ));

        assert_eq!(h.token_balance(&buyer_ata), BUYER_START);
        assert!(!h.account_exists(&escrow));
        assert!(!h.account_exists(&vault));
    });
}

/// What a closed buyer account reaches that a closed seller account does not.
///
/// `Settle` takes both payout accounts whichever way the verdict goes, so the
/// buyer's account is validated on a release the buyer is not the payee of —
/// and a buyer who closes it blocks that release. `reclaim` pays the same
/// account, so the buyer's own exit is blocked too: this is a buyer locking up
/// their own money, not taking anyone else's.
///
/// Recreating the account is the way out and needs no signature from the buyer,
/// so the relayer does it here. Note what the sequence buys the buyer: having
/// stalled the release until the deadline, the buyer reclaims instead. Nothing
/// moves that should not, and the seller's protection against it is a deadline
/// short enough to be worth less than the deal.
#[test]
fn a_closed_buyer_token_account_blocks_a_release_and_the_buyers_own_reclaim() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let deadline = h.now() + HOUR;
        let (escrow, result) = h.create_escrow_with(1, BUYER_START, deadline);
        assert_ok(&result);
        let vault = ata_for(&escrow, &h.mint, &h.token_program);
        let buyer = h.buyer.insecure_clone();
        let buyer_ata = h.ata(&buyer.pubkey());

        let ix = close_account_ix(
            &h.token_program,
            &buyer_ata,
            &buyer.pubkey(),
            &buyer.pubkey(),
        );
        assert_ok(&h.send(&[ix], &[&buyer]));

        let expires_at = h.now() + 600;
        let result = h.settle(escrow, Verdict::Release, expires_at);
        assert_error_on_account(
            &result,
            AnchorError::AccountNotInitialized,
            "buyer_token_account",
        );
        assert_eq!(h.token_balance(&h.ata(&h.seller.pubkey())), 0);
        assert_eq!(h.token_balance(&vault), BUYER_START);

        h.set_time(deadline);
        let result = h.reclaim(escrow);
        assert_error_on_account(
            &result,
            AnchorError::AccountNotInitialized,
            "buyer_token_account",
        );
        assert_eq!(h.token_balance(&vault), BUYER_START);

        let relayer = h.relayer.insecure_clone();
        let create_ix = create_ata_ix(
            &relayer.pubkey(),
            &buyer.pubkey(),
            &h.mint,
            &h.token_program,
        );
        assert_ok(&h.send(&[create_ix], &[&relayer]));
        assert_ok(&h.reclaim(escrow));

        assert_eq!(h.token_balance(&buyer_ata), BUYER_START);
        assert!(!h.account_exists(&vault));
        assert!(!h.account_exists(&escrow));
    });
}

/// The re-own, on the buyer's side. Under the classic program the buyer hands
/// the account — and the balance still in it — to a stranger, which blocks the
/// refund and `reclaim` alike on the recorded owner. The money is parked rather
/// than lost: the new owner can hand the account back, and then the buyer's
/// reclaim lands. Under Token-2022 `ImmutableOwner` refuses the whole move and
/// the refund is unaffected.
#[test]
fn re_owning_the_buyer_token_account_blocks_both_exits_under_classic_token_only() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let vault = ata_for(&escrow, &h.mint, &h.token_program);
        let buyer = h.buyer.insecure_clone();
        let buyer_ata = h.ata(&buyer.pubkey());

        let stranger = Keypair::new();
        let ix = set_account_owner_ix(
            &h.token_program,
            &buyer_ata,
            &buyer.pubkey(),
            &stranger.pubkey(),
        );
        let re_own = h.send(&[ix], &[&buyer]);

        let expires_at = h.now() + 600;
        let relayer = h.relayer.insecure_clone();

        match kind {
            TokenKind::Classic => {
                assert_ok(&re_own);

                let result = h.settle(escrow, Verdict::Refund, expires_at);
                assert_error_on_account(
                    &result,
                    AnchorError::ConstraintTokenOwner,
                    "buyer_token_account",
                );
                assert_eq!(h.token_balance(&vault), ESCROW_AMOUNT);

                let deadline = h.escrow_state(&escrow).deadline;
                h.set_time(deadline);
                let result = h.reclaim(escrow);
                assert_error_on_account(
                    &result,
                    AnchorError::ConstraintTokenOwner,
                    "buyer_token_account",
                );
                assert_eq!(h.token_balance(&vault), ESCROW_AMOUNT);

                // Handed back by its new owner, with the relayer paying the
                // fee so the stranger needs no lamports of its own.
                let ix = set_account_owner_ix(
                    &h.token_program,
                    &buyer_ata,
                    &stranger.pubkey(),
                    &buyer.pubkey(),
                );
                assert_ok(&h.send(&[ix], &[&relayer, &stranger]));
                assert_ok(&h.reclaim(escrow));
                assert_eq!(h.token_balance(&buyer_ata), BUYER_START);
            }
            TokenKind::Token2022 => {
                assert_error(&re_own, TokenError::ImmutableOwner);

                assert_ok(&h.settle(escrow, Verdict::Refund, expires_at));
                assert_eq!(h.token_balance(&buyer_ata), BUYER_START);
                assert!(!h.account_exists(&vault));
            }
        }
    });
}

// --- the token programs and the associated token program, by hand ----------
//
// The builder crate sends each of these in a transaction of its own and
// returns a result type the suite's assertions cannot read, and two tests
// above need the account creation inside the same transaction as `settle`. So
// the three instructions are assembled from their documented layouts. Both
// token programs share the layouts, and the error numbers as far as the
// classic one goes.

/// Instruction tags, identical in both token programs.
const CLOSE_ACCOUNT: u8 = 9;
const SET_AUTHORITY: u8 = 6;

/// `AuthorityType::AccountOwner`, as `SetAuthority` encodes it.
const AUTHORITY_ACCOUNT_OWNER: u8 = 2;

/// The associated token program's `Create`, which is its first instruction and
/// fails if the account already exists. `CreateIdempotent` is tag 1.
const CREATE: u8 = 0;

/// Token-2022's own error for an owner change on an account carrying the
/// `ImmutableOwner` extension, which is every associated token account that
/// program creates. The number is positional in SPL's error enum; the log line
/// is "The owner authority cannot be changed".
#[derive(Clone, Copy, Debug)]
#[repr(u32)]
enum TokenError {
    ImmutableOwner = 34,
}

impl From<TokenError> for u32 {
    fn from(error: TokenError) -> Self {
        error as u32
    }
}

/// Create `owner`'s associated token account for `mint`, paid for by `payer`.
/// The account address is derived rather than passed, which is why anyone can
/// send this for anyone else.
fn create_ata_ix(
    payer: &Pubkey,
    owner: &Pubkey,
    mint: &Pubkey,
    token_program: &Pubkey,
) -> Instruction {
    Instruction {
        program_id: ASSOCIATED_TOKEN_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(ata_for(owner, mint, token_program), false),
            AccountMeta::new_readonly(*owner, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            AccountMeta::new_readonly(*token_program, false),
        ],
        data: vec![CREATE],
    }
}

/// Close an empty token account, sending its rent to `destination`. The
/// account's recorded owner must sign.
fn close_account_ix(
    token_program: &Pubkey,
    account: &Pubkey,
    destination: &Pubkey,
    owner: &Pubkey,
) -> Instruction {
    Instruction {
        program_id: *token_program,
        accounts: vec![
            AccountMeta::new(*account, false),
            AccountMeta::new(*destination, false),
            AccountMeta::new_readonly(*owner, true),
        ],
        data: vec![CLOSE_ACCOUNT],
    }
}

/// Hand a token account's owner field to `new_owner`. The current owner signs;
/// the trailing `1` is the `COption::Some` tag before the new authority.
fn set_account_owner_ix(
    token_program: &Pubkey,
    account: &Pubkey,
    owner: &Pubkey,
    new_owner: &Pubkey,
) -> Instruction {
    let mut data = vec![SET_AUTHORITY, AUTHORITY_ACCOUNT_OWNER, 1];
    data.extend_from_slice(&new_owner.to_bytes());
    Instruction {
        program_id: *token_program,
        accounts: vec![
            AccountMeta::new(*account, false),
            AccountMeta::new_readonly(*owner, true),
        ],
        data,
    }
}
