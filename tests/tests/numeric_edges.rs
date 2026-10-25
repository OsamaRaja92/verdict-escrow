//! Arithmetic and boundary values.
//!
//! An escrow is a number moved into one account and out of another, so every
//! place the program adds, compares or stores one is a place money can appear
//! from nowhere or quietly vanish. These tests push each number the program
//! touches to the ends of its type: the amount to one base unit and to
//! `u64::MAX`, the deadline and the verdict expiry to both ends of `i64`, the
//! escrow id and the creation slot to 0 and `u64::MAX`. The pass condition is
//! never "it did not crash". It is that the balance afterwards is exactly the
//! number that went in, and that the comparison at each boundary falls the way
//! the rules say it does.
//!
//! One guard gets a section of its own. `create_escrow` adds the deposit to
//! whatever the vault already held, under a `checked_add` guarded by
//! `EscrowError::VaultBalanceOverflow`. Whether that sum can overflow at all
//! is a question about the token program rather than about this one, and the
//! four tests under (c) answer it rather than assuming it.
//!
//! One fact about the runtime is worth stating outright, because nothing in
//! the code says it and section (c) turns on it. `LiteSVM::new()` activates
//! every feature the runtime knows about, and one of those features is
//! `replace_spl_token_with_p_token`. With it active litesvm serves the account
//! at `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA` from its bundled
//! `pinocchio_token_program.so` rather than from `spl_token`, so what this
//! suite calls the classic token program is p-token, the Core BPF replacement,
//! and not the program that id has historically meant. That is invisible
//! almost everywhere — the two agree on the instructions and the error codes
//! the rest of the suite uses — and decisive in exactly one place, because
//! p-token's transfer credits the destination without a checked add and
//! `spl_token`'s does not. [`assert_classic_address_serves_p_token`] pins it,
//! so a change to litesvm's feature snapshot arrives named rather than as an
//! unexplained diff in a balance.
//!
//! Boundaries covered elsewhere are not repeated here: `settle` at the
//! deadline and `reclaim` before it are in `time_and_caller.rs`, a deadline of
//! right now is in `creation.rs`, and an `expires_at` of exactly now is in
//! `forged_verdicts.rs`.

use anchor_lang::prelude::Pubkey;
use escrow_harness::*;
use litesvm::types::TransactionResult;
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_sdk_ids::{bpf_loader, bpf_loader_upgradeable};
use verdict_escrow::errors::EscrowError;
use verdict_escrow::verdict::Verdict;

/// `TokenError::Overflow`, the fifteenth variant of an error enum both token
/// programs share, raised when a credit would take a balance or a mint supply
/// past `u64::MAX`.
const TOKEN_OVERFLOW: u32 = 14;

/// Mint `amount` more of the harness mint to `to`, built as a plain
/// instruction rather than taken from the helper, so a refusal comes back as a
/// result to assert on instead of a panic. Discriminator 7 is `MintTo` under
/// both token programs, and the harness mint's authority is the buyer.
fn mint_to(h: &mut Harness, to: &Pubkey, amount: u64) -> TransactionResult {
    let mut data = vec![7u8];
    data.extend_from_slice(&amount.to_le_bytes());
    let ix = Instruction {
        program_id: h.token_program,
        accounts: vec![
            AccountMeta::new(h.mint, false),
            AccountMeta::new(*to, false),
            AccountMeta::new_readonly(h.buyer.pubkey(), true),
        ],
        data,
    };
    let signer = h.buyer.insecure_clone();
    h.send(&[ix], &[&signer])
}

/// Top the buyer up to `u64::MAX` of the mint, which is the most any one
/// account can hold and, once held, the whole supply.
fn give_buyer_everything(h: &mut Harness) {
    let buyer_ata = h.ata(&h.buyer.pubkey());
    let held = h.token_balance(&buyer_ata);
    assert_ok(&mint_to(h, &buyer_ata, u64::MAX - held));
    assert_eq!(h.token_balance(&buyer_ata), u64::MAX);
}

/// Write a balance straight into a token account, bypassing the token
/// program's own accounting. Only the `amount` field at bytes 64..72 changes,
/// so every other field stays exactly as the token program left it.
///
/// This produces a state no token program would ever produce, which is the
/// point: it is the only way to put the vault near the top of the range, and
/// that it takes a planted account is itself most of the answer to whether the
/// overflow guard can fire in production.
fn plant_token_balance(h: &mut Harness, token_account: &Pubkey, amount: u64) {
    let existing = h
        .svm
        .get_account(token_account)
        .expect("the token account exists");
    let mut data = existing.data.clone();
    data[64..72].copy_from_slice(&amount.to_le_bytes());
    h.svm
        .set_account(
            *token_account,
            Account {
                lamports: existing.lamports,
                data,
                owner: existing.owner,
                executable: existing.executable,
                rent_epoch: existing.rent_epoch,
            },
        )
        .expect("plant the balance");
    assert_eq!(h.token_balance(token_account), amount);
}

/// Assert which binary is answering at the classic token program's address.
///
/// The two candidates arrive under different loaders, which is what makes this
/// checkable from outside: litesvm installs `pinocchio_token_program.so` with
/// the upgradeable loader and `spl_token-3.5.0.so` with BPFLoader2, so the
/// account's owner names the binary without reading a byte of it.
///
/// Worth asserting rather than assuming, because the fact is not a property of
/// this repository. It comes from whichever feature set the installed litesvm
/// happens to ship, and the test below is the one place in the suite whose
/// expected outcome would change if that answer changed.
#[track_caller]
fn assert_classic_address_serves_p_token(h: &Harness) {
    let account = h
        .svm
        .get_account(&TOKEN_PROGRAM_ID)
        .expect("the classic token program is loaded");
    assert_eq!(
        account.owner,
        bpf_loader_upgradeable::ID,
        "litesvm is serving {TOKEN_PROGRAM_ID} from spl_token-3.5.0, under \
         {}, rather than from p-token, under {}, so its feature set no longer \
         activates replace_spl_token_with_p_token. The wrapping transfer this \
         test depends on is p-token's; measure spl_token's before changing \
         what the test expects.",
        bpf_loader::ID,
        bpf_loader_upgradeable::ID,
    );
}

/// A vault planted at `balance`, and a buyer depositing `amount` into it.
/// Returns the escrow address, the vault address and the result.
fn deposit_into_a_planted_vault(
    h: &mut Harness,
    balance: u64,
    amount: u64,
) -> (Pubkey, Pubkey, TransactionResult) {
    let buyer = h.buyer.pubkey();
    let escrow = h.escrow_pda(&buyer, 1);
    // A stranger may create the vault before the escrow exists, which is how
    // it comes to hold anything at deposit time at all.
    let vault = h.create_ata(&escrow);
    plant_token_balance(h, &vault, balance);

    let deadline = h.now() + HOUR;
    let (opened, result) = h.create_escrow_with(1, amount, deadline);
    assert_eq!(opened, escrow);
    (escrow, vault, result)
}

// --- (a) the whole range -------------------------------------------------

/// The largest escrow the type allows. Nothing in the program scales the
/// amount, takes a percentage of it or converts it, so the seller receives the
/// deposit to the base unit.
#[test]
fn an_escrow_of_the_entire_u64_range_pays_the_seller_exactly() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        give_buyer_everything(&mut h);
        let buyer_ata = h.ata(&h.buyer.pubkey());
        let seller_ata = h.ata(&h.seller.pubkey());

        let deadline = h.now() + HOUR;
        let (escrow, result) = h.create_escrow_with(1, u64::MAX, deadline);
        assert_ok(&result);
        let vault = ata_for(&escrow, &h.mint, &h.token_program);
        assert_eq!(h.token_balance(&vault), u64::MAX);
        assert_eq!(h.token_balance(&buyer_ata), 0);
        assert_eq!(h.escrow_state(&escrow).amount, u64::MAX);

        let expires_at = h.now() + 600;
        assert_ok(&h.settle(escrow, Verdict::Release, expires_at));
        assert_eq!(h.token_balance(&seller_ata), u64::MAX);
        assert_eq!(h.token_balance(&buyer_ata), 0);
        assert!(!h.account_exists(&vault), "vault should be closed");
        assert!(!h.account_exists(&escrow), "escrow should be closed");
    });
}

/// The same deposit taken back instead. Funding it emptied the buyer's
/// account, so the balance afterwards is the whole range again rather than a
/// sum in which a lost unit could hide.
#[test]
fn an_escrow_of_the_entire_u64_range_is_reclaimed_exactly() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        give_buyer_everything(&mut h);
        let buyer_ata = h.ata(&h.buyer.pubkey());

        let deadline = h.now() + HOUR;
        let (escrow, result) = h.create_escrow_with(1, u64::MAX, deadline);
        assert_ok(&result);
        assert_eq!(h.token_balance(&buyer_ata), 0);

        h.set_time(deadline);
        assert_ok(&h.reclaim(escrow));
        assert_eq!(h.token_balance(&buyer_ata), u64::MAX);
        assert_eq!(h.token_balance(&h.ata(&h.seller.pubkey())), 0);
        assert!(!h.account_exists(&escrow), "escrow should be closed");
    });
}

// --- (b) one base unit ---------------------------------------------------

/// The smallest escrow that is not the zero `create_escrow` refuses. Rounding
/// or truncation anywhere on the payout path would land this one at nothing.
#[test]
fn an_escrow_of_one_base_unit_pays_that_one_unit() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let seller_ata = h.ata(&h.seller.pubkey());

        let deadline = h.now() + HOUR;
        let (escrow, result) = h.create_escrow_with(1, 1, deadline);
        assert_ok(&result);
        let vault = ata_for(&escrow, &h.mint, &h.token_program);
        assert_eq!(h.token_balance(&vault), 1);
        assert_eq!(h.token_balance(&h.ata(&h.buyer.pubkey())), BUYER_START - 1);
        assert_eq!(h.escrow_state(&escrow).amount, 1);

        let expires_at = h.now() + 600;
        assert_ok(&h.settle(escrow, Verdict::Release, expires_at));
        assert_eq!(h.token_balance(&seller_ata), 1);
        assert!(!h.account_exists(&vault), "vault should be closed");
    });
}

// --- (c) the vault balance plus the deposit ------------------------------

/// The last sum that does not overflow: a vault one unit short of the top of
/// the range, and the one unit that fills it. `checked_add` returns exactly
/// `u64::MAX`, the equality check against the reloaded balance holds, and the
/// escrow opens recording the single unit it was given.
///
/// The payout is the whole vault rather than the recorded amount, so the full
/// range leaves in one transfer. That is the behaviour the donation test in
/// `creation.rs` describes, at the largest value it can take.
#[test]
fn a_vault_one_unit_short_of_the_range_accepts_the_unit_that_fills_it() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, vault, result) = deposit_into_a_planted_vault(&mut h, u64::MAX - 1, 1);
        assert_ok(&result);
        assert_eq!(h.token_balance(&vault), u64::MAX);
        assert_eq!(h.escrow_state(&escrow).amount, 1);

        let expires_at = h.now() + 600;
        assert_ok(&h.settle(escrow, Verdict::Release, expires_at));
        assert_eq!(h.token_balance(&h.ata(&h.seller.pubkey())), u64::MAX);
    });
}

/// Why that sum cannot be made to overflow on a live chain, stated as a test
/// rather than as a comment.
///
/// The deposit comes out of the buyer's account, and the vault's balance and
/// the buyer's are both counted in a mint supply that is itself a `u64` with a
/// checked add on issuance. Once any account holds the whole range there is
/// nothing left to issue, so the vault's balance plus anything a buyer can
/// send is at most the supply, at most `u64::MAX`. Both token programs enforce
/// that, and this is the error they enforce it with.
#[test]
fn the_mint_supply_is_why_the_vault_overflow_guard_cannot_fire() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        give_buyer_everything(&mut h);
        let escrow = h.escrow_pda(&h.buyer.pubkey(), 1);
        let vault = h.create_ata(&escrow);

        let result = mint_to(&mut h, &vault, 1);
        assert_eq!(
            custom_error_code(&result),
            Some(TOKEN_OVERFLOW),
            "minting past the supply cap must be refused"
        );
        assert_eq!(h.token_balance(&vault), 0);
    });
}

/// With the state planted anyway, Token-2022 is the token program that stops
/// the deposit before this program's guard is reached.
///
/// `transfer_checked` runs before the `checked_add`, and Token-2022 credits
/// the destination with a checked add of its own, so the CPI fails and the
/// whole transaction is rolled back with the token program's error rather than
/// this program's. Under this token program the guard behind it is unreachable
/// for two independent reasons: the supply cap above, and this ordering.
#[test]
fn token_2022_stops_a_deposit_past_the_top_of_the_range_itself() {
    let mut h = Harness::new(TokenKind::Token2022);
    let (escrow, vault, result) = deposit_into_a_planted_vault(&mut h, u64::MAX, 1);

    assert_eq!(custom_error_code(&result), Some(TOKEN_OVERFLOW));
    assert!(!h.account_exists(&escrow), "no escrow may be left behind");
    assert_eq!(h.token_balance(&vault), u64::MAX, "rolled back");
}

/// The classic token program does not stop it, and this is the test that shows
/// the guard earning its place.
///
/// The classic program id in this runtime is served by p-token, the Core BPF
/// replacement, because litesvm's default feature set has that swap turned on
/// — which the first line of the test asserts rather than assuming, since it is
/// litesvm's choice and not this suite's. Its transfer credits the destination
/// without a checked add: on a chain the supply cap already guarantees the sum
/// fits, so the check would be dead weight in the busiest instruction on the
/// network. Measured straight against the token program, a destination holding
/// `u64::MAX - 3` that is sent 10 units ends up holding 6, and the transfer
/// reports success.
///
/// So under this token program nothing below the escrow catches the overflow,
/// and `EscrowError::VaultBalanceOverflow` is what refuses the transaction.
/// Without it the deposit check would compare a wrapped expectation against a
/// wrapped balance, the two would agree, and the escrow would open recording
/// an amount its vault does not hold. The guard is still out of reach through
/// any sequence of instructions a chain allows, which is the honest summary of
/// it: not dead code, but the check that keeps a wrapping token program from
/// becoming this program's problem.
#[test]
fn the_classic_token_program_wraps_and_leaves_the_guard_to_refuse_it() {
    let mut h = Harness::new(TokenKind::Classic);
    assert_classic_address_serves_p_token(&h);
    let (escrow, vault, result) = deposit_into_a_planted_vault(&mut h, u64::MAX, 1);

    assert_error(&result, EscrowError::VaultBalanceOverflow);
    assert!(!h.account_exists(&escrow), "no escrow may be left behind");
    assert_eq!(h.token_balance(&vault), u64::MAX, "rolled back");
}

// --- (d) the deadline at both ends ---------------------------------------

/// A deadline at the end of representable time. `settle` compares the clock
/// against it with a strict less-than, which holds for every clock value but
/// `i64::MAX` itself, so the verdict window is effectively the whole of time.
#[test]
fn a_deadline_at_the_end_of_time_settles() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow_with(1, ESCROW_AMOUNT, i64::MAX);
        assert_ok(&result);
        assert_eq!(h.escrow_state(&escrow).deadline, i64::MAX);

        let expires_at = h.now() + 600;
        assert_ok(&h.settle(escrow, Verdict::Release, expires_at));
        assert_eq!(h.token_balance(&h.ata(&h.seller.pubkey())), ESCROW_AMOUNT);
    });
}

/// The other side of that deadline, and the reason a buyer should not choose
/// it. `reclaim` wants the clock at or past the deadline, which only the last
/// representable second satisfies, so picking `i64::MAX` gives up the refund
/// path in every second before it and leaves the verdict signer in sole charge
/// of the money.
#[test]
fn a_deadline_at_the_end_of_time_is_reclaimable_only_in_the_last_second() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow_with(1, ESCROW_AMOUNT, i64::MAX);
        assert_ok(&result);

        h.set_time(i64::MAX - 1);
        assert_error(&h.reclaim(escrow), EscrowError::DeadlineNotReached);

        h.set_time(i64::MAX);
        assert_ok(&h.reclaim(escrow));
        assert_eq!(h.token_balance(&h.ata(&h.buyer.pubkey())), BUYER_START);
        assert!(!h.account_exists(&escrow), "escrow should be closed");
    });
}

/// A deadline at the other end of the type is simply in the past, and is
/// refused for that reason rather than by any special case.
#[test]
fn a_deadline_at_the_dawn_of_time_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (_, result) = h.create_escrow_with(1, ESCROW_AMOUNT, i64::MIN);
        assert_error(&result, EscrowError::DeadlineNotInFuture);
    });
}

/// The smallest deadline `create_escrow` accepts: one second ahead of the
/// clock. That leaves exactly one second in which a verdict can be settled,
/// and it is the second the escrow was created in.
#[test]
fn the_smallest_valid_deadline_leaves_exactly_one_second_to_settle() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let created_at = h.now();
        let (escrow, result) = h.create_escrow_with(1, ESCROW_AMOUNT, created_at + 1);
        assert_ok(&result);

        // The clock has not moved, so this is the deadline second minus one.
        assert_eq!(h.now(), created_at);
        assert_ok(&h.settle(escrow, Verdict::Release, created_at));
        assert_eq!(h.token_balance(&h.ata(&h.seller.pubkey())), ESCROW_AMOUNT);
    });
}

/// The same escrow one second later: the single second has elapsed, the
/// verdict window has closed, and the money belongs to the buyer.
#[test]
fn the_smallest_valid_deadline_belongs_to_the_buyer_one_second_on() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let created_at = h.now();
        let (escrow, result) = h.create_escrow_with(1, ESCROW_AMOUNT, created_at + 1);
        assert_ok(&result);

        h.set_time(created_at + 1);
        assert_error(
            &h.settle(escrow, Verdict::Release, created_at + 600),
            EscrowError::DeadlinePassed,
        );
        assert_ok(&h.reclaim(escrow));
        assert_eq!(h.token_balance(&h.ata(&h.buyer.pubkey())), BUYER_START);
    });
}

// --- (e) the verdict expiry at both ends ---------------------------------

/// An expiry at the end of representable time is a verdict that never
/// expires. The check is inclusive and every clock value satisfies it, so this
/// is the value that switches the protection off rather than one the program
/// treats specially.
#[test]
fn a_verdict_that_expires_at_the_end_of_time_is_accepted() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        assert_ok(&h.settle(escrow, Verdict::Release, i64::MAX));
        assert_eq!(h.token_balance(&h.ata(&h.seller.pubkey())), ESCROW_AMOUNT);
    });
}

/// An expiry at the other end expired before the clock started. The signature
/// over it is genuine, which is the point: the expiry field refuses it, not
/// the signature check, and the bytes it is refused over are the bytes the
/// signer chose.
#[test]
fn a_verdict_that_expired_at_the_dawn_of_time_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, i64::MIN);
        let accounts = h.settle_accounts(escrow);
        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, i64::MIN);
        assert_error(&result, EscrowError::VerdictExpired);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
    });
}

// --- (f) the escrow id and the creation slot -----------------------------

/// The escrow id is part of the PDA seeds, so the two ends of its range are
/// two addresses and two independent escrows. An id of 0 is eight zero bytes
/// in those seeds, which is what a caller gets by leaving the field unset, and
/// an id of `u64::MAX` is eight `0xff` bytes.
#[test]
fn an_escrow_id_of_zero_and_one_of_u64_max_are_separate_escrows() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (first, result) = h.create_escrow_with(0, ESCROW_AMOUNT, h.now() + HOUR);
        assert_ok(&result);
        let (second, result) = h.create_escrow_with(u64::MAX, ESCROW_AMOUNT, h.now() + HOUR);
        assert_ok(&result);

        assert_ne!(first, second);
        assert_eq!(first, h.escrow_pda(&h.buyer.pubkey(), 0));
        assert_eq!(second, h.escrow_pda(&h.buyer.pubkey(), u64::MAX));
        assert_eq!(h.escrow_state(&first).escrow_id, 0);
        assert_eq!(h.escrow_state(&second).escrow_id, u64::MAX);

        // Both exits rebuild the seeds from the stored id, so each escrow can
        // only sign for its own vault. Settling one leaves the other whole.
        let expires_at = h.now() + 600;
        assert_ok(&h.settle(first, Verdict::Release, expires_at));
        assert_eq!(h.token_balance(&h.ata(&h.seller.pubkey())), ESCROW_AMOUNT);
        assert!(h.account_exists(&second));
        assert_eq!(
            h.token_balance(&ata_for(&second, &h.mint, &h.token_program)),
            ESCROW_AMOUNT
        );

        h.set_time(h.escrow_state(&second).deadline);
        assert_ok(&h.reclaim(second));
        // One escrow went to the seller and one came back, so the buyer is out
        // exactly the escrow that was released.
        assert_eq!(
            h.token_balance(&h.ata(&h.buyer.pubkey())),
            BUYER_START - ESCROW_AMOUNT
        );
    });
}

/// The creation slot is eight bytes of the signed message. At slot 0 they are
/// all zero, which is also what a message with the field omitted would carry,
/// so an escrow created there still has to be settled against a verdict whose
/// bytes match it exactly.
#[test]
fn an_escrow_created_in_slot_zero_settles_against_a_zero_slot_verdict() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        h.set_clock(0, START_TIME);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        assert_eq!(h.escrow_state(&escrow).created_slot, 0);

        let expires_at = h.now() + 600;
        assert_ok(&h.settle(escrow, Verdict::Release, expires_at));
        assert_eq!(h.token_balance(&h.ata(&h.seller.pubkey())), ESCROW_AMOUNT);
    });
}

/// The same field at the top of its range, where those eight bytes are all
/// `0xff`.
#[test]
fn an_escrow_created_in_the_last_slot_settles_against_that_slot() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        h.set_clock(u64::MAX, START_TIME);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        assert_eq!(h.escrow_state(&escrow).created_slot, u64::MAX);

        let expires_at = h.now() + 600;
        assert_ok(&h.settle(escrow, Verdict::Release, expires_at));
        assert_eq!(h.token_balance(&h.ata(&h.seller.pubkey())), ESCROW_AMOUNT);
    });
}
