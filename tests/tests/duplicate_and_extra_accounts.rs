//! One account in two slots, and accounts the instruction never declared.
//!
//! The drain this class is named for needs two things: a program that writes
//! an account back when the instruction ends, and an account list that names
//! that same account in two mutable slots. The program reads the balance,
//! spends it through a CPI, and then writes its own stale copy over the
//! result — so the money it just moved is still there to move again. Anchor
//! 1.2 refuses a repeated mutable account before the handler runs, unless the
//! slot carries a `dup` constraint. This program declares no `dup` anywhere,
//! so the check is in force on all three instructions, and every assertion
//! below that names `ConstraintDuplicateMutableAccount` turns red the day
//! somebody adds one.
//!
//! Two structural facts narrow the class further, and both are worth having
//! before reading the tests. Anchor serialises an account on exit only when
//! that account's owner is this program, so the vault and the two payout
//! accounts — owned by a token program — are never written back by this
//! program at all; their balances change inside the token program's own CPI,
//! which reads live data. And `escrow` is the only program-owned slot in any
//! of the three instructions, so there is no second slot to put it in. The
//! stale-copy double spend is therefore not constructible here even with the
//! duplicate check switched off; what the check does stop is a payout account
//! that doubles as the vault, which would pay the money into the account it
//! came from.
//!
//! The question the payout pair invites, answered plainly: a self-dealing
//! escrow, where the buyer names itself as the seller, can be created —
//! the only rule `create_escrow` applies to the seller is that it is not the
//! default address — and can then never be settled, because
//! `seller_token_account` and `buyer_token_account` are one and the same
//! associated token account and the duplicate check refuses the list for
//! either verdict. The same holds for an escrow whose seller is the escrow PDA
//! itself, where the seller's associated token account *is* the vault. Neither
//! loses money: the deadline arrives and `reclaim` returns everything. Both
//! cost the verdict signer its authority over that escrow for the whole of the
//! escrow's life, which is a liveness bug a `require_keys_neq!(seller, buyer)`
//! at creation would turn into an error at the point the mistake is made.
//!
//! One ordering detail these assertions pin down. The duplicate check runs
//! after every account has been deserialised and before any of the per-account
//! constraints, so a repeated token account reports
//! `ConstraintDuplicateMutableAccount` even where the authority constraint
//! behind it would have refused it anyway, and an account of the wrong type
//! reports its deserialisation error and never reaches the duplicate check at
//! all. The error codes here are therefore a record of which gate is doing the
//! work, not just that some gate did.

use anchor_lang::error::ErrorCode as AnchorError;
use anchor_lang::prelude::Pubkey;
use escrow_harness::*;
use litesvm::types::TransactionResult;
use solana_instruction::{AccountMeta, Instruction};
use solana_instruction_error::InstructionError;
use solana_transaction_error::TransactionError;
use verdict_escrow::verdict::Verdict;

/// Assert the exact `TransactionError` for a failure that carries no program
/// error code. A slot holding the wrong kind of account fails inside the token
/// program's own unpack, which reaches the client as plain
/// `InvalidAccountData`, so there is no Anchor variant to name.
#[track_caller]
fn assert_invalid_account_data(result: &TransactionResult, instruction_index: u8) {
    let failure = result
        .as_ref()
        .err()
        .unwrap_or_else(|| panic!("expected this transaction to be refused"));
    assert_eq!(
        failure.err,
        TransactionError::InstructionError(instruction_index, InstructionError::InvalidAccountData),
        "logs: {:?}",
        failure.meta.logs
    );
}

/// `TransferChecked` by hand: instruction 12 under both token programs, with
/// the source, the mint, the destination and the authority in that order.
fn transfer_checked_ix(
    token_program: &Pubkey,
    source: &Pubkey,
    mint: &Pubkey,
    destination: &Pubkey,
    authority: &Pubkey,
    amount: u64,
) -> Instruction {
    let mut data = vec![12u8];
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(DECIMALS);
    Instruction {
        program_id: *token_program,
        accounts: vec![
            AccountMeta::new(*source, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new(*destination, false),
            AccountMeta::new_readonly(*authority, true),
        ],
        data,
    }
}

// --- the duplicate the program's own arguments can create ------------------

/// The self-dealing escrow, and the plain answer to whether it can be settled.
///
/// A buyer names itself as the seller. Creation goes through: the only thing
/// `create_escrow` asks of the seller is that it is not the default address.
/// From then on the two payout slots derive to one address, so neither verdict
/// can be applied, and the escrow is a deadline with money behind it.
#[test]
fn a_self_dealing_escrow_can_be_created_but_can_never_be_settled() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let buyer = h.buyer.pubkey();
        let buyer_ata = h.ata(&buyer);
        let deadline = h.now() + HOUR;

        let ix = h.create_escrow_ix(
            &buyer,
            1,
            ESCROW_AMOUNT,
            deadline,
            buyer,
            h.verdict_signer.pubkey(),
        );
        let signer = h.buyer.insecure_clone();
        assert_ok(&h.send(&[ix], &[&signer]));
        let escrow = h.escrow_pda(&buyer, 1);
        let vault = ata_for(&escrow, &h.mint, &h.token_program);

        let accounts = h.settle_accounts(escrow);
        assert_eq!(
            accounts.seller_token_account, accounts.buyer_token_account,
            "a buyer who is also the seller has one payout account, not two"
        );

        // Both verdicts, both refused, and refused before the handler reads
        // the verdict at all: the duplicate check sits in the account list.
        let expires_at = h.now() + 600;
        for verdict in [Verdict::Release, Verdict::Refund] {
            let result = h.settle(escrow, verdict, expires_at);
            assert_error(&result, AnchorError::ConstraintDuplicateMutableAccount);
            assert_eq!(h.token_balance(&vault), ESCROW_AMOUNT);
        }

        // Stuck, not lost.
        h.set_time(deadline);
        assert_ok(&h.reclaim(escrow));
        assert_eq!(h.token_balance(&buyer_ata), BUYER_START);
        assert!(!h.account_exists(&vault));
    });
}

/// The same shape reached from the other side: the seller is the escrow PDA,
/// so the seller's associated token account is the vault itself.
///
/// This is the duplicate worth caring about. Both slots satisfy every
/// constraint on them — the account really is the associated token account of
/// `escrow.seller`, and really is the vault — so the authority pins that
/// refuse every other substitution have nothing to object to, and the
/// duplicate check is the only thing standing in the way. A `Release` that got
/// through would pay the vault into itself.
#[test]
fn an_escrow_whose_seller_owns_the_vault_cannot_be_settled_either() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let buyer = h.buyer.pubkey();
        let escrow = h.escrow_pda(&buyer, 1);
        let deadline = h.now() + HOUR;

        // The escrow's address is derivable before it exists, so the buyer can
        // name it as the payee of the escrow it is about to open.
        let ix = h.create_escrow_ix(
            &buyer,
            1,
            ESCROW_AMOUNT,
            deadline,
            escrow,
            h.verdict_signer.pubkey(),
        );
        let signer = h.buyer.insecure_clone();
        assert_ok(&h.send(&[ix], &[&signer]));

        let accounts = h.settle_accounts(escrow);
        assert_eq!(
            accounts.seller_token_account, accounts.vault,
            "the seller's associated token account is the vault"
        );

        let expires_at = h.now() + 600;
        let result = h.settle(escrow, Verdict::Release, expires_at);
        assert_error(&result, AnchorError::ConstraintDuplicateMutableAccount);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);

        h.set_time(deadline);
        assert_ok(&h.reclaim(escrow));
        assert_eq!(h.token_balance(&h.ata(&buyer)), BUYER_START);
    });
}

/// What a payout-into-the-vault duplicate would actually buy, measured on the
/// token program alone.
///
/// A transfer whose source and destination are the same account is not an
/// error: the token program checks the authority, the mint and the amount, and
/// then returns without moving anything. So a `settle` that paid the vault
/// into itself would report a payout, leave the balance where it was, and then
/// hand `close_account` a vault that still held it — which the token program
/// refuses, because a non-native account may only be closed empty. The money
/// would not leave, but the escrow's one exit would be unusable. Anchor's
/// duplicate check simply stops the attempt earlier.
#[test]
fn the_token_program_treats_a_transfer_to_itself_as_a_no_op() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let buyer = h.buyer.pubkey();
        let buyer_ata = h.ata(&buyer);
        let token_program = h.token_program;
        let mint = h.mint;

        let ix = transfer_checked_ix(
            &token_program,
            &buyer_ata,
            &mint,
            &buyer_ata,
            &buyer,
            BUYER_START,
        );
        let signer = h.buyer.insecure_clone();
        assert_ok(&h.send(&[ix], &[&signer]));
        assert_eq!(
            h.token_balance(&buyer_ata),
            BUYER_START,
            "a self transfer validates and then moves nothing"
        );
    });
}

// --- the duplicate an attacker builds by hand ------------------------------

/// The buyer's own account in both payout slots: a buyer keeping the money
/// despite a release.
///
/// Two gates refuse it, and the assertion fixes which one fires first. The
/// duplicate check comes before the per-account constraints, so the owner pin
/// on `seller_token_account` — the gate `destinations.rs` exercises with a
/// stranger's account — never gets its turn.
#[test]
fn the_same_token_account_in_both_payout_slots_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let expires_at = h.now() + 600;
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let mut accounts = h.settle_accounts(escrow);
        accounts.seller_token_account = accounts.buyer_token_account;

        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_error(&result, AnchorError::ConstraintDuplicateMutableAccount);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
        assert_eq!(
            h.token_balance(&h.ata(&h.buyer.pubkey())),
            BUYER_START - ESCROW_AMOUNT
        );
    });
}

/// The vault in the seller's payout slot, on an ordinary escrow: the release
/// destination is the account the money is already in.
#[test]
fn the_vault_in_the_seller_payout_slot_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let expires_at = h.now() + 600;
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let mut accounts = h.settle_accounts(escrow);
        accounts.seller_token_account = accounts.vault;

        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_error(&result, AnchorError::ConstraintDuplicateMutableAccount);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
        assert_eq!(h.token_balance(&h.ata(&h.seller.pubkey())), 0);
    });
}

/// The same bend on the refund side, with the verdict that would use it.
#[test]
fn the_vault_in_the_buyer_payout_slot_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let expires_at = h.now() + 600;
        let verdict_ix = h.verdict_ix(escrow, Verdict::Refund, expires_at);
        let mut accounts = h.settle_accounts(escrow);
        accounts.buyer_token_account = accounts.vault;

        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Refund, expires_at);
        assert_error(&result, AnchorError::ConstraintDuplicateMutableAccount);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
    });
}

/// `reclaim` has the same pair — the vault and the buyer's account — and the
/// same check covers it.
#[test]
fn reclaim_with_the_vault_in_the_payout_slot_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let vault = ata_for(&escrow, &h.mint, &h.token_program);
        let deadline = h.escrow_state(&escrow).deadline;
        h.set_time(deadline);

        let mut ix = h.reclaim_ix(escrow);
        let buyer_ata = h.ata(&h.buyer.pubkey());
        let meta = ix
            .accounts
            .iter_mut()
            .find(|meta| meta.pubkey == buyer_ata)
            .expect("the buyer's token account is one of the accounts");
        meta.pubkey = vault;

        let signer = h.buyer.insecure_clone();
        let result = h.send(&[ix], &[&signer]);
        assert_error(&result, AnchorError::ConstraintDuplicateMutableAccount);
        assert_eq!(h.token_balance(&vault), ESCROW_AMOUNT);
    });
}

/// The deposit side of the same trick: fund the escrow out of the vault.
///
/// If the source and the vault were one account, `transfer_checked` would move
/// nothing and the escrow would record an amount that never arrived. Two
/// things stop it. The duplicate check covers `vault` because `init_if_needed`
/// slots take part in it — an account that may already exist may already be
/// named elsewhere — and behind that the deposit check compares the vault's
/// balance before and after and would have caught the shortfall anyway.
///
/// It only reaches the duplicate check when the vault already exists, which a
/// stranger can arrange: the address is derivable, and anyone may create an
/// associated token account for any owner. With no vault yet, the slot holds a
/// non-existent account and deserialisation refuses it first, because every
/// account is deserialised before `init_if_needed` creates anything.
#[test]
fn the_vault_in_both_of_create_escrows_token_slots_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let buyer = h.buyer.pubkey();
        let escrow = h.escrow_pda(&buyer, 1);
        let vault = ata_for(&escrow, &h.mint, &h.token_program);
        let buyer_ata = h.ata(&buyer);
        let signer = h.buyer.insecure_clone();

        let bend = |h: &Harness| {
            let mut ix = h.create_escrow_ix(
                &buyer,
                1,
                ESCROW_AMOUNT,
                h.now() + HOUR,
                h.seller.pubkey(),
                h.verdict_signer.pubkey(),
            );
            let meta = ix
                .accounts
                .iter_mut()
                .find(|meta| meta.pubkey == buyer_ata)
                .expect("the buyer's token account is one of the accounts");
            meta.pubkey = vault;
            ix
        };

        // No vault yet.
        let ix = bend(&h);
        let result = h.send(&[ix], &[&signer]);
        assert_error(&result, AnchorError::AccountNotInitialized);

        // A stranger creates the vault, and now both slots deserialise.
        h.create_ata(&escrow);
        let ix = bend(&h);
        let result = h.send(&[ix], &[&signer]);
        assert_error(&result, AnchorError::ConstraintDuplicateMutableAccount);

        assert_eq!(h.token_balance(&vault), 0);
        assert_eq!(h.token_balance(&buyer_ata), BUYER_START);
        assert!(!h.account_exists(&escrow), "no escrow was opened");
    });
}

/// The deposit side again, pointed the other way: the buyer's own account in
/// the vault slot, so the escrow would be funded by a transfer to itself.
///
/// Here the two slots hold the same account but the vault's authority pin
/// fires first, inside the `init_if_needed` block, which runs before the
/// duplicate check. Either way nothing moves.
#[test]
fn the_buyers_own_account_in_create_escrows_vault_slot_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let buyer = h.buyer.pubkey();
        let escrow = h.escrow_pda(&buyer, 1);
        let vault = ata_for(&escrow, &h.mint, &h.token_program);
        let buyer_ata = h.ata(&buyer);

        let mut ix = h.create_escrow_ix(
            &buyer,
            1,
            ESCROW_AMOUNT,
            h.now() + HOUR,
            h.seller.pubkey(),
            h.verdict_signer.pubkey(),
        );
        let meta = ix
            .accounts
            .iter_mut()
            .find(|meta| meta.pubkey == vault)
            .expect("the vault is one of the accounts");
        meta.pubkey = buyer_ata;

        let signer = h.buyer.insecure_clone();
        let result = h.send(&[ix], &[&signer]);
        assert_error(&result, AnchorError::ConstraintTokenOwner);
        assert_eq!(h.token_balance(&buyer_ata), BUYER_START);
        assert!(!h.account_exists(&escrow));
    });
}

// --- accounts of the wrong kind in a money slot ----------------------------

/// The escrow account itself in each of the three token-account slots.
///
/// This is the one duplicate that never reaches the duplicate check: the
/// escrow is already in the `escrow` slot, so the list does repeat a mutable
/// account, but `InterfaceAccount<TokenAccount>` refuses an account that no
/// token program owns, and deserialisation runs first. The error names the
/// owner, which is the more useful of the two answers.
#[test]
fn the_escrow_account_in_a_token_account_slot_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let vault = ata_for(&escrow, &h.mint, &h.token_program);
        let expires_at = h.now() + 600;
        let release = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let refund = h.verdict_ix(escrow, Verdict::Refund, expires_at);
        let base = h.settle_accounts(escrow);

        let mut accounts = base;
        accounts.vault = escrow;
        let result = h.send_settle(&accounts, &release, Verdict::Release, expires_at);
        assert_error(&result, AnchorError::AccountOwnedByWrongProgram);

        let mut accounts = base;
        accounts.seller_token_account = escrow;
        let result = h.send_settle(&accounts, &release, Verdict::Release, expires_at);
        assert_error(&result, AnchorError::AccountOwnedByWrongProgram);

        let mut accounts = base;
        accounts.buyer_token_account = escrow;
        let result = h.send_settle(&accounts, &refund, Verdict::Refund, expires_at);
        assert_error(&result, AnchorError::AccountOwnedByWrongProgram);

        assert_eq!(h.token_balance(&vault), ESCROW_AMOUNT);
        assert_eq!(h.escrow_state(&escrow).amount, ESCROW_AMOUNT);
    });
}

/// The escrow in the slot that receives the rent.
///
/// That slot is mutable but is a `SystemAccount`, which the duplicate check
/// skips, because Anchor never serialises one on exit and so cannot overwrite
/// anything with a stale copy. Nothing is lost by skipping it: the type pins
/// the slot to a system-owned account and `has_one = buyer` pins it to the
/// stored buyer, so it cannot be made to double as the escrow, the vault or
/// either payout account.
#[test]
fn the_escrow_account_in_the_rent_destination_slot_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let expires_at = h.now() + 600;
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let mut accounts = h.settle_accounts(escrow);
        accounts.buyer = escrow;

        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_error(&result, AnchorError::AccountNotSystemOwned);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
    });
}

/// The mint in a token-account slot, and a token account in the mint slot.
///
/// The mint slot is read-only, so it sits outside the duplicate check
/// entirely. That is sound for a reason worth stating: no account can be both
/// a mint and a token account under either token program. The base layouts are
/// 82 bytes and 165, and both programs unpack by exact length; a Token-2022
/// account long enough to carry extensions declares which of the two it is in
/// the byte at offset 165. The refusal therefore comes from the token program's
/// own unpack rather than from an Anchor constraint, which is why this test
/// asserts the exact `TransactionError` — there is no error code to name.
#[test]
fn the_mint_and_a_token_account_cannot_change_places() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let expires_at = h.now() + 600;
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let base = h.settle_accounts(escrow);

        // The mint, where a token account belongs. `settle` is instruction 1 in
        // every transaction this harness builds; the verdict is instruction 0.
        let mut accounts = base;
        accounts.vault = base.mint;
        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_invalid_account_data(&result, 1);

        // And the swap: the vault in the mint slot as well.
        let mut accounts = base;
        accounts.mint = base.vault;
        accounts.vault = base.mint;
        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_invalid_account_data(&result, 1);

        assert_eq!(h.token_balance(&base.vault), ESCROW_AMOUNT);
    });
}

// --- accounts the struct never declared ------------------------------------

/// Everything past the declared slots, with a second escrow and a second
/// verdict thrown in, and none of it able to matter.
///
/// The list carries the first escrow's accounts, then a second live escrow,
/// its vault, the first vault a second time, the seller's account, the
/// instructions sysvar a second time and the Ed25519 program. The transaction
/// carries two genuine verdicts: a release for the second escrow at index 0,
/// and the refund for the first immediately before `settle`.
///
/// Three things follow from the result. Anchor takes the declared accounts
/// from the front of the list and leaves the rest in `remaining_accounts`,
/// which this program never reads, so the extras change nothing. The duplicate
/// check looks only at declared slots, so repeating the vault among the extras
/// is allowed — and is harmless for the same reason. And the verdict at index
/// 0 is ignored however valid it is, because the program reads the instruction
/// directly before itself and nowhere else: the second escrow keeps its money
/// with a signed release for it sitting in the same transaction.
///
/// A note on what "a second Ed25519 instruction's worth of accounts" comes to:
/// the precompile declares no accounts at all, and `verify_verdict` refuses a
/// verdict instruction that carries any, so there is no such set of accounts
/// to append. What can be appended is the pair an attacker would reach for
/// instead — the Ed25519 program's own address and a second copy of the
/// instructions sysvar — together with a real second Ed25519 instruction in
/// the transaction, which is what this test does.
#[test]
fn extra_accounts_appended_to_settle_cannot_be_made_to_matter() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (first, result) = h.create_escrow(1);
        assert_ok(&result);
        let (second, result) = h.create_escrow(2);
        assert_ok(&result);

        let second_vault = ata_for(&second, &h.mint, &h.token_program);
        let escrow_before = h.svm.get_account(&second).expect("the second escrow");
        let vault_before = h.svm.get_account(&second_vault).expect("its vault");

        let expires_at = h.now() + 600;
        let release_second = h.verdict_ix(second, Verdict::Release, expires_at);
        let refund_first = h.verdict_ix(first, Verdict::Refund, expires_at);

        let accounts = h.settle_accounts(first);
        let mut settle_ix = accounts.instruction(Verdict::Refund, expires_at);
        for meta in [
            AccountMeta::new(second, false),
            AccountMeta::new(second_vault, false),
            AccountMeta::new(accounts.vault, false),
            AccountMeta::new(accounts.seller_token_account, false),
            AccountMeta::new_readonly(INSTRUCTIONS_SYSVAR_ID, false),
            AccountMeta::new_readonly(ED25519_PROGRAM_ID, false),
        ] {
            settle_ix.accounts.push(meta);
        }

        let relayer = h.relayer.insecure_clone();
        let result = h.send(
            &[
                release_second.instruction(),
                refund_first.instruction(),
                settle_ix,
            ],
            &[&relayer],
        );
        assert_ok(&result);

        // The first escrow was refunded, as its own verdict said. The buyer is
        // down one escrow: the second one's money is still in its vault.
        assert_eq!(
            h.token_balance(&h.ata(&h.buyer.pubkey())),
            BUYER_START - ESCROW_AMOUNT
        );
        assert_eq!(h.token_balance(&h.ata(&h.seller.pubkey())), 0);
        assert!(!h.account_exists(&first));

        // The second escrow is byte for byte what it was.
        let escrow_after = h.svm.get_account(&second).expect("the second escrow");
        let vault_after = h.svm.get_account(&second_vault).expect("its vault");
        assert_eq!(escrow_after.data, escrow_before.data);
        assert_eq!(escrow_after.lamports, escrow_before.lamports);
        assert_eq!(escrow_after.owner, escrow_before.owner);
        assert_eq!(vault_after.data, vault_before.data);
        assert_eq!(vault_after.lamports, vault_before.lamports);
        assert_eq!(h.token_balance(&second_vault), ESCROW_AMOUNT);
    });
}

/// The same for `create_escrow`: a PDA it could have opened, a token account
/// it could have funded, and a program it could have called, all appended.
#[test]
fn extra_accounts_appended_to_create_escrow_are_ignored() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let buyer = h.buyer.pubkey();
        let unused_pda = h.escrow_pda(&buyer, 99);
        let seller_ata = h.ata(&h.seller.pubkey());
        let deadline = h.now() + HOUR;

        let mut ix = h.create_escrow_ix(
            &buyer,
            1,
            ESCROW_AMOUNT,
            deadline,
            h.seller.pubkey(),
            h.verdict_signer.pubkey(),
        );
        for meta in [
            AccountMeta::new(unused_pda, false),
            AccountMeta::new(seller_ata, false),
            AccountMeta::new_readonly(MEMO_PROGRAM_ID, false),
        ] {
            ix.accounts.push(meta);
        }

        let signer = h.buyer.insecure_clone();
        assert_ok(&h.send(&[ix], &[&signer]));

        let escrow = h.escrow_pda(&buyer, 1);
        assert_eq!(h.escrow_state(&escrow).amount, ESCROW_AMOUNT);
        assert_eq!(
            h.token_balance(&ata_for(&escrow, &h.mint, &h.token_program)),
            ESCROW_AMOUNT
        );
        assert!(
            !h.account_exists(&unused_pda),
            "the appended PDA was not opened"
        );
        assert_eq!(h.token_balance(&seller_ata), 0);
    });
}

/// And for `reclaim`, with another escrow's vault appended to the list the
/// buyer signs.
#[test]
fn extra_accounts_appended_to_reclaim_are_ignored() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (first, result) = h.create_escrow(1);
        assert_ok(&result);
        let (second, result) = h.create_escrow(2);
        assert_ok(&result);
        let second_vault = ata_for(&second, &h.mint, &h.token_program);
        let seller_ata = h.ata(&h.seller.pubkey());

        let deadline = h.escrow_state(&first).deadline;
        h.set_time(deadline);

        let mut ix = h.reclaim_ix(first);
        for meta in [
            AccountMeta::new(seller_ata, false),
            AccountMeta::new(second_vault, false),
            AccountMeta::new(second, false),
        ] {
            ix.accounts.push(meta);
        }

        let signer = h.buyer.insecure_clone();
        assert_ok(&h.send(&[ix], &[&signer]));

        // One escrow's worth came back, not two.
        assert_eq!(
            h.token_balance(&h.ata(&h.buyer.pubkey())),
            BUYER_START - ESCROW_AMOUNT
        );
        assert_eq!(h.token_balance(&seller_ata), 0);
        assert_eq!(h.token_balance(&second_vault), ESCROW_AMOUNT);
        assert!(h.account_exists(&second));
    });
}

/// The one position where an extra account does matter, and why that is a
/// reorder rather than an extra.
///
/// Anchor takes the declared slots from the front of the list, so an account
/// put at the front takes the first slot and every real account moves one
/// place along. The `escrow` slot then holds the relayer, which is
/// system-owned with a balance, and `Account<Escrow>` refuses it on its owner.
/// The token program, pushed off the end, becomes a remaining account.
#[test]
fn an_account_prepended_to_settle_shifts_every_slot_and_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let expires_at = h.now() + 600;
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let accounts = h.settle_accounts(escrow);
        let mut settle_ix = accounts.instruction(Verdict::Release, expires_at);
        settle_ix
            .accounts
            .insert(0, AccountMeta::new(h.relayer.pubkey(), false));

        let relayer = h.relayer.insecure_clone();
        let result = h.send(&[verdict_ix.instruction(), settle_ix], &[&relayer]);
        assert_error(&result, AnchorError::AccountOwnedByWrongProgram);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
    });
}

// --- reordering and truncating the declared accounts -----------------------

/// The two payout slots exchanged: a release that pays the buyer.
///
/// The accounts are both real, both for the right mint, and both named in the
/// struct — only in each other's places. They are different accounts, so the
/// duplicate check has nothing to say and the authority pin does the work.
#[test]
fn swapping_the_two_payout_slots_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let expires_at = h.now() + 600;
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let base = h.settle_accounts(escrow);
        let mut accounts = base;
        accounts.seller_token_account = base.buyer_token_account;
        accounts.buyer_token_account = base.seller_token_account;

        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_error(&result, AnchorError::ConstraintTokenOwner);
        assert_eq!(h.token_balance(&base.vault), ESCROW_AMOUNT);
        assert_eq!(
            h.token_balance(&h.ata(&h.buyer.pubkey())),
            BUYER_START - ESCROW_AMOUNT,
            "the buyer gained nothing"
        );
    });
}

/// The vault and the seller's account exchanged: the money would be paid out
/// of the seller's account and into the vault.
#[test]
fn swapping_the_vault_and_the_seller_payout_slot_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let expires_at = h.now() + 600;
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let base = h.settle_accounts(escrow);
        let mut accounts = base;
        accounts.vault = base.seller_token_account;
        accounts.seller_token_account = base.vault;

        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        // Both slots fail the same check — a token account's authority must be
        // the key the struct pins it to — so this is the error whichever of the
        // two Anchor reaches first.
        assert_error(&result, AnchorError::ConstraintTokenOwner);
        assert_eq!(h.token_balance(&base.vault), ESCROW_AMOUNT);
    });
}

/// The escrow and the rent destination exchanged, which is the reorder that
/// shows there is no name-based recovery: both slots are mutable, neither is a
/// signer, and the list is the right length, so only the types tell them
/// apart.
#[test]
fn swapping_the_escrow_and_the_rent_destination_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let expires_at = h.now() + 600;
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let base = h.settle_accounts(escrow);
        let mut accounts = base;
        accounts.escrow = base.buyer;
        accounts.buyer = base.escrow;

        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_error(&result, AnchorError::AccountOwnedByWrongProgram);
        assert_eq!(h.token_balance(&base.vault), ESCROW_AMOUNT);
        assert_eq!(h.escrow_state(&escrow).amount, ESCROW_AMOUNT);
    });
}

/// A list one account short, on each instruction in turn.
///
/// Dropping the trailing account is the cheapest way to test whether a program
/// reads its slots by position or by name. Anchor reads by position and counts,
/// so a short list is refused before any constraint runs — the slot is not
/// defaulted, and the instruction does not proceed with a CPI to whatever the
/// previous account happened to be.
#[test]
fn a_truncated_account_list_is_refused_on_every_instruction() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let vault = ata_for(&escrow, &h.mint, &h.token_program);

        let expires_at = h.now() + 600;
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let accounts = h.settle_accounts(escrow);
        let relayer = h.relayer.insecure_clone();

        // `settle` without its token program.
        let mut settle_ix = accounts.instruction(Verdict::Release, expires_at);
        settle_ix.accounts.pop();
        let result = h.send(&[verdict_ix.instruction(), settle_ix], &[&relayer]);
        assert_error(&result, AnchorError::AccountNotEnoughKeys);

        // And with only half of its accounts.
        let mut settle_ix = accounts.instruction(Verdict::Release, expires_at);
        settle_ix.accounts.truncate(4);
        let result = h.send(&[verdict_ix.instruction(), settle_ix], &[&relayer]);
        assert_error(&result, AnchorError::AccountNotEnoughKeys);

        // `create_escrow` without its system program.
        let buyer = h.buyer.pubkey();
        let mut ix = h.create_escrow_ix(
            &buyer,
            7,
            ESCROW_AMOUNT,
            h.now() + HOUR,
            h.seller.pubkey(),
            h.verdict_signer.pubkey(),
        );
        ix.accounts.pop();
        let signer = h.buyer.insecure_clone();
        let result = h.send(&[ix], &[&signer]);
        assert_error(&result, AnchorError::AccountNotEnoughKeys);
        assert!(!h.account_exists(&h.escrow_pda(&buyer, 7)));

        // `reclaim` without its token program.
        let deadline = h.escrow_state(&escrow).deadline;
        h.set_time(deadline);
        let mut ix = h.reclaim_ix(escrow);
        ix.accounts.pop();
        let result = h.send(&[ix], &[&signer]);
        assert_error(&result, AnchorError::AccountNotEnoughKeys);

        assert_eq!(h.token_balance(&vault), ESCROW_AMOUNT);
        assert_eq!(h.escrow_state(&escrow).amount, ESCROW_AMOUNT);
    });
}
