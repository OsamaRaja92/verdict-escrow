//! Closing accounts: revival, lamport draining and rent games.
//!
//! Closing an account does not delete an address. It zeroes the lamports and
//! the data and hands the address back to the system program, which leaves it
//! free to be created again by whoever could create it in the first place.
//! Programs get drained around that in three ways: an account that has already
//! been closed but is still accepted by a later instruction; a close whose
//! destination the caller gets to choose; and an address a stranger can fund
//! in advance, so that creation, or the close itself, fails on state nobody
//! asked for.
//!
//! Both exits here close the escrow with Anchor's `close = buyer` and the
//! vault with a `close_account` CPI, and both read their state from the very
//! account they close. The tests below come at that from each of the three
//! directions: fund the addresses before they exist, act on them after they
//! are gone, and redirect the rent.

use anchor_lang::error::ErrorCode as AnchorError;
use anchor_lang::prelude::Pubkey;
use escrow_harness::*;
use solana_account::Account;
use solana_keypair::Keypair;
use solana_message::{v0, AddressLookupTableAccount, VersionedMessage};
use solana_transaction::versioned::VersionedTransaction;
use verdict_escrow::verdict::{build_message, Verdict};

/// One signature at the standard fee.
const SIGNATURE_FEE: u64 = 5_000;

/// A donation far larger than the rent either account needs, so the top-up
/// Anchor and the associated token program would otherwise pay is zero and the
/// balance after creation is the donation itself.
const DONATION: u64 = 1_000_000_000;

/// What one packet can carry, and therefore the largest transaction that can
/// reach a validator.
const PACKET_DATA_SIZE: usize = 1_232;

const ADDRESS_LOOKUP_TABLE_PROGRAM_ID: Pubkey =
    Pubkey::from_str_const("AddressLookupTab1e1111111111111111111111111");

/// Put an active address lookup table holding `addresses` on the ledger.
///
/// Planted rather than created through the lookup table program, because a
/// table may not be used in the slot its addresses were added in, and the
/// rebuild below has to happen in the slot the escrow was created in. The
/// layout is the account's own: a four-byte state tag, the deactivation slot,
/// the slot the table was last extended in, then the addresses from offset 56.
/// The remaining header bytes — the start index, the authority's `None` tag
/// and the padding — are all zero.
fn plant_lookup_table(h: &mut Harness, addresses: &[Pubkey]) -> Pubkey {
    const META_SIZE: usize = 56;

    let mut data = vec![0u8; META_SIZE];
    data[0..4].copy_from_slice(&1u32.to_le_bytes());
    data[4..12].copy_from_slice(&u64::MAX.to_le_bytes());
    let extended_in = h.clock().slot - 1;
    data[12..20].copy_from_slice(&extended_in.to_le_bytes());
    for address in addresses {
        data.extend_from_slice(address.as_ref());
    }

    let key = Keypair::new().pubkey();
    let lamports = h.svm.minimum_balance_for_rent_exemption(data.len());
    h.svm
        .set_account(
            key,
            Account {
                lamports,
                data,
                owner: ADDRESS_LOOKUP_TABLE_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
        )
        .expect("plant a lookup table");
    key
}

// --- (a) funding an address before the program creates it ------------------

/// A stranger pays a plain system transfer to the escrow's address before the
/// escrow exists. The address is derivable from the buyer and the id, so this
/// costs nothing to arrange and needs no cooperation.
///
/// `init` has to tolerate it. Anchor's `init` only tops the balance up to the
/// rent minimum, so an address that is already funded is created without any
/// top-up — and because the close pays everything to the buyer, the griefer
/// has made the buyer a present rather than a problem. A program whose `init`
/// insisted on creating the account from zero would hand anyone a way to make
/// a given `(buyer, escrow_id)` unusable for the price of one lamport.
#[test]
fn lamports_parked_at_the_escrow_address_in_advance_do_not_block_creation() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let buyer = h.buyer.pubkey();
        let escrow = h.escrow_pda(&buyer, 1);

        // Anyone can send lamports anywhere; who sent them does not matter.
        h.svm.airdrop(&escrow, DONATION).expect("park lamports");
        let parked = h.svm.get_account(&escrow).expect("a bare funded address");
        assert_eq!(parked.lamports, DONATION);
        assert_eq!(parked.owner, SYSTEM_PROGRAM_ID);
        assert!(
            parked.data.is_empty(),
            "lamports are all a stranger can put at someone else's PDA"
        );

        let buyer_before = h.lamports(&buyer);
        let (opened, result) = h.create_escrow(1);
        assert_ok(&result);
        assert_eq!(opened, escrow);

        // Still exactly the donation: the buyer paid no rent for this account.
        assert_eq!(h.lamports(&escrow), DONATION);
        assert_eq!(h.escrow_state(&escrow).amount, ESCROW_AMOUNT);

        let expires_at = h.now() + 600;
        assert_ok(&h.settle(escrow, Verdict::Release, expires_at));

        // The donation left with the rent, to the buyer. The vault's rent,
        // which the buyer did pay, came back at the same time, so the buyer is
        // out one signature fee and up one donation.
        assert_eq!(h.lamports(&escrow), 0);
        assert_eq!(h.lamports(&buyer), buyer_before - SIGNATURE_FEE + DONATION);
    });
}

/// The same trick against the vault's address, which is the escrow's
/// associated token account and just as derivable.
///
/// This is not the case `creation.rs` covers: there a stranger creates the
/// token account itself. Here the address holds lamports and no account at
/// all, which is the branch of the associated token program that allocates
/// over an existing balance instead of creating from zero.
#[test]
fn lamports_parked_at_the_vault_address_in_advance_do_not_block_creation() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let buyer = h.buyer.pubkey();
        let escrow = h.escrow_pda(&buyer, 1);
        let vault = ata_for(&escrow, &h.mint, &h.token_program);

        h.svm.airdrop(&vault, DONATION).expect("park lamports");
        let buyer_before = h.lamports(&buyer);

        let (opened, result) = h.create_escrow(1);
        assert_ok(&result);
        assert_eq!(opened, escrow);

        // The token account was allocated over the donation, which stayed.
        assert_eq!(h.lamports(&vault), DONATION);
        assert_eq!(h.token_balance(&vault), ESCROW_AMOUNT);

        let expires_at = h.now() + 600;
        assert_ok(&h.settle(escrow, Verdict::Release, expires_at));

        // As above: the buyer paid the escrow's rent and got it back, and the
        // donation came to the buyer with the vault's close.
        assert_eq!(h.lamports(&vault), 0);
        assert_eq!(h.lamports(&buyer), buyer_before - SIGNATURE_FEE + DONATION);
    });
}

// --- (b) acting on an account that has already been closed -----------------

/// The revival attack in its plainest form: close the escrow and use it again
/// a few instructions later, inside the same transaction, so that nothing
/// off-chain has a chance to react between the two.
///
/// Each `settle` carries its own Ed25519 instruction immediately before it, so
/// both verdicts are real and the failure is about the account rather than
/// about a missing verdict. Anchor's `close` hands the address to the system
/// program, and `Account<Escrow>` refuses a system-owned account with no
/// lamports — which is the only thing standing between a signed verdict and a
/// second payout.
#[test]
fn settling_twice_in_one_transaction_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let expires_at = h.now() + 600;
        let accounts = h.settle_accounts(escrow);
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let settle_ix = accounts.instruction(Verdict::Release, expires_at);

        let relayer = h.relayer.insecure_clone();
        let result = h.send(
            &[
                verdict_ix.instruction(),
                settle_ix.clone(),
                verdict_ix.instruction(),
                settle_ix,
            ],
            &[&relayer],
        );
        assert_error(&result, AnchorError::AccountNotInitialized);

        // The second instruction failing takes the first one with it, so the
        // attacker does not even get the one payout they were entitled to.
        assert_eq!(h.escrow_state(&escrow).amount, ESCROW_AMOUNT);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
        assert_eq!(h.token_balance(&h.ata(&h.seller.pubkey())), 0);
    });
}

/// The same thing across the two exits: pay the seller against a verdict, then
/// hand the vault back to the buyer as well.
///
/// There are two independent reasons this cannot work, and the account check
/// is the one that fires. The other is the clock: a transaction has a single
/// timestamp, and `settle` needs it before the deadline while `reclaim` needs
/// it at or after, so the pair can never both be in their window. Account
/// constraints run before the handler, so the deadline rule is never reached.
#[test]
fn settling_then_reclaiming_in_one_transaction_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let expires_at = h.now() + 600;
        let accounts = h.settle_accounts(escrow);
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let settle_ix = accounts.instruction(Verdict::Release, expires_at);
        // Built while the escrow is still readable; after `settle` there is no
        // state left to build it from.
        let reclaim_ix = h.reclaim_ix(escrow);

        let buyer = h.buyer.insecure_clone();
        let result = h.send(
            &[verdict_ix.instruction(), settle_ix, reclaim_ix],
            &[&buyer],
        );
        assert_error(&result, AnchorError::AccountNotInitialized);

        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
        assert_eq!(
            h.token_balance(&h.ata(&h.buyer.pubkey())),
            BUYER_START - ESCROW_AMOUNT
        );
    });
}

/// And in the other order, after the deadline, where the buyer is the one with
/// a legitimate first move: take the money back, then settle the same escrow
/// against a verdict signed before the deadline passed.
#[test]
fn reclaiming_then_settling_in_one_transaction_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let deadline = h.escrow_state(&escrow).deadline;

        let expires_at = deadline + 600;
        let accounts = h.settle_accounts(escrow);
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let settle_ix = accounts.instruction(Verdict::Release, expires_at);
        let reclaim_ix = h.reclaim_ix(escrow);

        h.set_time(deadline);
        let buyer = h.buyer.insecure_clone();
        let result = h.send(
            &[reclaim_ix, verdict_ix.instruction(), settle_ix],
            &[&buyer],
        );
        assert_error(&result, AnchorError::AccountNotInitialized);

        // Rolled back whole: the escrow is still open and still funded.
        assert_eq!(h.escrow_state(&escrow).amount, ESCROW_AMOUNT);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
    });
}

// --- (c) the rebuild the README documents ----------------------------------

/// The documented limit, pinned, and all of it inside one transaction.
///
/// `close` leaves the escrow's address free, so the buyer can settle one deal
/// and open the next one at the same address a few instructions later, in the
/// same slot. The README says so under "Limits" and explains why it is
/// tolerable: the signed message names the seller, the amount, the mint and
/// the deadline, so an *old* verdict only fits a rebuild that pays the same
/// seller the same amount — which `replay.rs` tests from both sides. This
/// test is the other half of that claim: a *fresh* verdict for the rebuilt
/// escrow works, and two deals can run through one address in one transaction.
/// If a future change ever started refusing this, it would be a change in
/// documented behaviour and this test would say so.
///
/// The transaction needs an address lookup table, which is worth a word. The
/// five instructions as a legacy transaction come to 1,237 bytes, five over
/// the 1,232 a packet can carry, so the single-transaction form is only
/// deliverable with the accounts moved into a lookup table — the assertions
/// below measure both. LiteSVM does not enforce the packet limit, so a test
/// that ignored it would be pinning something no validator would ever accept.
#[test]
fn a_fresh_verdict_settles_a_rebuilt_escrow_in_the_same_transaction() {
    const SECOND_AMOUNT: u64 = 125_000_000;

    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let buyer = h.buyer.pubkey();
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let state = h.escrow_state(&escrow);
        let deadline = state.deadline;
        assert_eq!(
            state.created_slot,
            h.clock().slot,
            "the rebuild has to land in the slot the first escrow was created in"
        );

        let expires_at = h.now() + 600;
        let accounts = h.settle_accounts(escrow);
        let first_verdict = h.verdict_ix(escrow, Verdict::Release, expires_at);

        // The escrow the buyer will rebuild differs from the one being settled
        // in its amount, so the verdict for it is a different 178 bytes and a
        // different signature. Everything else about it is identical, down to
        // the address and the creation slot.
        let mut rebuilt_state = state;
        rebuilt_state.amount = SECOND_AMOUNT;
        let second_verdict = Ed25519Ix::sign(
            &h.verdict_signer,
            &build_message(
                &verdict_escrow::ID,
                &escrow,
                &rebuilt_state,
                Verdict::Release,
                expires_at,
            ),
        );
        assert_ne!(
            first_verdict.message, second_verdict.message,
            "the second verdict must be a fresh one, not the first one again"
        );

        let instructions = vec![
            first_verdict.instruction(),
            accounts.instruction(Verdict::Release, expires_at),
            h.create_escrow_ix(
                &buyer,
                1,
                SECOND_AMOUNT,
                deadline,
                h.seller.pubkey(),
                h.verdict_signer.pubkey(),
            ),
            second_verdict.instruction(),
            accounts.instruction(Verdict::Release, expires_at),
        ];

        let buyer_kp = h.buyer.insecure_clone();
        let legacy = solana_transaction::Transaction::new_signed_with_payer(
            &instructions,
            Some(&buyer),
            &[&buyer_kp],
            h.svm.latest_blockhash(),
        );
        let legacy_size = 1 + 64 * legacy.signatures.len() + legacy.message.serialize().len();
        assert!(
            legacy_size > PACKET_DATA_SIZE,
            "a legacy transaction was expected not to fit; it measured {legacy_size} bytes"
        );

        // Everything but the signer and the programs goes in the table; the
        // compiler leaves the rest in the static key list by itself.
        let table_addresses = vec![
            accounts.escrow,
            accounts.mint,
            accounts.vault,
            accounts.seller_token_account,
            accounts.buyer_token_account,
        ];
        let table = plant_lookup_table(&mut h, &table_addresses);
        let message = v0::Message::try_compile(
            &buyer,
            &instructions,
            &[AddressLookupTableAccount {
                key: table,
                addresses: table_addresses,
            }],
            h.svm.latest_blockhash(),
        )
        .expect("compile a v0 message");
        let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[&buyer_kp])
            .expect("sign the v0 transaction");
        let size = 1 + 64 * tx.signatures.len() + tx.message.serialize().len();
        assert!(
            size <= PACKET_DATA_SIZE,
            "{size} bytes does not fit a packet"
        );

        let result = h.svm.send_transaction(tx);
        assert_ok(&result);

        // Both deals paid out, through one address, in one transaction.
        assert_eq!(
            h.token_balance(&h.ata(&h.seller.pubkey())),
            ESCROW_AMOUNT + SECOND_AMOUNT
        );
        assert_eq!(
            h.token_balance(&h.ata(&buyer)),
            BUYER_START - ESCROW_AMOUNT - SECOND_AMOUNT
        );
        assert!(
            !h.account_exists(&escrow),
            "the rebuilt escrow is closed too"
        );
        assert!(!h.account_exists(&accounts.vault));
    });
}

// --- (d) what the close leaves behind --------------------------------------

/// Where the lamports are after a settlement, to the lamport.
///
/// Both accounts end at zero and the buyer holds both rents, which is the
/// claim the rest of the suite makes in passing. Nothing is left at either
/// address for anyone to sweep, and nothing is stranded in an account the
/// program can no longer sign for.
#[test]
fn a_settlement_leaves_both_addresses_empty_and_the_buyer_holds_the_rent() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let buyer = h.buyer.pubkey();
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let vault = ata_for(&escrow, &h.mint, &h.token_program);
        let escrow_rent = h.lamports(&escrow);
        let vault_rent = h.lamports(&vault);
        assert!(escrow_rent > 0 && vault_rent > 0);
        let buyer_before = h.lamports(&buyer);

        // The relayer pays this transaction, so the buyer's balance moves by
        // the rent and nothing else.
        let expires_at = h.now() + 600;
        assert_ok(&h.settle(escrow, Verdict::Release, expires_at));

        assert_eq!(h.lamports(&escrow), 0);
        assert_eq!(h.lamports(&vault), 0);
        assert!(!h.account_exists(&escrow));
        assert!(!h.account_exists(&vault));
        assert_eq!(h.lamports(&buyer), buyer_before + escrow_rent + vault_rent);
    });
}

/// Lamports parked at a settled escrow's address, which is the one thing a
/// stranger can still do to it.
///
/// Note which check refuses the settle afterwards. With no lamports the
/// address fails Anchor's "not initialized" test; with lamports it is a live,
/// system-owned account and fails the owner test instead. Both refuse, but a
/// program that treated `AccountNotInitialized` as its revival guard would be
/// relying on the error a stranger can change for one lamport. The guard that
/// matters is the owner.
///
/// The lamports themselves are not strandable and not stealable: nothing can
/// move them out of a PDA except this program signing for it, and the only
/// instruction that does pays them to the stored buyer.
#[test]
fn lamports_parked_at_a_settled_escrow_can_only_come_back_through_the_buyer() {
    const ESCROW_DONATION: u64 = 1_000_000;
    const VAULT_DONATION: u64 = 2_000_000;

    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let buyer = h.buyer.pubkey();
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let vault = ata_for(&escrow, &h.mint, &h.token_program);
        let expires_at = h.now() + 600;
        let accounts = h.settle_accounts(escrow);
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        assert_ok(&h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at));

        // A stranger puts lamports back at both dead addresses, and the
        // verdict is replayed against the escrow's address.
        h.svm
            .airdrop(&escrow, ESCROW_DONATION)
            .expect("fund the dead escrow address");
        h.svm
            .airdrop(&vault, VAULT_DONATION)
            .expect("fund the dead vault address");
        assert_eq!(h.lamports(&escrow), ESCROW_DONATION);

        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_error(&result, AnchorError::AccountOwnedByWrongProgram);
        assert_eq!(h.token_balance(&h.ata(&h.seller.pubkey())), ESCROW_AMOUNT);

        // The buyer reopens the same id. Both donations are absorbed as rent
        // and both come back to the buyer when it closes again, which is the
        // only exit they have.
        let buyer_before = h.lamports(&buyer);
        let (reborn, result) = h.create_escrow(1);
        assert_ok(&result);
        assert_eq!(reborn, escrow);
        let expires_at = h.now() + 600;
        assert_ok(&h.settle(reborn, Verdict::Release, expires_at));

        assert_eq!(
            h.lamports(&buyer),
            buyer_before - SIGNATURE_FEE + ESCROW_DONATION + VAULT_DONATION
        );
    });
}

// --- (e) choosing the close's destination ----------------------------------

/// `settle` takes no signer at all, so the account that receives the rent from
/// both closes is just an address the sender picked. A relayer who swapped it
/// for their own would be paid twice over: the escrow's rent through Anchor's
/// `close = buyer`, and the vault's through the `close_account` CPI, which
/// names the same account.
///
/// `has_one = buyer` is what refuses it. The escrow stores its buyer, so the
/// account passed in has to be that key and the sender has no say in it. The
/// substitute here is an ordinary funded wallet, so it satisfies the
/// `SystemAccount` type on `buyer` and fails on the constraint instead.
#[test]
fn closing_to_a_stranger_instead_of_the_buyer_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let thief = Keypair::new();
        h.svm
            .airdrop(&thief.pubkey(), 1_000_000_000)
            .expect("fund the thief");
        let thief_before = h.lamports(&thief.pubkey());
        let escrow_rent = h.lamports(&escrow);

        let expires_at = h.now() + 600;
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let mut accounts = h.settle_accounts(escrow);
        accounts.buyer = thief.pubkey();

        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_error(&result, AnchorError::ConstraintHasOne);
        assert_eq!(h.lamports(&thief.pubkey()), thief_before);
        assert_eq!(h.lamports(&escrow), escrow_rent);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
    });
}

/// The same substitution, but pointing the rent at a token account rather than
/// at a wallet — the shape of close that strands rent inside an account whose
/// program will never hand it back.
///
/// A different check catches this one, and the order is worth knowing.
/// `has_one` is a constraint, and constraints run after every account in the
/// instruction has been deserialised, so the `SystemAccount` type on `buyer`
/// gets there first and refuses the account on its owner. The two checks
/// together say the destination has to be both a plain wallet and the stored
/// buyer; which error comes back depends on which of the two a substitute
/// fails. An address holding no account at all passes the type check, because
/// the runtime presents it as system-owned and empty, and then fails
/// `has_one` — that is the case the test above covers.
#[test]
fn closing_into_a_token_account_is_refused_by_the_account_type() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let thief = Keypair::new();
        let thief_ata = h.create_ata(&thief.pubkey());

        let expires_at = h.now() + 600;
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let mut accounts = h.settle_accounts(escrow);
        accounts.buyer = thief_ata;

        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_error(&result, AnchorError::AccountNotSystemOwned);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
        assert_eq!(h.token_balance(&thief_ata), 0);
    });
}

// --- what this file could not build ---------------------------------------
//
// A pre-funded address is the limit of what a stranger can do to an address
// this program will later create. Giving it *data* as well — a system-owned
// account of the right size, say, so that `init` collides with it — is not
// constructible: allocating or creating an account at an address needs that
// address to sign, and for a PDA only its owning program can produce that
// signature. The one way the escrow's address can hold data is this program
// having put it there, which is the live-escrow case, and `replay.rs` covers
// it under `an_escrow_id_cannot_be_reused_while_it_is_open`.
