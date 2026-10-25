//! Escrow accounts that were planted rather than created: the owner check,
//! type cosplay, and PDA address confusion.
//!
//! Everything this program trusts lives in the escrow account — the buyer, the
//! seller, the amount, and above all the verdict signer. A program that accepts
//! an account because it merely looks like its own state hands over the whole
//! file: the attacker supplies a copy that names a key of theirs as the verdict
//! signer, signs a release with it, and the vault pays out.
//!
//! Three gates stand in the way, and they fire in this order:
//!
//! 1. the owner check, inside Anchor's `Account` deserialisation: the account
//!    must be owned by this program;
//! 2. the discriminator, in the same step: the first eight bytes must be the
//!    ones this program writes for an `Escrow`;
//! 3. the `seeds` constraint: the address the account sits at must be the PDA
//!    that the account's own stored buyer, escrow id and bump re-derive.
//!
//! The third is the one that is easy to leave out, and the only one that ties
//! the contents of the account to where it lives. Without it, a correctly
//! tagged, program-owned account planted at any address at all would be read
//! as state.
//!
//! These tests plant accounts with `set_account`, which writes straight into
//! the ledger. Two runtime rules bound what the real version of that is worth.
//! An attacker can have an account created under this program's ownership at
//! an address of their choosing, since the system program lets the payer name
//! any owner; what they cannot do is put bytes in it, because only an account's
//! owning program may write its data. The best they get is an all-zero account,
//! which is the discriminator test below. The second rule covers accounts this
//! program did write: it sets an escrow's fields once, under `init`, and has no
//! instruction that changes them afterwards. The last test prices that second
//! rule in tokens.
//!
//! One of those stored fields is the escrow's own bump, and it is canonical for
//! the same reason the others are right: `init` derived it that way. Nothing
//! afterwards checks that it is canonical, because the third gate above does
//! not ask for that — it asks only that the stored bump re-derive the address
//! the account was read from. The two bump tests below keep those claims apart,
//! since a reader who merges them walks away with a guarantee this program does
//! not make.

use anchor_lang::error::ErrorCode as AnchorError;
use anchor_lang::prelude::Pubkey;
use anchor_lang::{AccountSerialize, InstructionData, ToAccountMetas};
use escrow_harness::*;
use litesvm_token::MintTo;
use solana_account::Account as RawAccount;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use verdict_escrow::state::{Escrow, ESCROW_SEED};
use verdict_escrow::verdict::{build_message, Verdict};

/// An address the attacker picks for an account it plants. Derived from a
/// label rather than generated, so nothing in these tests depends on a random
/// key landing on a particular bump.
fn planted_address(label: &[u8]) -> Pubkey {
    Pubkey::find_program_address(&[b"planted", label], &verdict_escrow::ID).0
}

/// Write `data` to `address` under `owner`, rent-exempt for its own length.
fn plant(h: &mut Harness, address: Pubkey, owner: Pubkey, data: Vec<u8>) {
    let lamports = h.svm.minimum_balance_for_rent_exemption(data.len());
    h.svm
        .set_account(
            address,
            RawAccount {
                lamports,
                data,
                owner,
                executable: false,
                rent_epoch: 0,
            },
        )
        .expect("plant the account");
}

/// The bytes the program itself writes for an escrow: the eight-byte
/// discriminator, then the borsh body.
fn escrow_bytes(state: &Escrow) -> Vec<u8> {
    let mut data = Vec::new();
    state
        .try_serialize(&mut data)
        .expect("serialise the escrow state");
    data
}

/// A `reclaim` instruction aimed at `escrow`, with every other account named
/// explicitly. Built by hand because the harness helper reads the escrow's
/// state first, and a planted escrow need not deserialise at all.
fn reclaim_aimed_at(h: &Harness, escrow: Pubkey, buyer: Pubkey, vault: Pubkey) -> Instruction {
    Instruction {
        program_id: verdict_escrow::ID,
        accounts: verdict_escrow::accounts::Reclaim {
            escrow,
            buyer,
            mint: h.mint,
            vault,
            buyer_token_account: h.ata(&buyer),
            token_program: h.token_program,
        }
        .to_account_metas(None),
        data: verdict_escrow::instruction::Reclaim {}.data(),
    }
}

/// The first bump below the canonical one that `create_program_address` still
/// accepts for these seeds, and the address it derives.
///
/// About half of all bump values put the result on the ed25519 curve, where it
/// is a possible wallet key rather than a program address, and have no program
/// address at all — which is why the canonical bump is found by counting down
/// from 255 until one works. Carrying on down from there finds a second address
/// for the same seeds, every bit as real and as signable as the first.
fn next_address_below_canonical(buyer: &Pubkey, escrow_id: u64) -> (Pubkey, u8) {
    let id_bytes = escrow_id.to_le_bytes();
    let (_, canonical) = Pubkey::find_program_address(
        &[ESCROW_SEED, buyer.as_ref(), id_bytes.as_ref()],
        &verdict_escrow::ID,
    );
    for bump in (0..canonical).rev() {
        if let Ok(address) = Pubkey::create_program_address(
            &[ESCROW_SEED, buyer.as_ref(), id_bytes.as_ref(), &[bump]],
            &verdict_escrow::ID,
        ) {
            return (address, bump);
        }
    }
    panic!("no bump below {canonical} derives an address for these seeds");
}

/// Give `owner` lamports for fees and an account for the escrowed mint holding
/// `amount`, so an attacker can open an escrow without borrowing the buyer's
/// money.
fn fund(h: &mut Harness, owner: &Keypair, amount: u64) -> Pubkey {
    h.svm
        .airdrop(&owner.pubkey(), 1_000_000_000)
        .expect("airdrop");
    let token_account = h.create_ata(&owner.pubkey());
    if amount > 0 {
        let payer = h.buyer.insecure_clone();
        let mint = h.mint;
        let token_program = h.token_program;
        MintTo::new(&mut h.svm, &payer, &mint, &token_account, amount)
            .token_program_id(&token_program)
            .send()
            .expect("mint to the attacker");
    }
    token_account
}

/// A byte-for-byte copy of a live escrow, owned by a different program.
///
/// Nothing about the bytes is wrong: they are the real escrow's, discriminator
/// included, and the verdict handed in with them is genuine. The copy is
/// planted at the escrow's own address, so the stored buyer, escrow id and bump
/// still re-derive the address they are read from and the `seeds` constraint
/// has nothing to object to. The only thing that differs is who owns the
/// account, which is the first thing Anchor looks at and here the only thing
/// left standing between the verdict and the vault.
///
/// A copy at some other address would be refused too, but for two reasons at
/// once, and the one that fired would be an accident of the order the checks
/// run in. Planting it here leaves one reason. The last test in this file
/// plants state at this same address with this program as the owner and the
/// vault pays out, which is what the owner field is worth.
#[test]
fn a_forged_escrow_owned_by_another_program_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        // Read and signed before the owner changes, over the same bytes the
        // copy carries: the verdict is the escrow's real one.
        let expires_at = h.now() + 600;
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let accounts = h.settle_accounts(escrow);

        let live = h.svm.get_account(&escrow).expect("the escrow exists");
        plant(&mut h, escrow, TOKEN_PROGRAM_ID, live.data.clone());

        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_error(&result, AnchorError::AccountOwnedByWrongProgram);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
        assert_eq!(h.token_balance(&accounts.seller_token_account), 0);
    });
}

/// The same copy, passed to `reclaim` by the escrow's own buyer.
///
/// `reclaim` has a privileged signer, and here the right key signs for an
/// account whose seeds are in order: the owner check depends on neither, and
/// refuses the account anyway.
#[test]
fn a_forged_escrow_owned_by_another_program_cannot_be_reclaimed() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let vault = ata_for(&escrow, &h.mint, &h.token_program);
        let deadline = h.escrow_state(&escrow).deadline;

        let live = h.svm.get_account(&escrow).expect("the escrow exists");
        plant(&mut h, escrow, TOKEN_PROGRAM_ID, live.data.clone());

        h.set_time(deadline);
        let buyer = h.buyer.insecure_clone();
        let ix = reclaim_aimed_at(&h, escrow, buyer.pubkey(), vault);
        let result = h.send(&[ix], &[&buyer]);
        assert_error(&result, AnchorError::AccountOwnedByWrongProgram);
        assert_eq!(h.token_balance(&vault), ESCROW_AMOUNT);
    });
}

/// Type cosplay, first form: the right owner, no discriminator.
///
/// The account is owned by this program and its body is a valid `Escrow`, so
/// the only thing left to tell it apart from real state is the tag. This is
/// also the one planted account an attacker can really produce: anyone may pay
/// the system program to create an account and name this program as its owner,
/// and the bytes they get are zeros. The body here is a real escrow's rather
/// than zeros, which only makes the forgery better than the one available.
#[test]
fn an_escrow_whose_discriminator_is_zeroed_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let live = h.svm.get_account(&escrow).expect("the escrow exists");
        let mut data = live.data.clone();
        data[..8].fill(0);
        let copy = planted_address(b"zero-discriminator");
        plant(&mut h, copy, verdict_escrow::ID, data);

        let expires_at = h.now() + 600;
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let mut accounts = h.settle_accounts(escrow);
        accounts.escrow = copy;

        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_error(&result, AnchorError::AccountDiscriminatorMismatch);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
    });
}

/// Type cosplay, second form: the right owner, a tag from the same program.
///
/// Eight bytes of this program's own making, rather than a random mangling:
/// the sighash that prefixes a `settle` instruction. An account whose first
/// eight bytes are plausible is the realistic case, and the comparison is
/// against one exact value, so plausible is not enough.
#[test]
fn an_escrow_carrying_another_discriminator_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let settle_sighash = verdict_escrow::instruction::Settle {
            verdict: Verdict::Release,
            expires_at: 0,
        }
        .data();
        let live = h.svm.get_account(&escrow).expect("the escrow exists");
        let mut data = live.data.clone();
        data[..8].copy_from_slice(&settle_sighash[..8]);
        let copy = planted_address(b"foreign-discriminator");
        plant(&mut h, copy, verdict_escrow::ID, data);

        let expires_at = h.now() + 600;
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let mut accounts = h.settle_accounts(escrow);
        accounts.escrow = copy;

        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_error(&result, AnchorError::AccountDiscriminatorMismatch);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
    });
}

/// An account too short to carry a discriminator at all.
///
/// A separate error from the mismatch above, because the length is checked
/// before the eight bytes are compared. A program that read the tag without
/// checking the length first would read past the end of the account.
#[test]
fn an_account_too_short_to_carry_a_discriminator_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let live = h.svm.get_account(&escrow).expect("the escrow exists");
        let copy = planted_address(b"four-bytes");
        plant(&mut h, copy, verdict_escrow::ID, live.data[..4].to_vec());

        let expires_at = h.now() + 600;
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let mut accounts = h.settle_accounts(escrow);
        accounts.escrow = copy;

        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_error(&result, AnchorError::AccountDiscriminatorNotFound);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
    });
}

/// Address confusion: a perfect escrow at the wrong address.
///
/// Correct owner, correct discriminator, valid borsh, and a verdict signed by
/// the escrow's real verdict signer over bytes that name this very account. The
/// one thing wrong is where the account sits, and the `seeds` constraint is the
/// only check that can notice: the stored buyer, escrow id and bump re-derive
/// the real escrow's address, not this one.
#[test]
fn a_valid_escrow_planted_away_from_its_pda_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let state = h.escrow_state(&escrow);
        let copy = planted_address(b"away-from-its-pda");
        plant(&mut h, copy, verdict_escrow::ID, escrow_bytes(&state));

        let expires_at = h.now() + 600;
        let message = build_message(
            &verdict_escrow::ID,
            &copy,
            &state,
            Verdict::Release,
            expires_at,
        );
        let verdict_ix = Ed25519Ix::sign(&h.verdict_signer, &message);
        let mut accounts = h.settle_accounts(escrow);
        accounts.escrow = copy;

        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_error(&result, AnchorError::ConstraintSeeds);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
    });
}

/// The same planted escrow, handed to `reclaim` at its deadline by the buyer
/// it names. Being the right signer for the contents does not make the address
/// right.
#[test]
fn a_valid_escrow_planted_away_from_its_pda_cannot_be_reclaimed() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let vault = ata_for(&escrow, &h.mint, &h.token_program);

        let state = h.escrow_state(&escrow);
        let copy = planted_address(b"away-from-its-pda-reclaim");
        plant(&mut h, copy, verdict_escrow::ID, escrow_bytes(&state));

        h.set_time(state.deadline);
        let buyer = h.buyer.insecure_clone();
        let ix = reclaim_aimed_at(&h, copy, buyer.pubkey(), vault);
        let result = h.send(&[ix], &[&buyer]);
        assert_error(&result, AnchorError::ConstraintSeeds);
        assert_eq!(h.token_balance(&vault), ESCROW_AMOUNT);
    });
}

/// The attack the whole design is pointed at.
///
/// The attacker copies the live escrow, swaps the seller and the verdict signer
/// for keys of their own, plants it, and signs a release with their own key —
/// a signature the Ed25519 precompile accepts without complaint, because it is
/// a real signature over the bytes the program would rebuild from the account
/// it was handed. Had the program read its state from whatever account arrived
/// in that position, this single transaction would have moved the whole
/// 250-token vault into the attacker's own token account and the vault's rent
/// along with it, with no key but the attacker's involved.
///
/// The `seeds` constraint refuses it before the verdict is read at all. The
/// vault's `associated_token::authority` constraint would refuse it a second
/// time, since the real vault's authority is the real escrow.
#[test]
fn a_planted_escrow_naming_the_attacker_as_verdict_signer_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let attacker = Keypair::new();
        let attacker_ata = h.create_ata(&attacker.pubkey());

        let mut state = h.escrow_state(&escrow);
        state.seller = attacker.pubkey();
        state.verdict_signer = attacker.pubkey();
        let forged = planted_address(b"attacker-verdict-signer");
        plant(&mut h, forged, verdict_escrow::ID, escrow_bytes(&state));

        let expires_at = h.now() + 600;
        let message = build_message(
            &verdict_escrow::ID,
            &forged,
            &state,
            Verdict::Release,
            expires_at,
        );
        let verdict_ix = Ed25519Ix::sign(&attacker, &message);
        let mut accounts = h.settle_accounts(escrow);
        accounts.escrow = forged;
        accounts.seller_token_account = attacker_ata;

        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_error(&result, AnchorError::ConstraintSeeds);
        assert_eq!(h.token_balance(&attacker_ata), 0);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
    });
}

/// The same attack with nothing forged at all, which is why it matters most.
///
/// Opening an escrow that names yourself the verdict signer is allowed, and
/// costs the attacker one base unit of their own tokens. Their escrow is real:
/// right owner, right discriminator, right address for its own seeds, and its
/// verdict signer is a key they hold. They sign a release and point the vault
/// at a stranger's escrow vault. What stops it here is the vault's own
/// derivation: the only account that passes `associated_token::authority =
/// escrow` is the vault belonging to the escrow being settled.
#[test]
fn an_escrow_the_attacker_opened_cannot_reach_another_escrows_vault() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (victim, result) = h.create_escrow(1);
        assert_ok(&result);
        let victim_vault = ata_for(&victim, &h.mint, &h.token_program);

        let attacker = Keypair::new();
        let accomplice = Keypair::new();
        fund(&mut h, &attacker, 10);
        let accomplice_ata = h.create_ata(&accomplice.pubkey());

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
        let own = h.escrow_pda(&attacker.pubkey(), 7);

        let expires_at = h.now() + 600;
        let message = h.verdict_message(own, Verdict::Release, expires_at);
        let verdict_ix = Ed25519Ix::sign(&attacker, &message);
        let mut accounts = h.settle_accounts(own);
        accounts.vault = victim_vault;

        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_error(&result, AnchorError::ConstraintTokenOwner);
        assert_eq!(h.token_balance(&victim_vault), ESCROW_AMOUNT);
        assert_eq!(h.token_balance(&accomplice_ata), 0);
    });
}

/// The reclaim half of the same idea, where the attacker needs no verdict at
/// all: their own escrow, past its own deadline, pointed at a stranger's vault
/// while that stranger's escrow is still live.
#[test]
fn an_escrow_the_attacker_opened_cannot_reclaim_another_escrows_vault() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (victim, result) = h.create_escrow(1);
        assert_ok(&result);
        let victim_vault = ata_for(&victim, &h.mint, &h.token_program);

        let attacker = Keypair::new();
        let attacker_ata = fund(&mut h, &attacker, 10);

        let short_deadline = h.now() + 60;
        let ix = h.create_escrow_ix(
            &attacker.pubkey(),
            7,
            1,
            short_deadline,
            attacker.pubkey(),
            attacker.pubkey(),
        );
        assert_ok(&h.send(&[ix], &[&attacker]));
        let own = h.escrow_pda(&attacker.pubkey(), 7);

        // Past the attacker's own deadline, and well inside the victim's.
        h.set_time(short_deadline);
        let ix = reclaim_aimed_at(&h, own, attacker.pubkey(), victim_vault);
        let result = h.send(&[ix], &[&attacker]);
        assert_error(&result, AnchorError::ConstraintTokenOwner);
        assert_eq!(h.token_balance(&victim_vault), ESCROW_AMOUNT);
        assert_eq!(h.token_balance(&attacker_ata), 9);
    });
}

/// An escrow at its own address whose stored bump does not re-derive it.
///
/// The bump is stored rather than searched for, which is what keeps both exits
/// cheap. What makes that safe is narrower than it first looks. Anchor compiles
/// `bump = escrow.bump` to one `create_program_address` over the stored seeds
/// and the stored bump, compared against the address the account sits at: a
/// consistency check between state and address, not a test of canonicality. A
/// bump one below the canonical one either derives some other address or no
/// address at all, and both come back as the same refusal — which is all this
/// test shows. A bump that does re-derive the address is the next test.
#[test]
fn an_escrow_whose_stored_bump_does_not_derive_its_address_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let mut state = h.escrow_state(&escrow);
        state.bump = state.bump.wrapping_sub(1);
        plant(&mut h, escrow, verdict_escrow::ID, escrow_bytes(&state));

        let expires_at = h.now() + 600;
        let message = build_message(
            &verdict_escrow::ID,
            &escrow,
            &state,
            Verdict::Release,
            expires_at,
        );
        let verdict_ix = Ed25519Ix::sign(&h.verdict_signer, &message);
        let accounts = h.settle_accounts(escrow);

        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_error(&result, AnchorError::ConstraintSeeds);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
    });
}

/// The control for the test above: a bump that is not canonical and does
/// re-derive its address.
///
/// Count down past the canonical bump to the next value that derives anything
/// at all. What comes out is a real program address of this program, reached
/// from the same seeds, and an escrow planted there with that bump satisfies
/// the `seeds` constraint exactly as a canonical one does, because the
/// constraint only asks that the two agree. The attacker names themselves the
/// verdict signer and the seller, signs a release, and the money moves: the
/// runtime signs for this address as readily as for the canonical one, since
/// `invoke_signed` derives the signer from the seeds it is handed, bump
/// included.
///
/// This is not a hole in this program, and the reason is worth stating exactly.
/// `create_escrow` derives the escrow with Anchor's bare `bump`, which is the
/// canonical bump by definition, and no instruction rewrites the field
/// afterwards, so an escrow carrying any other bump cannot exist on a cluster;
/// `set_account` is what put this one there, writing the ledger directly. What
/// the test is here to prevent is a reader taking away the wrong rule. "Anchor
/// refuses a non-canonical bump" is false. "This program never creates one" is
/// true, and is what the money rests on.
#[test]
fn an_escrow_planted_at_a_non_canonical_bump_pays_out_because_its_seeds_still_agree() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let buyer = h.buyer.pubkey();
        let canonical = h.escrow_pda(&buyer, 1);
        let (forged, bump) = next_address_below_canonical(&buyer, 1);
        assert_ne!(
            forged, canonical,
            "the same seeds, a second address, a different bump"
        );

        let attacker = Keypair::new();
        let attacker_ata = fund(&mut h, &attacker, 0);

        // An ordinary associated token account of the forged address, holding
        // what a real deposit would hold.
        let vault = h.create_ata(&forged);
        let payer = h.buyer.insecure_clone();
        let mint = h.mint;
        let token_program = h.token_program;
        MintTo::new(&mut h.svm, &payer, &mint, &vault, ESCROW_AMOUNT)
            .token_program_id(&token_program)
            .send()
            .expect("fund the vault of the forged escrow");

        // Valid escrow state in every field, including the bump, which is the
        // one this address was derived with.
        let state = Escrow {
            buyer,
            seller: attacker.pubkey(),
            mint: h.mint,
            verdict_signer: attacker.pubkey(),
            amount: ESCROW_AMOUNT,
            deadline: h.now() + HOUR,
            created_slot: h.clock().slot,
            escrow_id: 1,
            bump,
        };
        plant(&mut h, forged, verdict_escrow::ID, escrow_bytes(&state));

        let expires_at = h.now() + 600;
        let message = build_message(
            &verdict_escrow::ID,
            &forged,
            &state,
            Verdict::Release,
            expires_at,
        );
        let verdict_ix = Ed25519Ix::sign(&attacker, &message);
        let accounts = h.settle_accounts(forged);
        assert_eq!(accounts.vault, vault, "the vault is the derived one");
        assert_eq!(accounts.seller_token_account, attacker_ata);

        // It pays. Reported rather than softened: the whole vault reaches the
        // attacker, both accounts close, and no check anywhere in the
        // instruction objected to the bump.
        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_ok(&result);
        assert_eq!(h.token_balance(&attacker_ata), ESCROW_AMOUNT);
        assert!(!h.account_exists(&vault), "the forged vault is closed");
        assert!(!h.account_exists(&forged), "the forged escrow is closed");

        // And the canonical address, the only one a caller could ever have
        // opened an escrow at, never held an account at all.
        assert!(!h.account_exists(&canonical));
    });
}

/// An escrow at its own address whose stored id is no longer the one in the
/// seeds. Nothing else is changed: the address is a real escrow PDA of this
/// program, and the account is a valid escrow. The pair simply no longer agree,
/// and the seeds check is what notices.
#[test]
fn an_escrow_whose_stored_id_no_longer_matches_its_address_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let mut state = h.escrow_state(&escrow);
        state.escrow_id = 2;
        plant(&mut h, escrow, verdict_escrow::ID, escrow_bytes(&state));

        let expires_at = h.now() + 600;
        let message = build_message(
            &verdict_escrow::ID,
            &escrow,
            &state,
            Verdict::Release,
            expires_at,
        );
        let verdict_ix = Ed25519Ix::sign(&h.verdict_signer, &message);
        let accounts = h.settle_accounts(escrow);

        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_error(&result, AnchorError::ConstraintSeeds);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
    });
}

/// An escrow at its own address whose stored buyer has been swapped for the
/// attacker's key.
///
/// Rewriting the buyer is how a refund would be redirected: the refund
/// destination is the stored buyer's token account, and `has_one = buyer` would
/// be satisfied by the attacker signing for themselves. Having the buyer in the
/// seeds makes the rewrite self-defeating — change it and the account no longer
/// sits at the address its own contents derive, so the seeds check fires before
/// `has_one` is reached.
#[test]
fn an_escrow_whose_stored_buyer_no_longer_matches_its_address_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let attacker = Keypair::new();
        let attacker_ata = fund(&mut h, &attacker, 0);

        let mut state = h.escrow_state(&escrow);
        state.buyer = attacker.pubkey();
        state.verdict_signer = attacker.pubkey();
        plant(&mut h, escrow, verdict_escrow::ID, escrow_bytes(&state));

        let expires_at = h.now() + 600;
        let message = build_message(
            &verdict_escrow::ID,
            &escrow,
            &state,
            Verdict::Refund,
            expires_at,
        );
        let verdict_ix = Ed25519Ix::sign(&attacker, &message);
        let accounts = h.settle_accounts(escrow);

        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Refund, expires_at);
        assert_error(&result, AnchorError::ConstraintSeeds);
        assert_eq!(h.token_balance(&attacker_ata), 0);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
    });
}

/// What the three gates are worth, in tokens.
///
/// This is one of the two tests in the file that succeed, and neither is a
/// finding: both are controls that give the rest their price. The forged state
/// from
/// `a_planted_escrow_naming_the_attacker_as_verdict_signer_is_refused` is
/// written here to the escrow's own address, so every gate passes — the owner
/// is this program, the discriminator is the right one, and the stored buyer,
/// escrow id and bump still re-derive this address. Two fields differ from what
/// the buyer agreed to, and the whole vault leaves for the attacker on a
/// signature only the attacker holds.
///
/// No caller can reach this state. `set_account` writes the ledger directly,
/// past the rule that only an account's owning program may change its data,
/// and this program writes an escrow's fields once, under `init`, and has no
/// instruction that touches them afterwards. That rule, and the three gates
/// above for accounts that were never written by this program at all, are the
/// whole of the defence.
#[test]
fn a_tampered_verdict_signer_pays_the_attacker_once_the_runtime_is_out_of_the_way() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let attacker = Keypair::new();
        let attacker_ata = h.create_ata(&attacker.pubkey());

        let mut state = h.escrow_state(&escrow);
        state.seller = attacker.pubkey();
        state.verdict_signer = attacker.pubkey();
        plant(&mut h, escrow, verdict_escrow::ID, escrow_bytes(&state));

        let expires_at = h.now() + 600;
        let message = build_message(
            &verdict_escrow::ID,
            &escrow,
            &state,
            Verdict::Release,
            expires_at,
        );
        let verdict_ix = Ed25519Ix::sign(&attacker, &message);
        let accounts = h.settle_accounts(escrow);
        assert_eq!(accounts.seller_token_account, attacker_ata);

        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_ok(&result);
        assert_eq!(h.token_balance(&attacker_ata), ESCROW_AMOUNT);
        assert!(!h.account_exists(&escrow));
    });
}
