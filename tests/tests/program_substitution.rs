//! Arbitrary CPI: getting the program to call code the attacker chose, or to
//! believe an account that is not what it claims to be.
//!
//! Every instruction in this program ends in a CPI to a token program, and the
//! program id of that CPI arrives as an account the caller passes in. So does
//! the mint whose decimals the transfer is checked against. Neither is
//! something the program can take on trust, because of what the CPI carries
//! with it: `create_escrow` transfers with the buyer's own signature, so a
//! chosen callee would be handed the buyer's token account and the right to
//! move all of it rather than the escrowed amount; `settle` and `reclaim`
//! transfer with `invoke_signed` under the escrow PDA's seeds, which is the
//! vault's only authority, so a chosen callee would be handed a signature from
//! the account that owns the money. In both cases the attacker's own code
//! decides what that signature does. That is why this class drains programs
//! outright rather than merely bending them.
//!
//! What stops it here is typing, and the tests below are about naming which
//! piece of typing fires. `Interface<TokenInterface>` pins the token program to
//! one of the two real token programs by address. `Program<AssociatedToken>`
//! and `Program<System>` pin theirs to a single address each.
//! `InterfaceAccount<Mint>` refuses an account that no token program owns, and
//! `mint::token_program = token_program` ties the two together so a forged pair
//! cannot be made self-consistent. The 82-byte rule in `create_escrow` is a
//! length check and nothing more: on its own it would pass a forgery, and
//! `a_consistently_forged_mint_and_token_program_pair_is_refused` is the
//! forgery it would have passed.
//!
//! Almost every test here ends by asserting that the attacker's program was
//! never invoked, and that assertion is a search through the transaction's
//! logs. A search cannot tell a program that was not called from a transaction
//! that logged nothing, so the two tests at the end of the file hold
//! [`assert_no_cpi_into`] to its own standard: given silence, it has to refuse
//! the question rather than answer it in the attacker's favour.

// Same reason as the harness: LiteSVM's failure type carries the logs the
// assertions read, so the `Err` variant of a send is large by design.
#![allow(clippy::result_large_err)]

use anchor_lang::error::ErrorCode as AnchorError;
use anchor_lang::prelude::Pubkey;
use anchor_lang::{InstructionData, ToAccountMetas};
use escrow_harness::*;
use litesvm::types::TransactionResult;
use solana_account::Account;
use solana_instruction::Instruction;
use solana_instruction_error::InstructionError;
use solana_keypair::Keypair;
use solana_transaction_error::TransactionError;
use verdict_escrow::verdict::Verdict;

/// Every account `create_escrow` takes, so a test can point one of them at a
/// program of its own choosing and leave the rest correct. The harness only
/// ever builds the honest set.
#[derive(Clone, Copy, Debug)]
struct CreateAccounts {
    buyer: Pubkey,
    mint: Pubkey,
    escrow: Pubkey,
    vault: Pubkey,
    buyer_token_account: Pubkey,
    token_program: Pubkey,
    associated_token_program: Pubkey,
    system_program: Pubkey,
}

impl CreateAccounts {
    fn new(h: &Harness, escrow_id: u64) -> Self {
        let buyer = h.buyer.pubkey();
        let escrow = h.escrow_pda(&buyer, escrow_id);
        Self {
            buyer,
            mint: h.mint,
            escrow,
            vault: ata_for(&escrow, &h.mint, &h.token_program),
            buyer_token_account: ata_for(&buyer, &h.mint, &h.token_program),
            token_program: h.token_program,
            associated_token_program: ASSOCIATED_TOKEN_PROGRAM_ID,
            system_program: SYSTEM_PROGRAM_ID,
        }
    }

    fn instruction(
        &self,
        escrow_id: u64,
        deadline: i64,
        seller: Pubkey,
        verdict_signer: Pubkey,
    ) -> Instruction {
        Instruction {
            program_id: verdict_escrow::ID,
            accounts: verdict_escrow::accounts::CreateEscrow {
                buyer: self.buyer,
                mint: self.mint,
                escrow: self.escrow,
                vault: self.vault,
                buyer_token_account: self.buyer_token_account,
                token_program: self.token_program,
                associated_token_program: self.associated_token_program,
                system_program: self.system_program,
            }
            .to_account_metas(None),
            data: verdict_escrow::instruction::CreateEscrow {
                escrow_id,
                amount: ESCROW_AMOUNT,
                deadline,
                seller,
                verdict_signer,
            }
            .data(),
        }
    }
}

/// Send `create_escrow` with a deadline an hour out, which every test here
/// leaves alone: the subject is always an account, never the clock.
fn send_create(h: &mut Harness, accounts: &CreateAccounts, escrow_id: u64) -> TransactionResult {
    let deadline = h.now() + HOUR;
    let ix = accounts.instruction(
        escrow_id,
        deadline,
        h.seller.pubkey(),
        h.verdict_signer.pubkey(),
    );
    let buyer = h.buyer.insecure_clone();
    h.send(&[ix], &[&buyer])
}

/// The same for `reclaim`, which the harness also builds only one way.
#[derive(Clone, Copy, Debug)]
struct ReclaimAccounts {
    escrow: Pubkey,
    buyer: Pubkey,
    mint: Pubkey,
    vault: Pubkey,
    buyer_token_account: Pubkey,
    token_program: Pubkey,
}

impl ReclaimAccounts {
    fn new(h: &Harness, escrow: Pubkey) -> Self {
        let state = h.escrow_state(&escrow);
        Self {
            escrow,
            buyer: state.buyer,
            mint: state.mint,
            vault: ata_for(&escrow, &state.mint, &h.token_program),
            buyer_token_account: ata_for(&state.buyer, &state.mint, &h.token_program),
            token_program: h.token_program,
        }
    }

    fn instruction(&self) -> Instruction {
        Instruction {
            program_id: verdict_escrow::ID,
            accounts: verdict_escrow::accounts::Reclaim {
                escrow: self.escrow,
                buyer: self.buyer,
                mint: self.mint,
                vault: self.vault,
                buyer_token_account: self.buyer_token_account,
                token_program: self.token_program,
            }
            .to_account_metas(None),
            data: verdict_escrow::instruction::Reclaim {}.data(),
        }
    }
}

fn send_reclaim(h: &mut Harness, accounts: &ReclaimAccounts) -> TransactionResult {
    let ix = accounts.instruction();
    let buyer = h.buyer.insecure_clone();
    h.send(&[ix], &[&buyer])
}

/// An escrow at its deadline, ready for `reclaim`.
fn escrow_at_its_deadline(h: &mut Harness, escrow_id: u64) -> Pubkey {
    let (escrow, result) = h.create_escrow(escrow_id);
    assert_ok(&result);
    let deadline = h.escrow_state(&escrow).deadline;
    h.set_time(deadline);
    escrow
}

/// Plant an account that is exactly the 82 bytes of a bare SPL mint — a set
/// mint authority, a supply, the right decimals, the initialised flag, no
/// freeze authority — and hand it to `owner`.
///
/// Every byte here is attacker-chosen, which is the point: the shape of a mint
/// is public, so the only thing that distinguishes a real mint from these 82
/// bytes is which program owns the account.
fn plant_forged_mint(h: &mut Harness, owner: Pubkey) -> Pubkey {
    let address = Keypair::new().pubkey();
    let authority = Keypair::new().pubkey();
    let mut data = vec![0u8; 82];
    data[0..4].copy_from_slice(&1u32.to_le_bytes()); // mint authority is set
    data[4..36].copy_from_slice(&authority.to_bytes());
    data[36..44].copy_from_slice(&BUYER_START.to_le_bytes()); // supply
    data[44] = DECIMALS;
    data[45] = 1; // initialised
    let lamports = h.svm.minimum_balance_for_rent_exemption(data.len());
    h.svm
        .set_account(
            address,
            Account {
                lamports,
                data,
                owner,
                executable: false,
                rent_epoch: 0,
            },
        )
        .expect("plant the forged mint");
    address
}

/// A plain, rent-paying, non-executable account at an address of the
/// attacker's choosing.
fn plant_data_account(h: &mut Harness) -> Pubkey {
    let address = Keypair::new().pubkey();
    let lamports = h.svm.minimum_balance_for_rent_exemption(165);
    h.svm
        .set_account(
            address,
            Account {
                lamports,
                data: vec![7u8; 165],
                owner: SYSTEM_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
        )
        .expect("plant the data account");
    address
}

/// A genuinely deployed, genuinely executable program at an address the
/// attacker picked. Nothing new is built for this: the already-compiled program
/// under test is loaded a second time under a different id, which is enough to
/// make the account executable and the address the attacker's.
fn deploy_program_at_an_attacker_address(h: &mut Harness) -> Pubkey {
    let address = Keypair::new().pubkey();
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../target/deploy/verdict_escrow.so"
    );
    let bytes = std::fs::read(path).expect("read the compiled program");
    h.svm
        .add_program(address, &bytes)
        .expect("deploy at the attacker's address");
    address
}

/// Assert that the runtime threw the transaction out with one exact
/// instruction error.
///
/// [`assert_error`] covers program error codes, which is what almost every
/// test in this suite wants. A runtime refusal such as `MissingAccount` is
/// raised while a CPI is being set up, so it carries no program code of its own
/// and has to be matched on the error itself.
#[track_caller]
fn assert_instruction_error(result: &TransactionResult, index: u8, expected: InstructionError) {
    let failure = result
        .as_ref()
        .err()
        .unwrap_or_else(|| panic!("expected {expected:?}, got a successful transaction"));
    match &failure.err {
        TransactionError::InstructionError(got_index, got)
            if (*got_index, got) == (index, &expected) => {}
        other => panic!(
            "expected instruction {index} to fail with {expected:?}, got {other:?}\n{:?}",
            failure.meta.logs
        ),
    }
}

/// Assert that nothing called into a program.
///
/// Every invocation logs `Program <id> invoke [depth]` before the callee's
/// first instruction, and a CPI is one at depth two or deeper; depth one is the
/// transaction's own call into the program under test, which is not a CPI and
/// is expected. Matching the line rather than the bare address matters, because
/// Anchor prints the address it rejected in the error it logs: a forged program
/// id appears in the logs of the very transaction that refused to call it.
///
/// The two checks in front of the search are what make its answer mean
/// anything. Searching for an invocation that is not there is an `all()` over
/// a vector, and `all()` over an empty vector is true, so a transaction that
/// logged nothing would come back as proof that the attacker's program was
/// never called. An empty log vector is not proof of anything. It is what the
/// runtime leaves behind when it throws a transaction out before any program
/// runs — a precompile rejection, or a refusal while the instruction is still
/// being set up — which is exactly the case where a CPI would have gone
/// unlogged whether or not it happened. Logs that never show the program under
/// test starting say no more. The absence of a line is evidence only where a
/// line would have been written.
#[track_caller]
fn assert_no_cpi_into(result: &TransactionResult, program: &Pubkey) {
    let failure = result
        .as_ref()
        .err()
        .unwrap_or_else(|| panic!("this transaction was supposed to fail"));
    let logs = &failure.meta.logs;
    assert!(
        !logs.is_empty(),
        "this transaction logged nothing, so it says nothing either way about \
         {program}: the runtime threw it out before any program ran, and a \
         search of no logs is not evidence of no call"
    );
    let under_test = format!("Program {} invoke [1]", verdict_escrow::ID);
    assert!(
        logs.iter().any(|line| line.starts_with(&under_test)),
        "the program under test never started, so its logs cannot show whether \
         it called into {program}: {logs:?}"
    );

    let invocation = format!("Program {program} invoke [");
    let top_level = format!("Program {program} invoke [1]");
    assert!(
        logs.iter()
            .all(|line| !line.starts_with(&invocation) || line.starts_with(&top_level)),
        "nothing should have called into {program}, but the logs show it did: {logs:?}"
    );
}

// --- (a) an attacker-controlled program id in the token_program slot --------

/// The buyer names their own program as the token program. Had the program
/// trusted the slot, `transfer_checked` would have become an `invoke` into that
/// program carrying the buyer's token account and the buyer's signature, which
/// is a licence to move the buyer's whole balance rather than the escrowed
/// amount. Anchor compares the address against the two real token programs
/// first.
#[test]
fn an_unknown_program_id_as_the_token_program_in_create_escrow_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let mut accounts = CreateAccounts::new(&h, 1);
        let attacker = Keypair::new().pubkey();
        accounts.token_program = attacker;

        let result = send_create(&mut h, &accounts, 1);
        assert_error(&result, AnchorError::InvalidProgramId);
        assert_no_cpi_into(&result, &attacker);
        assert!(!h.account_exists(&accounts.escrow));
        assert_eq!(h.token_balance(&h.ata(&h.buyer.pubkey())), BUYER_START);
    });
}

/// `settle` takes no privileged signer, so anybody may send it, and the money
/// moves under the escrow PDA's seeds. A trusted token program slot would hand
/// the sender's chosen code an `invoke_signed` from the vault's own authority:
/// one correctly signed verdict, and every token the vault holds goes wherever
/// that code says.
#[test]
fn an_unknown_program_id_as_the_token_program_in_settle_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let expires_at = h.now() + 600;
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let mut accounts = h.settle_accounts(escrow);
        let attacker = Keypair::new().pubkey();
        accounts.token_program = attacker;

        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_error(&result, AnchorError::InvalidProgramId);
        assert_no_cpi_into(&result, &attacker);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
        assert!(h.account_exists(&escrow));
    });
}

/// The same slot in `reclaim`, which the buyer signs. The buyer is the one
/// person entitled to this money after the deadline, so there is nothing to
/// steal from themselves; the danger is the PDA signature the CPI carries,
/// which a chosen callee could spend on something other than the transfer it
/// was asked for.
#[test]
fn an_unknown_program_id_as_the_token_program_in_reclaim_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let escrow = escrow_at_its_deadline(&mut h, 1);

        let mut accounts = ReclaimAccounts::new(&h, escrow);
        let attacker = Keypair::new().pubkey();
        accounts.token_program = attacker;

        let result = send_reclaim(&mut h, &accounts);
        assert_error(&result, AnchorError::InvalidProgramId);
        assert_no_cpi_into(&result, &attacker);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
        assert!(h.account_exists(&escrow));
    });
}

// --- (e) what the attacker can put at that address, which is nothing useful -

/// Nothing is deployed for this test, and nothing needs to be.
///
/// `Interface<TokenInterface>` compares the address it was given against the
/// two token program ids and stops there; it never reaches the question of
/// whether the account is executable. So every one of these gets the same
/// answer: an address with no account at all, an address holding a funded
/// non-executable account, an address where a real program genuinely is
/// deployed, a native program, this program itself — which is where a trusted
/// slot would let `settle` re-enter its own `settle` — and the associated token
/// program, which is a legitimate program that simply is not a token program.
/// There is no account an attacker can create, fund or deploy that makes an
/// address of theirs acceptable, which is the useful thing to know: the check
/// is on identity, so the usual escalation of "deploy something convincing"
/// has nowhere to go.
#[test]
fn an_attackers_address_is_refused_as_the_token_program_whatever_is_deployed_there() {
    let candidates: [fn(&mut Harness) -> Pubkey; 6] = [
        |_| Keypair::new().pubkey(),
        plant_data_account,
        deploy_program_at_an_attacker_address,
        |_| SYSTEM_PROGRAM_ID,
        |_| verdict_escrow::ID,
        |_| ASSOCIATED_TOKEN_PROGRAM_ID,
    ];

    for_each_token_program(|kind| {
        for make_candidate in candidates {
            // A fresh escrow per candidate, so each one is tried against a
            // full vault rather than against whatever the last one left.
            let mut h = Harness::new(kind);
            let candidate = make_candidate(&mut h);
            let (escrow, result) = h.create_escrow(1);
            assert_ok(&result);

            let expires_at = h.now() + 600;
            let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
            let mut accounts = h.settle_accounts(escrow);
            accounts.token_program = candidate;

            let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
            assert_error(&result, AnchorError::InvalidProgramId);
            assert_no_cpi_into(&result, &candidate);
            assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
            assert!(h.account_exists(&escrow));
        }
    });
}

// --- (b) the other token program, which is real but still wrong -------------

/// The real other token program, in place of the one that owns the mint. The
/// suite already covers this for `settle`; `create_escrow` fails differently
/// and earlier, so it is worth its own test.
///
/// Anchor derives the vault address it is about to create from the mint, the
/// authority and the token program it was handed, and builds the associated
/// token CPI around that derived address rather than around the account the
/// caller passed. Under the other token program the derivation lands somewhere
/// the transaction never mentioned, so the CPI names an account the runtime
/// cannot supply. The transfer is never reached.
///
/// `MissingAccount` is recorded here because the order the checks fire in is
/// worth pinning, but it is an artifact of that derivation and not a statement
/// about the `token_program` slot: the same substitution in `reclaim` below is
/// refused by a constraint instead, and a future Anchor that validated the slot
/// before deriving the vault would refuse this with a program error while being
/// no weaker. What has to hold either way is what the two assertions after it
/// say — the substituted program was never invoked, and nothing was created at
/// the address Anchor derived under it.
#[test]
fn the_other_token_program_in_create_escrow_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let mut accounts = CreateAccounts::new(&h, 1);
        accounts.token_program = kind.other_program_id();

        // Where the vault would land under the substituted program, which is
        // not the account the instruction passes.
        let derived_vault = ata_for(&accounts.escrow, &h.mint, &accounts.token_program);
        assert_ne!(derived_vault, accounts.vault);

        let result = send_create(&mut h, &accounts, 1);
        assert_instruction_error(&result, 0, InstructionError::MissingAccount);
        assert_no_cpi_into(&result, &accounts.token_program);
        assert!(
            !h.account_exists(&derived_vault),
            "no vault may be created under the substituted token program"
        );
        assert!(!h.account_exists(&accounts.vault));
        assert!(!h.account_exists(&accounts.escrow));
        assert_eq!(h.token_balance(&h.ata(&h.buyer.pubkey())), BUYER_START);
    });
}

/// The same substitution, made self-consistent: the vault and the buyer's
/// token account are re-derived under the other token program, so the
/// addresses match what Anchor will derive. That gets past the missing account
/// above and stops one account later, because the buyer has no token account
/// for this mint under a token program that does not own the mint.
///
/// Nor could they obtain one. An associated token account is built by the token
/// program named in its own derivation, and that program refuses to size or
/// initialise an account for a mint it does not own — `IncorrectProgramId`,
/// raised inside the token program itself — so this forged world cannot be
/// completed from the outside at all.
#[test]
fn the_other_token_program_with_its_own_vault_addresses_is_refused_by_create_escrow() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let other = kind.other_program_id();
        let mut accounts = CreateAccounts::new(&h, 1);
        accounts.token_program = other;
        accounts.vault = ata_for(&accounts.escrow, &h.mint, &other);
        accounts.buyer_token_account = ata_for(&accounts.buyer, &h.mint, &other);

        let result = send_create(&mut h, &accounts, 1);
        assert_error(&result, AnchorError::AccountNotInitialized);
        assert!(!h.account_exists(&accounts.escrow));
        assert_eq!(h.token_balance(&h.ata(&h.buyer.pubkey())), BUYER_START);
    });
}

/// `reclaim`'s turn. Here the escrow already stores its mint, and the mint
/// account pins the token program that owns it, so the mismatch is caught by a
/// constraint rather than by a derivation that goes nowhere.
#[test]
fn the_other_token_program_in_reclaim_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let escrow = escrow_at_its_deadline(&mut h, 1);

        let mut accounts = ReclaimAccounts::new(&h, escrow);
        accounts.token_program = kind.other_program_id();

        let result = send_reclaim(&mut h, &accounts);
        assert_error(&result, AnchorError::ConstraintMintTokenProgram);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
        assert!(h.account_exists(&escrow));
    });
}

// --- (c) a forged mint that passes the length check -------------------------

/// Exactly 82 bytes of plausible mint, owned by an attacker's program.
///
/// `create_escrow`'s own rule about mints is a length check — not 82 bytes
/// means extensions, which the program does not model — and a length check is
/// precisely what a forgery satisfies. What refuses this is the type: an
/// `InterfaceAccount<Mint>` must be owned by a token program, and this one is
/// not. Without that check the decimals passed to `transfer_checked` would come
/// from attacker-chosen bytes, and the escrow would record a mint whose
/// behaviour nothing on chain constrains.
#[test]
fn a_forged_mint_of_exactly_82_bytes_is_refused_by_create_escrow() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let attacker_program = Keypair::new().pubkey();
        let forged = plant_forged_mint(&mut h, attacker_program);

        // The length rule on its own would have let this through.
        let planted = h.svm.get_account(&forged).expect("the forgery is there");
        assert_eq!(planted.data.len(), 82);
        assert_eq!(planted.owner, attacker_program);

        let mut accounts = CreateAccounts::new(&h, 1);
        accounts.mint = forged;

        let result = send_create(&mut h, &accounts, 1);
        assert_error(&result, AnchorError::AccountOwnedByWrongProgram);
        assert!(!h.account_exists(&accounts.escrow));
        assert_eq!(h.token_balance(&h.ata(&h.buyer.pubkey())), BUYER_START);
    });
}

/// The same forgery offered to `settle` in place of the escrow's stored mint.
/// The escrow's `has_one = mint` would have caught it too, but the owner check
/// runs first, while the account is being deserialised: the program declines to
/// read an account as a mint before it ever asks whether it is the right one.
#[test]
fn a_forged_mint_cannot_stand_in_for_the_stored_mint_in_settle() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let forged = plant_forged_mint(&mut h, Keypair::new().pubkey());
        let expires_at = h.now() + 600;
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let mut accounts = h.settle_accounts(escrow);
        accounts.mint = forged;

        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_error(&result, AnchorError::AccountOwnedByWrongProgram);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
        assert!(h.account_exists(&escrow));
    });
}

/// And to `reclaim`, where the buyer is the signer. Same forgery, same check.
#[test]
fn a_forged_mint_cannot_stand_in_for_the_stored_mint_in_reclaim() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let escrow = escrow_at_its_deadline(&mut h, 1);

        let forged = plant_forged_mint(&mut h, Keypair::new().pubkey());
        let mut accounts = ReclaimAccounts::new(&h, escrow);
        accounts.mint = forged;

        let result = send_reclaim(&mut h, &accounts);
        assert_error(&result, AnchorError::AccountOwnedByWrongProgram);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
        assert!(h.account_exists(&escrow));
    });
}

/// The stored mint pubkey, with the account behind it re-owned by an attacker
/// program after the escrow was opened.
///
/// A mint's owner cannot change like this on a live chain, and the test does
/// not pretend otherwise: it is here to show where the program's trust sits. It
/// re-validates the mint on the way out rather than treating the pubkey it
/// stored at creation as proof that the account is still a mint — so an escrow
/// is not a standing permission to read that address as one.
#[test]
fn the_stored_mint_re_owned_by_an_attacker_program_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let mint = h.mint;
        let mut account = h.svm.get_account(&mint).expect("the mint exists");
        account.owner = Keypair::new().pubkey();
        h.svm
            .set_account(mint, account)
            .expect("re-own the mint account");

        let expires_at = h.now() + 600;
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let accounts = h.settle_accounts(escrow);

        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_error(&result, AnchorError::AccountOwnedByWrongProgram);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
        assert!(h.account_exists(&escrow));
    });
}

// --- (d) the other two program slots in create_escrow ----------------------

/// The associated token program is the one `create_escrow` asks to build the
/// vault. A trusted slot would mean the caller choosing which program creates
/// an account at an address the caller also chose, with the buyer paying for
/// it — the vault would stop being the escrow's associated token account and
/// become whatever the caller wanted the program to sign for.
///
/// Both candidates get the same answer, by identity: an address with nothing at
/// it, and the SPL token program, which is deployed, executable, and plainly a
/// real program — just not the one this slot names.
#[test]
fn a_substitute_associated_token_program_is_refused() {
    for_each_token_program(|kind| {
        for candidate in [Keypair::new().pubkey(), TOKEN_PROGRAM_ID] {
            let mut h = Harness::new(kind);
            let mut accounts = CreateAccounts::new(&h, 1);
            accounts.associated_token_program = candidate;

            let result = send_create(&mut h, &accounts, 1);
            assert_error(&result, AnchorError::InvalidProgramId);
            assert_no_cpi_into(&result, &candidate);
            assert!(!h.account_exists(&accounts.escrow));
            assert_eq!(h.token_balance(&h.ata(&h.buyer.pubkey())), BUYER_START);
        }
    });
}

/// The system program slot, which is what actually allocates the escrow
/// account and pays its rent out of the buyer's lamports. A trusted slot here
/// would put the buyer's signature in front of code of the caller's choosing
/// with a lamport transfer already set up for it.
///
/// The second candidate is this program itself, so the substitution is not even
/// an unknown address: it is an account the transaction legitimately mentions.
/// Nothing calls into either of them — for the second, nothing beyond the
/// transaction's own top-level call into `create_escrow`.
#[test]
fn a_substitute_system_program_is_refused() {
    for_each_token_program(|kind| {
        for candidate in [Keypair::new().pubkey(), verdict_escrow::ID] {
            let mut h = Harness::new(kind);
            let mut accounts = CreateAccounts::new(&h, 1);
            accounts.system_program = candidate;

            let result = send_create(&mut h, &accounts, 1);
            assert_error(&result, AnchorError::InvalidProgramId);
            assert_no_cpi_into(&result, &candidate);
            assert!(!h.account_exists(&accounts.escrow));
            assert_eq!(h.token_balance(&h.ata(&h.buyer.pubkey())), BUYER_START);
        }
    });
}

// --- the whole forgery at once ---------------------------------------------

/// The attack this class is really about, assembled so that no single
/// constraint in `create_escrow` looks violated.
///
/// A real program is deployed at the attacker's address. The mint is 82 bytes
/// of attacker-chosen data owned by that program, so `mint::token_program =
/// token_program` holds. The vault and the buyer's token account are derived
/// under that same program, so the associated token constraints line up too.
/// Every relationship the program checks between the accounts is internally
/// consistent; the one thing the attacker cannot forge is membership of the set
/// of two real token programs. `InterfaceAccount<Mint>` refuses to read the
/// mint at all, because no token program owns it, and the attacker's program is
/// never invoked.
///
/// A program that had kept the length check and dropped the typing would have
/// reached `transfer_checked` here and CPI'd into attacker code with the
/// buyer's signature attached.
#[test]
fn a_consistently_forged_mint_and_token_program_pair_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let attacker = deploy_program_at_an_attacker_address(&mut h);
        let forged_mint = plant_forged_mint(&mut h, attacker);

        let mut accounts = CreateAccounts::new(&h, 1);
        accounts.mint = forged_mint;
        accounts.token_program = attacker;
        accounts.vault = ata_for(&accounts.escrow, &forged_mint, &attacker);
        accounts.buyer_token_account = ata_for(&accounts.buyer, &forged_mint, &attacker);

        let result = send_create(&mut h, &accounts, 1);
        assert_error(&result, AnchorError::AccountOwnedByWrongProgram);
        assert_no_cpi_into(&result, &attacker);
        assert!(!h.account_exists(&accounts.escrow));
        assert_eq!(h.token_balance(&h.ata(&h.buyer.pubkey())), BUYER_START);
    });
}

// --- the assertion this file leans on, checked against silence --------------

/// Not an attack on the program: an attack on the strongest claim in this
/// file, which is made by searching logs.
///
/// Every test above ends in [`assert_no_cpi_into`], and a search for a line
/// that is not there cannot distinguish "the program was never called" from
/// "nothing was ever written down". A corrupted signature makes the Ed25519
/// precompile throw the transaction out before any program runs, which is the
/// cheapest way to produce the empty log vector that used to satisfy the
/// helper's `all()` unconditionally. The helper now refuses the question
/// instead of answering it, and this test is what keeps it refusing: delete the
/// non-empty check and this passes, taking the file's central claim with it.
#[test]
#[should_panic(expected = "logged nothing")]
fn no_logs_at_all_is_not_proof_that_a_program_was_never_called() {
    let mut h = Harness::new(TokenKind::Classic);
    let (escrow, result) = h.create_escrow(1);
    assert_ok(&result);

    let expires_at = h.now() + 600;
    let mut verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
    verdict_ix.signature[0] ^= 0xff;
    let accounts = h.settle_accounts(escrow);
    let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
    assert_precompile_rejection(&result);

    assert_no_cpi_into(&result, &Keypair::new().pubkey());
}

/// The same hole one step along: logs that were written, by somebody else.
///
/// Two memo instructions, the second carrying bytes that are not UTF-8, so the
/// memo program fails and the transaction never reaches any other program. The
/// log vector is not empty, and it still says nothing about whether the program
/// under test called anywhere, because the program under test never started.
#[test]
#[should_panic(expected = "never started")]
fn logs_from_another_program_are_not_proof_either() {
    let mut h = Harness::new(TokenKind::Classic);
    // The memo program rejects data that is not UTF-8, and the text the helper
    // takes cannot express that, so the bytes are set directly.
    let mut invalid_memo = memo_ix("");
    invalid_memo.data = vec![0xff, 0xfe];

    let relayer = h.relayer.insecure_clone();
    let result = h.send(&[memo_ix("a memo that works"), invalid_memo], &[&relayer]);

    assert_no_cpi_into(&result, &Keypair::new().pubkey());
}
