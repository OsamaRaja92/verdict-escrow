//! Test harness: one escrow, one mint, and the pieces every test bends.
//!
//! The suite runs twice, once per token program, so `TokenKind` threads through
//! everything. Nothing here hides the Ed25519 instruction behind a helper that
//! only produces valid layouts — [`Ed25519Ix`] is a plain struct of the exact
//! bytes the precompile reads, so a test can corrupt one field and leave the
//! rest alone.

use anchor_lang::{AccountDeserialize, InstructionData, ToAccountMetas};
use litesvm::types::{FailedTransactionMetadata, TransactionResult};
use litesvm::LiteSVM;
use litesvm_token::{CreateAssociatedTokenAccount, CreateMint, MintTo};
use solana_clock::Clock;
use solana_instruction::Instruction;
use solana_instruction_error::InstructionError;
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;

use anchor_lang::prelude::Pubkey;
use verdict_escrow::state::{Escrow, ESCROW_SEED};
use verdict_escrow::verdict::{build_message, Verdict, MESSAGE_LEN};

/// Re-exported so a test file only needs `use escrow_harness::*`.
pub use solana_signer::Signer as _;

pub const TOKEN_PROGRAM_ID: Pubkey =
    Pubkey::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
pub const TOKEN_2022_PROGRAM_ID: Pubkey =
    Pubkey::from_str_const("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
pub const ASSOCIATED_TOKEN_PROGRAM_ID: Pubkey =
    Pubkey::from_str_const("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
pub const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::from_str_const("11111111111111111111111111111111");
pub const ED25519_PROGRAM_ID: Pubkey =
    Pubkey::from_str_const("Ed25519SigVerify111111111111111111111111111");
pub const INSTRUCTIONS_SYSVAR_ID: Pubkey =
    Pubkey::from_str_const("Sysvar1nstructions1111111111111111111111111");
/// Used only as a harmless filler instruction, to put something between the
/// verdict and `settle`.
pub const MEMO_PROGRAM_ID: Pubkey =
    Pubkey::from_str_const("Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo");

/// A filler instruction that always succeeds and touches nothing.
pub fn memo_ix(text: &str) -> Instruction {
    Instruction {
        program_id: MEMO_PROGRAM_ID,
        accounts: vec![],
        data: text.as_bytes().to_vec(),
    }
}

pub const DECIMALS: u8 = 6;
/// 1,000 tokens for the buyer to start with.
pub const BUYER_START: u64 = 1_000_000_000;
/// 250 tokens per escrow.
pub const ESCROW_AMOUNT: u64 = 250_000_000;

/// A fixed starting point, so every time assertion in the suite is about the
/// program's rules rather than about the wall clock.
pub const START_SLOT: u64 = 1_000;
pub const START_TIME: i64 = 1_800_000_000;
/// Default deadline: one hour after [`START_TIME`].
pub const HOUR: i64 = 3_600;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenKind {
    Classic,
    Token2022,
}

impl TokenKind {
    pub const ALL: [TokenKind; 2] = [TokenKind::Classic, TokenKind::Token2022];

    pub fn program_id(self) -> Pubkey {
        match self {
            TokenKind::Classic => TOKEN_PROGRAM_ID,
            TokenKind::Token2022 => TOKEN_2022_PROGRAM_ID,
        }
    }

    /// The *other* token program, for the wrong-token-program test.
    pub fn other_program_id(self) -> Pubkey {
        match self {
            TokenKind::Classic => TOKEN_2022_PROGRAM_ID,
            TokenKind::Token2022 => TOKEN_PROGRAM_ID,
        }
    }
}

/// Run one test body against both token programs. A failure names the program
/// it failed under.
pub fn for_each_token_program(mut body: impl FnMut(TokenKind)) {
    for kind in TokenKind::ALL {
        body(kind);
    }
}

fn program_bytes() -> Vec<u8> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../target/deploy/verdict_escrow.so"
    );
    std::fs::read(path).unwrap_or_else(|err| {
        panic!(
            "cannot read {path}: {err}\n\
             Build the program first:\n  \
             cargo-build-sbf --manifest-path programs/verdict-escrow/Cargo.toml"
        )
    })
}

pub struct Harness {
    pub svm: LiteSVM,
    pub kind: TokenKind,
    pub token_program: Pubkey,
    /// Pays the fee for `settle`. Deliberately nobody special: it holds no
    /// authority over any escrow.
    pub relayer: Keypair,
    pub buyer: Keypair,
    pub seller: Keypair,
    pub verdict_signer: Keypair,
    pub mint: Pubkey,
}

impl Harness {
    pub fn new(kind: TokenKind) -> Self {
        let mut svm = LiteSVM::new();
        svm.add_program(verdict_escrow::ID, &program_bytes())
            .expect("load verdict escrow program");

        let relayer = Keypair::new();
        let buyer = Keypair::new();
        let seller = Keypair::new();
        let verdict_signer = Keypair::new();
        for who in [&relayer, &buyer, &seller] {
            svm.airdrop(&who.pubkey(), 100_000_000_000)
                .expect("airdrop");
        }

        let token_program = kind.program_id();
        let mint = CreateMint::new(&mut svm, &buyer)
            .token_program_id(&token_program)
            .decimals(DECIMALS)
            .send()
            .expect("create mint");

        let mut harness = Self {
            svm,
            kind,
            token_program,
            relayer,
            buyer,
            seller,
            verdict_signer,
            mint,
        };

        harness.set_clock(START_SLOT, START_TIME);
        let buyer_ata = harness.create_ata(&harness.buyer.pubkey());
        harness.create_ata(&harness.seller.pubkey());

        let payer = harness.buyer.insecure_clone();
        MintTo::new(
            &mut harness.svm,
            &payer,
            &harness.mint,
            &buyer_ata,
            BUYER_START,
        )
        .token_program_id(&token_program)
        .send()
        .expect("mint to buyer");

        harness
    }

    /// Create `owner`'s associated token account for the escrowed mint. The
    /// program never creates these: it requires them to exist already.
    pub fn create_ata(&mut self, owner: &Pubkey) -> Pubkey {
        let payer = self.buyer.insecure_clone();
        let mint = self.mint;
        let token_program = self.token_program;
        CreateAssociatedTokenAccount::new(&mut self.svm, &payer, &mint)
            .owner(owner)
            .token_program_id(&token_program)
            .send()
            .expect("create associated token account")
    }

    pub fn ata(&self, owner: &Pubkey) -> Pubkey {
        ata_for(owner, &self.mint, &self.token_program)
    }

    pub fn escrow_pda(&self, buyer: &Pubkey, escrow_id: u64) -> Pubkey {
        Pubkey::find_program_address(
            &[ESCROW_SEED, buyer.as_ref(), &escrow_id.to_le_bytes()],
            &verdict_escrow::ID,
        )
        .0
    }

    pub fn escrow_state(&self, escrow: &Pubkey) -> Escrow {
        let account = self.svm.get_account(escrow).expect("escrow account exists");
        Escrow::try_deserialize(&mut account.data.as_slice()).expect("escrow deserializes")
    }

    pub fn account_exists(&self, address: &Pubkey) -> bool {
        self.svm
            .get_account(address)
            .is_some_and(|account| !account.data.is_empty() || account.lamports > 0)
    }

    pub fn token_balance(&self, token_account: &Pubkey) -> u64 {
        let account = self
            .svm
            .get_account(token_account)
            .expect("token account exists");
        // Amount sits at the same offset in both token programs' account
        // layouts; Token-2022 appends its extensions after this base.
        u64::from_le_bytes(account.data[64..72].try_into().unwrap())
    }

    pub fn lamports(&self, address: &Pubkey) -> u64 {
        self.svm.get_balance(address).unwrap_or_default()
    }

    pub fn clock(&self) -> Clock {
        self.svm.get_sysvar::<Clock>()
    }

    pub fn now(&self) -> i64 {
        self.clock().unix_timestamp
    }

    pub fn set_clock(&mut self, slot: u64, unix_timestamp: i64) {
        let mut clock = self.svm.get_sysvar::<Clock>();
        clock.slot = slot;
        clock.unix_timestamp = unix_timestamp;
        self.svm.set_sysvar(&clock);
    }

    pub fn set_time(&mut self, unix_timestamp: i64) {
        let slot = self.clock().slot;
        self.set_clock(slot, unix_timestamp);
    }

    pub fn advance_slots(&mut self, slots: u64) {
        let clock = self.clock();
        self.set_clock(clock.slot + slots, clock.unix_timestamp);
    }

    // --- instructions -----------------------------------------------------

    pub fn create_escrow_ix(
        &self,
        buyer: &Pubkey,
        escrow_id: u64,
        amount: u64,
        deadline: i64,
        seller: Pubkey,
        verdict_signer: Pubkey,
    ) -> Instruction {
        let escrow = self.escrow_pda(buyer, escrow_id);
        Instruction {
            program_id: verdict_escrow::ID,
            accounts: verdict_escrow::accounts::CreateEscrow {
                buyer: *buyer,
                mint: self.mint,
                escrow,
                vault: ata_for(&escrow, &self.mint, &self.token_program),
                buyer_token_account: self.ata(buyer),
                token_program: self.token_program,
                associated_token_program: ASSOCIATED_TOKEN_PROGRAM_ID,
                system_program: SYSTEM_PROGRAM_ID,
            }
            .to_account_metas(None),
            data: verdict_escrow::instruction::CreateEscrow {
                escrow_id,
                amount,
                deadline,
                seller,
                verdict_signer,
            }
            .data(),
        }
    }

    /// The common case: the buyer funds an escrow that expires an hour out.
    pub fn create_escrow(&mut self, escrow_id: u64) -> (Pubkey, TransactionResult) {
        let deadline = self.now() + HOUR;
        self.create_escrow_with(escrow_id, ESCROW_AMOUNT, deadline)
    }

    pub fn create_escrow_with(
        &mut self,
        escrow_id: u64,
        amount: u64,
        deadline: i64,
    ) -> (Pubkey, TransactionResult) {
        let buyer = self.buyer.pubkey();
        let ix = self.create_escrow_ix(
            &buyer,
            escrow_id,
            amount,
            deadline,
            self.seller.pubkey(),
            self.verdict_signer.pubkey(),
        );
        let signer = self.buyer.insecure_clone();
        let result = self.send(&[ix], &[&signer]);
        (self.escrow_pda(&buyer, escrow_id), result)
    }

    pub fn settle_accounts(&self, escrow: Pubkey) -> SettleAccounts {
        let state = self.escrow_state(&escrow);
        SettleAccounts {
            escrow,
            buyer: state.buyer,
            mint: state.mint,
            vault: ata_for(&escrow, &state.mint, &self.token_program),
            seller_token_account: ata_for(&state.seller, &state.mint, &self.token_program),
            buyer_token_account: ata_for(&state.buyer, &state.mint, &self.token_program),
            instructions_sysvar: INSTRUCTIONS_SYSVAR_ID,
            token_program: self.token_program,
        }
    }

    pub fn reclaim_ix(&self, escrow: Pubkey) -> Instruction {
        let state = self.escrow_state(&escrow);
        Instruction {
            program_id: verdict_escrow::ID,
            accounts: verdict_escrow::accounts::Reclaim {
                escrow,
                buyer: state.buyer,
                mint: state.mint,
                vault: ata_for(&escrow, &state.mint, &self.token_program),
                buyer_token_account: ata_for(&state.buyer, &state.mint, &self.token_program),
                token_program: self.token_program,
            }
            .to_account_metas(None),
            data: verdict_escrow::instruction::Reclaim {}.data(),
        }
    }

    /// The 178 bytes the verdict signer is meant to sign for this escrow,
    /// built from the escrow's live on-chain state.
    pub fn verdict_message(
        &self,
        escrow: Pubkey,
        verdict: Verdict,
        expires_at: i64,
    ) -> [u8; MESSAGE_LEN] {
        let state = self.escrow_state(&escrow);
        build_message(&verdict_escrow::ID, &escrow, &state, verdict, expires_at)
    }

    /// A correctly signed verdict, ready to be bent out of shape by a test.
    pub fn verdict_ix(&self, escrow: Pubkey, verdict: Verdict, expires_at: i64) -> Ed25519Ix {
        let message = self.verdict_message(escrow, verdict, expires_at);
        Ed25519Ix::sign(&self.verdict_signer, &message)
    }

    /// The whole happy path for `settle`: verdict instruction, then settle,
    /// in one transaction paid for by the relayer.
    pub fn settle(
        &mut self,
        escrow: Pubkey,
        verdict: Verdict,
        expires_at: i64,
    ) -> TransactionResult {
        let accounts = self.settle_accounts(escrow);
        let verdict_ix = self.verdict_ix(escrow, verdict, expires_at);
        self.send_settle(&accounts, &verdict_ix, verdict, expires_at)
    }

    pub fn send_settle(
        &mut self,
        accounts: &SettleAccounts,
        verdict_ix: &Ed25519Ix,
        verdict: Verdict,
        expires_at: i64,
    ) -> TransactionResult {
        let settle_ix = accounts.instruction(verdict, expires_at);
        let relayer = self.relayer.insecure_clone();
        self.send(&[verdict_ix.instruction(), settle_ix], &[&relayer])
    }

    pub fn reclaim(&mut self, escrow: Pubkey) -> TransactionResult {
        let ix = self.reclaim_ix(escrow);
        let buyer = self.buyer.insecure_clone();
        self.send(&[ix], &[&buyer])
    }

    /// Send a transaction whose first signer pays the fee.
    pub fn send(
        &mut self,
        instructions: &[Instruction],
        signers: &[&Keypair],
    ) -> TransactionResult {
        // A fresh blockhash per send: without it, two identical transactions
        // collide on their signature instead of reaching the program.
        self.svm.expire_blockhash();
        let blockhash = self.svm.latest_blockhash();
        let payer = signers[0].pubkey();
        let tx = Transaction::new_signed_with_payer(instructions, Some(&payer), signers, blockhash);
        self.svm.send_transaction(tx)
    }
}

/// Every account `settle` takes, so a test can point one of them somewhere
/// else and leave the rest correct.
#[derive(Clone, Copy, Debug)]
pub struct SettleAccounts {
    pub escrow: Pubkey,
    pub buyer: Pubkey,
    pub mint: Pubkey,
    pub vault: Pubkey,
    pub seller_token_account: Pubkey,
    pub buyer_token_account: Pubkey,
    pub instructions_sysvar: Pubkey,
    pub token_program: Pubkey,
}

impl SettleAccounts {
    pub fn instruction(&self, verdict: Verdict, expires_at: i64) -> Instruction {
        Instruction {
            program_id: verdict_escrow::ID,
            accounts: verdict_escrow::accounts::Settle {
                escrow: self.escrow,
                buyer: self.buyer,
                mint: self.mint,
                vault: self.vault,
                seller_token_account: self.seller_token_account,
                buyer_token_account: self.buyer_token_account,
                instructions_sysvar: self.instructions_sysvar,
                token_program: self.token_program,
            }
            .to_account_metas(None),
            data: verdict_escrow::instruction::Settle {
                verdict,
                expires_at,
            }
            .data(),
        }
    }
}

/// The Ed25519 precompile instruction, field by field.
///
/// Built by hand rather than through a helper, because half the suite is about
/// what happens when one of these fields is wrong.
#[derive(Clone, Debug)]
pub struct Ed25519Ix {
    pub num_signatures: u8,
    pub padding: u8,
    pub signature_offset: u16,
    pub signature_instruction_index: u16,
    pub public_key_offset: u16,
    pub public_key_instruction_index: u16,
    pub message_data_offset: u16,
    pub message_data_size: u16,
    pub message_instruction_index: u16,
    pub public_key: [u8; 32],
    pub signature: [u8; 64],
    pub message: Vec<u8>,
}

impl Ed25519Ix {
    pub const HEADER_LEN: usize = 16;

    /// A well-formed instruction: `signer` signs `message`, and every offset
    /// points inside this instruction's own data.
    pub fn sign(signer: &Keypair, message: &[u8]) -> Self {
        let signature = signer.sign_message(message);
        Self {
            num_signatures: 1,
            padding: 0,
            signature_offset: (Self::HEADER_LEN + 32) as u16,
            signature_instruction_index: u16::MAX,
            public_key_offset: Self::HEADER_LEN as u16,
            public_key_instruction_index: u16::MAX,
            message_data_offset: (Self::HEADER_LEN + 32 + 64) as u16,
            message_data_size: message.len() as u16,
            message_instruction_index: u16::MAX,
            public_key: signer.pubkey().to_bytes(),
            signature: signature.as_ref().try_into().expect("64 byte signature"),
            message: message.to_vec(),
        }
    }

    pub fn data(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(Self::HEADER_LEN + 96 + self.message.len());
        data.push(self.num_signatures);
        data.push(self.padding);
        data.extend_from_slice(&self.signature_offset.to_le_bytes());
        data.extend_from_slice(&self.signature_instruction_index.to_le_bytes());
        data.extend_from_slice(&self.public_key_offset.to_le_bytes());
        data.extend_from_slice(&self.public_key_instruction_index.to_le_bytes());
        data.extend_from_slice(&self.message_data_offset.to_le_bytes());
        data.extend_from_slice(&self.message_data_size.to_le_bytes());
        data.extend_from_slice(&self.message_instruction_index.to_le_bytes());
        data.extend_from_slice(&self.public_key);
        data.extend_from_slice(&self.signature);
        data.extend_from_slice(&self.message);
        data
    }

    pub fn instruction(&self) -> Instruction {
        Instruction {
            program_id: ED25519_PROGRAM_ID,
            accounts: vec![],
            data: self.data(),
        }
    }
}

/// One signature's worth of the Ed25519 offsets header: 14 bytes that tell the
/// precompile where to find the key, the signature and the message.
#[derive(Clone, Copy, Debug)]
pub struct Ed25519Offsets {
    pub signature_offset: u16,
    pub signature_instruction_index: u16,
    pub public_key_offset: u16,
    pub public_key_instruction_index: u16,
    pub message_data_offset: u16,
    pub message_data_size: u16,
    pub message_instruction_index: u16,
}

impl Ed25519Offsets {
    pub const LEN: usize = 14;

    pub fn to_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::LEN);
        for field in [
            self.signature_offset,
            self.signature_instruction_index,
            self.public_key_offset,
            self.public_key_instruction_index,
            self.message_data_offset,
            self.message_data_size,
            self.message_instruction_index,
        ] {
            bytes.extend_from_slice(&field.to_le_bytes());
        }
        bytes
    }
}

/// Assemble Ed25519 instruction data from an explicit header and an explicit
/// body, with nothing inferred. The layout tests need to produce headers no
/// helper would ever write.
pub fn ed25519_data(offsets: &[Ed25519Offsets], body: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(2 + offsets.len() * Ed25519Offsets::LEN + body.len());
    data.push(offsets.len() as u8);
    data.push(0); // padding
    for entry in offsets {
        data.extend_from_slice(&entry.to_bytes());
    }
    data.extend_from_slice(body);
    data
}

pub fn ed25519_ix_from_data(data: Vec<u8>) -> Instruction {
    Instruction {
        program_id: ED25519_PROGRAM_ID,
        accounts: vec![],
        data,
    }
}

/// The associated token account address, derived here rather than imported, so
/// the tests do not share a derivation with the program under test.
pub fn ata_for(owner: &Pubkey, mint: &Pubkey, token_program: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[owner.as_ref(), token_program.as_ref(), mint.as_ref()],
        &ASSOCIATED_TOKEN_PROGRAM_ID,
    )
    .0
}

// --- assertions -----------------------------------------------------------

pub fn custom_error_code(result: &TransactionResult) -> Option<u32> {
    let failure: &FailedTransactionMetadata = result.as_ref().err()?;
    match failure.err {
        TransactionError::InstructionError(_, InstructionError::Custom(code)) => Some(code),
        _ => None,
    }
}

/// Assert that a transaction failed with one specific program error. "It
/// failed" is not an assertion: a test that passes for the wrong reason proves
/// nothing.
#[track_caller]
pub fn assert_error(result: &TransactionResult, expected: impl Into<u32> + Copy + std::fmt::Debug) {
    let expected_code: u32 = (expected).into();
    match custom_error_code(result) {
        Some(code) if code == expected_code => {}
        Some(code) => panic!(
            "expected {expected:?} (code {expected_code}), got custom error {code}\n{:?}",
            result.as_ref().err().map(|f| &f.meta.logs)
        ),
        None => panic!(
            "expected {expected:?} (code {expected_code}), got {:?}",
            result.as_ref().err().map(|f| &f.err)
        ),
    }
}

#[track_caller]
pub fn assert_ok(result: &TransactionResult) {
    if let Err(failure) = result {
        panic!(
            "expected success, got {:?}\n{:?}",
            failure.err, failure.meta.logs
        );
    }
}

/// The Ed25519 precompile's own code for a signature that does not verify.
pub const ED25519_INVALID_SIGNATURE: u32 = 2;

/// Assert that the runtime threw the transaction out at the Ed25519
/// instruction, before any program code ran.
///
/// The Ed25519 instruction is index 0 in every transaction this harness
/// builds, so a failure there, with no program logs, means the precompile
/// rejected the signature on its own.
#[track_caller]
pub fn assert_precompile_rejection(result: &TransactionResult) {
    let failure = result
        .as_ref()
        .err()
        .unwrap_or_else(|| panic!("expected the precompile to reject this transaction"));
    match failure.err {
        TransactionError::InstructionError(index, InstructionError::Custom(code)) => {
            assert_eq!(
                (index, code),
                (0, ED25519_INVALID_SIGNATURE),
                "expected the Ed25519 instruction (index 0) to fail with InvalidSignature"
            );
        }
        ref other => panic!("expected a precompile rejection, got {other:?}"),
    }
    assert!(
        failure.meta.logs.is_empty(),
        "the program must not have run at all, but it logged: {:?}",
        failure.meta.logs
    );
}
