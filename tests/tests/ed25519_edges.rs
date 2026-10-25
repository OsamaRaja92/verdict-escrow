//! The Ed25519 precompile at its edges, and the arithmetic that finds it.
//!
//! A verdict is worth exactly as much as the one instruction that proves it,
//! and proving it is split between two parties: the runtime checks that the
//! signature is a signature, and the program checks whose key it was and over
//! which bytes. Everything here sits on the seam between those two jobs.
//!
//! The seam is where programs get drained, for three reasons. A precompile
//! instruction can report success while verifying nothing, so "the Ed25519
//! instruction succeeded" is not evidence that anybody signed anything. The
//! header that tells the precompile where to look is attacker-chosen, so a
//! program reading fixed positions can be shown bytes the precompile never
//! saw. And "the instruction immediately before this one" is a subtraction on
//! an unsigned index, which has to be guarded before it is performed.
//!
//! The field-at-a-time layout attacks live in `instruction_layout.rs` and are
//! not repeated here: no verdict at all, a verdict pushed one slot back, the
//! wrong total data length, a short declared message size, two signature
//! blocks, a re-ordered body, offsets aimed at another instruction that does
//! exist, a verdict instruction carrying accounts, and a substituted
//! instructions sysvar.
//!
//! The three instruction-index fields of that header are the last class in
//! this file, and the one the rest of the suite leaves alone. Only the message
//! index is bent anywhere else; the other two aim at something worse than the
//! bytes, which is the identity of the signer. A header can leave the escrow's
//! real verdict signer sitting at byte 16, where the program reads it, and send
//! the precompile to a stranger's instruction for the key it actually verifies.
//! No signature in such a transaction is forged and every one of them verifies
//! — under a key the escrow never named. The signature index alone cannot reach
//! that far, for a reason its own test gives in full, but the program pins all
//! three fields in one check and each of the three has to be pinned.
//!
//! Three things in this class can be written down but cannot be made to work,
//! and are worth knowing as absences. A non-canonical `S` cannot be smuggled
//! past this runtime at all: `S + ℓ` necessarily sets bit 252, which is what
//! sends the verifier down its full canonical check. A small-order verdict
//! signer cannot be forged against for the same kind of reason: the verifier
//! refuses the point, not the signature. And the index underflow in the last
//! test cannot actually be reached from any transaction, because the guard runs
//! before the subtraction — the test proves the guard fires, not what would
//! happen without it, which only a change to the program could show.

use anchor_lang::prelude::Pubkey;
use escrow_harness::*;
use litesvm::types::TransactionResult;
use solana_instruction_error::InstructionError;
use solana_keypair::Keypair;
use solana_transaction_error::TransactionError;
use verdict_escrow::errors::EscrowError;
use verdict_escrow::verdict::Verdict;

/// The one layout the program accepts: key at 16, signature at 48, message at
/// 112, every field in this same instruction.
const PUBKEY_OFFSET: u16 = 16;
const SIGNATURE_OFFSET: u16 = 48;
const MESSAGE_OFFSET: u16 = 112;
const MESSAGE_LEN: u16 = 178;
/// 16 header + 32 key + 64 signature + the message.
const IX_DATA_LEN: usize = 16 + 32 + 64 + MESSAGE_LEN as usize;
const THIS_INSTRUCTION: u16 = u16::MAX;

/// Codes from the runtime's `PrecompileError`, which arrive as a custom error
/// on the precompile instruction itself rather than on `settle`. Variant two,
/// `InvalidSignature`, is already exported by the harness as
/// `ED25519_INVALID_SIGNATURE` and is asserted through
/// `assert_precompile_rejection`.
const INVALID_DATA_OFFSETS: u32 = 3;
const INVALID_INSTRUCTION_DATA_SIZE: u32 = 4;

/// The order of the Ed25519 basepoint, little-endian:
/// `2^252 + 27742317777372353535851937790883648493`. Checked against that
/// decimal value in [`plus_group_order`] rather than taken on trust.
const GROUP_ORDER: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

/// The neutral element of the curve, encoded: `y = 1`, sign bit clear. A valid
/// point, of order one, and a valid-looking 32-byte public key.
const IDENTITY_POINT: [u8; 32] = {
    let mut bytes = [0u8; 32];
    bytes[0] = 1;
    bytes
};

fn standard_offsets() -> Ed25519Offsets {
    Ed25519Offsets {
        signature_offset: SIGNATURE_OFFSET,
        signature_instruction_index: THIS_INSTRUCTION,
        public_key_offset: PUBKEY_OFFSET,
        public_key_instruction_index: THIS_INSTRUCTION,
        message_data_offset: MESSAGE_OFFSET,
        message_data_size: MESSAGE_LEN,
        message_instruction_index: THIS_INSTRUCTION,
    }
}

/// Assert that the runtime threw the transaction out at the Ed25519
/// instruction, with one named precompile code, before any program code ran.
///
/// The Ed25519 instruction is index 0 in every transaction below, so an error
/// there with no program logs means the precompile refused the instruction on
/// its own and `settle` never executed.
#[track_caller]
fn assert_precompile_error(result: &TransactionResult, expected_code: u32) {
    let failure = result
        .as_ref()
        .err()
        .unwrap_or_else(|| panic!("expected the precompile to reject this transaction"));
    match failure.err {
        TransactionError::InstructionError(index, InstructionError::Custom(code)) => {
            assert_eq!(
                (index, code),
                (0, expected_code),
                "expected the Ed25519 instruction (index 0) to fail with precompile code \
                 {expected_code}"
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

/// Add the group order to a signature's `S` half.
///
/// `S + ℓ` is the same scalar modulo the group order, so the verification
/// equation still balances: this is the classic malleability shape, a second
/// encoding of one signature. A verifier that only checks the top three bits
/// of `S` accepts it; RFC 8032 requires `0 <= S < ℓ` and rejects it.
fn plus_group_order(s: [u8; 32]) -> [u8; 32] {
    // The constant, against the decimal order in its doc comment. A wrong
    // value here would quietly turn the test below into one more corrupted
    // signature, which `forged_verdicts.rs` already covers.
    assert_eq!(
        u128::from_le_bytes(GROUP_ORDER[..16].try_into().unwrap()),
        27_742_317_777_372_353_535_851_937_790_883_648_493,
    );
    assert!(GROUP_ORDER[16..31].iter().all(|byte| *byte == 0));
    assert_eq!(GROUP_ORDER[31], 0x10, "bit 252, and nothing above it");

    let mut sum = [0u8; 32];
    let mut carry = 0u16;
    for i in 0..32 {
        let total = u16::from(s[i]) + u16::from(GROUP_ORDER[i]) + carry;
        sum[i] = total as u8;
        carry = total >> 8;
    }
    // S < ℓ and ℓ < 2^253, so the sum is below 2^254 and cannot carry out.
    assert_eq!(carry, 0, "S + ℓ overflowed 32 bytes");
    sum
}

/// A settle whose verdict instruction carries the genuine key, signature and
/// message in their usual places, under an offsets header the caller chooses.
/// The body is the correct 290 bytes, so only the header is under test.
fn settle_with_offsets(
    h: &mut Harness,
    escrow: Pubkey,
    offsets: Ed25519Offsets,
    expires_at: i64,
) -> TransactionResult {
    let message = h.verdict_message(escrow, Verdict::Release, expires_at);
    let signature = h.verdict_signer.sign_message(&message);
    let mut body = Vec::new();
    body.extend_from_slice(&h.verdict_signer.pubkey().to_bytes());
    body.extend_from_slice(signature.as_ref());
    body.extend_from_slice(&message);

    let data = ed25519_data(&[offsets], &body);
    assert_eq!(data.len(), IX_DATA_LEN, "only the header is under test");

    let accounts = h.settle_accounts(escrow);
    let settle_ix = accounts.instruction(Verdict::Release, expires_at);
    let relayer = h.relayer.insecure_clone();
    h.send(&[ed25519_ix_from_data(data), settle_ix], &[&relayer])
}

/// Verdict instruction data in the one body layout the program accepts — key
/// at 16, signature at 48, message at 112 — with the three fields supplied
/// separately and the header chosen by the caller.
///
/// The body is always the full 290 bytes, so only the header is under test,
/// and each field can be filled with something the precompile will never look
/// at. That is the point of the attacks below: a field the precompile reads out
/// of another instruction leaves whatever the attacker likes in its usual place
/// here, which is where the program reads.
fn verdict_ix_data(
    offsets: Ed25519Offsets,
    public_key: &Pubkey,
    signature: &[u8; 64],
    message: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&public_key.to_bytes());
    body.extend_from_slice(signature);
    body.extend_from_slice(message);

    let data = ed25519_data(&[offsets], &body);
    assert_eq!(data.len(), IX_DATA_LEN, "only the header is under test");
    data
}

/// An escrow whose seller is the attacker, so a forged release pays the
/// attacker directly and the attacker's own token balance is the evidence.
///
/// Nothing else about it is unusual: the buyer funds it and names the harness's
/// verdict signer as the arbiter, exactly as everywhere else in the suite. In
/// the key-index tests that arbiter never signs anything at all.
fn escrow_sold_by_the_attacker(h: &mut Harness, escrow_id: u64) -> (Pubkey, Keypair) {
    let attacker = Keypair::new();
    h.create_ata(&attacker.pubkey());

    let buyer = h.buyer.pubkey();
    let deadline = h.now() + HOUR;
    let create_ix = h.create_escrow_ix(
        &buyer,
        escrow_id,
        ESCROW_AMOUNT,
        deadline,
        attacker.pubkey(),
        h.verdict_signer.pubkey(),
    );
    let payer = h.buyer.insecure_clone();
    assert_ok(&h.send(&[create_ix], &[&payer]));

    let escrow = h.escrow_pda(&buyer, escrow_id);
    assert_eq!(h.escrow_state(&escrow).seller, attacker.pubkey());
    assert_eq!(h.token_balance(&h.ata(&attacker.pubkey())), 0);
    (escrow, attacker)
}

/// A header that claims no signatures, over a body that is the full 290 bytes.
///
/// The attacker wants the precompile to verify nothing and still succeed,
/// leaving a key, a signature and a message nobody ever signed sitting at
/// exactly the offsets the program reads. The runtime refuses the shape: a
/// count of zero is only legal when the instruction carries nothing but its
/// two header bytes, so this never reaches the program at all.
#[test]
fn a_verdict_instruction_claiming_zero_signatures_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let expires_at = h.now() + 600;
        let mut verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        verdict_ix.num_signatures = 0;
        assert_eq!(
            verdict_ix.data().len(),
            IX_DATA_LEN,
            "the body must stay the size the program expects"
        );

        let accounts = h.settle_accounts(escrow);
        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);

        assert_precompile_error(&result, INVALID_INSTRUCTION_DATA_SIZE);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
        assert!(h.account_exists(&escrow));
    });
}

/// The same idea, legally encoded: an Ed25519 instruction of two bytes, which
/// declares no signatures and carries no body.
///
/// This one the precompile accepts, having verified nothing — the loop over
/// signatures simply does not run. So a successful Ed25519 instruction in a
/// transaction is no evidence that any key signed anything, and a program that
/// checked only the preceding instruction's program id would settle on it. The
/// length check is what stops it, and this is the transaction that shows the
/// check is load-bearing rather than tidy.
#[test]
fn an_empty_verdict_instruction_verifies_nothing_and_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let expires_at = h.now() + 600;
        let empty = ed25519_data(&[], &[]);
        assert_eq!(empty, vec![0u8, 0u8]);

        let accounts = h.settle_accounts(escrow);
        let settle_ix = accounts.instruction(Verdict::Release, expires_at);
        let relayer = h.relayer.insecure_clone();
        let result = h.send(&[ed25519_ix_from_data(empty), settle_ix], &[&relayer]);

        assert_error(&result, EscrowError::BadVerdictDataLength);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
    });
}

/// A message window that starts inside the instruction and ends past its end.
///
/// The hope is a lenient read: a precompile that clamped the window to the
/// data it has would verify a signature over fewer bytes than the program
/// then reads at offset 112, and the program would believe the whole message
/// was covered. The precompile bounds-checks every window against the
/// instruction it was told to read and errors instead. The program's own
/// offsets check would refuse this header too, but it never gets the chance,
/// which is why the assertion names the precompile's code and not the
/// program's.
#[test]
fn offsets_pointing_past_the_end_of_the_instruction_are_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let expires_at = h.now() + 600;
        // 200 + 178 = 378, in an instruction of 290 bytes.
        let offsets = Ed25519Offsets {
            message_data_offset: 200,
            ..standard_offsets()
        };
        let result = settle_with_offsets(&mut h, escrow, offsets, expires_at);

        assert_precompile_error(&result, INVALID_DATA_OFFSETS);
        let vault = h.settle_accounts(escrow).vault;
        assert_eq!(h.token_balance(&vault), ESCROW_AMOUNT);
    });
}

/// Two windows whose start and size cannot both be held in a `u16`.
///
/// The offsets header is seven `u16` fields, so an offset of 65,534 and a size
/// of 178 are both expressible while their sum is not. A bounds check done in
/// `u16` would wrap: 65,534 + 178 is 176 modulo 65,536, and 176 is inside this
/// instruction, so the check would pass and the slice would be taken from
/// somewhere else entirely — the key and signature bytes the precompile has
/// already read. The precompile widens both numbers to a machine word and
/// saturates the addition, so each window is simply out of range.
#[test]
fn an_offset_that_overflows_when_its_size_is_added_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let expires_at = h.now() + 600;
        let shapes = [
            // A start at the top of the range, with the true message size.
            Ed25519Offsets {
                message_data_offset: u16::MAX - 1,
                ..standard_offsets()
            },
            // The true start, with a size that runs off the end of the range.
            Ed25519Offsets {
                message_data_size: u16::MAX,
                ..standard_offsets()
            },
        ];
        for offsets in shapes {
            let result = settle_with_offsets(&mut h, escrow, offsets, expires_at);
            assert_precompile_error(&result, INVALID_DATA_OFFSETS);
        }

        let vault = h.settle_accounts(escrow).vault;
        assert_eq!(h.token_balance(&vault), ESCROW_AMOUNT);
    });
}

/// An offsets header that names an instruction the transaction does not have.
///
/// Where `instruction_layout.rs` aims the message index at instruction 0,
/// which exists and leaves the program to refuse the header, this aims it at
/// instruction 9 of a two-instruction transaction. That is a different check
/// in a different place: the precompile bounds the instruction index against
/// the transaction before it bounds any offset within an instruction. Worth
/// pinning because it is the shape an attacker reaches for first, before
/// discovering that a real instruction has to be put there.
#[test]
fn offsets_naming_an_instruction_the_transaction_lacks_are_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let expires_at = h.now() + 600;
        let offsets = Ed25519Offsets {
            message_instruction_index: 9,
            ..standard_offsets()
        };
        let result = settle_with_offsets(&mut h, escrow, offsets, expires_at);

        assert_precompile_error(&result, INVALID_DATA_OFFSETS);
        let vault = h.settle_accounts(escrow).vault;
        assert_eq!(h.token_balance(&vault), ESCROW_AMOUNT);
    });
}

/// The reserved byte at index 1, set to something other than zero.
///
/// The runtime documents this byte as neither checked nor used — it is padding
/// that aligns the offsets that follow — so the signature is verified, the
/// verdict inside is genuine, and the transaction reaches the program. The
/// program refuses it anyway: it accepts one encoding of a verdict, not a
/// family of 256. That matters because a byte an attacker can set freely is a
/// byte a later runtime can start reading, and because any program that keys
/// off these bytes off-chain would see two different instructions carrying one
/// signature.
#[test]
fn a_non_zero_padding_byte_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let expires_at = h.now() + 600;
        let mut verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        verdict_ix.padding = 0xff;

        let accounts = h.settle_accounts(escrow);
        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);

        assert_error(&result, EscrowError::BadSignatureCount);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
        assert!(h.account_exists(&escrow));
    });
}

/// A genuine signature re-encoded with a non-canonical `S`.
///
/// `S + ℓ` is the same scalar modulo the group order, so the verification
/// equation balances and the pair is a second, different encoding of the
/// verdict signer's own signature over the same 178 bytes. Verifiers that only
/// test the top three bits of `S` accept it; this precompile verifies strictly
/// and requires `S < ℓ`, so it is refused before the program runs.
///
/// If it had been accepted, it would not have moved money anywhere the genuine
/// verdict did not already send it: the signed bytes are unchanged, so the
/// escrow, the amount and the destination are unchanged, and `settle` closes
/// the escrow either way. Malleability would bite a system that treated the
/// signature bytes as an identifier — a relayer deduplicating submissions, or
/// an off-chain ledger keyed by signature — because one verdict would have two
/// valid spellings and only one of them would be on the deny list.
#[test]
fn a_signature_with_a_non_canonical_s_value_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let expires_at = h.now() + 600;
        let mut verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let s: [u8; 32] = verdict_ix.signature[32..].try_into().unwrap();
        let malleable = plus_group_order(s);
        // ℓ is above 2^252, so the sum is too, and the verifier's fast path —
        // "the top four bits are clear, therefore the scalar is reduced" — is
        // skipped in favour of the full canonical check.
        assert_ne!(malleable[31] & 0xf0, 0);
        verdict_ix.signature[32..].copy_from_slice(&malleable);

        let accounts = h.settle_accounts(escrow);
        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);

        assert_precompile_rejection(&result);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
        assert!(h.account_exists(&escrow));
    });
}

/// A verdict signer of small order, and the forgery that would follow.
///
/// A buyer can be talked into naming any arbiter key, and the program checks
/// only that it is not the default address. The neutral element passes that
/// check, and the pair `R = identity, S = 0` satisfies the verification
/// equation for *every* message under it, so any verifier that does not reject
/// small-order points accepts it: whoever proposed the key could release or
/// refund any escrow that named it, with no secret at all. Strict verification
/// is the only thing in the way — it refuses a small-order `A` or `R` outright
/// — so this is a case where the program's safety is borrowed from the runtime
/// rather than its own.
///
/// Note what does not save it: the `verdict_signer != default` check. The
/// all-zero address is itself a small-order encoding, and there are seven
/// others the program does not enumerate, of which this is one.
#[test]
fn a_universal_forgery_under_a_small_order_verdict_signer_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);

        let small_order = Pubkey::new_from_array(IDENTITY_POINT);
        assert_ne!(small_order, Pubkey::default());
        let buyer = h.buyer.pubkey();
        let deadline = h.now() + HOUR;
        let create_ix = h.create_escrow_ix(
            &buyer,
            1,
            ESCROW_AMOUNT,
            deadline,
            h.seller.pubkey(),
            small_order,
        );
        let payer = h.buyer.insecure_clone();
        assert_ok(&h.send(&[create_ix], &[&payer]));
        let escrow = h.escrow_pda(&buyer, 1);
        assert_eq!(h.escrow_state(&escrow).verdict_signer, small_order);

        // R = the neutral element, S = 0, and the message the program will
        // rebuild for itself. Everything the program checks is correct here:
        // the layout, the offsets, the signer's key and all 178 bytes.
        let expires_at = h.now() + 600;
        let message = h.verdict_message(escrow, Verdict::Release, expires_at);
        let mut forged_signature = [0u8; 64];
        forged_signature[..32].copy_from_slice(&IDENTITY_POINT);

        let mut body = Vec::new();
        body.extend_from_slice(&IDENTITY_POINT);
        body.extend_from_slice(&forged_signature);
        body.extend_from_slice(&message);
        let data = ed25519_data(&[standard_offsets()], &body);
        assert_eq!(data.len(), IX_DATA_LEN);

        let accounts = h.settle_accounts(escrow);
        let settle_ix = accounts.instruction(Verdict::Release, expires_at);
        let relayer = h.relayer.insecure_clone();
        let result = h.send(&[ed25519_ix_from_data(data), settle_ix], &[&relayer]);

        assert_precompile_rejection(&result);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
        assert_eq!(h.token_balance(&h.ata(&h.seller.pubkey())), 0);
        assert!(h.account_exists(&escrow));
    });
}

/// The same genuine verdict instruction twice, with `settle` at index 2.
///
/// The program reads index 1 and nowhere else, and index 1 here is a real
/// verdict, so this settles. Pinned because the rule is "immediately before",
/// not "the only one in the transaction": a relayer that prepends anything, or
/// retries by appending, must not be refused, and a future change that started
/// scanning for the first or the last Ed25519 instruction would still pass
/// this test while breaking the one in `instruction_layout.rs` that depends on
/// reading exactly one position.
#[test]
fn the_same_verdict_twice_before_settle_still_settles() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let buyer = h.buyer.pubkey();
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let expires_at = h.now() + 600;
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let accounts = h.settle_accounts(escrow);
        let settle_ix = accounts.instruction(Verdict::Release, expires_at);
        let relayer = h.relayer.insecure_clone();
        let result = h.send(
            &[
                verdict_ix.instruction(),
                verdict_ix.instruction(),
                settle_ix,
            ],
            &[&relayer],
        );

        assert_ok(&result);
        assert_eq!(h.token_balance(&h.ata(&h.seller.pubkey())), ESCROW_AMOUNT);
        assert_eq!(h.token_balance(&h.ata(&buyer)), BUYER_START - ESCROW_AMOUNT);
        assert!(!h.account_exists(&escrow));
        assert!(!h.account_exists(&accounts.vault));
    });
}

/// Two escrows, two verdicts, one transaction.
///
/// Each `settle` reads the instruction directly before itself, so a relayer
/// can batch: verdict A, settle A, verdict B, settle B. Both pay out, and the
/// two verdicts are not interchangeable — A releases to the seller while B
/// refunds the buyer, and each message names its own escrow. This is the case
/// that would break silently if the index arithmetic ever went from "the
/// instruction before this one" to a fixed position or a search, because a
/// single-settle transaction would carry on working.
#[test]
fn two_settles_with_their_own_verdicts_in_one_transaction_both_pay_out() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let buyer = h.buyer.pubkey();
        let (escrow_a, result) = h.create_escrow(1);
        assert_ok(&result);
        let (escrow_b, result) = h.create_escrow(2);
        assert_ok(&result);

        let expires_at = h.now() + 600;
        let verdict_a = h.verdict_ix(escrow_a, Verdict::Release, expires_at);
        let verdict_b = h.verdict_ix(escrow_b, Verdict::Refund, expires_at);
        let accounts_a = h.settle_accounts(escrow_a);
        let accounts_b = h.settle_accounts(escrow_b);
        let relayer = h.relayer.insecure_clone();
        let result = h.send(
            &[
                verdict_a.instruction(),
                accounts_a.instruction(Verdict::Release, expires_at),
                verdict_b.instruction(),
                accounts_b.instruction(Verdict::Refund, expires_at),
            ],
            &[&relayer],
        );

        assert_ok(&result);
        // A released to the seller; B came back to the buyer.
        assert_eq!(h.token_balance(&h.ata(&h.seller.pubkey())), ESCROW_AMOUNT);
        assert_eq!(h.token_balance(&h.ata(&buyer)), BUYER_START - ESCROW_AMOUNT);
        assert!(!h.account_exists(&escrow_a));
        assert!(!h.account_exists(&escrow_b));
        assert!(!h.account_exists(&accounts_a.vault));
        assert!(!h.account_exists(&accounts_b.vault));
    });
}

/// `settle` first, with a genuine verdict behind it.
///
/// The verdict is in the transaction and is perfectly valid; it is simply at
/// index 1 while `settle` is at index 0. There is nothing before index 0, so
/// the program's index guard has to fire before the subtraction is performed.
/// Without it, `current_index - 1` on an unsigned index either aborts the
/// instruction outright — the program is built with overflow checks on — or
/// wraps to 65,535 and asks for an instruction that is not there. Either way
/// the money stays put, but only one of the three is a named error a caller
/// can act on.
///
/// The transaction with no instruction before `settle` at all is in
/// `instruction_layout.rs`; what this adds is a real verdict placed where the
/// program must refuse to look.
#[test]
fn settle_as_the_first_instruction_cannot_reach_behind_itself() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let expires_at = h.now() + 600;
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let accounts = h.settle_accounts(escrow);
        let settle_ix = accounts.instruction(Verdict::Release, expires_at);
        let relayer = h.relayer.insecure_clone();
        let result = h.send(&[settle_ix, verdict_ix.instruction()], &[&relayer]);

        assert_error(&result, EscrowError::MissingVerdictInstruction);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
        assert_eq!(h.token_balance(&h.ata(&h.seller.pubkey())), 0);
        assert!(h.account_exists(&escrow));
    });
}

/// A header that sends the precompile to a stranger's instruction for the key
/// it verifies, and leaves the escrow's real verdict signer where the program
/// reads.
///
/// The attacker is the seller of this escrow and wants a release the arbiter
/// never granted. Instruction 0 is an honest Ed25519 verification: the attacker
/// signs, with their own key, the exact 178 bytes the program will rebuild for
/// this escrow. It proves only that a stranger approves of being paid and
/// authorises nothing; its use is as somewhere to keep the attacker's key at
/// byte 16, where the precompile can be sent to fetch it.
///
/// Instruction 1 is the forgery, and everything the program inspects in it is
/// correct. Byte 16 holds the escrow's real verdict signer, so the signer check
/// passes. Byte 112 holds the real message, so the rebuild comparison passes.
/// One field of the header is bent: the public key index names instruction 0,
/// so the key the precompile verifies is the attacker's, and the signature at
/// byte 48 is the attacker's as well — a consistent triple over the real
/// message, which the precompile reports as a success.
///
/// The runtime therefore says "a valid signature over these bytes" and means
/// the attacker's, while the program is looking at the arbiter's key. The index
/// check is the only thing standing between this transaction and the vault.
#[test]
fn a_key_index_pointing_at_a_strangers_instruction_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, attacker) = escrow_sold_by_the_attacker(&mut h, 1);

        let expires_at = h.now() + 600;
        let message = h.verdict_message(escrow, Verdict::Release, expires_at);
        let attackers_own = Ed25519Ix::sign(&attacker, &message);
        assert_eq!(attackers_own.public_key, attacker.pubkey().to_bytes());

        let offsets = Ed25519Offsets {
            public_key_instruction_index: 0,
            ..standard_offsets()
        };
        let forged = verdict_ix_data(
            offsets,
            &h.verdict_signer.pubkey(),
            &attackers_own.signature,
            &message,
        );

        let accounts = h.settle_accounts(escrow);
        let settle_ix = accounts.instruction(Verdict::Release, expires_at);
        let relayer = h.relayer.insecure_clone();
        let result = h.send(
            &[
                attackers_own.instruction(),
                ed25519_ix_from_data(forged),
                settle_ix,
            ],
            &[&relayer],
        );

        assert_error(&result, EscrowError::OffsetsPointAtAnotherInstruction);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
        assert_eq!(h.token_balance(&h.ata(&attacker.pubkey())), 0);
        assert!(h.account_exists(&escrow));
    });
}

/// A header whose signature lives in another instruction, over a verdict
/// instruction that carries no signature of its own.
///
/// The 64 bytes at byte 48 here are zero, and nobody reads them: the signature
/// index names instruction 0, which holds the arbiter's genuine verdict, so
/// that is the signature the precompile verifies. The key and the message stay
/// in this instruction and are both the real ones, which is not a choice. The
/// program pins byte 16 to the escrow's signer and byte 112 to the bytes it
/// rebuilds, so the only signature that can satisfy the precompile over that
/// pair is the arbiter's own over this exact verdict. That is why this field,
/// alone of the three, cannot be turned into a forgery: whoever can satisfy it
/// is holding a genuine verdict already and has no use for one.
///
/// What it is instead is a second encoding of a single verdict, and the program
/// accepts one. Pinned for the reason the malleable-S test above is pinned:
/// anything keyed on the verdict instruction's own bytes, such as a relayer
/// deduplicating submissions or an indexer reading the signature at byte 48,
/// would be reading bytes that took no part in the verification.
#[test]
fn a_signature_index_pointing_at_another_instruction_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let expires_at = h.now() + 600;
        let message = h.verdict_message(escrow, Verdict::Release, expires_at);
        let genuine = h.verdict_ix(escrow, Verdict::Release, expires_at);

        let offsets = Ed25519Offsets {
            signature_instruction_index: 0,
            ..standard_offsets()
        };
        let respelled = verdict_ix_data(offsets, &h.verdict_signer.pubkey(), &[0u8; 64], &message);

        let accounts = h.settle_accounts(escrow);
        let settle_ix = accounts.instruction(Verdict::Release, expires_at);
        let relayer = h.relayer.insecure_clone();
        let result = h.send(
            &[
                genuine.instruction(),
                ed25519_ix_from_data(respelled),
                settle_ix,
            ],
            &[&relayer],
        );

        assert_error(&result, EscrowError::OffsetsPointAtAnotherInstruction);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
        assert_eq!(h.token_balance(&h.ata(&h.seller.pubkey())), 0);
        assert!(h.account_exists(&escrow));
    });
}

/// All three fields in another instruction, which leaves the verdict
/// instruction the program reads holding nothing but props.
///
/// Instruction 0 is the attacker's own Ed25519 instruction over 178 bytes of
/// the attacker's own: not a verdict, not about this escrow, signed by a key
/// the escrow never named. It verifies, being honest about what it is.
///
/// Instruction 1 claims it. All three indices name instruction 0, so the
/// precompile re-verifies that key, that signature and those bytes and
/// succeeds, and the data at the three offsets this instruction carries takes
/// no part in it. The attacker is left free to write exactly what the program
/// wants to see: the real verdict signer at byte 16, the real release message
/// at byte 112, and 64 zero bytes at 48 where a signature would go. Nothing in
/// the transaction is a signature over this escrow's verdict, and nothing in it
/// is by this escrow's signer.
///
/// This is the shape in full, and it is why the check is one `require!` over
/// all three fields: any single field left unpinned is a drained vault.
#[test]
fn a_header_whose_key_signature_and_message_all_live_elsewhere_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, attacker) = escrow_sold_by_the_attacker(&mut h, 1);

        let expires_at = h.now() + 600;
        // The window the header describes is 178 bytes wide, so the attacker's
        // bytes have to be 178 long. Their content means nothing here.
        let mut unrelated = [0u8; MESSAGE_LEN as usize];
        unrelated[..13].copy_from_slice(b"not a verdict");
        let attackers_own = Ed25519Ix::sign(&attacker, &unrelated);

        let offsets = Ed25519Offsets {
            signature_instruction_index: 0,
            public_key_instruction_index: 0,
            message_instruction_index: 0,
            ..standard_offsets()
        };
        let message = h.verdict_message(escrow, Verdict::Release, expires_at);
        let forged = verdict_ix_data(offsets, &h.verdict_signer.pubkey(), &[0u8; 64], &message);

        let accounts = h.settle_accounts(escrow);
        let settle_ix = accounts.instruction(Verdict::Release, expires_at);
        let relayer = h.relayer.insecure_clone();
        let result = h.send(
            &[
                attackers_own.instruction(),
                ed25519_ix_from_data(forged),
                settle_ix,
            ],
            &[&relayer],
        );

        assert_error(&result, EscrowError::OffsetsPointAtAnotherInstruction);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
        assert_eq!(h.token_balance(&h.ata(&attacker.pubkey())), 0);
        assert!(h.account_exists(&escrow));
    });
}
