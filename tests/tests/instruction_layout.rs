//! The two instructions a settle transaction is made of, bent one field at a
//! time: the Ed25519 instruction in front, and `settle`'s own data behind it.
//!
//! The runtime verifies the signature; it does not care where in the
//! transaction the key, the signature and the message came from. The first
//! half of this file is about the part only the program can check: that the
//! bytes it reads are the bytes that were verified.
//!
//! The second half steps below the generated encoder. Every other test in the
//! suite builds `settle`'s data through `InstructionData::data()`, which cannot
//! produce a verdict the enum does not have, a sighash that names no
//! instruction, or a payload that stops halfway. These tests write those bytes
//! by hand, and pin the shape the honest encoder produces.

use anchor_lang::error::ErrorCode as AnchorError;
use anchor_lang::prelude::Pubkey;
use anchor_lang::InstructionData;
use escrow_harness::*;
use litesvm::types::TransactionResult;
use solana_keypair::Keypair;
use verdict_escrow::errors::EscrowError;
use verdict_escrow::verdict::Verdict;

/// The one layout the program accepts: key at 16, signature at 48, message at
/// 112, all in this same instruction.
const PUBKEY_OFFSET: u16 = 16;
const SIGNATURE_OFFSET: u16 = 48;
const MESSAGE_OFFSET: u16 = 112;
const MESSAGE_LEN: u16 = 178;
/// 16 header + 32 key + 64 signature + the message.
const IX_DATA_LEN: usize = 16 + 32 + 64 + MESSAGE_LEN as usize;
const THIS_INSTRUCTION: u16 = u16::MAX;

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

#[test]
fn settle_without_any_verdict_instruction_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let expires_at = h.now() + 600;
        let accounts = h.settle_accounts(escrow);
        let settle_ix = accounts.instruction(Verdict::Release, expires_at);
        let relayer = h.relayer.insecure_clone();
        let result = h.send(&[settle_ix], &[&relayer]);

        // Nothing precedes `settle`, so there is nothing to read.
        assert_error(&result, EscrowError::MissingVerdictInstruction);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
    });
}

#[test]
fn a_verdict_that_is_not_immediately_before_settle_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let expires_at = h.now() + 600;
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let accounts = h.settle_accounts(escrow);
        let settle_ix = accounts.instruction(Verdict::Release, expires_at);
        let relayer = h.relayer.insecure_clone();

        // A real verdict, pushed one instruction further back. The program reads the
        // instruction directly before it and nowhere else, so it never finds
        // the verdict — which is the point: scanning for it would let an
        // attacker append a real signature after a fake one.
        let result = h.send(
            &[verdict_ix.instruction(), memo_ix("filler"), settle_ix],
            &[&relayer],
        );
        assert_error(&result, EscrowError::NotEd25519Instruction);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
    });
}

#[test]
fn a_message_of_the_wrong_length_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let expires_at = h.now() + 600;
        let mut message = h
            .verdict_message(escrow, Verdict::Release, expires_at)
            .to_vec();
        message.push(0); // 179 bytes, correctly signed
        let verdict_ix = Ed25519Ix::sign(&h.verdict_signer, &message);

        let accounts = h.settle_accounts(escrow);
        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_error(&result, EscrowError::BadVerdictDataLength);
    });
}

#[test]
fn a_declared_message_size_other_than_178_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let expires_at = h.now() + 600;
        let full = h.verdict_message(escrow, Verdict::Release, expires_at);

        // The whole 290 bytes of instruction data, as the program expects, but
        // the header claims the signed message is only the first 100 of its
        // 178 bytes — and the signature really does cover only those 100, so
        // the precompile is satisfied. Everything after byte 100 would be
        // unsigned.
        let truncated = &full[..100];
        let signature = h.verdict_signer.sign_message(truncated);
        let mut body = Vec::new();
        body.extend_from_slice(&h.verdict_signer.pubkey().to_bytes());
        body.extend_from_slice(signature.as_ref());
        body.extend_from_slice(&full);

        let offsets = Ed25519Offsets {
            message_data_size: 100,
            ..standard_offsets()
        };
        let verdict_ix = ed25519_ix_from_data(ed25519_data(&[offsets], &body));
        let accounts = h.settle_accounts(escrow);
        let settle_ix = accounts.instruction(Verdict::Release, expires_at);
        let relayer = h.relayer.insecure_clone();
        let result = h.send(&[verdict_ix, settle_ix], &[&relayer]);

        assert_error(&result, EscrowError::BadMessageSize);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
    });
}

#[test]
fn two_signatures_in_one_instruction_are_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let expires_at = h.now() + 600;

        // Two signature blocks, both valid, both pointing at the same key,
        // signature and message. The total is still 290 bytes, so the length
        // check passes and the signature count is what refuses it.
        //
        //   header: 2 + 2 * 14 = 30 bytes
        //   key at 30, signature at 62, message at 126, 164 bytes long
        let message = vec![7u8; IX_DATA_LEN - 126];
        let signature = h.verdict_signer.sign_message(&message);
        let mut body = Vec::new();
        body.extend_from_slice(&h.verdict_signer.pubkey().to_bytes());
        body.extend_from_slice(signature.as_ref());
        body.extend_from_slice(&message);

        let offsets = Ed25519Offsets {
            signature_offset: 62,
            signature_instruction_index: THIS_INSTRUCTION,
            public_key_offset: 30,
            public_key_instruction_index: THIS_INSTRUCTION,
            message_data_offset: 126,
            message_data_size: message.len() as u16,
            message_instruction_index: THIS_INSTRUCTION,
        };
        let data = ed25519_data(&[offsets, offsets], &body);
        assert_eq!(
            data.len(),
            IX_DATA_LEN,
            "the length check must not be what fires"
        );

        let accounts = h.settle_accounts(escrow);
        let settle_ix = accounts.instruction(Verdict::Release, expires_at);
        let relayer = h.relayer.insecure_clone();
        let result = h.send(&[ed25519_ix_from_data(data), settle_ix], &[&relayer]);

        assert_error(&result, EscrowError::BadSignatureCount);
    });
}

#[test]
fn an_unexpected_field_layout_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let expires_at = h.now() + 600;
        let message = h.verdict_message(escrow, Verdict::Release, expires_at);
        let signature = h.verdict_signer.sign_message(&message);

        // The same three pieces, in a different order: message first, then
        // key, then signature. Self-consistent, so the precompile verifies it
        // happily. The program accepts one layout and no other.
        let mut body = Vec::new();
        body.extend_from_slice(&message);
        body.extend_from_slice(&h.verdict_signer.pubkey().to_bytes());
        body.extend_from_slice(signature.as_ref());

        let offsets = Ed25519Offsets {
            signature_offset: 16 + MESSAGE_LEN + 32,
            signature_instruction_index: THIS_INSTRUCTION,
            public_key_offset: 16 + MESSAGE_LEN,
            public_key_instruction_index: THIS_INSTRUCTION,
            message_data_offset: 16,
            message_data_size: MESSAGE_LEN,
            message_instruction_index: THIS_INSTRUCTION,
        };
        let data = ed25519_data(&[offsets], &body);
        assert_eq!(data.len(), IX_DATA_LEN);

        let accounts = h.settle_accounts(escrow);
        let settle_ix = accounts.instruction(Verdict::Release, expires_at);
        let relayer = h.relayer.insecure_clone();
        let result = h.send(&[ed25519_ix_from_data(data), settle_ix], &[&relayer]);

        assert_error(&result, EscrowError::BadFieldOffsets);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
    });
}

/// The attack the offsets header exists to stop.
///
/// A second Ed25519 instruction carries a forged message in its own data at
/// the usual position, but points the precompile at the *first* instruction,
/// where a genuinely signed message lives. The precompile verifies the real
/// one. A program that read its message from the fixed offset without checking
/// the instruction-index fields would be shown the forgery and accept it.
///
/// Only `message_instruction_index` is bent. The key and the signature are the
/// genuine ones, at their usual offsets in this instruction, so every other
/// check the program makes — the program id, the data length, the signature
/// count, the field offsets, the declared message size, and the signer's key —
/// passes. Delete the three instruction-index requires from `verify_verdict`
/// and this transaction drains the escrow.
#[test]
fn offsets_pointing_at_another_instruction_are_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let expires_at = h.now() + 600;

        // What the verdict signer really agreed to: a refund.
        let real_message = h.verdict_message(escrow, Verdict::Refund, expires_at);
        let real_ix = Ed25519Ix::sign(&h.verdict_signer, &real_message);

        // What the attacker wants the program to read: a release.
        let forged_message = h.verdict_message(escrow, Verdict::Release, expires_at);

        // The real key and the real signature, in their usual places. The
        // signature covers the refund message, which lives in instruction 0.
        let mut body = Vec::new();
        body.extend_from_slice(&h.verdict_signer.pubkey().to_bytes());
        body.extend_from_slice(&real_ix.signature);
        body.extend_from_slice(&forged_message);

        let offsets = Ed25519Offsets {
            // Key and signature: genuine, and in this instruction.
            signature_offset: SIGNATURE_OFFSET,
            signature_instruction_index: THIS_INSTRUCTION,
            public_key_offset: PUBKEY_OFFSET,
            public_key_instruction_index: THIS_INSTRUCTION,
            // Message: the precompile is sent to instruction 0 for the bytes
            // it verifies, while byte 112 of *this* instruction holds the
            // forgery the program would otherwise read.
            message_data_offset: MESSAGE_OFFSET,
            message_data_size: MESSAGE_LEN,
            message_instruction_index: 0,
        };
        let data = ed25519_data(&[offsets], &body);
        assert_eq!(data.len(), IX_DATA_LEN);

        let accounts = h.settle_accounts(escrow);
        let settle_ix = accounts.instruction(Verdict::Release, expires_at);
        let relayer = h.relayer.insecure_clone();
        let result = h.send(
            &[real_ix.instruction(), ed25519_ix_from_data(data), settle_ix],
            &[&relayer],
        );

        assert_error(&result, EscrowError::OffsetsPointAtAnotherInstruction);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
        assert_eq!(h.token_balance(&h.ata(&h.seller.pubkey())), 0);
    });
}

#[test]
fn a_verdict_instruction_carrying_accounts_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let expires_at = h.now() + 600;
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let mut raw = verdict_ix.instruction();
        raw.accounts = vec![solana_instruction::AccountMeta::new_readonly(
            h.relayer.pubkey(),
            false,
        )];

        let accounts = h.settle_accounts(escrow);
        let settle_ix = accounts.instruction(Verdict::Release, expires_at);
        let relayer = h.relayer.insecure_clone();
        let result = h.send(&[raw, settle_ix], &[&relayer]);

        assert_error(&result, EscrowError::VerdictInstructionHasAccounts);
    });
}

#[test]
fn an_instruction_from_another_program_is_not_a_verdict() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let expires_at = h.now() + 600;
        let accounts = h.settle_accounts(escrow);
        let settle_ix = accounts.instruction(Verdict::Release, expires_at);
        let relayer = h.relayer.insecure_clone();
        let result = h.send(&[memo_ix("not a verdict"), settle_ix], &[&relayer]);

        assert_error(&result, EscrowError::NotEd25519Instruction);
    });
}

#[test]
fn a_substitute_instructions_sysvar_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let expires_at = h.now() + 600;
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let mut accounts = h.settle_accounts(escrow);
        // An account the caller controls, in place of the sysvar the program
        // reads the transaction's own instructions from.
        accounts.instructions_sysvar = Keypair::new().pubkey();

        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_error(&result, AnchorError::ConstraintAddress);
    });
}

// --- `settle`'s own instruction data --------------------------------------

/// The payload Borsh produces for `settle`: eight bytes of sighash, one byte
/// for the verdict, eight little-endian bytes for `expires_at`.
const SIGHASH_LEN: usize = 8;
const VERDICT_LEN: usize = 1;
const EXPIRES_AT_LEN: usize = 8;
const SETTLE_DATA_LEN: usize = SIGHASH_LEN + VERDICT_LEN + EXPIRES_AT_LEN;

/// What an honest client sends, from the generated encoder, so the tests below
/// cannot bend a layout the program does not have in the first place.
fn settle_data(verdict: Verdict, expires_at: i64) -> Vec<u8> {
    verdict_escrow::instruction::Settle {
        verdict,
        expires_at,
    }
    .data()
}

fn settle_sighash() -> [u8; SIGHASH_LEN] {
    settle_data(Verdict::Release, 0)[..SIGHASH_LEN]
        .try_into()
        .expect("the sighash is the first eight bytes of the payload")
}

/// `create_escrow`'s payload. The argument values matter to nobody here, only
/// how many bytes they take.
fn create_escrow_data() -> Vec<u8> {
    verdict_escrow::instruction::CreateEscrow {
        escrow_id: 1,
        amount: ESCROW_AMOUNT,
        deadline: START_TIME + HOUR,
        seller: Pubkey::new_from_array([7; 32]),
        verdict_signer: Pubkey::new_from_array([8; 32]),
    }
    .data()
}

fn reclaim_data() -> Vec<u8> {
    verdict_escrow::instruction::Reclaim {}.data()
}

/// Send a transaction that is right in every respect except the bytes of
/// `settle`'s own data: a genuine release verdict for this escrow, signed by
/// the escrow's own verdict signer, sits immediately before it, and the
/// accounts are the ones the escrow names. Only `data` is the attacker's.
fn send_settle_with_data(
    h: &mut Harness,
    escrow: Pubkey,
    expires_at: i64,
    data: Vec<u8>,
) -> (SettleAccounts, TransactionResult) {
    let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
    let accounts = h.settle_accounts(escrow);
    let mut settle_ix = accounts.instruction(Verdict::Release, expires_at);
    settle_ix.data = data;
    let relayer = h.relayer.insecure_clone();
    let result = h.send(&[verdict_ix.instruction(), settle_ix], &[&relayer]);
    (accounts, result)
}

/// A verdict byte with no variant behind it.
///
/// The payout is a match with exactly two arms, so the attacker is looking for
/// a third way through it: some byte that reaches the transfer with the
/// destination left over from somewhere else. Borsh refuses the byte while it
/// is still decoding the arguments, before any of this program's code runs, so
/// there is no arm to reach and the vault keeps the money.
#[test]
fn a_verdict_discriminant_the_enum_does_not_have_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let expires_at = h.now() + 600;

        // Borsh writes the variant's position, so 0 is a release, 1 is a
        // refund, and every other byte up to 255 is nothing. The sweep starts
        // at 2 for a reason worth naming: 2 is the code the signed message
        // uses for a refund at byte 169, and the two encodings are
        // deliberately not the same numbers.
        for byte in 2u8..=255 {
            let mut data = settle_sighash().to_vec();
            data.push(byte);
            data.extend_from_slice(&expires_at.to_le_bytes());
            assert_eq!(
                data.len(),
                SETTLE_DATA_LEN,
                "only the verdict byte is bent here"
            );

            let (accounts, result) = send_settle_with_data(&mut h, escrow, expires_at, data);
            assert_error(&result, AnchorError::InstructionDidNotDeserialize);
            assert_eq!(
                h.token_balance(&accounts.vault),
                ESCROW_AMOUNT,
                "verdict byte {byte}"
            );
            assert_eq!(h.token_balance(&h.ata(&h.seller.pubkey())), 0);
        }

        assert!(h.account_exists(&escrow));
    });
}

/// Eight bytes that name no instruction.
///
/// Anchor dispatches on the whole sighash, so a near miss is not a hit: the
/// first case below is `settle`'s own sighash with its last bit flipped, and it
/// reaches no handler at all.
#[test]
fn a_sighash_that_names_no_instruction_reaches_no_handler() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let expires_at = h.now() + 600;

        let mut near_miss = settle_sighash();
        near_miss[SIGHASH_LEN - 1] ^= 0x01;
        let unrelated = [0x2a, 0x7b, 0xc3, 0x11, 0x5e, 0x90, 0xd4, 0x68];

        let known: [Vec<u8>; 3] = [
            settle_sighash().to_vec(),
            create_escrow_data()[..SIGHASH_LEN].to_vec(),
            reclaim_data()[..SIGHASH_LEN].to_vec(),
        ];
        for sighash in [near_miss, unrelated] {
            assert!(
                !known.contains(&sighash.to_vec()),
                "the point of this test is a sighash the program does not have"
            );

            // A release's own arguments behind it, so the name is the only
            // thing wrong with this payload.
            let mut data = sighash.to_vec();
            data.push(0);
            data.extend_from_slice(&expires_at.to_le_bytes());

            let (accounts, result) = send_settle_with_data(&mut h, escrow, expires_at, data);
            assert_error(&result, AnchorError::InstructionFallbackNotFound);
            assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
        }

        assert!(h.account_exists(&escrow));
    });
}

/// Settle data that stops before the arguments are complete.
///
/// Three places to stop: after the sighash, after the verdict byte, and one
/// byte short of the end of `expires_at`. The last is the one worth having.
/// The top byte of this timestamp is zero, so a decoder that quietly
/// zero-filled the byte it was missing would read back the same number and
/// carry on, having been handed one byte less than the signature covers.
/// Borsh refuses the short buffer instead.
#[test]
fn settle_data_that_stops_early_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let expires_at = h.now() + 600;

        let full = settle_data(Verdict::Release, expires_at);
        assert_eq!(full.len(), SETTLE_DATA_LEN);
        assert_eq!(
            full[SETTLE_DATA_LEN - 1],
            0,
            "the top byte of this expiry is zero, which is what makes the \
             one-byte-short case worth testing"
        );

        for len in [SIGHASH_LEN, SIGHASH_LEN + VERDICT_LEN, SETTLE_DATA_LEN - 1] {
            let (accounts, result) =
                send_settle_with_data(&mut h, escrow, expires_at, full[..len].to_vec());
            assert_error(&result, AnchorError::InstructionDidNotDeserialize);
            assert_eq!(
                h.token_balance(&accounts.vault),
                ESCROW_AMOUNT,
                "{len} bytes of settle data"
            );
        }

        assert!(h.account_exists(&escrow));
    });
}

/// Bytes after the end of the arguments, which the program never reads.
///
/// Anchor matches the sighash on a prefix and Borsh stops reading once its
/// fields are full, so padding neither fails nor does anything: the settle
/// below succeeds. What makes that harmless is the shape of the payload rather
/// than the leniency. No argument names a destination or an amount, and the
/// message the signature is checked against is rebuilt from the escrow's own
/// state, so there is nothing for an extra byte to steer. The padding here is
/// a whole second verdict — a refund — appended after the signed release, and
/// the money still goes to the seller.
#[test]
fn trailing_bytes_after_the_settle_arguments_change_nothing() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let buyer_ata = h.ata(&h.buyer.pubkey());
        let seller_ata = h.ata(&h.seller.pubkey());
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let expires_at = h.now() + 600;

        let mut data = settle_data(Verdict::Release, expires_at);
        data.extend_from_slice(&settle_data(Verdict::Refund, expires_at)[SIGHASH_LEN..]);
        assert_eq!(data.len(), SETTLE_DATA_LEN + VERDICT_LEN + EXPIRES_AT_LEN);

        let (accounts, result) = send_settle_with_data(&mut h, escrow, expires_at, data);
        assert_ok(&result);

        // The first verdict, the signed one, is the one that was acted on.
        assert_eq!(h.token_balance(&seller_ata), ESCROW_AMOUNT);
        assert_eq!(h.token_balance(&buyer_ata), BUYER_START - ESCROW_AMOUNT);
        assert!(!h.account_exists(&accounts.vault));
        assert!(!h.account_exists(&escrow));
    });
}

/// The guard on the shape of the payload.
///
/// `settle` has no privileged signer, so its arguments are the only thing a
/// caller gets to choose, and both of them are inside the signed message. A
/// third argument — a destination, an amount, a fee recipient — would be a
/// byte the verdict signer never saw and the program would act on anyway. The
/// length is pinned here so that argument cannot be added quietly.
#[test]
fn the_settle_payload_is_a_verdict_and_an_expiry_and_nothing_more() {
    let expires_at = START_TIME + 600;
    let release = settle_data(Verdict::Release, expires_at);

    assert_eq!(release.len(), 8 + 1 + 8);
    assert_eq!(release.len(), SETTLE_DATA_LEN);
    assert_eq!(&release[..SIGHASH_LEN], settle_sighash().as_slice());
    assert_eq!(release[SIGHASH_LEN], 0, "a release is Borsh index 0");
    assert_eq!(
        &release[SIGHASH_LEN + VERDICT_LEN..],
        &expires_at.to_le_bytes()
    );

    // The sighash is the instruction's name, not a function of its arguments:
    // the two verdicts differ in exactly one byte of the payload.
    let refund = settle_data(Verdict::Refund, expires_at);
    assert_eq!(refund.len(), SETTLE_DATA_LEN);
    assert_eq!(&refund[..SIGHASH_LEN], &release[..SIGHASH_LEN]);
    assert_eq!(refund[SIGHASH_LEN], 1, "a refund is Borsh index 1");
    assert_eq!(
        &refund[SIGHASH_LEN + VERDICT_LEN..],
        &release[SIGHASH_LEN + VERDICT_LEN..]
    );
}

/// The same guard for the other two instructions.
///
/// `create_escrow` is signed by the buyer, so its five arguments are the
/// buyer's own choice and the length is here only so a sixth cannot appear
/// unremarked. `reclaim` takes no arguments at all: the buyer signs it and the
/// destination is the stored buyer, so an argument appearing there would mean
/// the buyer had started naming something.
#[test]
fn the_create_escrow_and_reclaim_payloads_are_pinned_too() {
    // sighash, escrow_id, amount, deadline, seller, verdict_signer.
    assert_eq!(create_escrow_data().len(), 8 + 8 + 8 + 8 + 32 + 32);
    // The sighash and nothing else.
    assert_eq!(reclaim_data().len(), 8);

    // Three instructions, three sighashes. Dispatch compares all eight bytes,
    // so these being distinct is what keeps one instruction from answering for
    // another.
    let create = create_escrow_data()[..SIGHASH_LEN].to_vec();
    let reclaim = reclaim_data()[..SIGHASH_LEN].to_vec();
    let settle = settle_sighash().to_vec();
    assert_ne!(create, reclaim);
    assert_ne!(create, settle);
    assert_ne!(reclaim, settle);
}

/// The two encodings of one verdict, which are deliberately different numbers.
///
/// Borsh writes the variant's position into the instruction data: 0 for a
/// release, 1 for a refund. The signed message carries the protocol's own code
/// at byte 169: 1 for a release, 2 for a refund, and `message_layout.rs` pins
/// that position and those bytes. So the byte that means "refund" in the data
/// is the code for "release" in the message, and anything that derived one
/// from the other would pay the wrong party. The two sequences also have to be
/// kept in step by hand: a third variant would take Borsh index 2, which is
/// already a message code.
#[test]
fn the_borsh_index_and_the_message_code_are_different_numbers() {
    let expires_at = START_TIME + 600;
    assert_eq!(settle_data(Verdict::Release, expires_at)[SIGHASH_LEN], 0);
    assert_eq!(settle_data(Verdict::Refund, expires_at)[SIGHASH_LEN], 1);

    assert_eq!(Verdict::Release.message_code(), 1);
    assert_eq!(Verdict::Refund.message_code(), 2);

    assert_eq!(
        settle_data(Verdict::Refund, expires_at)[SIGHASH_LEN],
        Verdict::Release.message_code(),
        "a refund's byte in the data is a release's code in the message"
    );

    // And no verdict's message code is zero, so a zeroed byte 169 names
    // nothing at all.
    assert_ne!(Verdict::Release.message_code(), 0);
    assert_ne!(Verdict::Refund.message_code(), 0);
}
