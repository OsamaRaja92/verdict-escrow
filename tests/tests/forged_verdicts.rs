//! Verdicts that are signed, but not by the right key, or not over the right
//! bytes. Each one must be refused, and refused for the stated reason.
//!
//! Two sweeps close the file, and between them they say the same thing at two
//! scales. The first walks all 178 bytes of the signed message with the real
//! verdict signer re-signing every tampered copy, so the runtime is satisfied
//! and the only thing that can refuse the transaction is the program rebuilding
//! those bytes from its own state. That is the on-chain half of what
//! `message_layout.rs` establishes off-chain, where no transaction is ever
//! sent. The second walks all 2,320 bits of a correct verdict instruction and
//! records which side refuses each one, which turns out to be a sharp division:
//! the runtime covers 289 of the 290 bytes, and the program covers the byte the
//! runtime ignores.

use escrow_harness::*;
use litesvm::types::TransactionResult;
use solana_instruction_error::InstructionError;
use solana_keypair::Keypair;
use solana_transaction_error::TransactionError;
use verdict_escrow::errors::EscrowError;
use verdict_escrow::verdict::{build_message, Verdict};

/// The ten fields of the signed message, each with the half-open byte range it
/// occupies. Written out here rather than imported from the program, so the
/// layout has to be changed twice before this file stops testing it.
const FIELDS: [(&str, usize, usize); 10] = [
    ("domain tag", 0, 17),
    ("program id", 17, 49),
    ("escrow address", 49, 81),
    ("created_slot", 81, 89),
    ("mint", 89, 121),
    ("amount", 121, 129),
    ("seller", 129, 161),
    ("deadline", 161, 169),
    ("verdict", 169, 170),
    ("expires_at", 170, 178),
];

const MESSAGE_LEN: usize = 178;
/// 16 header + 32 key + 64 signature + the message.
const IX_DATA_LEN: usize = 16 + 32 + 64 + MESSAGE_LEN;

/// Codes from the runtime's `PrecompileError`, which arrive as a custom error
/// on the Ed25519 instruction rather than on `settle`. Code two,
/// `InvalidSignature`, is the harness's `ED25519_INVALID_SIGNATURE`.
const INVALID_PUBLIC_KEY: u32 = 0;
const INVALID_DATA_OFFSETS: u32 = 3;
const INVALID_INSTRUCTION_DATA_SIZE: u32 = 4;

#[test]
fn a_verdict_signed_by_the_wrong_key_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let expires_at = h.now() + 600;
        // A real signature over the right bytes — by someone else's key. The
        // precompile is satisfied; the program is not.
        let impostor = Keypair::new();
        let message = h.verdict_message(escrow, Verdict::Release, expires_at);
        let verdict_ix = Ed25519Ix::sign(&impostor, &message);

        let accounts = h.settle_accounts(escrow);
        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_error(&result, EscrowError::WrongVerdictSigner);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
    });
}

#[test]
fn a_message_that_differs_by_one_byte_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let expires_at = h.now() + 600;
        let mut message = h.verdict_message(escrow, Verdict::Release, expires_at);
        // Byte 121 is the first byte of the amount. One unit more than the
        // escrow holds, correctly signed.
        message[121] = message[121].wrapping_add(1);
        let verdict_ix = Ed25519Ix::sign(&h.verdict_signer, &message);

        let accounts = h.settle_accounts(escrow);
        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_error(&result, EscrowError::VerdictMessageMismatch);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
    });
}

#[test]
fn a_verdict_for_another_escrow_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow_a, result) = h.create_escrow(1);
        assert_ok(&result);
        let (escrow_b, result) = h.create_escrow(2);
        assert_ok(&result);

        let expires_at = h.now() + 600;
        // A perfectly good verdict for A, submitted against B. The escrow
        // address is in the signed bytes, so B's rebuild does not match.
        let verdict_ix = h.verdict_ix(escrow_a, Verdict::Release, expires_at);
        let accounts = h.settle_accounts(escrow_b);
        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_error(&result, EscrowError::VerdictMessageMismatch);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
    });
}

#[test]
fn a_release_verdict_cannot_be_submitted_as_a_refund() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let expires_at = h.now() + 600;
        // Signed for release; submitted as a refund. The verdict byte is
        // inside the signature, so the swap cannot be hidden.
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let accounts = h.settle_accounts(escrow);
        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Refund, expires_at);
        assert_error(&result, EscrowError::VerdictMessageMismatch);
    });
}

#[test]
fn an_expired_verdict_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        // Signed correctly, and expired one second ago.
        let expires_at = h.now() - 1;
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let accounts = h.settle_accounts(escrow);
        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_error(&result, EscrowError::VerdictExpired);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
    });
}

#[test]
fn a_verdict_is_still_good_in_its_last_second() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        // `expires_at` is inclusive: the boundary belongs to the verdict.
        let expires_at = h.now();
        let result = h.settle(escrow, Verdict::Release, expires_at);
        assert_ok(&result);
    });
}

/// The harness check the whole suite rests on.
///
/// Every test above hands the precompile a valid signature and leans on the
/// program to reject the contents. If the test environment did not verify
/// signatures at all, those tests would still pass, and would prove nothing.
/// This one corrupts the signature itself: it must be refused before the
/// program is ever reached.
#[test]
fn a_corrupted_signature_never_reaches_the_program() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let expires_at = h.now() + 600;
        let mut verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        verdict_ix.signature[0] ^= 0xff;

        let accounts = h.settle_accounts(escrow);
        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_precompile_rejection(&result);
        assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
        assert!(h.account_exists(&escrow));
    });
}

#[test]
fn a_verdict_signed_over_another_programs_message_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        // Same fields, same signer, different program id: what a verdict for
        // another deployment of this code would look like.
        let expires_at = h.now() + 600;
        let other_program = Keypair::new().pubkey();
        let state = h.escrow_state(&escrow);
        let message = build_message(
            &other_program,
            &escrow,
            &state,
            Verdict::Release,
            expires_at,
        );
        let verdict_ix = Ed25519Ix::sign(&h.verdict_signer, &message);

        let accounts = h.settle_accounts(escrow);
        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_error(&result, EscrowError::VerdictMessageMismatch);
    });
}

#[test]
fn a_verdict_without_the_domain_tag_is_refused() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let expires_at = h.now() + 600;
        let mut message = h.verdict_message(escrow, Verdict::Release, expires_at);
        message[0..17].copy_from_slice(b"some-other-tag:v1");
        let verdict_ix = Ed25519Ix::sign(&h.verdict_signer, &message);

        let accounts = h.settle_accounts(escrow);
        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);
        assert_error(&result, EscrowError::VerdictMessageMismatch);
    });
}

/// Assert that the program rebuilt the message, compared it, and found this
/// byte wrong.
///
/// `assert_error` makes the same comparison but cannot say which field moved,
/// and a sweep that fails without naming the field leaves the next reader
/// counting bytes by hand.
#[track_caller]
fn assert_message_mismatch(result: &TransactionResult, field: &str, offset: usize) {
    let expected = u32::from(EscrowError::VerdictMessageMismatch);
    let flip = format!("a flipped byte at offset {offset}, in the {field} field,");
    assert!(result.is_err(), "{flip} settled the escrow");
    match custom_error_code(result) {
        Some(code) if code == expected => {}
        Some(code) => panic!(
            "{flip} was refused with custom error {code}, not VerdictMessageMismatch ({expected})"
        ),
        None => panic!(
            "{flip} was refused by something other than the program: {:?}",
            result.as_ref().err().map(|failure| &failure.err)
        ),
    }
}

/// Every byte of the signed message, tampered one at a time, and signed by the
/// real verdict signer.
///
/// The attacker here has the signer's cooperation for the wrong bytes: a
/// verdict over a message naming a larger amount, a different seller, another
/// escrow, no domain tag at all. Every one of them carries a signature that
/// verifies, so the runtime passes the instruction through and the only thing
/// left is `verify_verdict` rebuilding all 178 bytes from the escrow's own
/// state and comparing them. A field left out of the rebuild, or a comparison
/// that stopped a byte short, settles here.
///
/// `message_layout.rs` makes the neighbouring claim off-chain — that each field
/// changes the bytes `build_message` produces — but it sends no transaction, so
/// it cannot show the program refusing one. Four fields also have a named test
/// of their own above: the amount, the domain tag, the program id and the
/// escrow address, each bent the way an attacker would bend it rather than byte
/// by byte. This is the exhaustive version, and it walks every byte of all ten
/// fields rather than one byte per field, so that a rebuild which skipped a
/// field, or a comparison which ignored a field's first or last byte, has
/// nowhere to hide.
///
/// The verdict byte at 169 is in the sweep like any other. Flipped, it is
/// neither of the two legal codes, so the mismatch shows the rebuild comparing
/// the signed byte itself; `a_release_verdict_cannot_be_submitted_as_a_refund`
/// above makes the other half of that claim, where the byte is the legal code
/// for the other direction and the instruction argument is what disagrees.
#[test]
fn a_tampered_byte_in_any_field_of_the_message_is_refused() {
    // The table has to tile the message exactly, or a field could go untested
    // while the loop below still reports every byte refused.
    let mut covered = 0;
    for (field, start, end) in FIELDS {
        assert_eq!(
            start, covered,
            "the {field} field does not start where the previous one ends"
        );
        assert!(end > start, "the {field} field is empty");
        covered = end;
    }
    assert_eq!(covered, MESSAGE_LEN, "the table stops short of the message");

    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);

        let expires_at = h.now() + 600;
        let accounts = h.settle_accounts(escrow);
        let correct = h.verdict_message(escrow, Verdict::Release, expires_at);
        assert_eq!(correct.len(), MESSAGE_LEN);

        for (field, start, end) in FIELDS {
            for offset in start..end {
                let mut message = correct;
                message[offset] ^= 0xff;
                // The real key over the tampered bytes: the precompile is
                // satisfied, so this reaches the program with nothing but the
                // rebuild in the way.
                let verdict_ix = Ed25519Ix::sign(&h.verdict_signer, &message);
                let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);

                assert_message_mismatch(&result, field, offset);
                assert_eq!(
                    h.token_balance(&accounts.vault),
                    ESCROW_AMOUNT,
                    "the vault moved on a flipped byte at offset {offset}, in the {field} field"
                );
            }
        }

        // 178 refusals later, the escrow is untouched and still settleable.
        assert_eq!(h.token_balance(&h.ata(&h.seller.pubkey())), 0);
        assert!(h.account_exists(&escrow));
        assert_ok(&h.settle(escrow, Verdict::Release, expires_at));
        assert_eq!(h.token_balance(&h.ata(&h.seller.pubkey())), ESCROW_AMOUNT);
    });
}

/// The two sides a verdict is proved across: the runtime, which checks that the
/// signature is a signature, and the program, which checks whose key it was and
/// over which bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Side {
    Precompile,
    Program,
}

/// Each region of a correct verdict instruction, with the side that refuses a
/// bit flipped inside it and the code it is refused with — where that code
/// follows from the layout rather than from whichever bytes happen to be in the
/// way, in which case the sweep pins only the side.
fn regions() -> [(&'static str, usize, usize, Side, Option<u32>); 12] {
    [
        // A count of zero, or one too large for 290 bytes of data, is refused
        // as a size; a count that still fits reads its extra offsets header
        // out of the key and signature bytes, which name instructions this
        // transaction does not have.
        ("num_signatures", 0, 1, Side::Precompile, None),
        // The one byte the precompile documents as unused, so the signature
        // verifies and the program is the only reader left. `ed25519_edges.rs`
        // pins the single `padding = 0xff` case; all eight bits land here.
        (
            "padding",
            1,
            2,
            Side::Program,
            Some(u32::from(EscrowError::BadSignatureCount)),
        ),
        // The four offset and size fields behave the same way, and in two
        // ways: a window that still lies inside the instruction makes the
        // precompile verify the wrong bytes, while one that runs off the end is
        // refused as a window. Both happen in each of them, so the sweep pins
        // the side and not the code.
        ("signature_offset", 2, 4, Side::Precompile, None),
        // Every single-bit change to 0xFFFF names an instruction index this
        // two-instruction transaction does not have.
        (
            "signature_instruction_index",
            4,
            6,
            Side::Precompile,
            Some(INVALID_DATA_OFFSETS),
        ),
        ("public_key_offset", 6, 8, Side::Precompile, None),
        (
            "public_key_instruction_index",
            8,
            10,
            Side::Precompile,
            Some(INVALID_DATA_OFFSETS),
        ),
        ("message_data_offset", 10, 12, Side::Precompile, None),
        ("message_data_size", 12, 14, Side::Precompile, None),
        (
            "message_instruction_index",
            14,
            16,
            Side::Precompile,
            Some(INVALID_DATA_OFFSETS),
        ),
        // Roughly half of the flipped keys are not curve points at all and are
        // refused as keys rather than as signatures, so which of the two codes
        // fires depends on this run's keypair.
        ("public key", 16, 48, Side::Precompile, None),
        (
            "signature",
            48,
            112,
            Side::Precompile,
            Some(ED25519_INVALID_SIGNATURE),
        ),
        (
            "message",
            112,
            IX_DATA_LEN,
            Side::Precompile,
            Some(ED25519_INVALID_SIGNATURE),
        ),
    ]
}

/// Which side refused this transaction, and with which code.
///
/// The Ed25519 instruction is index 0 and `settle` is index 1, so the index in
/// the error names the side; empty logs confirm that a failure at index 0
/// happened before any program code ran.
#[track_caller]
fn classify_refusal(result: &TransactionResult, flip: &str) -> (Side, u32) {
    let known = [
        INVALID_PUBLIC_KEY,
        ED25519_INVALID_SIGNATURE,
        INVALID_DATA_OFFSETS,
        INVALID_INSTRUCTION_DATA_SIZE,
    ];
    let failure = result.as_ref().err().unwrap_or_else(|| {
        panic!("{flip} settled the escrow: a bit neither the runtime nor the program reads")
    });
    match failure.err {
        TransactionError::InstructionError(0, InstructionError::Custom(code)) => {
            assert!(
                failure.meta.logs.is_empty(),
                "{flip} was refused at the Ed25519 instruction, but the program logged: {:?}",
                failure.meta.logs
            );
            assert!(
                known.contains(&code),
                "{flip} was refused with precompile code {code}, which is none of {known:?}"
            );
            (Side::Precompile, code)
        }
        TransactionError::InstructionError(1, InstructionError::Custom(code)) => {
            (Side::Program, code)
        }
        ref other => panic!("{flip} failed in a way this sweep does not model: {other:?}"),
    }
}

/// Every bit of a correct verdict instruction, flipped one at a time.
///
/// The attacker starts from the instruction that does settle this escrow and
/// hunts for one bit, anywhere in its 290 bytes, that neither side reads: a bit
/// the runtime leaves outside the signature and the program never compares.
/// There is exactly one byte like that, the padding at index one, and the
/// program refuses it anyway, so all 2,320 flips are refused and the vault is
/// still full at the end.
///
/// The sweep is also a description of the instruction, which is why [`regions`]
/// names a side per region and the counts are asserted rather than printed. The
/// division of labour it pins is lopsided: the runtime refuses 2,312 flips and
/// the program refuses 8. That is worth writing down because it says what the
/// program's own header checks are not for. None of them fires here — random
/// corruption is caught by the precompile first — which is why
/// `instruction_layout.rs` has to build self-consistent forgeries, headers that
/// are wrong and signed for, to reach `BadFieldOffsets`, `BadMessageSize` or
/// `OffsetsPointAtAnotherInstruction` at all.
///
/// One token program, not both. The 2,320 transactions take twenty seconds or
/// so, and running them again under the other program buys nothing: every
/// refusal lands before `settle` reaches a token CPI, so the token program is
/// not part of any of them. The only transaction here that pays anyone is the
/// control at the end, and `happy_path.rs` already pays under both.
#[test]
fn no_single_bit_flip_of_a_correct_verdict_instruction_can_settle() {
    // As with the message, the regions have to tile the instruction exactly, or
    // a byte could go unswept while the counts below still add up.
    let mut covered = 0;
    for (region, start, end, _, _) in regions() {
        assert_eq!(
            start, covered,
            "the {region} region does not start where the previous one ends"
        );
        covered = end;
    }
    assert_eq!(covered, IX_DATA_LEN, "the table stops short of the data");

    let mut h = Harness::new(TokenKind::Classic);
    let (escrow, result) = h.create_escrow(1);
    assert_ok(&result);

    let expires_at = h.now() + 600;
    let accounts = h.settle_accounts(escrow);
    let correct = h.verdict_ix(escrow, Verdict::Release, expires_at).data();
    assert_eq!(correct.len(), IX_DATA_LEN);
    let settle_ix = accounts.instruction(Verdict::Release, expires_at);
    let relayer = h.relayer.insecure_clone();

    let mut summary = Vec::new();
    let mut by_precompile = 0;
    let mut by_program = 0;
    for (region, start, end, side, code) in regions() {
        let mut refusals = 0;
        for offset in start..end {
            for bit in 0..8u32 {
                let mut data = correct.clone();
                data[offset] ^= 1u8 << bit;
                let result = h.send(
                    &[ed25519_ix_from_data(data), settle_ix.clone()],
                    &[&relayer],
                );

                let flip = format!("bit {bit} of byte {offset}, in the {region} region,");
                let (refused_by, refused_with) = classify_refusal(&result, &flip);
                assert_eq!(refused_by, side, "{flip} was refused by the wrong side");
                if let Some(code) = code {
                    assert_eq!(refused_with, code, "{flip} was refused with the wrong code");
                }
                match refused_by {
                    Side::Precompile => by_precompile += 1,
                    Side::Program => by_program += 1,
                }
                refusals += 1;
            }
        }
        summary.push((region, refusals, side));
    }

    // The shape of the instruction, as the sweep measured it: eight flips per
    // byte, all of them refused, and only the padding byte answered by the
    // program rather than by the runtime.
    assert_eq!(
        summary,
        vec![
            ("num_signatures", 8, Side::Precompile),
            ("padding", 8, Side::Program),
            ("signature_offset", 16, Side::Precompile),
            ("signature_instruction_index", 16, Side::Precompile),
            ("public_key_offset", 16, Side::Precompile),
            ("public_key_instruction_index", 16, Side::Precompile),
            ("message_data_offset", 16, Side::Precompile),
            ("message_data_size", 16, Side::Precompile),
            ("message_instruction_index", 16, Side::Precompile),
            ("public key", 256, Side::Precompile),
            ("signature", 512, Side::Precompile),
            ("message", 1_424, Side::Precompile),
        ]
    );
    assert_eq!(
        by_precompile, 2_312,
        "the runtime's share of the instruction"
    );
    assert_eq!(by_program, 8, "the program's share: the padding byte");
    assert_eq!(by_precompile + by_program, 8 * IX_DATA_LEN);

    // Nothing moved in 2,320 attempts.
    assert_eq!(h.token_balance(&accounts.vault), ESCROW_AMOUNT);
    assert_eq!(h.token_balance(&h.ata(&h.seller.pubkey())), 0);
    assert!(h.account_exists(&escrow));

    // The control, without which a sweep over a broken transaction would pass:
    // the same instruction with nothing flipped settles, so the refusals above
    // are about the flipped bit and not about how this test builds its
    // transaction.
    let result = h.send(&[ed25519_ix_from_data(correct), settle_ix], &[&relayer]);
    assert_ok(&result);
    assert_eq!(h.token_balance(&h.ata(&h.seller.pubkey())), ESCROW_AMOUNT);
    assert!(!h.account_exists(&escrow));
}
