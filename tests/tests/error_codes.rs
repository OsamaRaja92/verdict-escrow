//! The error numbers and the error messages, pinned one variant at a time.
//!
//! A client never sees `EscrowError::VerdictExpired`. It sees
//! `InstructionError::Custom(6018)` — a bare number, with no name and no text
//! attached. The name and the message live in the IDL, which is published
//! separately and is only as current as whoever regenerated it last. So the
//! numbers are the interface: a relayer that retries on "the verdict expired"
//! and gives up on "the signed message does not match" has those two
//! behaviours wired to 6018 and 6017, and nothing else.
//!
//! Anchor derives those numbers from position. The first variant is 6000, the
//! second 6001, and so on, which means inserting a variant in the middle of
//! `EscrowError` renumbers every variant after it. The program still compiles,
//! the IDL still regenerates, and the relayer above quietly starts retrying on
//! the wrong condition.
//!
//! Every other assertion in this suite goes through the enum, so every other
//! assertion moves with the renumbering and stays green. This file is the one
//! place that does not: it writes the numbers out as literals, and the messages
//! out as text, so the diff that moves one of them has to say so.
//!
//! Two of the messages quote a byte count from the layout. Those are built here
//! from the program's own constants rather than typed out, so changing the
//! layout and leaving the message behind fails here instead of shipping a
//! message that tells a client to look for the wrong number of bytes.
//!
//! No LiteSVM and no transactions: this is a unit test over the enum itself.

use anchor_lang::error::{ErrorCode as AnchorError, ERROR_CODE_OFFSET};
use verdict_escrow::errors::EscrowError;
use verdict_escrow::verdict::{ED25519_IX_DATA_LEN, MESSAGE_LEN};

/// The number Anchor gives the first variant of a program's own error enum.
const FIRST_CODE: u32 = 6000;

/// Every variant of `EscrowError`, in declaration order, which is also code
/// order. Walked by the whole-enum checks below.
const ALL_ERRORS: [EscrowError; 20] = [
    EscrowError::ZeroAmount,
    EscrowError::DeadlineNotInFuture,
    EscrowError::SellerNotSet,
    EscrowError::VerdictSignerNotSet,
    EscrowError::UnsupportedMintExtensions,
    EscrowError::VaultAmountMismatch,
    EscrowError::DeadlinePassed,
    EscrowError::DeadlineNotReached,
    EscrowError::MissingVerdictInstruction,
    EscrowError::NotEd25519Instruction,
    EscrowError::VerdictInstructionHasAccounts,
    EscrowError::BadVerdictDataLength,
    EscrowError::BadSignatureCount,
    EscrowError::BadFieldOffsets,
    EscrowError::BadMessageSize,
    EscrowError::OffsetsPointAtAnotherInstruction,
    EscrowError::WrongVerdictSigner,
    EscrowError::VerdictMessageMismatch,
    EscrowError::VerdictExpired,
    EscrowError::VaultBalanceOverflow,
];

/// The position this file believes each variant occupies.
///
/// The match is exhaustive, which is the point: a variant added to
/// `EscrowError` has no arm here and this file stops compiling, so the change
/// cannot be made without reading the rules above and appending the variant to
/// the three tables below. Returning the position rather than the code keeps
/// the numbers themselves in one place.
fn declared_position(error: EscrowError) -> usize {
    match error {
        EscrowError::ZeroAmount => 0,
        EscrowError::DeadlineNotInFuture => 1,
        EscrowError::SellerNotSet => 2,
        EscrowError::VerdictSignerNotSet => 3,
        EscrowError::UnsupportedMintExtensions => 4,
        EscrowError::VaultAmountMismatch => 5,
        EscrowError::DeadlinePassed => 6,
        EscrowError::DeadlineNotReached => 7,
        EscrowError::MissingVerdictInstruction => 8,
        EscrowError::NotEd25519Instruction => 9,
        EscrowError::VerdictInstructionHasAccounts => 10,
        EscrowError::BadVerdictDataLength => 11,
        EscrowError::BadSignatureCount => 12,
        EscrowError::BadFieldOffsets => 13,
        EscrowError::BadMessageSize => 14,
        EscrowError::OffsetsPointAtAnotherInstruction => 15,
        EscrowError::WrongVerdictSigner => 16,
        EscrowError::VerdictMessageMismatch => 17,
        EscrowError::VerdictExpired => 18,
        EscrowError::VaultBalanceOverflow => 19,
    }
}

/// One variant's number. The failure names the variant, so a renumbering says
/// which one moved rather than leaving a line number to look up.
#[track_caller]
fn assert_code(error: EscrowError, expected: u32) {
    assert_eq!(
        u32::from(error),
        expected,
        "{} is no longer error {expected}. Error numbers are positional, so a variant was \
         inserted, removed or reordered above it, and every number from here on now means \
         something else to a client already handling the old ones. A new error is appended, \
         never inserted.",
        error.name()
    );
}

/// One variant's message, as a client would display it.
#[track_caller]
fn assert_message(error: EscrowError, expected: &str) {
    assert_eq!(
        error.to_string(),
        expected,
        "the message for {} changed. It reaches users through the IDL and the program logs, so \
         it is part of the published interface; update it here deliberately.",
        error.name()
    );
}

#[test]
fn anchor_still_counts_a_programs_own_errors_from_six_thousand() {
    assert_eq!(
        ERROR_CODE_OFFSET, FIRST_CODE,
        "Anchor moved the offset every code in this file is built on"
    );
}

/// The published table. Each line is one variant and the number clients handle.
#[test]
fn every_error_keeps_the_number_it_was_published_with() {
    assert_code(EscrowError::ZeroAmount, 6000);
    assert_code(EscrowError::DeadlineNotInFuture, 6001);
    assert_code(EscrowError::SellerNotSet, 6002);
    assert_code(EscrowError::VerdictSignerNotSet, 6003);
    assert_code(EscrowError::UnsupportedMintExtensions, 6004);
    assert_code(EscrowError::VaultAmountMismatch, 6005);
    assert_code(EscrowError::DeadlinePassed, 6006);
    assert_code(EscrowError::DeadlineNotReached, 6007);
    assert_code(EscrowError::MissingVerdictInstruction, 6008);
    assert_code(EscrowError::NotEd25519Instruction, 6009);
    assert_code(EscrowError::VerdictInstructionHasAccounts, 6010);
    assert_code(EscrowError::BadVerdictDataLength, 6011);
    assert_code(EscrowError::BadSignatureCount, 6012);
    assert_code(EscrowError::BadFieldOffsets, 6013);
    assert_code(EscrowError::BadMessageSize, 6014);
    assert_code(EscrowError::OffsetsPointAtAnotherInstruction, 6015);
    assert_code(EscrowError::WrongVerdictSigner, 6016);
    assert_code(EscrowError::VerdictMessageMismatch, 6017);
    assert_code(EscrowError::VerdictExpired, 6018);
    assert_code(EscrowError::VaultBalanceOverflow, 6019);
}

/// Catches the shapes the table above cannot: a variant renamed, the list left
/// out of declaration order, or a gap opened in the middle of the block.
#[test]
fn the_pinned_list_still_matches_the_enum_variant_for_variant() {
    for (index, error) in ALL_ERRORS.into_iter().enumerate() {
        assert_eq!(
            declared_position(error),
            index,
            "{} sits at position {index} of the pinned list but position {} of the enum",
            error.name(),
            declared_position(error)
        );
        assert_eq!(
            u32::from(error),
            FIRST_CODE + index as u32,
            "the block of codes is no longer contiguous from {FIRST_CODE}: {} is {}",
            error.name(),
            u32::from(error)
        );
    }
}

/// The text a wallet or a relayer shows when one of these fires.
#[test]
fn every_error_message_is_still_the_one_clients_display() {
    assert_message(EscrowError::ZeroAmount, "Amount must be greater than zero");
    assert_message(
        EscrowError::DeadlineNotInFuture,
        "Deadline must be in the future",
    );
    assert_message(
        EscrowError::SellerNotSet,
        "Seller address must not be the default address",
    );
    assert_message(
        EscrowError::VerdictSignerNotSet,
        "Verdict signer must not be the default address",
    );
    assert_message(
        EscrowError::UnsupportedMintExtensions,
        "Mint carries extensions this program does not support",
    );
    assert_message(
        EscrowError::VaultAmountMismatch,
        "Vault did not gain exactly the escrowed amount",
    );
    assert_message(
        EscrowError::DeadlinePassed,
        "Deadline has passed; only reclaim can move the money now",
    );
    assert_message(
        EscrowError::DeadlineNotReached,
        "Deadline has not been reached yet",
    );
    assert_message(
        EscrowError::MissingVerdictInstruction,
        "No instruction precedes this one, so there is no verdict to check",
    );
    assert_message(
        EscrowError::NotEd25519Instruction,
        "The preceding instruction is not an Ed25519 program instruction",
    );
    assert_message(
        EscrowError::VerdictInstructionHasAccounts,
        "The Ed25519 instruction carries accounts; the expected layout has none",
    );
    assert_message(
        EscrowError::BadSignatureCount,
        "The Ed25519 instruction does not carry exactly one signature",
    );
    assert_message(
        EscrowError::BadFieldOffsets,
        "The Ed25519 offsets header does not match the expected layout",
    );
    assert_message(
        EscrowError::OffsetsPointAtAnotherInstruction,
        "The Ed25519 offsets point at a different instruction",
    );
    assert_message(
        EscrowError::WrongVerdictSigner,
        "The verdict was signed by a key other than this escrow's verdict signer",
    );
    assert_message(
        EscrowError::VerdictMessageMismatch,
        "The signed message does not match this escrow's state",
    );
    assert_message(
        EscrowError::VerdictExpired,
        "The verdict expired before it was submitted",
    );
    assert_message(
        EscrowError::VaultBalanceOverflow,
        "Vault balance would overflow",
    );
}

/// The two messages that quote a number of bytes, checked against the constants
/// the program actually enforces.
///
/// The expected text is formatted from `ED25519_IX_DATA_LEN` and `MESSAGE_LEN`,
/// not typed out, so a change to the layout moves the expectation with it and
/// the test fails on the message that was left behind. A hard-coded "290" here
/// would agree with a stale message forever.
#[test]
fn the_messages_that_quote_a_byte_count_still_agree_with_the_layout() {
    assert_message(
        EscrowError::BadVerdictDataLength,
        &format!("The Ed25519 instruction data is not the expected {ED25519_IX_DATA_LEN} bytes"),
    );
    assert_message(
        EscrowError::BadMessageSize,
        &format!("The signed message is not the expected {MESSAGE_LEN} bytes"),
    );
}

/// Anchor's own codes, which this suite asserts in place of the program's
/// wherever a constraint refuses an account before any handler runs.
///
/// These are as positional as the program's, and they come from a dependency
/// that gets upgraded. Pinning them here means an upgrade that renumbers one
/// fails with a line that names it, instead of turning twenty attack tests in
/// other files into puzzles about why a seeds violation now reports as
/// something else.
#[test]
fn the_anchor_built_in_codes_this_suite_asserts_are_unchanged() {
    assert_eq!(u32::from(AnchorError::ConstraintHasOne), 2001);
    assert_eq!(u32::from(AnchorError::ConstraintSeeds), 2006);
    assert_eq!(u32::from(AnchorError::ConstraintAddress), 2012);
    assert_eq!(u32::from(AnchorError::ConstraintTokenOwner), 2015);
    assert_eq!(u32::from(AnchorError::ConstraintMintTokenProgram), 2022);
    assert_eq!(u32::from(AnchorError::AccountDiscriminatorMismatch), 3002);
    assert_eq!(u32::from(AnchorError::AccountOwnedByWrongProgram), 3007);
    assert_eq!(u32::from(AnchorError::AccountNotSigner), 3010);
    assert_eq!(u32::from(AnchorError::AccountNotInitialized), 3012);
}

/// Anchor's codes and the program's cannot be confused for one another: the
/// built-ins sit below the offset the program's own block starts at, so a test
/// that expects a constraint violation can never be satisfied by an escrow
/// error, or the other way round.
#[test]
fn anchor_built_in_codes_stay_below_the_programs_own_block() {
    for error in [
        AnchorError::ConstraintHasOne,
        AnchorError::ConstraintSeeds,
        AnchorError::ConstraintAddress,
        AnchorError::ConstraintTokenOwner,
        AnchorError::ConstraintMintTokenProgram,
        AnchorError::AccountDiscriminatorMismatch,
        AnchorError::AccountOwnedByWrongProgram,
        AnchorError::AccountNotSigner,
        AnchorError::AccountNotInitialized,
    ] {
        let code = u32::from(error);
        assert!(
            code < FIRST_CODE,
            "{} is {code}, which is inside the range this program's own errors use",
            error.name()
        );
    }
}
