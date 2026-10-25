use anchor_lang::prelude::*;

/// Every failure gets its own code so a test can assert which check fired.
/// A test that only asserts "the transaction failed" proves nothing.
///
/// The numbers clients see are positional: Anchor assigns 6000 to the first
/// variant, 6001 to the second and so on. A new error goes at the end, never
/// in the middle, or every error after it silently changes meaning for anyone
/// already handling the old numbers. Both the numbers and the messages are
/// pinned by `tests/tests/error_codes.rs`, which is also what stops a message
/// quoting a byte count from going stale when the layout changes.
#[error_code]
pub enum EscrowError {
    #[msg("Amount must be greater than zero")]
    ZeroAmount,
    #[msg("Deadline must be in the future")]
    DeadlineNotInFuture,
    #[msg("Seller address must not be the default address")]
    SellerNotSet,
    #[msg("Verdict signer must not be the default address")]
    VerdictSignerNotSet,
    #[msg("Mint carries extensions this program does not support")]
    UnsupportedMintExtensions,
    #[msg("Vault did not gain exactly the escrowed amount")]
    VaultAmountMismatch,
    #[msg("Deadline has passed; only reclaim can move the money now")]
    DeadlinePassed,
    #[msg("Deadline has not been reached yet")]
    DeadlineNotReached,
    #[msg("No instruction precedes this one, so there is no verdict to check")]
    MissingVerdictInstruction,
    #[msg("The preceding instruction is not an Ed25519 program instruction")]
    NotEd25519Instruction,
    #[msg("The Ed25519 instruction carries accounts; the expected layout has none")]
    VerdictInstructionHasAccounts,
    #[msg("The Ed25519 instruction data is not the expected 290 bytes")]
    BadVerdictDataLength,
    #[msg("The Ed25519 instruction does not carry exactly one signature")]
    BadSignatureCount,
    #[msg("The Ed25519 offsets header does not match the expected layout")]
    BadFieldOffsets,
    #[msg("The signed message is not the expected 178 bytes")]
    BadMessageSize,
    #[msg("The Ed25519 offsets point at a different instruction")]
    OffsetsPointAtAnotherInstruction,
    #[msg("The verdict was signed by a key other than this escrow's verdict signer")]
    WrongVerdictSigner,
    #[msg("The signed message does not match this escrow's state")]
    VerdictMessageMismatch,
    #[msg("The verdict expired before it was submitted")]
    VerdictExpired,
    #[msg("Vault balance would overflow")]
    VaultBalanceOverflow,
}
