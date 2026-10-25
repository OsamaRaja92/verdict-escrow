use anchor_lang::prelude::*;

/// Seed prefix for the escrow PDA: `["escrow", buyer, escrow_id]`.
pub const ESCROW_SEED: &[u8] = b"escrow";

/// Everything the program needs to settle a deal, written once at creation and
/// never changed afterwards. Both exits close this account, so its lifetime is
/// exactly the lifetime of the deal.
#[account]
#[derive(InitSpace)]
pub struct Escrow {
    /// Funded the vault, signs `reclaim`, and receives all rent when the
    /// escrow closes.
    pub buyer: Pubkey,
    /// Paid by a `Release` verdict. Stored, never passed as an argument.
    pub seller: Pubkey,
    /// The token being escrowed. Pins both payout destinations to one mint.
    pub mint: Pubkey,
    /// The only key whose signature can move the money before the deadline.
    pub verdict_signer: Pubkey,
    /// Deposited amount, in the mint's base units.
    pub amount: u64,
    /// Unix seconds. `settle` works strictly before it, `reclaim` at or after.
    pub deadline: i64,
    /// Slot this escrow was created in. Part of the signed verdict message, so
    /// a verdict cannot be replayed against a later escrow at the same address.
    pub created_slot: u64,
    /// Caller-chosen id, part of the PDA seeds. Stored so both exits can
    /// rebuild the seeds without searching.
    pub escrow_id: u64,
    /// Canonical bump for this PDA, found once at creation and reused.
    pub bump: u8,
}
