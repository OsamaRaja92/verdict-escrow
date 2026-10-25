use anchor_lang::prelude::*;

/// One event per state change, so an indexer can follow every escrow from
/// funding to payout without replaying account snapshots.
#[event]
pub struct EscrowCreated {
    pub escrow: Pubkey,
    pub buyer: Pubkey,
    pub seller: Pubkey,
    pub mint: Pubkey,
    pub verdict_signer: Pubkey,
    pub amount: u64,
    pub deadline: i64,
    pub created_slot: u64,
    pub escrow_id: u64,
}

#[event]
pub struct EscrowSettled {
    pub escrow: Pubkey,
    pub buyer: Pubkey,
    pub seller: Pubkey,
    pub mint: Pubkey,
    /// Whose signature authorised this payout. Carried here as well as on
    /// `EscrowCreated` so a monitor can alarm on a settlement signed by an
    /// unexpected key without first joining back to the creation event.
    pub verdict_signer: Pubkey,
    /// 1 = release (seller paid), 2 = refund (buyer paid). Same codes as the
    /// signed message, so an indexer reads one value, not two encodings.
    pub verdict: u8,
    /// Who actually received the tokens.
    pub destination: Pubkey,
    pub amount: u64,
}

#[event]
pub struct EscrowReclaimed {
    pub escrow: Pubkey,
    pub buyer: Pubkey,
    pub mint: Pubkey,
    pub amount: u64,
}
