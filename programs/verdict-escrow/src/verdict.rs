//! The signed verdict: what the verdict signer signs off-chain, and how this
//! program satisfies itself that the signature it is being shown really covers
//! those bytes.
//!
//! The Ed25519 signature is not verified here. The runtime verifies it, in a
//! precompiled instruction that sits immediately before `settle` in the same
//! transaction. What is left to this program is the part the runtime cannot
//! know: *which* key signed *which* bytes. That is the whole job of
//! [`verify_verdict`].

use anchor_lang::prelude::*;
use solana_instructions_sysvar::{load_current_index_checked, load_instruction_at_checked};

use crate::errors::EscrowError;
use crate::state::Escrow;

/// Domain tag, so a signature over these bytes cannot be valid for anything
/// else the verdict signer might ever sign.
pub const DOMAIN_TAG: &[u8; 17] = b"verdict-escrow:v1";

/// The signed message is a fixed 178 bytes:
///
/// | offset | len | field                        |
/// |--------|-----|------------------------------|
/// |   0    |  17 | domain tag                   |
/// |  17    |  32 | program id                   |
/// |  49    |  32 | escrow address               |
/// |  81    |   8 | created_slot  (u64 LE)       |
/// |  89    |  32 | mint                         |
/// | 121    |   8 | amount        (u64 LE)       |
/// | 129    |  32 | seller                       |
/// | 161    |   8 | deadline      (i64 LE)       |
/// | 169    |   1 | verdict: 1 release, 2 refund |
/// | 170    |   8 | expires_at    (i64 LE)       |
///
/// The buyer is not a field of its own: the escrow address is a PDA of
/// `["escrow", buyer, escrow_id]` and the program re-derives those seeds from
/// stored state on every call, so naming the escrow names the buyer.
///
/// The seller and the deadline are here because the escrow address alone does
/// not pin them. An escrow that has been settled and re-created at the same
/// address in the same slot shares its `created_slot`, and without these two
/// fields an old verdict would fit a rebuilt escrow that names a different
/// payee. With them, a rebuild that an old verdict still fits is one where the
/// buyer pays the same seller the same amount by the same deadline — which is
/// what the verdict signer agreed to in the first place.
pub const MESSAGE_LEN: usize = 178;

/// Byte layout of the Ed25519 instruction this program accepts, and only this
/// one. The offsets are what the standard client helpers produce for a single
/// signature whose key, signature and message all live in that same
/// instruction's data: 16 header + 32 key + 64 signature + the message.
pub const ED25519_IX_DATA_LEN: usize = 16 + 32 + 64 + MESSAGE_LEN;
pub const PUBKEY_OFFSET: u16 = 16;
pub const SIGNATURE_OFFSET: u16 = 48;
pub const MESSAGE_OFFSET: u16 = 112;

/// `0xFFFF` in an instruction-index field means "this instruction". Any other
/// value makes the precompile read its key, signature or message out of a
/// *different* instruction in the transaction, which is exactly how a program
/// that trusts fixed offsets gets shown one message while the signature covers
/// another.
pub const THIS_INSTRUCTION: u16 = u16::MAX;

/// Which way the money goes.
///
/// Note the two encodings, which are deliberately not the same thing:
/// Borsh puts the *variant index* (0, 1) in the instruction data, while the
/// signed message carries the protocol's own code (1, 2) from
/// [`Verdict::message_code`]. The message code is part of the signature and
/// must never be derived from the Borsh index.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict {
    /// Pay the whole vault to the seller.
    Release,
    /// Return the whole vault to the buyer.
    Refund,
}

impl Verdict {
    pub fn message_code(&self) -> u8 {
        match self {
            Verdict::Release => 1,
            Verdict::Refund => 2,
        }
    }
}

/// Rebuild the exact bytes the verdict signer was supposed to sign, from this
/// program's own state. Nothing here comes from the caller except the two
/// arguments that are themselves covered by the signature.
pub fn build_message(
    program_id: &Pubkey,
    escrow_key: &Pubkey,
    escrow: &Escrow,
    verdict: Verdict,
    expires_at: i64,
) -> [u8; MESSAGE_LEN] {
    let mut message = [0u8; MESSAGE_LEN];
    message[0..17].copy_from_slice(DOMAIN_TAG);
    message[17..49].copy_from_slice(program_id.as_ref());
    message[49..81].copy_from_slice(escrow_key.as_ref());
    message[81..89].copy_from_slice(&escrow.created_slot.to_le_bytes());
    message[89..121].copy_from_slice(escrow.mint.as_ref());
    message[121..129].copy_from_slice(&escrow.amount.to_le_bytes());
    message[129..161].copy_from_slice(escrow.seller.as_ref());
    message[161..169].copy_from_slice(&escrow.deadline.to_le_bytes());
    message[169] = verdict.message_code();
    message[170..178].copy_from_slice(&expires_at.to_le_bytes());
    message
}

/// Confirm that the instruction immediately before this one is an Ed25519
/// verification of `expected_message` under `expected_signer`.
///
/// The order matters: the runtime has already verified the signature by the
/// time this runs, so every check below is about *what* was verified, not
/// whether it was. The instruction is read at `current_index - 1` and nowhere
/// else; scanning the transaction for "the first Ed25519 instruction" would let
/// an attacker append a real verification after a fake one.
///
/// One precision about "immediately before". The instructions sysvar exposes
/// only the transaction's top-level instructions, and `load_current_index`
/// returns a top-level index. Called directly, that is the instruction before
/// `settle`. Reached through a CPI, it is the instruction before the top-level
/// instruction that led here — so an integrator wrapping this program must put
/// the verdict before *their* instruction. Nothing is weakened either way: the
/// bytes still have to be the ones this program rebuilds, under the key this
/// escrow stored.
pub fn verify_verdict(
    instructions_sysvar: &AccountInfo,
    expected_signer: &Pubkey,
    expected_message: &[u8; MESSAGE_LEN],
) -> Result<()> {
    let current_index = load_current_index_checked(instructions_sysvar)?;
    require!(current_index >= 1, EscrowError::MissingVerdictInstruction);

    let instruction =
        load_instruction_at_checked((current_index - 1) as usize, instructions_sysvar)
            .map_err(|_| error!(EscrowError::MissingVerdictInstruction))?;

    require_keys_eq!(
        instruction.program_id,
        solana_sdk_ids::ed25519_program::ID,
        EscrowError::NotEd25519Instruction
    );
    require!(
        instruction.accounts.is_empty(),
        EscrowError::VerdictInstructionHasAccounts
    );

    // Pin the total length first. Every slice below is inside these 290 bytes,
    // so nothing past this point can read out of bounds.
    let data = &instruction.data;
    require!(
        data.len() == ED25519_IX_DATA_LEN,
        EscrowError::BadVerdictDataLength
    );

    // One signature, and the padding byte the layout reserves.
    require!(data[0] == 1 && data[1] == 0, EscrowError::BadSignatureCount);

    let u16_at = |offset: usize| u16::from_le_bytes([data[offset], data[offset + 1]]);

    // The offsets header, field by field. Skipping this is the bug that gets
    // programs drained: the precompile happily verifies a signature over bytes
    // that live in another instruction, and a program reading fixed positions
    // never notices.
    require!(
        u16_at(2) == SIGNATURE_OFFSET && u16_at(6) == PUBKEY_OFFSET && u16_at(10) == MESSAGE_OFFSET,
        EscrowError::BadFieldOffsets
    );
    require!(
        u16_at(12) == MESSAGE_LEN as u16,
        EscrowError::BadMessageSize
    );
    require!(
        u16_at(4) == THIS_INSTRUCTION
            && u16_at(8) == THIS_INSTRUCTION
            && u16_at(14) == THIS_INSTRUCTION,
        EscrowError::OffsetsPointAtAnotherInstruction
    );

    let signed_key = &data[PUBKEY_OFFSET as usize..PUBKEY_OFFSET as usize + 32];
    require!(
        signed_key == expected_signer.as_ref(),
        EscrowError::WrongVerdictSigner
    );

    let signed_message = &data[MESSAGE_OFFSET as usize..MESSAGE_OFFSET as usize + MESSAGE_LEN];
    require!(
        signed_message == expected_message.as_slice(),
        EscrowError::VerdictMessageMismatch
    );

    Ok(())
}
