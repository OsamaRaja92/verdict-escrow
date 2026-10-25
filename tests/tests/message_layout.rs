//! The 178 bytes themselves.
//!
//! Everything else in the suite trusts `build_message`. These two tests are
//! what that trust rests on: one rebuilds the message independently, field by
//! field, and one pins the whole thing — key, bytes and signature — to a fixed
//! vector that any other implementation can be checked against.

use anchor_lang::prelude::Pubkey;
use escrow_harness::*;
use solana_keypair::Keypair;
use verdict_escrow::state::Escrow;
use verdict_escrow::verdict::{build_message, Verdict, DOMAIN_TAG, MESSAGE_LEN};

/// Fixed inputs for the vector below. A reader can follow each one into the
/// hex and find it.
const SEED: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];
const ESCROW: Pubkey = Pubkey::from_str_const("5h5xW5GTjLPcYZQnMxLjEHbBqN5YXGMeKHULPeKbVHP3");
/// USDC on Solana mainnet, used here only as a recognisable 32-byte value.
const MINT: Pubkey = Pubkey::from_str_const("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
const BUYER: Pubkey = Pubkey::from_str_const("4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7D4xWLs4gDB4T");
const SELLER: Pubkey = Pubkey::from_str_const("8pM1DN3RiT8vbom5u1sNryaNT1nyL8CTTW3b5PwWXYBK");
const CREATED_SLOT: u64 = 123_456;
const AMOUNT: u64 = 250_000_000;
const DEADLINE: i64 = 1_900_000_000;
const EXPIRES_AT: i64 = 1_800_000_000;

const EXPECTED_MESSAGE_HEX: &str =
    "766572646963742d657363726f773a7631bcae5684fbbaee1436d75c406603580c154838c857a48465cba6309f8489394d45b395ba4c5b044bcd48ae206dcd7d80c6c3f11cd941649a21d68c891642943e40e2010000000000c6fa7af3bedbad3a3d65f36aabc97431b1bbe4c2d2f6e0e47ca60203452f5d6180b2e60e000000007422b9887598068e32c4448a949adb290d0f4e35b9e01b0ee5f1a1e600fe827200b33f71000000000100d2496b00000000";
const EXPECTED_SIGNATURE_HEX: &str =
    "729c3a6181920d6f5d2a21faa40b807a5b1e68ad9e7a3266227fcbe49be6d423cfdfbc3df84dc6e8595b63a7ac7b494f86ce1ee36cc6c219bc9866549fbb7c06";
const EXPECTED_SIGNER: &str = "9C6hybhQ6Aycep9jaUnP6uL9ZYvDjUp1aSkFWPUFJtpj";

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The escrow the vector is built from. Every field is a value a reader can
/// find in the hex.
fn fixture(verdict_signer: Pubkey) -> Escrow {
    Escrow {
        buyer: BUYER,
        seller: SELLER,
        mint: MINT,
        verdict_signer,
        amount: AMOUNT,
        deadline: DEADLINE,
        created_slot: CREATED_SLOT,
        escrow_id: 42,
        bump: 254,
    }
}

#[test]
fn the_message_is_what_the_table_says_it_is() {
    let escrow_state = fixture(Pubkey::new_from_array([0xcc; 32]));

    let built = build_message(
        &verdict_escrow::ID,
        &ESCROW,
        &escrow_state,
        Verdict::Release,
        EXPIRES_AT,
    );

    // The same 178 bytes, assembled here without touching the program's code.
    let mut expected = Vec::with_capacity(MESSAGE_LEN);
    expected.extend_from_slice(b"verdict-escrow:v1");
    expected.extend_from_slice(&verdict_escrow::ID.to_bytes());
    expected.extend_from_slice(&ESCROW.to_bytes());
    expected.extend_from_slice(&CREATED_SLOT.to_le_bytes());
    expected.extend_from_slice(&MINT.to_bytes());
    expected.extend_from_slice(&AMOUNT.to_le_bytes());
    expected.extend_from_slice(&SELLER.to_bytes());
    expected.extend_from_slice(&DEADLINE.to_le_bytes());
    expected.push(1); // release
    expected.extend_from_slice(&EXPIRES_AT.to_le_bytes());

    assert_eq!(expected.len(), 178);
    assert_eq!(built.as_slice(), expected.as_slice());

    // And the fields sit where the table in the README says they do.
    assert_eq!(&built[0..17], DOMAIN_TAG.as_slice());
    assert_eq!(&built[17..49], verdict_escrow::ID.as_ref());
    assert_eq!(&built[49..81], ESCROW.as_ref());
    assert_eq!(&built[81..89], &CREATED_SLOT.to_le_bytes());
    assert_eq!(&built[89..121], MINT.as_ref());
    assert_eq!(&built[121..129], &AMOUNT.to_le_bytes());
    assert_eq!(&built[129..161], SELLER.as_ref());
    assert_eq!(&built[161..169], &DEADLINE.to_le_bytes());
    assert_eq!(built[169], 1);
    assert_eq!(&built[170..178], &EXPIRES_AT.to_le_bytes());

    // Only the verdict byte changes between a release and a refund.
    let refund = build_message(
        &verdict_escrow::ID,
        &ESCROW,
        &escrow_state,
        Verdict::Refund,
        EXPIRES_AT,
    );
    assert_eq!(refund[169], 2);
    assert_eq!(&refund[..169], &built[..169]);
    assert_eq!(&refund[170..], &built[170..]);
}

/// Every field the signature covers has to change the signature. A field that
/// is in the message but does not move the bytes would be decoration.
#[test]
fn every_field_changes_the_message() {
    let signer = Pubkey::new_from_array([0xcc; 32]);
    let base = build_message(
        &verdict_escrow::ID,
        &ESCROW,
        &fixture(signer),
        Verdict::Release,
        EXPIRES_AT,
    );

    let mut other_seller = fixture(signer);
    other_seller.seller = Pubkey::new_from_array([0xdd; 32]);
    let mut other_deadline = fixture(signer);
    other_deadline.deadline = DEADLINE + 1;
    let mut other_slot = fixture(signer);
    other_slot.created_slot = CREATED_SLOT + 1;
    let mut other_amount = fixture(signer);
    other_amount.amount = AMOUNT + 1;
    let mut other_mint = fixture(signer);
    other_mint.mint = Pubkey::new_from_array([0xee; 32]);

    for (name, state) in [
        ("seller", other_seller),
        ("deadline", other_deadline),
        ("created_slot", other_slot),
        ("amount", other_amount),
        ("mint", other_mint),
    ] {
        let changed = build_message(
            &verdict_escrow::ID,
            &ESCROW,
            &state,
            Verdict::Release,
            EXPIRES_AT,
        );
        assert_ne!(changed, base, "{name} does not change the signed message");
    }

    // And the three arguments that are not escrow state.
    assert_ne!(
        build_message(
            &verdict_escrow::ID,
            &ESCROW,
            &fixture(signer),
            Verdict::Release,
            EXPIRES_AT + 1
        ),
        base
    );
    assert_ne!(
        build_message(
            &verdict_escrow::ID,
            &Pubkey::new_from_array([0x11; 32]),
            &fixture(signer),
            Verdict::Release,
            EXPIRES_AT
        ),
        base
    );
    assert_ne!(
        build_message(
            &Pubkey::new_from_array([0x22; 32]),
            &ESCROW,
            &fixture(signer),
            Verdict::Release,
            EXPIRES_AT
        ),
        base
    );
}

/// The vector published in the README. Ed25519 signatures are deterministic,
/// so these bytes are fixed: another implementation that produces different
/// ones has a bug.
#[test]
fn the_published_test_vector_still_holds() {
    let signer = Keypair::new_from_array(SEED);
    let message = build_message(
        &verdict_escrow::ID,
        &ESCROW,
        &fixture(signer.pubkey()),
        Verdict::Release,
        EXPIRES_AT,
    );
    let signature = signer.sign_message(&message);

    assert_eq!(signer.pubkey().to_string(), EXPECTED_SIGNER);
    assert_eq!(to_hex(&message), EXPECTED_MESSAGE_HEX);
    assert_eq!(to_hex(signature.as_ref()), EXPECTED_SIGNATURE_HEX);
}
