//! The three events, read back out of the logs the way an indexer reads them.
//!
//! `emit!` writes one `Program data:` line per event: eight bytes of
//! discriminator, then the struct's fields in Borsh order. The program's own
//! types are deliberately not used to parse that line. The discriminator is
//! derived from the documented rule, the payload is split field by field, and
//! the decode has to end exactly on the last byte — because the log line, not
//! the Rust struct, is what a monitor outside this repository parses. Reading
//! the line back through `EscrowSettled::try_from_slice` would agree with any
//! layout the program happened to emit, including a wrong one.
//!
//! Two things get pinned beyond the field values. The verdict byte carries the
//! protocol code, 1 and 2, and not the Borsh variant index, 0 and 1, that the
//! same enum has in the instruction data. And the amount is the whole vault,
//! donations included, which is the number that actually moved rather than the
//! amount the escrow recorded at creation.

use anchor_lang::prelude::Pubkey;
use anchor_lang::Discriminator;
use escrow_harness::*;
use litesvm::types::TransactionResult;
use solana_instruction::{AccountMeta, Instruction};
use solana_instruction_error::InstructionError;
use solana_keypair::Keypair;
use solana_transaction_error::TransactionError;
use verdict_escrow::errors::EscrowError;
use verdict_escrow::events::{EscrowCreated, EscrowReclaimed, EscrowSettled};
use verdict_escrow::verdict::Verdict;

/// What a stranger leaves in the vault. Small and odd, so no sum below could
/// come out right by accident.
const DONATION: u64 = 7;

/// `settle`'s instruction data: eight bytes of discriminator, the Borsh-encoded
/// verdict, and the i64 expiry.
const SETTLE_DATA_LEN: usize = 8 + 1 + 8;

/// Every event this program can emit, in a fixed order so a census of a
/// transaction's logs can be compared against one array.
const EVENT_NAMES: [&str; 3] = ["EscrowCreated", "EscrowSettled", "EscrowReclaimed"];

// --- decoding -------------------------------------------------------------

/// Standard base64, decoded by hand: the test crate has no base64 dependency
/// and this is the only place in the suite that needs one. Padding ends the
/// stream, and anything outside the alphabet is a malformed log line.
fn base64_decode(text: &str) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut bytes = Vec::with_capacity(text.len() / 4 * 3);
    let mut bits: u32 = 0;
    let mut held = 0u32;
    for character in text.bytes() {
        if character == b'=' {
            break;
        }
        let value = ALPHABET
            .iter()
            .position(|candidate| *candidate == character)
            .unwrap_or_else(|| panic!("{character:?} is not a base64 character"));
        bits = (bits << 6) | value as u32;
        held += 6;
        if held >= 8 {
            held -= 8;
            bytes.push((bits >> held) as u8);
        }
    }
    bytes
}

/// SHA-256, so the discriminators come from the documented rule rather than
/// from the program's own macro output. Two published vectors in
/// [`the_event_discriminators_are_the_documented_sha256_prefixes`] keep this
/// honest, the second long enough to need a second block.
fn sha256(input: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    // The 0x80 terminator, zeroes up to 56 bytes into the final block, then the
    // input length in bits.
    let mut padded = input.to_vec();
    let bit_length = (input.len() as u64) * 8;
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_length.to_be_bytes());

    for block in padded.chunks(64) {
        let mut schedule = [0u32; 64];
        for (index, word) in block.chunks(4).enumerate() {
            schedule[index] = u32::from_be_bytes(word.try_into().unwrap());
        }
        for index in 16..64 {
            let previous = schedule[index - 15];
            let recent = schedule[index - 2];
            let mix_low = previous.rotate_right(7) ^ previous.rotate_right(18) ^ (previous >> 3);
            let mix_high = recent.rotate_right(17) ^ recent.rotate_right(19) ^ (recent >> 10);
            schedule[index] = schedule[index - 16]
                .wrapping_add(mix_low)
                .wrapping_add(schedule[index - 7])
                .wrapping_add(mix_high);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let sigma_one = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ (!e & g);
            let temp_one = h
                .wrapping_add(sigma_one)
                .wrapping_add(choose)
                .wrapping_add(K[index])
                .wrapping_add(schedule[index]);
            let sigma_zero = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp_two = sigma_zero.wrapping_add(majority);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp_one);
            d = c;
            c = b;
            b = a;
            a = temp_one.wrapping_add(temp_two);
        }
        for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }

    let mut digest = [0u8; 32];
    for (index, word) in state.iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// An event's discriminator: the first eight bytes of
/// `sha256("event:" + struct name)`.
fn event_discriminator(name: &str) -> [u8; 8] {
    let mut tagged = b"event:".to_vec();
    tagged.extend_from_slice(name.as_bytes());
    sha256(&tagged)[..8].try_into().unwrap()
}

/// Every `Program data:` payload a transaction logged, base64-decoded. Logs
/// survive a failed transaction, so this reads either outcome.
fn program_data(result: &TransactionResult) -> Vec<Vec<u8>> {
    let logs = match result {
        Ok(meta) => &meta.logs,
        Err(failure) => &failure.meta.logs,
    };
    logs.iter()
        .filter_map(|line| line.strip_prefix("Program data: "))
        .map(base64_decode)
        .collect()
}

fn count_named(payloads: &[Vec<u8>], name: &str) -> usize {
    let discriminator = event_discriminator(name);
    payloads
        .iter()
        .filter(|payload| payload.starts_with(&discriminator))
        .count()
}

/// How many events of each kind a transaction logged, in [`EVENT_NAMES`] order.
fn event_counts(result: &TransactionResult) -> [usize; 3] {
    let payloads = program_data(result);
    EVENT_NAMES.map(|name| count_named(&payloads, name))
}

/// The one event of the named kind, with every other kind asserted absent: one
/// instruction emits one event and says nothing else.
#[track_caller]
fn sole_event(result: &TransactionResult, name: &'static str) -> EventFields {
    let payloads = program_data(result);
    let counts = EVENT_NAMES.map(|other| count_named(&payloads, other));
    let expected = EVENT_NAMES.map(|other| usize::from(other == name));
    assert_eq!(
        counts, expected,
        "expected exactly one {name} and no other event, but {EVENT_NAMES:?} were logged {counts:?} times"
    );

    let discriminator = event_discriminator(name);
    let payload = payloads
        .into_iter()
        .find(|payload| payload.starts_with(&discriminator))
        .expect("the census above found one");
    EventFields {
        name,
        bytes: payload[discriminator.len()..].to_vec(),
        read: 0,
    }
}

/// One event's payload, past its discriminator, read field by field in
/// declaration order. Running off the end and leaving bytes behind both fail,
/// so a field added, removed, retyped or reordered shows up here instead of
/// quietly changing what an indexer sees.
struct EventFields {
    name: &'static str,
    bytes: Vec<u8>,
    read: usize,
}

impl EventFields {
    #[track_caller]
    fn take(&mut self, length: usize) -> &[u8] {
        let end = self.read + length;
        assert!(
            end <= self.bytes.len(),
            "{} is {} bytes, too short for a {length}-byte field at offset {}",
            self.name,
            self.bytes.len(),
            self.read
        );
        let field = &self.bytes[self.read..end];
        self.read = end;
        field
    }

    #[track_caller]
    fn pubkey(&mut self) -> Pubkey {
        Pubkey::new_from_array(self.take(32).try_into().unwrap())
    }

    #[track_caller]
    fn u8(&mut self) -> u8 {
        self.take(1)[0]
    }

    #[track_caller]
    fn u64(&mut self) -> u64 {
        u64::from_le_bytes(self.take(8).try_into().unwrap())
    }

    #[track_caller]
    fn i64(&mut self) -> i64 {
        i64::from_le_bytes(self.take(8).try_into().unwrap())
    }

    #[track_caller]
    fn end(self) {
        assert_eq!(
            self.read,
            self.bytes.len(),
            "{} carries {} bytes past the fields this test knows about",
            self.name,
            self.bytes.len() - self.read
        );
    }
}

/// `EscrowCreated`, in wire order. Rust evaluates a struct literal's fields in
/// the order they are written, so the initialiser below *is* the layout.
struct Created {
    escrow: Pubkey,
    buyer: Pubkey,
    seller: Pubkey,
    mint: Pubkey,
    verdict_signer: Pubkey,
    amount: u64,
    deadline: i64,
    created_slot: u64,
    escrow_id: u64,
}

#[track_caller]
fn created_event(result: &TransactionResult) -> Created {
    let mut fields = sole_event(result, "EscrowCreated");
    let created = Created {
        escrow: fields.pubkey(),
        buyer: fields.pubkey(),
        seller: fields.pubkey(),
        mint: fields.pubkey(),
        verdict_signer: fields.pubkey(),
        amount: fields.u64(),
        deadline: fields.i64(),
        created_slot: fields.u64(),
        escrow_id: fields.u64(),
    };
    fields.end();
    created
}

/// `EscrowSettled`, in wire order. `verdict_signer` sits between `mint` and
/// `verdict`; reading it anywhere else shifts every field after it.
struct Settled {
    escrow: Pubkey,
    buyer: Pubkey,
    seller: Pubkey,
    mint: Pubkey,
    verdict_signer: Pubkey,
    verdict: u8,
    destination: Pubkey,
    amount: u64,
}

#[track_caller]
fn settled_event(result: &TransactionResult) -> Settled {
    let mut fields = sole_event(result, "EscrowSettled");
    let settled = Settled {
        escrow: fields.pubkey(),
        buyer: fields.pubkey(),
        seller: fields.pubkey(),
        mint: fields.pubkey(),
        verdict_signer: fields.pubkey(),
        verdict: fields.u8(),
        destination: fields.pubkey(),
        amount: fields.u64(),
    };
    fields.end();
    settled
}

/// `EscrowReclaimed`, in wire order. It names no seller and no destination:
/// reclaim can only ever pay the buyer.
struct Reclaimed {
    escrow: Pubkey,
    buyer: Pubkey,
    mint: Pubkey,
    amount: u64,
}

#[track_caller]
fn reclaimed_event(result: &TransactionResult) -> Reclaimed {
    let mut fields = sole_event(result, "EscrowReclaimed");
    let reclaimed = Reclaimed {
        escrow: fields.pubkey(),
        buyer: fields.pubkey(),
        mint: fields.pubkey(),
        amount: fields.u64(),
    };
    fields.end();
    reclaimed
}

/// Send tokens to an account whose owner never asked for them. Anyone may do
/// this to a vault, and both payout paths have to carry the donation out.
fn donate(h: &mut Harness, token_account: &Pubkey, amount: u64) {
    let payer = h.buyer.insecure_clone();
    let mint = h.mint;
    let token_program = h.token_program;
    litesvm_token::MintTo::new(&mut h.svm, &payer, &mint, token_account, amount)
        .token_program_id(&token_program)
        .send()
        .expect("donate to the token account");
}

// --- the discriminator rule -----------------------------------------------

/// The rule an indexer applies to tell one event from another, checked against
/// two published SHA-256 vectors and against the constants Anchor baked into
/// the program. Both directions matter: if the macro ever stopped using this
/// rule, every monitor built on the documented one would go deaf.
#[test]
fn the_event_discriminators_are_the_documented_sha256_prefixes() {
    assert_eq!(
        hex(&sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    // 56 bytes, so the padding spills into a second block.
    assert_eq!(
        hex(&sha256(
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        )),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );

    assert_eq!(
        EscrowCreated::DISCRIMINATOR,
        &event_discriminator("EscrowCreated")[..]
    );
    assert_eq!(
        EscrowSettled::DISCRIMINATOR,
        &event_discriminator("EscrowSettled")[..]
    );
    assert_eq!(
        EscrowReclaimed::DISCRIMINATOR,
        &event_discriminator("EscrowReclaimed")[..]
    );
}

// --- the events -----------------------------------------------------------

/// The created event is the only record an indexer gets of the terms, so every
/// field has to agree with the account the program went on to write.
///
/// A stranger's donation is already in the vault when the escrow opens, which
/// separates the two numbers that are easy to confuse: the event reports what
/// the buyer deposited, not what the vault holds.
#[test]
fn create_escrow_emits_one_created_event_matching_the_stored_escrow() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let buyer = h.buyer.pubkey();
        let buyer_ata = h.ata(&buyer);

        // A stranger opens the vault and funds it before the escrow exists.
        let vault = h.create_ata(&h.escrow_pda(&buyer, 7));
        donate(&mut h, &vault, DONATION);
        let buyer_before = h.token_balance(&buyer_ata);

        let slot_at_creation = h.clock().slot;
        let deadline = h.now() + HOUR;
        let (escrow, result) = h.create_escrow_with(7, ESCROW_AMOUNT, deadline);
        assert_ok(&result);

        let deposited = buyer_before - h.token_balance(&buyer_ata);
        assert_eq!(deposited, ESCROW_AMOUNT);
        assert_eq!(h.token_balance(&vault), ESCROW_AMOUNT + DONATION);

        let state = h.escrow_state(&escrow);
        let created = created_event(&result);
        assert_eq!(created.escrow, escrow, "escrow");
        assert_eq!(created.buyer, state.buyer, "buyer");
        assert_eq!(created.seller, state.seller, "seller");
        assert_eq!(created.mint, state.mint, "mint");
        assert_eq!(
            created.verdict_signer, state.verdict_signer,
            "verdict_signer"
        );
        assert_eq!(created.amount, state.amount, "amount");
        assert_eq!(created.deadline, state.deadline, "deadline");
        assert_eq!(created.created_slot, state.created_slot, "created_slot");
        assert_eq!(created.escrow_id, state.escrow_id, "escrow_id");

        // The same fields against something outside the program, so a state
        // and an event that are wrong together cannot both pass.
        assert_eq!(created.buyer, buyer);
        assert_eq!(created.seller, h.seller.pubkey());
        assert_eq!(created.mint, h.mint);
        assert_eq!(created.verdict_signer, h.verdict_signer.pubkey());
        assert_eq!(created.amount, deposited);
        assert_eq!(created.deadline, deadline);
        assert_eq!(created.created_slot, slot_at_creation);
        assert_eq!(created.escrow_id, 7);
        assert_ne!(
            created.amount,
            h.token_balance(&vault),
            "the deposit, not the vault balance"
        );
    });
}

/// A release pays the seller's associated token account, and the event has to
/// name that account and the amount that really left the vault — the donation
/// included, because the payout carries it.
#[test]
fn a_release_settle_emits_one_settled_event_naming_the_sellers_account() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let vault = ata_for(&escrow, &h.mint, &h.token_program);
        donate(&mut h, &vault, DONATION);

        // Read the state before settling: the instruction closes the account.
        let state = h.escrow_state(&escrow);
        let seller_ata = h.ata(&h.seller.pubkey());
        let buyer_ata = h.ata(&h.buyer.pubkey());
        let seller_before = h.token_balance(&seller_ata);
        let buyer_before = h.token_balance(&buyer_ata);
        let vault_before = h.token_balance(&vault);
        assert_eq!(vault_before, ESCROW_AMOUNT + DONATION);

        let expires_at = h.now() + 600;
        let result = h.settle(escrow, Verdict::Release, expires_at);
        assert_ok(&result);

        let moved = h.token_balance(&seller_ata) - seller_before;
        assert_eq!(moved, vault_before, "the whole vault went to the seller");
        assert_eq!(
            h.token_balance(&buyer_ata),
            buyer_before,
            "the buyer got none of it"
        );

        let settled = settled_event(&result);
        assert_eq!(settled.escrow, escrow, "escrow");
        assert_eq!(settled.buyer, state.buyer, "buyer");
        assert_eq!(settled.seller, state.seller, "seller");
        assert_eq!(settled.mint, state.mint, "mint");
        assert_eq!(
            settled.verdict_signer, state.verdict_signer,
            "verdict_signer"
        );
        assert_eq!(settled.verdict, 1, "1 is release");
        assert_eq!(settled.destination, seller_ata, "destination");
        assert_eq!(settled.amount, moved, "amount");
        assert_eq!(
            settled.amount,
            state.amount + DONATION,
            "the donation rides along, so the event is above the recorded amount"
        );
    });
}

/// A refund pays the buyer's own associated token account. The seller is still
/// named in the event — the deal was with them — but is not the destination.
#[test]
fn a_refund_settle_emits_one_settled_event_naming_the_buyers_account() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let vault = ata_for(&escrow, &h.mint, &h.token_program);
        donate(&mut h, &vault, DONATION);

        let state = h.escrow_state(&escrow);
        let seller_ata = h.ata(&h.seller.pubkey());
        let buyer_ata = h.ata(&h.buyer.pubkey());
        let seller_before = h.token_balance(&seller_ata);
        let buyer_before = h.token_balance(&buyer_ata);
        let vault_before = h.token_balance(&vault);

        let expires_at = h.now() + 600;
        let result = h.settle(escrow, Verdict::Refund, expires_at);
        assert_ok(&result);

        let moved = h.token_balance(&buyer_ata) - buyer_before;
        assert_eq!(moved, vault_before, "the whole vault came back");
        assert_eq!(
            h.token_balance(&seller_ata),
            seller_before,
            "the seller got none of it"
        );

        let settled = settled_event(&result);
        assert_eq!(settled.escrow, escrow, "escrow");
        assert_eq!(settled.buyer, state.buyer, "buyer");
        assert_eq!(settled.seller, state.seller, "seller");
        assert_eq!(settled.mint, state.mint, "mint");
        assert_eq!(
            settled.verdict_signer, state.verdict_signer,
            "verdict_signer"
        );
        assert_eq!(settled.verdict, 2, "2 is refund");
        assert_eq!(settled.destination, buyer_ata, "destination");
        assert_ne!(
            settled.destination, seller_ata,
            "a refund must not name the seller's account"
        );
        assert_eq!(settled.amount, moved, "amount");
        assert_eq!(settled.amount, state.amount + DONATION);
    });
}

/// Reclaim pays the buyer and says so in four fields. It has no verdict and no
/// destination, and like settle it hands over the donation too.
#[test]
fn reclaim_emits_one_reclaimed_event_for_the_whole_vault() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let vault = ata_for(&escrow, &h.mint, &h.token_program);
        donate(&mut h, &vault, DONATION);

        let state = h.escrow_state(&escrow);
        let buyer_ata = h.ata(&h.buyer.pubkey());
        let seller_ata = h.ata(&h.seller.pubkey());
        let buyer_before = h.token_balance(&buyer_ata);
        let vault_before = h.token_balance(&vault);

        h.set_time(state.deadline);
        let result = h.reclaim(escrow);
        assert_ok(&result);

        let moved = h.token_balance(&buyer_ata) - buyer_before;
        assert_eq!(moved, vault_before, "the whole vault came back");
        assert_eq!(h.token_balance(&seller_ata), 0, "the seller got none of it");

        let reclaimed = reclaimed_event(&result);
        assert_eq!(reclaimed.escrow, escrow, "escrow");
        assert_eq!(reclaimed.buyer, state.buyer, "buyer");
        assert_eq!(reclaimed.mint, state.mint, "mint");
        assert_eq!(reclaimed.amount, moved, "amount");

        assert_eq!(reclaimed.buyer, h.buyer.pubkey());
        assert_eq!(reclaimed.mint, h.mint);
        assert_eq!(reclaimed.amount, state.amount + DONATION);
    });
}

/// The trap `verdict.rs` warns about, pinned from both ends at once.
///
/// `Verdict` has two encodings that are deliberately not the same number.
/// Borsh puts the variant index in the instruction data: 0 for a release, 1 for
/// a refund. The protocol's own code, in the signed message and in the event,
/// is 1 and 2. Simplifying the event to a cast of the Borsh index would publish
/// 0 for a release — which no indexer has a meaning for — and 1 for a refund,
/// which every indexer reads as a release. The money would be in the right
/// place and the record of it would name the wrong party.
#[test]
fn the_settled_event_carries_the_protocol_code_not_the_borsh_variant_index() {
    for_each_token_program(|kind| {
        for (verdict, borsh_index, protocol_code) in
            [(Verdict::Release, 0u8, 1u8), (Verdict::Refund, 1u8, 2u8)]
        {
            assert_ne!(
                borsh_index, protocol_code,
                "a test where the two encodings agree would prove nothing"
            );

            let mut h = Harness::new(kind);
            let (escrow, result) = h.create_escrow(1);
            assert_ok(&result);

            let expires_at = h.now() + 600;
            let accounts = h.settle_accounts(escrow);

            // The instruction data really does carry the Borsh index, so the
            // event's code cannot have been copied from it.
            let data = accounts.instruction(verdict, expires_at).data;
            assert_eq!(data.len(), SETTLE_DATA_LEN);
            assert_eq!(
                data[8], borsh_index,
                "the instruction data carries the Borsh variant index"
            );

            let result = h.settle(escrow, verdict, expires_at);
            assert_ok(&result);
            assert_eq!(
                settled_event(&result).verdict,
                protocol_code,
                "the event carries the protocol code"
            );
        }
    });
}

/// A settle the program refuses must not have announced a payout first. The
/// verdict here is well formed and covers exactly the right 178 bytes, but a
/// stranger signed it, so `verify_verdict` throws it out. An indexer that saw a
/// settled event in these logs would record a payment that never happened.
#[test]
fn a_refused_settle_emits_no_event() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let vault = ata_for(&escrow, &h.mint, &h.token_program);

        let expires_at = h.now() + 600;
        let stranger = Keypair::new();
        let message = h.verdict_message(escrow, Verdict::Release, expires_at);
        let verdict_ix = Ed25519Ix::sign(&stranger, &message);
        let accounts = h.settle_accounts(escrow);
        let result = h.send_settle(&accounts, &verdict_ix, Verdict::Release, expires_at);

        assert_error(&result, EscrowError::WrongVerdictSigner);
        assert_eq!(
            event_counts(&result),
            [0, 0, 0],
            "a refused settle logged an event"
        );
        assert_eq!(h.token_balance(&vault), ESCROW_AMOUNT);
        assert_eq!(h.token_balance(&h.ata(&h.seller.pubkey())), 0);
    });
}

/// The one case where a settled event is not a payout, and the reason a monitor
/// cannot read log lines alone.
///
/// `settle` succeeds and emits, and a later instruction in the same transaction
/// overdraws the relayer. The transaction rolls back: no tokens moved and the
/// escrow is still open. The logs, though, keep the settled line, complete and
/// correct-looking, because logs are not rolled back. Anything built on these
/// events has to join them to the transaction's status.
#[test]
fn a_settled_event_survives_in_the_logs_of_a_rolled_back_transaction() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);
        let (escrow, result) = h.create_escrow(1);
        assert_ok(&result);
        let vault = ata_for(&escrow, &h.mint, &h.token_program);
        let seller_ata = h.ata(&h.seller.pubkey());

        let expires_at = h.now() + 600;
        let verdict_ix = h.verdict_ix(escrow, Verdict::Release, expires_at);
        let accounts = h.settle_accounts(escrow);
        let settle_ix = accounts.instruction(Verdict::Release, expires_at);

        // SystemInstruction::Transfer of more lamports than the relayer holds.
        let relayer = h.relayer.insecure_clone();
        let mut transfer_data = Vec::new();
        transfer_data.extend_from_slice(&2u32.to_le_bytes());
        transfer_data.extend_from_slice(&(h.lamports(&relayer.pubkey()) + 1).to_le_bytes());
        let overdraft = Instruction {
            program_id: SYSTEM_PROGRAM_ID,
            accounts: vec![
                AccountMeta::new(relayer.pubkey(), true),
                AccountMeta::new(h.seller.pubkey(), false),
            ],
            data: transfer_data,
        };

        let result = h.send(
            &[verdict_ix.instruction(), settle_ix, overdraft],
            &[&relayer],
        );
        // Custom(1) at index 2 is the system program's
        // `SystemError::ResultWithNegativeLamports`, so the transfer is what
        // failed and `settle`, at index 1, had already run.
        assert_eq!(
            result.as_ref().err().map(|failure| failure.err.clone()),
            Some(TransactionError::InstructionError(
                2,
                InstructionError::Custom(1)
            )),
            "the third instruction must be what failed"
        );

        // Nothing moved and nothing closed.
        assert_eq!(h.token_balance(&vault), ESCROW_AMOUNT);
        assert_eq!(h.token_balance(&seller_ata), 0);
        assert!(h.account_exists(&escrow));
        assert_eq!(h.escrow_state(&escrow).amount, ESCROW_AMOUNT);

        // And yet the event is in the logs, naming a payout that was undone.
        assert_eq!(event_counts(&result), [0, 1, 0]);
        let settled = settled_event(&result);
        assert_eq!(settled.escrow, escrow);
        assert_eq!(settled.verdict, 1);
        assert_eq!(settled.destination, seller_ata);
        assert_eq!(settled.amount, ESCROW_AMOUNT);
    });
}
