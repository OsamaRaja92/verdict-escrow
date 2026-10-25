# verdict-escrow

A Solana program that holds tokens until someone with the right key says where
they go.

A buyer locks tokens in a vault the program owns. The money moves only when an
outside signer's signed verdict says to release it to the seller or refund it
to the buyer. If no verdict arrives before the deadline, the buyer takes it
back. That is the whole lifecycle: `create_escrow`, then exactly one of
`settle` or `reclaim`.

The interesting part is not moving the tokens. It is proving that nobody can
fake the instruction that moves them. The verdict is checked against an Ed25519
signature over 178 fixed bytes that the program rebuilds from its own state,
and most of this repository is the set of attacks that check has to survive.

- **Program:** [`programs/verdict-escrow`](programs/verdict-escrow/src) — three
  instructions, 737 lines of which 171 are comment.
- **Tests:** [`tests/tests`](tests/tests) — 219 tests in 21 files, 195 of them
  run twice, once per token program. Most of them are attacks.
- **CLI:** [`tools/verdict-cli`](tools/verdict-cli/src) — open, sign and settle
  an escrow by hand.

---

## The signed verdict

The verdict signer never sends a transaction. It signs 178 bytes offline and
hands them to anyone — the seller, the buyer, a relayer — who carries them to
the chain and pays the fee. The program's authority check is the signature, not
the sender.

Those bytes are:

| Offset | Bytes | Field | Why it is in the message |
|-------:|------:|-------|--------------------------|
| 0 | 17 | `verdict-escrow:v1` | The signature cannot be valid for any other purpose |
| 17 | 32 | Program id | A verdict for one deployment cannot be used on another |
| 49 | 32 | Escrow address | Pins the exact escrow — and with it the buyer, since the address is a PDA of `["escrow", buyer, escrow_id]` |
| 81 | 8 | `created_slot`, u64 LE | A verdict cannot be replayed on a new escrow created later at the same address |
| 89 | 32 | Mint | Pins the token |
| 121 | 8 | Amount, u64 LE | Pins what the buyer escrowed |
| 129 | 32 | Seller | Pins who a release pays. The escrow address does not: see the limits below |
| 161 | 8 | `deadline`, i64 LE | Pins the window the verdict was issued for |
| 169 | 1 | Verdict: 1 release, 2 refund | Which way the money goes |
| 170 | 8 | `expires_at`, i64 LE | An unused verdict stops working after this time |

Solana verifies the signature in a precompiled instruction that must sit
immediately before `settle` in the same transaction. By the time program code
runs, the runtime has already checked that *some* key signed *some* bytes. What
is left to the program is the part the runtime cannot know: **which** key
signed **which** bytes. [`verdict.rs`](programs/verdict-escrow/src/verdict.rs)
does that in five steps:

1. Load the instruction at `current_index - 1` through the instructions sysvar.
   Never scan the transaction for the first Ed25519 instruction — that would
   let an attacker append a real signature after a fake one.
2. Require the Ed25519 program id, no accounts, and data of exactly 290 bytes.
3. Check **every field** of the offsets header against the one layout the
   client builds: key at 16, signature at 48, message at 112, message size 178,
   and all three instruction-index fields set to `0xFFFF`, meaning "this
   instruction".
4. Require the key in that data to equal the escrow's stored `verdict_signer`,
   and the message to equal the 178 bytes rebuilt from escrow state.
5. Require the current time to be at or before `expires_at`.

**Step 3 is the one that gets skipped.** Those index fields can point at a
different instruction in the same transaction, so the precompile can verify a
signature over bytes that live somewhere else entirely, while the program reads
a forgery from the fixed offset and never notices. Asymmetric Research found
exactly this in a Relay contract. The attack is reproduced in
[`instruction_layout.rs`](tests/tests/instruction_layout.rs):
`offsets_pointing_at_another_instruction_are_refused` builds a transaction
where a genuine refund verdict is signed in one instruction and a forged
release sits at byte 112 of the next one.

### Test vector

Ed25519 signatures are deterministic, so these bytes are fixed. Another
implementation that produces different ones has a bug. Checked on every run by
`the_published_test_vector_still_holds` in
[`message_layout.rs`](tests/tests/message_layout.rs).

```
signer seed    0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
signer pubkey  9C6hybhQ6Aycep9jaUnP6uL9ZYvDjUp1aSkFWPUFJtpj

program id     DhXqHjZuT3ZJoUXzj3XmeBUMmLAwiHV4VKPZcvntTfba
escrow         5h5xW5GTjLPcYZQnMxLjEHbBqN5YXGMeKHULPeKbVHP3
created_slot   123456
mint           EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v
amount         250000000
seller         8pM1DN3RiT8vbom5u1sNryaNT1nyL8CTTW3b5PwWXYBK
deadline       1900000000
verdict        1 (release)
expires_at     1800000000

message (178 bytes)
766572646963742d657363726f773a7631bcae5684fbbaee1436d75c40660358
0c154838c857a48465cba6309f8489394d45b395ba4c5b044bcd48ae206dcd7d
80c6c3f11cd941649a21d68c891642943e40e2010000000000c6fa7af3bedbad
3a3d65f36aabc97431b1bbe4c2d2f6e0e47ca60203452f5d6180b2e60e000000
007422b9887598068e32c4448a949adb290d0f4e35b9e01b0ee5f1a1e600fe82
7200b33f71000000000100d2496b00000000

signature (64 bytes)
729c3a6181920d6f5d2a21faa40b807a5b1e68ad9e7a3266227fcbe49be6d423
cfdfbc3df84dc6e8595b63a7ac7b494f86ce1ee36cc6c219bc9866549fbb7c06
```

---

## The three instructions

### `create_escrow(escrow_id, amount, deadline, seller, verdict_signer)`

The buyer signs. Creates the escrow account — a PDA of
`["escrow", buyer, escrow_id]` — and a vault that is the escrow's associated
token account for the mint, then moves `amount` in with `transfer_checked`.
Stores buyer, seller, mint, amount, verdict signer, deadline, the current slot
and the bump. Rejects a zero amount, a deadline that is not in the future, and
any mint carrying extensions.

### `settle(verdict, expires_at)`

Anyone can send it. Works only before the deadline, and only with a valid
verdict in the same transaction. Release pays the whole vault to the seller's
associated token account, refund pays it to the buyer's. **The destination
comes from the verdict and from stored state; no argument names a destination
or an amount.** Closes the vault and the escrow, with the rent going back to the
buyer.

### `reclaim()`

The buyer signs. Works only at or after the deadline. Returns the whole vault
to the buyer and closes both accounts.

The deadline splits the timeline cleanly, which is what keeps the two exits
from racing: before it, only a verdict can move the money; at or after it, only
the buyer.

---

## Threat model

| Attack | What stops it |
|--------|---------------|
| A verdict signed by some other key | The key in the Ed25519 instruction must equal the escrow's stored `verdict_signer` |
| A tampered message — a different amount, a different payee | The program rebuilds all 178 bytes from its own state and compares; one byte off is refused |
| A verdict for escrow A replayed against escrow B | The escrow's address is inside the signed bytes |
| A verdict for this escrow replayed after it was settled and re-created | `created_slot` is inside the signed bytes, and so are the seller and the deadline, so a rebuilt escrow that an old verdict still fits is one that pays the same seller the same amount by the same deadline |
| An old verdict kept around for later | `expires_at` is inside the signed bytes and is checked against the clock |
| A valid signature over bytes that live in another instruction | Every offsets-header field is checked, including the three instruction-index fields |
| A real verdict appended after a fake one | The program reads the instruction at `current_index - 1` and nowhere else |
| An Ed25519 instruction with two signatures, or an unexpected field order | The data length, the signature count and each offset are pinned to one layout |
| A substituted instructions sysvar | That account is constrained to the sysvar's address |
| Paying a destination the buyer or seller does not own | Both payout accounts must be the stored wallets' associated token accounts for the stored mint |
| Draining a different escrow's vault | The vault must be this escrow's associated token account |
| Settling twice | Both exits close the escrow and the vault; there is nothing left to read |
| `reclaim` by someone other than the buyer | The buyer must sign, and must be the key the escrow stored |
| A mint whose extensions change what a transfer does | Any mint longer than the bare 82 bytes is refused |
| A mint that takes a cut on transfer | After the deposit the vault is reloaded and must have gained exactly the escrowed amount |
| Blocking an escrow by creating its vault first | The vault is `init_if_needed`, and the deposit check is on the balance it gained, so a vault a stranger made or funded in advance changes nothing. A mint's freeze authority is a different matter — see the limits |

Each row has at least one test. The suite is grouped by what is under attack:

| | |
|---|---|
| [forged_verdicts](tests/tests/forged_verdicts.rs) | signatures by the wrong key, messages tampered field by field, and a sweep that flips every one of the 290 bytes |
| [instruction_layout](tests/tests/instruction_layout.rs) | the Ed25519 instruction's position, length and header, and the instruction data of `settle` itself |
| [ed25519_edges](tests/tests/ed25519_edges.rs) | the precompile's own corners: zero signatures, non-canonical `S`, small-order keys, offsets that overflow, and each instruction-index field bent on its own |
| [forged_escrow_accounts](tests/tests/forged_escrow_accounts.rs) | accounts planted with the wrong owner, the wrong discriminator, or at the wrong address |
| [signer_checks](tests/tests/signer_checks.rs) | who must sign each instruction, and a guard on the account metas themselves |
| [program_substitution](tests/tests/program_substitution.rs) | an attacker's program id in every program slot |
| [vault_substitution](tests/tests/vault_substitution.rs) | token accounts that pass the owner check but are not the derived address |
| [duplicate_and_extra_accounts](tests/tests/duplicate_and_extra_accounts.rs) | the same account twice, extra accounts, reordered accounts |
| [close_and_revival](tests/tests/close_and_revival.rs) | lamports parked at a dead address, and acting on a closed escrow |
| [mint_authority_attacks](tests/tests/mint_authority_attacks.rs) | what a freeze authority or a mint authority can do to a live escrow |
| [payout_availability](tests/tests/payout_availability.rs) | a payee who closes or re-owns the account they are owed into |
| [numeric_edges](tests/tests/numeric_edges.rs) | `u64::MAX`, the smallest escrow, and the deposit overflow guard |
| [replay](tests/tests/replay.rs) | settling twice, a verdict after an exit, and two live verdicts at once |
| [destinations](tests/tests/destinations.rs) · [time_and_caller](tests/tests/time_and_caller.rs) · [creation](tests/tests/creation.rs) | where the money may go, the deadline boundaries, and what will not open |
| [events](tests/tests/events.rs) · [error_codes](tests/tests/error_codes.rs) | the two published interfaces that are not the instructions: the emitted events and the numeric error codes |

### The test that holds up the rest

Most of the forged-verdict tests hand the runtime a *valid* signature and rely
on the program to reject the contents. If the test environment did not verify
signatures at all, every one of them would still pass and none would prove
anything. So one test corrupts a signature byte and asserts that the
transaction dies at the Ed25519 instruction, with no program logs at all:
`a_corrupted_signature_never_reaches_the_program`. If that test ever passes a
corrupted signature through to program code, the rest of the suite is worthless
and this one says so.

### What the tests are worth, measured

A passing test proves nothing on its own. The question is whether it would
*fail* if the defence it names were gone. For the checks that matter most, that
was measured by deleting them one at a time, rebuilding, and watching:

| Check deleted from `verify_verdict` | Result |
|---|---|
| `message_instruction_index == 0xFFFF` | A forged release drains the vault. One test catches it. |
| `public_key_instruction_index == 0xFFFF` | A forged release drains the vault, paying an attacker who never held the signer's key. One test catches it. |
| `signature_instruction_index == 0xFFFF` | A second, unverified encoding of a genuine verdict is accepted. No money moves. One test catches it. |
| All three at once | The vault drains. Three tests catch it. |

The second row is the one worth dwelling on, and it is the reason this section
exists. An earlier version of this suite tested only the first: all three index
fields are pinned by one `require!`, so deleting the key-index term left every
test passing. The gap was not in the program — the check was always there — but
in the evidence that it mattered.

That asymmetry is itself worth stating. The key index and the message index are
each worth the whole vault on their own. The signature index is not: the program
pins byte 16 to the escrow's stored signer and byte 112 to the bytes it rebuilds
itself, so any signature satisfying the precompile over that pair is already the
arbiter's own signature over this exact verdict. Its check earns its place on
strictness, not on theft — which is precisely what a future reader deleting
"the redundant third term" would need to know, and why
[`ed25519_edges.rs`](tests/tests/ed25519_edges.rs) says it in full.

One practical note for anyone repeating this. Restoring the source file is not
enough: if the restored file's timestamp is older than the build artefact,
cargo will not rebuild, and the tests run against the mutated binary while the
source reads clean. Check the `.so` by hash, not the source by eye.

---

## Design choices

**The buyer picks the verdict signer.** It keeps the demo to one program and no
admin keys. A real deployment would hold a platform key in a config account,
with its own rotation and revocation rules, rather than letting each buyer
nominate the arbiter of their own deal.

**The destination is not an argument.** `settle` takes a verdict and an expiry
and nothing else. The seller's and buyer's token accounts are derived from the
escrow's stored keys and stored mint, so there is no parameter an attacker
could point at their own account.

**The seller is in the signed message, even though the escrow address already
implies it.** The implication only holds while the escrow lives. Settle an
escrow and re-create the same id in the same transaction and you get a second
escrow at the same address with the same creation slot, free to name a
different payee. Naming the seller in the bytes means a verdict is a record of
*who was paid*, not only of which account the money left. The deadline is in
there for the same reason. See the limits below.

**The whole vault, not the recorded amount.** Both exits pay out
`vault.amount`. Anyone can send tokens to a vault, and refusing to pay them out
would strand the close, which fails on a non-empty account — so a donation
leaves with the payout, to the destination the verdict named. For the same
reason the deposit check at creation is on the balance the vault *gained*, not
on the balance it ends up with.

**The bump is stored, not searched,** and it is worth being precise about what
that buys. `create_escrow` uses Anchor's bare `bump`, which searches for the
canonical one, and stores it. Both exits pass `bump = escrow.bump`, which
Anchor compiles to `create_program_address(seeds + stored bump)` compared
against the account's own address — a *consistency* check, not a canonicality
check: it would accept any bump that re-derives that address. What rules out a
non-canonical escrow is not that check but the creation path, which is the only
way an escrow account can come into existence. The exits get the cheap check
because creation did the expensive one once.

**Extensions are refused outright, not handled.** A transfer fee, a transfer
hook, a permanent delegate or a confidential transfer each change what
`transfer_checked` means. Rather than model four behaviours, the program
requires the mint account to be exactly the 82 bytes of a mint with nothing
appended, and says so here.

**Compute cost**, over six runs of
[`compute_units.rs`](tests/tests/compute_units.rs):

| | `create_escrow` | `settle` | `reclaim` |
|---|---:|---:|---:|
| classic | 35,915 – 47,915 | 22,094 – 31,094 | 14,934 – 20,934 |
| Token-2022 | 40,689 – 73,689 | 23,996 – 34,496 | 18,330 – 25,830 |

The spread is not measurement noise, and it is wider than it looks like it
should be. Anchor's `associated_token::` constraints call
`find_program_address`, which walks the bump down from 255 until it lands off
the curve, discarding about 1,500 units a step — and how many steps that takes
depends on the keys. `create_escrow` does that three times, so an unlucky run
pays for all three. A program needing a tighter bound would store the vault's
address at creation and compare against it, trading 32 bytes of account space
for a predictable cost; this one re-derives, because deriving the address is
also what proves the caller did not choose it.

---

## Limits

- **Not audited.** Demo scale, written to be read.
- **One known gap in the replay protection**, and it is narrower than it
  looks but wider than "a race". A verdict is pinned to the escrow's creation
  slot, so it cannot be reused against an escrow created in a later slot at the
  same address. Two escrows created in the *same* slot share that slot — and
  that is not a timing accident a buyer has to be lucky to hit. `close` leaves
  the account empty and owned by the system program, so one transaction can
  settle an escrow and re-create the same `escrow_id` a few instructions later,
  at the identical `created_slot`, whenever the buyer likes.

  What stops that from mattering is the rest of the message. The signed bytes
  also name the seller, the amount, the mint and the deadline, so the only
  rebuild an old verdict still fits is one that pays **the same seller the same
  amount by the same deadline** — which is what the verdict signer agreed to.
  The buyer funds it with their own tokens, so they are paying a second time,
  to the payee of record. Both halves are tested:
  `a_used_verdict_still_fits_a_same_slot_rebuild` shows the gap that remains,
  and `a_used_verdict_does_not_fit_a_rebuild_that_names_another_seller` shows
  the part that is closed. Use a fresh `escrow_id` for every deal anyway.

  Closing it completely would mean never freeing the escrow address — keeping
  a tombstone account so the id can never be re-created — and that trades the
  rent back to the buyer, on every single escrow, for an edge case that costs
  the buyer their own money. This program returns the rent.
- **Token-2022 extensions are rejected**, not supported.
- **One verdict signer per escrow, chosen by the buyer**, and no partial
  releases, fees, disputes or admin keys.
- **A verdict is a bearer instrument.** There is no nonce, no sequence number
  and no revocation. If the signer issues a refund and then changes its mind
  and issues a release, both are live and whoever submits first wins. The only
  control is a short `expires_at`. Pinned by
  `two_verdicts_for_one_escrow_are_both_live_and_the_first_submitted_wins`.
- **Either party can stall a payout they dislike.** Both payout accounts are
  validated whichever way the verdict goes, so a seller who closes their token
  account blocks a release — and so does a *buyer* who closes theirs, even
  though they are not the payee. A mint's freeze authority can do the same, and
  can block creation outright by freezing the vault. Nothing is stolen and
  nothing is permanently stuck: the deadline ends it and the buyer reclaims. It
  does mean the deadline is not only the buyer's protection against a silent
  signer, it is also the thing that bounds an adverse one. See
  [`payout_availability.rs`](tests/tests/payout_availability.rs) and
  [`mint_authority_attacks.rs`](tests/tests/mint_authority_attacks.rs).
- **An event in the logs is not proof the money moved.** Logs are not rolled
  back. If `settle` succeeds and a later instruction in the same transaction
  fails, a complete and correct-looking `EscrowSettled` line stays in the logs
  while the tokens never left the vault. Any monitor built on these events must
  join each line to the transaction's status; one that tails logs alone will
  book payouts that were undone. Pinned by
  `a_settled_event_survives_in_the_logs_of_a_rolled_back_transaction`.
- **Trailing bytes after an instruction's arguments are accepted.** Anchor
  dispatches on the leading discriminator and Borsh's non-strict decoder stops
  once its fields are full. Nothing can be steered by them today, because no
  argument names a destination or an amount — but the day a sixth argument is
  added, an old client's payload would still deserialize and the new field
  would read whatever followed. That is what the instruction-shape guards in
  [`instruction_layout.rs`](tests/tests/instruction_layout.rs) are for.
- **The "classic" half of the test matrix is not SPL Token.** LiteSVM enables
  every runtime feature, which includes `replace_spl_token_with_p_token`, so
  the account at `TokenkegQ…` is served by the bundled `p-token` binary rather
  than `spl_token`. That is not a detail: `p-token` credits a destination
  without a checked add where `spl_token` does not, and that single difference
  is the only reason the deposit overflow guard is reachable at all in tests.
  [`numeric_edges.rs`](tests/tests/numeric_edges.rs) asserts which binary is
  loaded so this cannot change silently underneath the suite.

---

## Going to production

- **An external audit** before any real money, with the Ed25519 check and the
  account constraints as the focus.
- **The upgrade authority** held by a multisig, and revoked once the program is
  final. On the devnet deployment below it is a throwaway key.
- **Monitoring built on the events.** The program emits `EscrowCreated`,
  `EscrowSettled` (carrying the verdict, the signer who authorised it and the
  account actually paid) and `EscrowReclaimed`. That is enough for an indexer to
  follow every escrow from funding to payout, and enough to alarm on a
  settlement signed by an unexpected key without joining back to the creation
  event. Every field of all three is asserted in
  [`events.rs`](tests/tests/events.rs), because an untested event is a
  monitoring control nobody has checked.
- **A platform verdict key in a config account**, as described above.

### The same escrow on Base

The design carries over with two substitutions. The message would name the
chain id and the contract address where this one names the program id, so a
verdict for one deployment still cannot be used on another, and it would be
EIP-712 typed data rather than a flat byte string. The signature would be
recovered with `ecrecover` and compared against the stored verdict signer
instead of being verified by a precompile and then inspected. Everything else —
the domain separator, pinning the escrow, the creation marker, the amount, the
expiry, and taking the destination from state rather than from an argument — is
the same. The offsets problem is specific to Solana's precompile; on Base the
equivalent trap is accepting a signature without binding it to the chain and
the contract.

---

## Running it

Pinned versions: Anchor 1.2.1, Solana 4.2.0, Rust 1.97.1 for the tests and
1.89.0 for the program (`rust-toolchain.toml` pins the compiler; the program
crate is separate from the test crate so the on-chain build stays on the
toolchain Anchor supports).

```sh
# Build the program
cargo-build-sbf --manifest-path programs/verdict-escrow/Cargo.toml --arch v3

# Run the tests (they load the .so built above)
cargo test --manifest-path tests/Cargo.toml
```

`--arch v3` is deliberate. Mainnet and devnet have both accepted SBPFv3 since
SIMD-0178 activated, and SIMD-0500 will eventually stop new deployments of v0,
v1 and v2 — so a program built today should already be v3. It is also what a
validator running with every feature enabled will accept, which is what you get
from `solana-test-validator`.

The tests run in-process with [LiteSVM](https://github.com/LiteSVM/litesvm),
with its `precompiles` feature on so the real Ed25519 precompile runs. No
validator is started, the whole suite takes a few seconds, and the clock can be
moved to test the deadline without waiting for it.

### By hand, on devnet

```sh
cargo run -p verdict-cli -- create \
  --keypair buyer.json --mint <MINT> --seller <SELLER> \
  --verdict-signer <SIGNER> --amount 1000000 --escrow-id 1

cargo run -p verdict-cli -- show --escrow <ESCROW>

# Only this step needs the verdict signer's key. It makes no transaction.
cargo run -p verdict-cli -- sign \
  --keypair verdict-signer.json --escrow <ESCROW> --verdict release

# Anyone can run this, with the signature printed above.
cargo run -p verdict-cli -- settle \
  --keypair any-payer.json --escrow <ESCROW> --verdict release \
  --expires-at <UNIX> --signature <HEX>
```

### Live on devnet

Deployed and exercised end to end against the code in this repository. The
settle transaction below is the one worth opening: it has two instructions, the
Ed25519 verification and then `settle`, and the account that paid for it holds
no authority over the escrow.

| | |
|---|---|
| Program | [`DhXqHjZuT3ZJoUXzj3XmeBUMmLAwiHV4VKPZcvntTfba`](https://explorer.solana.com/address/DhXqHjZuT3ZJoUXzj3XmeBUMmLAwiHV4VKPZcvntTfba?cluster=devnet) |
| Current bytecode (an upgrade over the first deploy) | [`3bh4gE8V…f32Hw1`](https://explorer.solana.com/tx/3bh4gE8VVdJp2nYTcWMbaRXekoxvYHUx9L5dxKhv4uHKe7j8eGW29DJPS1x5jt98Txse9V1UztU8kkamwTf32Hw1?cluster=devnet) |
| Test mint (6 decimals) | [`75fSh49po9rr6sZTMAHQENAjCya572hmh3WuPNLt7NTY`](https://explorer.solana.com/address/75fSh49po9rr6sZTMAHQENAjCya572hmh3WuPNLt7NTY?cluster=devnet) |

**A release**, 250 tokens from buyer to seller:

| | |
|---|---|
| `create_escrow` | [`4sJ8bvuo…JdR2Uk`](https://explorer.solana.com/tx/4sJ8bvuorkmJDMWSVtW6ByRnHHwaebadfX1nVN1Jx6tKYQTJFYXsFt5jRT2qLXV3ZczDBZALjBevsEYgSFJdR2Uk?cluster=devnet) |
| **`settle`** | [**`4Mm8jxtb…rAtjYj`**](https://explorer.solana.com/tx/4Mm8jxtbuX2AWs7fx9jC9AEHuJQrm3iCpkU7g5AgadrqrDVGfAGT1mXTdSjRstjFpcgFSumBvzqFXkpwZtrAtjYj?cluster=devnet) |

**A reclaim**, 100 tokens back to the buyer after a 20-second deadline:

| | |
|---|---|
| `create_escrow` | [`3rymcrig…cuL8Ak`](https://explorer.solana.com/tx/3rymcrigB1Q662cc8XnixLfkHStHo6VfzAJZNFcUhZYTZszJBaAVdR7wAeCKBNy6rMxafEuKaBPbT9ZZfQcuL8Ak?cluster=devnet) |
| `reclaim` | [`3QUhkkc9…mV8ssT`](https://explorer.solana.com/tx/3QUhkkc9HhzZGfDaGtLN4C2RWsUUZ5t2Ezj5LZPpTjtj8jaC53owtkt3AajWpfEhxaiXV1tm7xRUF2mCwEmV8ssT?cluster=devnet) |

The deployed bytecode is byte-for-byte the build from this source. The SBF
build is reproducible, so anyone can check it:

```sh
cargo-build-sbf --manifest-path programs/verdict-escrow/Cargo.toml --arch v3
solana program dump DhXqHjZuT3ZJoUXzj3XmeBUMmLAwiHV4VKPZcvntTfba on-chain.so --url devnet
# on-chain.so is zero-padded to the allocated length; compare the first
# $(stat -c %s target/deploy/verdict_escrow.so) bytes
head -c $(stat -c %s target/deploy/verdict_escrow.so) on-chain.so | sha256sum
sha256sum target/deploy/verdict_escrow.so
# 9071d1133b781c2ef09c479780136952b042ee2d56089594b95226dcd1b439a1
```

The upgrade authority is `D63q2sw8MSAJo7zJmQ6stnnDFj3Yb712E53VMXEwhGmA`, a
throwaway devnet key held only by me. See *Going to production* above for what
a real deployment does instead.

---

## Repository layout

```
programs/verdict-escrow/src     737 lines
  lib.rs        the three instructions and their account constraints
  verdict.rs    the 178-byte message and the Ed25519 check
  state.rs      the escrow account
  errors.rs     one named error per failure, so tests assert which one fired
  events.rs     one event per state change
tests                           11,248 lines, 219 tests in 21 files
  src/lib.rs    harness: the escrow, both token programs, and a raw Ed25519
                instruction builder the layout tests bend field by field
  tests/*.rs    the suite, grouped by what is being attacked
tools/verdict-cli
  the CLI above, talking plain JSON-RPC
```

The ratio is the point. The program is small enough to read in one sitting;
the reason to trust it is not its size but what has been thrown at it.

## License

MIT. See [LICENSE](LICENSE).
