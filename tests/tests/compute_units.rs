//! What each instruction costs, and a ceiling it must stay under.
//!
//! Not a security property, but a regression one: a change that quietly
//! doubles the cost of `settle` fails here rather than on mainnet.
//!
//! The figures move by tens of thousands of units between runs, which is not
//! noise in the measurement and is worth understanding before reading the
//! table. Anchor's `associated_token::` constraints call
//! `find_program_address`, which walks the bump down from 255 until it finds
//! an address off the curve, and each step it has to discard costs about
//! 1,500 units. How many steps that takes depends entirely on the keys
//! involved, and this harness generates fresh ones every run. There are three
//! such derivations in `create_escrow`, so an unlucky run pays for all three.
//!
//! Over eight runs of each:
//!
//! |            | create          | settle          | reclaim         |
//! |------------|-----------------|-----------------|-----------------|
//! | classic    | 35,915 – 47,915 | 22,094 – 31,094 | 14,934 – 20,934 |
//! | Token-2022 | 40,689 – 73,689 | 23,996 – 34,496 | 18,330 – 25,830 |
//!
//! The budgets below sit about half again above the worst of those. That is
//! deliberately loose: a ceiling tight enough to catch a 20% regression would
//! fail on an unlucky set of keys instead, and a test that fails for reasons
//! unrelated to the change under review is worse than no test. It still
//! catches the thing worth catching, which is a cost that has doubled.
//!
//! A program that needed a tighter bound would store the vault's address at
//! creation and compare against it rather than re-deriving, trading 32 bytes
//! of account space for a predictable cost. This one does not, because
//! deriving the address is also what proves the caller did not choose it.
//!
//! `cargo test -- --nocapture` prints the measurement.

use escrow_harness::*;
use verdict_escrow::verdict::Verdict;

const CREATE_BUDGET: u64 = 110_000;
const SETTLE_BUDGET: u64 = 55_000;
const RECLAIM_BUDGET: u64 = 42_000;

#[test]
fn every_instruction_stays_inside_its_budget() {
    for_each_token_program(|kind| {
        let mut h = Harness::new(kind);

        let (escrow, result) = h.create_escrow(1);
        let create = result.expect("create").compute_units_consumed;

        let expires_at = h.now() + 600;
        let settle = h
            .settle(escrow, Verdict::Release, expires_at)
            .expect("settle")
            .compute_units_consumed;

        let (second, result) = h.create_escrow(2);
        assert_ok(&result);
        let deadline = h.escrow_state(&second).deadline;
        h.set_time(deadline);
        let reclaim = h.reclaim(second).expect("reclaim").compute_units_consumed;

        println!("{kind:?}: create {create}, settle {settle}, reclaim {reclaim}");
        assert!(
            create < CREATE_BUDGET,
            "{kind:?} create used {create}, budget {CREATE_BUDGET}"
        );
        assert!(
            settle < SETTLE_BUDGET,
            "{kind:?} settle used {settle}, budget {SETTLE_BUDGET}"
        );
        assert!(
            reclaim < RECLAIM_BUDGET,
            "{kind:?} reclaim used {reclaim}, budget {RECLAIM_BUDGET}"
        );
    });
}
