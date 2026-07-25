#![no_main]

//! Deep, coverage-guided version of the metamorphic "never fail open"
//! invariants. The same harness runs as fast proptests under `cargo test`
//! (tests/proptest_metamorphic.rs); here libfuzzer steers the byte decoder that
//! produces the command specs. See docs/fuzzing.md.

use std::cell::RefCell;

use libfuzzer_sys::fuzz_target;
use rippy_cli::analyzer::Analyzer;

#[path = "../../tests/metamorphic/mod.rs"]
mod metamorphic;

use metamorphic::grammar;
use metamorphic::invariants;

thread_local! {
    static ANALYZER: RefCell<Analyzer> = RefCell::new(metamorphic::analyzer::isolated_analyzer());
}

fuzz_target!(|data: &[u8]| {
    let spec = grammar::from_bytes(data);
    ANALYZER.with(|a| {
        if let Err(violation) = invariants::check_all(&mut a.borrow_mut(), &spec) {
            panic!("{violation}");
        }
    });

    let word = grammar::word_from_bytes(data);
    assert!(
        !rippy_cli::fuzz_support::resolution_leaks_expansion(&word),
        "metamorphic invariant `resolver_literal` violated: {word:?} resolved to a \
         literal that still carries an expansion"
    );
});
