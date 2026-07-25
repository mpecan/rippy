#![no_main]

//! Robustness target: `Analyzer::analyze` must never panic or hang, whatever
//! bytes it is handed. The oracle is libfuzzer's own crash/timeout detection —
//! `MAX_NODES`/`MAX_DEPTH` in the analyzer are what keep pathological input
//! terminating. See docs/fuzzing.md.

use std::cell::RefCell;

use libfuzzer_sys::fuzz_target;
use rippy_cli::analyzer::Analyzer;

#[path = "../../tests/common/analyzer.rs"]
mod harness;

thread_local! {
    /// Rebuilding the stdlib config and handler set per iteration would dominate
    /// the run; `analyze` truncates its locals stack back to the entry
    /// checkpoint, so one analyzer is safe to reuse.
    static ANALYZER: RefCell<Analyzer> = RefCell::new(harness::isolated_analyzer());
}

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        ANALYZER.with(|a| {
            let _ = a.borrow_mut().analyze(s);
        });
    }
});
