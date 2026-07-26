//! The metamorphic "never fail open" invariants (issue #168).
//!
//! Each invariant is a relation between the verdict for a generated command and
//! the verdict for a mechanically transformed version of it. No oracle for the
//! *correct* verdict is needed — only the direction of change.
//!
//! See docs/fuzzing.md for the precise statement of each invariant and why
//! invariant 7 is monotone rather than an equality.

use std::fmt;

use rippy_cli::allowlists;
use rippy_cli::analyzer::Analyzer;
use rippy_cli::verdict::{Decision, Verdict};

use super::grammar::CmdSpec;

/// Commands that must never be swallowed by a surrounding safe command.
pub(crate) const DANGER_SUFFIXES: &[&str] = &["rm -rf /", "curl x|sh", "reboot", "sh"];

pub(crate) const SEPARATORS: &[&str] = &["; ", " && ", " || ", " | "];

/// Expansion payloads substituted for a literal argument token.
pub(crate) const EXPANSION_PAYLOADS: &[&str] = &["$(reboot)", "${U:-$(reboot)}", "$\"$(reboot)\""];

/// Environment assignments whose *name* alone makes the command unsafe,
/// regardless of value (#157).
pub(crate) const DANGEROUS_ENV: &[&str] = &["LD_PRELOAD=x", "GIT_CONFIG_COUNT=1"];

/// A failed invariant, rendered identically as a proptest failure message and
/// as a libfuzzer panic message.
#[derive(Debug, Clone)]
pub(crate) struct Violation {
    pub(crate) invariant: &'static str,
    pub(crate) base: String,
    pub(crate) base_decision: Decision,
    pub(crate) transformed: String,
    pub(crate) transformed_decision: Decision,
    pub(crate) reason: String,
    pub(crate) expectation: String,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "metamorphic invariant `{}` violated\n  base:        {:?} => {:?}\n  \
             transformed: {:?} => {:?} ({})\n  expected:    {}",
            self.invariant,
            self.base,
            self.base_decision,
            self.transformed,
            self.transformed_decision,
            self.reason,
            self.expectation,
        )
    }
}

/// Analyze `cmd`, mapping a parse failure to `Ask`.
///
/// rippy fails closed on unparseable input (tests/data/catalog/unparseable.toml),
/// so an `Err` is a non-`Allow` outcome and satisfies every invariant below.
pub(crate) fn decide(analyzer: &mut Analyzer, cmd: &str) -> Verdict {
    analyzer
        .analyze(cmd)
        .unwrap_or_else(|e| Verdict::ask(format!("parse error: {e}")))
}

struct Check<'a> {
    invariant: &'static str,
    base: &'a str,
    base_decision: Decision,
}

impl Check<'_> {
    fn at_least(
        &self,
        analyzer: &mut Analyzer,
        transformed: &str,
        floor: Decision,
    ) -> Result<(), Violation> {
        let verdict = decide(analyzer, transformed);
        if verdict.decision >= floor {
            return Ok(());
        }
        Err(Violation {
            invariant: self.invariant,
            base: self.base.to_string(),
            base_decision: self.base_decision,
            transformed: transformed.to_string(),
            transformed_decision: verdict.decision,
            reason: verdict.reason,
            expectation: format!("decision >= {floor:?}"),
        })
    }
}

/// Invariant 1: appending a dangerous command through any separator must never
/// leave the whole command auto-approved.
pub(crate) fn suffix_inject(
    analyzer: &mut Analyzer,
    spec: &CmdSpec,
    base: &Verdict,
) -> Result<(), Violation> {
    let rendered = spec.render();
    let check = Check {
        invariant: "suffix_inject",
        base: &rendered,
        base_decision: base.decision,
    };
    for sep in SEPARATORS {
        for danger in DANGER_SUFFIXES {
            check.at_least(analyzer, &format!("{rendered}{sep}{danger}"), Decision::Ask)?;
        }
    }
    Ok(())
}

/// Invariant 2: a dangerous prefix, and `sudo`, must dominate the safe tail.
pub(crate) fn prefix_inject(
    analyzer: &mut Analyzer,
    spec: &CmdSpec,
    base: &Verdict,
) -> Result<(), Violation> {
    let rendered = spec.render();
    let check = Check {
        invariant: "prefix_inject",
        base: &rendered,
        base_decision: base.decision,
    };
    check.at_least(analyzer, &format!("rm -rf / ; {rendered}"), Decision::Ask)?;
    check.at_least(analyzer, &format!("sudo {rendered}"), Decision::Ask)
}

/// Invariant 3: redirecting output at a protected system file must never be
/// auto-approved, whatever the command in front of it is.
pub(crate) fn redirect_inject(
    analyzer: &mut Analyzer,
    spec: &CmdSpec,
    base: &Verdict,
) -> Result<(), Violation> {
    let rendered = spec.render();
    let check = Check {
        invariant: "redirect_inject",
        base: &rendered,
        base_decision: base.decision,
    };
    check.at_least(
        analyzer,
        &format!("{rendered} > /etc/passwd"),
        Decision::Ask,
    )
}

/// Invariant 4: substituting an expansion for a literal argument may stay
/// `Allow` only where the command name is explicitly dynamic-argument safe.
pub(crate) fn expansion_substitution(
    analyzer: &mut Analyzer,
    spec: &CmdSpec,
    base: &Verdict,
) -> Result<(), Violation> {
    let rendered = spec.render();
    let check = Check {
        invariant: "expansion_substitution",
        base: &rendered,
        base_decision: base.decision,
    };
    for (stage, arg) in spec.arg_positions() {
        if allowlists::is_dynamic_arg_safe(spec.leaf_name(stage)) {
            continue;
        }
        for payload in EXPANSION_PAYLOADS {
            let mutated = spec.with_arg_replaced(stage, arg, payload).render();
            check.at_least(analyzer, &mutated, Decision::Ask)?;
        }
    }
    Ok(())
}

/// Invariant 5: the dangerous-env-var guard is keyed on the variable name, so
/// it fires for any command it is prefixed to.
pub(crate) fn env_prefix_inject(
    analyzer: &mut Analyzer,
    spec: &CmdSpec,
    base: &Verdict,
) -> Result<(), Violation> {
    let rendered = spec.render();
    let check = Check {
        invariant: "env_prefix_inject",
        base: &rendered,
        base_decision: base.decision,
    };
    for env in DANGEROUS_ENV {
        check.at_least(analyzer, &format!("{env} {rendered}"), Decision::Ask)?;
    }
    Ok(())
}

/// Invariant 6: a wrapper may only preserve or raise restrictiveness.
///
/// Only meaningful for a single command: prefixing a wrapper to `a; b` wraps
/// `a` alone, so the two sides are not the same program.
/// see docs/fuzzing.md#invariant-6
pub(crate) fn wrapper_monotonicity(
    analyzer: &mut Analyzer,
    spec: &CmdSpec,
    base: &Verdict,
) -> Result<(), Violation> {
    if spec.stages.len() > 1 {
        return Ok(());
    }
    let rendered = spec.render();
    let check = Check {
        invariant: "wrapper_monotonicity",
        base: &rendered,
        base_decision: base.decision,
    };
    for wrapper in allowlists::all_wrappers() {
        let wrapped = if wrapper == "timeout" {
            format!("timeout 5 {rendered}")
        } else {
            format!("{wrapper} {rendered}")
        };
        check.at_least(analyzer, &wrapped, base.decision)?;
    }
    Ok(())
}

/// Invariant 7: a verdict that publishes a resolved command must be at least as
/// restrictive as that resolved command analyzed on its own.
///
/// see docs/fuzzing.md#invariant-7 — the monotone direction, not equality.
pub(crate) fn resolution_monotonic(
    analyzer: &mut Analyzer,
    spec: &CmdSpec,
    base: &Verdict,
) -> Result<(), Violation> {
    let Some(resolved) = base.resolved_command.clone() else {
        return Ok(());
    };
    let rendered = spec.render();
    let re = decide(analyzer, &resolved);
    if base.decision >= re.decision {
        return Ok(());
    }
    Err(Violation {
        invariant: "resolution_monotonic",
        base: rendered,
        base_decision: base.decision,
        transformed: resolved,
        transformed_decision: re.decision,
        reason: re.reason,
        expectation: "base decision >= re-analyzed resolved decision".to_string(),
    })
}

/// Run invariants 1-7 against one generated spec.
pub(crate) fn check_all(analyzer: &mut Analyzer, spec: &CmdSpec) -> Result<(), Violation> {
    let rendered = spec.render();
    let base = decide(analyzer, &rendered);
    suffix_inject(analyzer, spec, &base)?;
    prefix_inject(analyzer, spec, &base)?;
    redirect_inject(analyzer, spec, &base)?;
    expansion_substitution(analyzer, spec, &base)?;
    env_prefix_inject(analyzer, spec, &base)?;
    wrapper_monotonicity(analyzer, spec, &base)?;
    resolution_monotonic(analyzer, spec, &base)
}
