//! Structured decision-trace events emitted by [`crate::analyzer::Analyzer`].
//!
//! One recorder serves both consumers: `--verbose` echoes every event to stderr
//! as it happens, and `rippy inspect` / `rippy debug` collect the same events
//! and render them. Because the explain path reads this stream instead of
//! re-deriving routing, it cannot drift from the hook path.
//! see docs/security-invariants.md#inspect-delegation

/// Upper bound on recorded events. A compound command is bounded by the
/// analyzer's node budget (`10_000`) and could otherwise emit thousands of
/// events into a trace no human will read.
const MAX_TRACE_EVENTS: usize = 1024;

/// A stage of the decision pipeline that a trace event belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// A leading `NAME=VALUE` prefix was stripped before string matching, or
    /// gated because its name or value is unsafe.
    EnvPrefix,
    /// A Claude Code `permissions` entry was consulted.
    CcRule,
    /// A rippy config rule was consulted.
    ConfigRule,
    /// The bash parser ran.
    Parse,
    /// A simple command's name was resolved.
    Command,
    /// The allowlists (simple-safe, wrapper, help-flag) were consulted.
    Allowlist,
    /// A shell expansion was statically resolved (or refused).
    Expansion,
    /// A command-specific handler classified the invocation.
    Handler,
    /// A redirect target was run through the write pipeline.
    Redirect,
    /// The configured `default-action` decided the verdict.
    Default,
    /// The event cap was reached; later events were dropped.
    Truncated,
}

impl Stage {
    /// Short key printed by `--verbose` (`[rippy] <key>: <detail>`).
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::EnvPrefix => "env-prefix",
            Self::CcRule => "cc",
            Self::ConfigRule => "config",
            Self::Parse => "parse",
            Self::Command => "command",
            Self::Allowlist => "allowlist",
            Self::Expansion => "resolved",
            Self::Handler => "handler",
            Self::Redirect => "redirect",
            Self::Default => "default",
            Self::Truncated => "truncated",
        }
    }

    /// Human-readable column heading used by `rippy inspect`.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::EnvPrefix => "Env prefix",
            Self::CcRule => "CC permissions",
            Self::ConfigRule => "Config rules",
            Self::Parse => "Parse",
            Self::Command => "Command",
            Self::Allowlist => "Allowlist",
            Self::Expansion => "Expansion",
            Self::Handler => "Handler",
            Self::Redirect => "Redirect",
            Self::Default => "Default",
            Self::Truncated => "Truncated",
        }
    }
}

/// One observation made while analyzing a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceEvent {
    pub stage: Stage,
    /// Whether the consulted layer matched. `false` records a miss, which is
    /// just as informative as a hit when explaining a verdict.
    pub matched: bool,
    pub detail: String,
}

/// Collects [`TraceEvent`]s for the current analysis.
///
/// Recording is off by default so the hook path pays nothing; `rippy inspect`
/// turns it on. Verbose mode is independent — it echoes without collecting.
pub struct Trace {
    verbose: bool,
    enabled: bool,
    events: Vec<TraceEvent>,
}

impl Trace {
    #[must_use]
    pub const fn new(verbose: bool) -> Self {
        Self {
            verbose,
            enabled: false,
            events: Vec::new(),
        }
    }

    /// Start collecting events for later retrieval with [`Trace::take`].
    pub const fn enable(&mut self) {
        self.enabled = true;
    }

    /// Drop any collected events, so a reused analyzer starts each command clean.
    pub fn reset(&mut self) {
        self.events.clear();
    }

    /// Remove and return the events collected so far.
    pub fn take(&mut self) -> Vec<TraceEvent> {
        std::mem::take(&mut self.events)
    }

    /// Record one event. `detail` is a closure so its formatting cost is only
    /// paid when someone is listening.
    pub fn record(&mut self, stage: Stage, matched: bool, detail: impl FnOnce() -> String) {
        if !self.verbose && !self.enabled {
            return;
        }
        let detail = detail();
        if self.verbose {
            eprintln!("[rippy] {}: {detail}", stage.key());
        }
        self.push(TraceEvent {
            stage,
            matched,
            detail,
        });
    }

    fn push(&mut self, event: TraceEvent) {
        if !self.enabled {
            return;
        }
        match self.events.len() + 1 {
            n if n < MAX_TRACE_EVENTS => self.events.push(event),
            n if n == MAX_TRACE_EVENTS => self.events.push(TraceEvent {
                stage: Stage::Truncated,
                matched: false,
                detail: format!("trace truncated after {MAX_TRACE_EVENTS} events"),
            }),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_STAGES: [Stage; 11] = [
        Stage::EnvPrefix,
        Stage::CcRule,
        Stage::ConfigRule,
        Stage::Parse,
        Stage::Command,
        Stage::Allowlist,
        Stage::Expansion,
        Stage::Handler,
        Stage::Redirect,
        Stage::Default,
        Stage::Truncated,
    ];

    #[test]
    fn disabled_recorder_collects_nothing() {
        let mut trace = Trace::new(false);
        trace.record(Stage::Parse, true, || "1 node".to_owned());
        assert!(trace.take().is_empty());
    }

    #[test]
    fn enabled_recorder_collects_and_resets() {
        let mut trace = Trace::new(false);
        trace.enable();
        trace.record(Stage::Parse, true, || "1 node".to_owned());
        assert_eq!(trace.take().len(), 1);
        assert!(trace.take().is_empty(), "take drains the buffer");

        trace.record(Stage::Parse, false, || "boom".to_owned());
        trace.reset();
        assert!(trace.take().is_empty());
    }

    #[test]
    fn cap_emits_exactly_one_truncated_event_then_stops() {
        let mut trace = Trace::new(false);
        trace.enable();
        for _ in 0..(MAX_TRACE_EVENTS * 2) {
            trace.record(Stage::Command, true, || "x".to_owned());
        }
        let events = trace.take();
        assert_eq!(events.len(), MAX_TRACE_EVENTS);
        assert_eq!(
            events
                .iter()
                .filter(|e| e.stage == Stage::Truncated)
                .count(),
            1
        );
        assert_eq!(events[MAX_TRACE_EVENTS - 1].stage, Stage::Truncated);
    }

    #[test]
    fn stage_names_are_distinct_and_non_empty() {
        let mut keys: Vec<&str> = ALL_STAGES.iter().map(|s| s.key()).collect();
        let mut labels: Vec<&str> = ALL_STAGES.iter().map(|s| s.label()).collect();
        assert!(keys.iter().chain(labels.iter()).all(|s| !s.is_empty()));
        keys.sort_unstable();
        keys.dedup();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(keys.len(), ALL_STAGES.len());
        assert_eq!(labels.len(), ALL_STAGES.len());
    }
}
