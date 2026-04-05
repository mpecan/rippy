use crate::condition::Condition;
use crate::pattern::Pattern;
use crate::verdict::Decision;

use std::path::PathBuf;

/// What kind of entity a rule targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleTarget {
    Command,
    Redirect,
    Mcp,
    FileRead,
    FileWrite,
    FileEdit,
    After,
}

/// A single rule: target + decision + pattern + optional message + conditions.
///
/// Rules can use glob-pattern matching (the `pattern` field), structured matching
/// (command/subcommand/flags fields), or both. When both are present, all must match (AND).
#[derive(Debug, Clone)]
pub struct Rule {
    pub target: RuleTarget,
    pub decision: Decision,
    pub pattern: Pattern,
    pub message: Option<String>,
    pub conditions: Vec<Condition>,
    // Structured matching fields (all optional, combined with AND).
    pub command: Option<String>,
    pub subcommand: Option<String>,
    pub subcommands: Option<Vec<String>>,
    pub flags: Option<Vec<String>>,
    pub args_contain: Option<String>,
}

impl Rule {
    #[must_use]
    pub fn new(target: RuleTarget, decision: Decision, pattern: &str) -> Self {
        Self {
            target,
            decision,
            pattern: Pattern::new(pattern),
            message: None,
            conditions: vec![],
            command: None,
            subcommand: None,
            subcommands: None,
            flags: None,
            args_contain: None,
        }
    }

    #[must_use]
    pub fn with_message(mut self, msg: impl Into<String>) -> Self {
        self.message = Some(msg.into());
        self
    }

    #[must_use]
    pub fn with_conditions(mut self, c: Vec<Condition>) -> Self {
        self.conditions = c;
        self
    }

    /// Format structured fields as a human-readable description.
    #[must_use]
    pub fn structured_description(&self) -> String {
        let mut parts = Vec::new();
        if let Some(c) = &self.command {
            parts.push(format!("command={c}"));
        }
        if let Some(s) = &self.subcommand {
            parts.push(format!("subcommand={s}"));
        }
        if let Some(list) = &self.subcommands {
            parts.push(format!("subcommands=[{}]", list.join(",")));
        }
        if let Some(f) = &self.flags {
            parts.push(format!("flags=[{}]", f.join(",")));
        }
        if let Some(a) = &self.args_contain {
            parts.push(format!("args-contain={a}"));
        }
        parts.join(" ")
    }

    /// Returns `true` if this rule has any structured matching fields set.
    #[must_use]
    pub const fn has_structured_fields(&self) -> bool {
        self.command.is_some()
            || self.subcommand.is_some()
            || self.subcommands.is_some()
            || self.flags.is_some()
            || self.args_contain.is_some()
    }

    /// Return the action string for this rule (e.g. "allow", "deny-redirect", "ask-read").
    #[must_use]
    pub fn action_str(&self) -> String {
        let base = self.decision.as_str();
        match self.target {
            RuleTarget::Command => base.to_string(),
            RuleTarget::Redirect => format!("{base}-redirect"),
            RuleTarget::Mcp => format!("{base}-mcp"),
            RuleTarget::FileRead => format!("{base}-read"),
            RuleTarget::FileWrite => format!("{base}-write"),
            RuleTarget::FileEdit => format!("{base}-edit"),
            RuleTarget::After => "after".to_string(),
        }
    }
}

/// A parsed config directive — either a Rule, a Set key/value, or an Alias.
#[derive(Debug, Clone)]
pub enum ConfigDirective {
    Rule(Rule),
    Set {
        key: String,
        value: String,
    },
    Alias {
        source: String,
        target: String,
    },
    CdAllow(PathBuf),
    /// Marker separating baseline (stdlib + global) from project rules.
    ProjectBoundary,
}
