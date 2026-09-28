//! The Jev scope guarantees, checked over every catalog command
//! (docs/jev.md#scope-and-guarantees). Each command is analyzed, then reviewed
//! by a fake Jev that always approves, always flags exfiltration, or always
//! fails. Whatever it answers, Jev may only ever move an eligible uncertain
//! ask, and may never produce `Deny`.

#![cfg(feature = "jev")]
#![allow(clippy::unwrap_used, clippy::panic)]

mod common;

use std::path::Path;
use std::time::Duration;

use common::isolated_analyzer;
use rippy_cli::jev::transport::Transport;
use rippy_cli::jev::{Env, review};
use rippy_cli::jev_settings::{Effect, JevSettings};
use rippy_cli::verdict::{AskClass, Decision, UncertainKind, Verdict};
use serde_json::{Value, json};

struct Fixed(Result<Value, String>);

impl Transport for Fixed {
    fn post(&self, _: &str, _: &str, _: &Value, _: Duration) -> Result<Value, String> {
        self.0.clone()
    }
}

fn reply(effect: &str, exfiltration: f64) -> Fixed {
    let mut probabilities = json!({
        "read_only": 0.0, "remote_read": 0.0, "local_change": 0.0,
        "destructive": 0.0, "network_send": 0.0, "download_execute": 0.0
    });
    probabilities[effect] = json!(1.0);
    let noul = |p: f64| json!({ "type": "noul", "noul": p });
    Fixed(Ok(json!({
        "model": "fake",
        "answers": {
            "effect": { "type": "choice", "choice": effect,
                        "probabilities": probabilities, "confidence": 1.0 },
            "exfiltration": noul(exfiltration),
            "writes_outside_project": noul(0.0),
            "reads_secrets": noul(0.0),
            "irreversible": noul(0.0),
            "self_referential": noul(0.0),
        }
    })))
}

/// The most permissive settings validation allows.
fn permissive() -> JevSettings {
    JevSettings {
        enabled: true,
        api_key_env: "RIPPY_INVARIANT_KEY".to_owned(),
        allow_effects: vec![Effect::ReadOnly, Effect::RemoteRead, Effect::LocalChange],
        min_confidence: 0.0,
        ..JevSettings::default()
    }
}

fn eligible_class(v: &Verdict) -> bool {
    matches!(v.ask_class(), Some(AskClass::Uncertain(k)) if k != UncertainKind::Unanalyzable)
}

fn run(transport: &Fixed, check: impl Fn(&str, &Verdict, &Verdict)) -> usize {
    let key = |name: &str| (name == "RIPPY_INVARIANT_KEY").then(|| "k".to_owned());
    let env = Env {
        cwd: Path::new("/tmp"),
        home: None,
        var: &key,
    };
    let settings = permissive();
    let mut analyzer = isolated_analyzer();
    let mut moved = 0;
    for case in common::catalog::load() {
        let before = analyzer.analyze(&case.command).unwrap();
        let after = review(before.clone(), &case.command, &settings, &env, transport).verdict;
        if after.decision == Decision::Deny {
            assert_eq!(
                before.decision,
                Decision::Deny,
                "{}: jev produced a deny",
                case.command
            );
        }
        if !eligible_class(&before) {
            assert_eq!(
                after, before,
                "{}: jev touched an ineligible verdict",
                case.command
            );
        }
        if after.decision != before.decision {
            moved += 1;
        }
        check(&case.command, &before, &after);
    }
    moved
}

#[test]
fn an_always_approving_jev_only_moves_eligible_uncertain_asks() {
    let moved = run(&reply("read_only", 0.0), |cmd, before, after| {
        if after.decision == Decision::Allow && before.decision != Decision::Allow {
            assert!(eligible_class(before), "{cmd}: approved an ineligible ask");
        }
    });
    // The catalog holds eligible uncertain asks, so a vacuous pass is a bug.
    assert!(moved > 0, "no catalog command was eligible");
}

#[test]
fn an_always_alarmed_jev_never_approves() {
    let moved = run(&reply("network_send", 1.0), |cmd, before, after| {
        if before.decision != Decision::Allow {
            assert_ne!(
                after.decision,
                Decision::Allow,
                "{cmd}: approved despite alarm"
            );
        }
    });
    assert_eq!(moved, 0);
}

#[test]
fn a_failing_jev_changes_no_decision_or_class() {
    let moved = run(&Fixed(Err("HTTP 503".to_owned())), |cmd, before, after| {
        assert_eq!(after.ask_class(), before.ask_class(), "{cmd}");
    });
    assert_eq!(moved, 0);
}
