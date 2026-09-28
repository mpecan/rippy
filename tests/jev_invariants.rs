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
            "runs_project_code": noul(0.0),
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

// Review finding: wrappers hid a project-defined or approval command from the
// eligibility check. Wrapping a command must never make it approvable.
#[test]
fn wrapping_an_unreviewable_ask_never_makes_it_approvable() {
    let key = |name: &str| (name == "RIPPY_INVARIANT_KEY").then(|| "k".to_owned());
    let env = Env {
        cwd: Path::new("/tmp"),
        home: None,
        var: &key,
    };
    let settings = permissive();
    let approve = reply("read_only", 0.0);
    let mut analyzer = isolated_analyzer();
    let mut checked = 0;
    for case in common::catalog::load() {
        let base = analyzer.analyze(&case.command).unwrap();
        if base.decision != Decision::Ask || eligible_class(&base) {
            continue;
        }
        for wrapper in ["timeout 5", "nohup", "env", "nice -n 5", "command"] {
            let wrapped = format!("{wrapper} {}", case.command);
            let before = analyzer.analyze(&wrapped).unwrap();
            // An allow the analyzer itself returns (`env PATH=./bin ls`) is
            // not Jev's doing; Jev must never create one.
            if before.decision == Decision::Allow {
                continue;
            }
            let after = review(before, &wrapped, &settings, &env, &approve).verdict;
            assert_ne!(
                after.decision,
                Decision::Allow,
                "{wrapped}: approved by jev"
            );
            checked += 1;
        }
    }
    assert!(checked > 100, "only {checked} wrapped commands checked");
}

/// Every bypass the five reviews and the verification pass reported. Each was
/// once sent to Jev and approved by a fake that approves everything.
const REPORTED_BYPASSES: &[&str] = &[
    "timeout 5 ./scripts/x.sh",
    "env ./x",
    "nohup ./x",
    "nice ./x",
    "command ./x",
    "builtin ./x",
    "xargs ./x",
    "env -i ./x",
    "sh -c ./x",
    "bash -c \"./x --list\"",
    r"find . -exec ./x {} \;",
    "env -S ./x",
    ". ./x",
    "timeout 5 git frobnicate",
    "nohup rake db:drop",
    "timeout 9 tox -e lint",
    "uv run task",
    "poetry run deploy",
    "go run .",
    "watch ./x",
    "script -c ./x",
    "stdbuf -o0 ./x",
    "docker exec c somecli",
    "kubectl exec pod -- somecli",
    "git frobnicate; somecli",
    "rippy allow \"rm *\"",
    "rippy trust",
    "claude config set x",
    "export PATH=./bin; ls",
    "PATH=./bin somecli",
    "PATH=.:$PATH ls",
    "env PATH=./bin somecli",
    "hash -p ./evil ls; ls",
    "trap \"rm -rf ~\" EXIT",
    "export BASH_ENV=./x; bash -c ls",
    "sh -c \"$X\"",
    "bash $X",
    "python3 -c \"$X\"",
    "node -e \"$X\"",
    "env $X",
    "xargs $X",
    r"find . -exec $X \;",
    "git $X",
    "awk \"$X\"",
    "sed \"$X\" f",
    "sort --output=$X f",
    "sort -o$X f",
    "rg --pre=$X foo",
    "curl -o$X https://x",
    "dd if=/dev/zero of=$X",
    "timeout 5 $CMD",
    "python3 - < x.py",
    "(python3) < deploy.py",
    "{ python3; } < deploy.py",
    "(bash -s) <<< 'rm -rf ~'",
    "(python3; true) < deploy.py",
    "while read l; do python3; done < deploy.py",
    "if true; then python3; fi < deploy.py",
    "(python3) <<< 'import os'",
    "curl -s x | python3 -",
    "python3 -i deploy.py",
    "node -i -r ./x",
    "irb -r ./x",
    "kubectl get pods -n $U --kubeconfig=./x",
    "KUBECONFIG=./x kubectl get pods -n $U",
    "git --git-dir=./x log -n $U",
    "somecli < ~/.aws/credentials",
    "somecli list < /etc/shadow",
    "pipx run somecli",
    "coproc somecli",
    "timeout 5 mysql -e \"SELECT a-b FROM t; DROP TABLE tmp\"",
    "env xargs -0 -n 5",
    "eslint .",
    "jest",
    "cmake .",
    "pre-commit run",
    "direnv exec . somecli",
    "nix-shell --run somecli",
    "pulumi up",
    "mix test",
    "dotnet test",
    "fab deploy",
    "gulp",
    "nodemon",
    "tclsh deploy.tcl",
    "pypy -m mymod",
    "busybox sh x",
    "osascript -e 'do shell script \"id\"'",
    "pwsh -Command ls",
    "(( PATH=1 )) ; somecli list",
    "printf -v PATH 1 ; somecli list",
];

#[test]
fn no_reported_bypass_is_approved() {
    let key = |name: &str| (name == "RIPPY_INVARIANT_KEY").then(|| "k".to_owned());
    let env = Env {
        cwd: Path::new("/tmp"),
        home: None,
        var: &key,
    };
    let approve = reply("read_only", 0.0);
    let mut analyzer = isolated_analyzer();
    for command in REPORTED_BYPASSES {
        let before = analyzer.analyze(command).unwrap();
        if before.decision == Decision::Allow {
            continue;
        }
        let after = review(before, command, &permissive(), &env, &approve).verdict;
        assert_ne!(
            after.decision,
            Decision::Allow,
            "{command}: approved by jev"
        );
    }
}
