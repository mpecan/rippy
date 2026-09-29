//! Jev-assisted review of uncertain asks, compiled only with `--features jev`.
//!
//! [`review`] is the single entry point. It never produces `Deny`, never
//! touches an `Allow`, `Deny` or approval ask, and leaves the verdict's
//! decision unchanged on any failure. See docs/jev.md#scope-and-guarantees.

pub mod cmd;
pub mod eligibility;
pub mod facts;
pub mod policy;
pub mod request;
pub mod shape;
pub mod transport;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::jev_settings::JevSettings;
use crate::parser::BashParser;
use crate::verdict::{AllowReason, Verdict};
use facts::Places;
use policy::{Answers, Outcome};
use shape::Shape;
use transport::Transport;

/// Largest request body sent. The hosted model caps input at 32k tokens, and
/// a command this large is not one a quick classification should be trusted on.
const MAX_BODY_BYTES: usize = 64 * 1024;

/// The environment a review runs in, injectable for tests.
pub struct Env<'a> {
    pub cwd: &'a Path,
    pub home: Option<PathBuf>,
    pub var: &'a dyn Fn(&str) -> Option<String>,
}

/// The result of a review.
#[derive(Debug)]
pub struct Review {
    pub verdict: Verdict,
    /// Emit `ask` even where `auto-mode = defer` would hand the decision to
    /// the agent's own auto mode: Jev saw something a human should look at.
    pub force_prompt: bool,
    /// What happened, for the JSON log and `rippy jev`. `None` when Jev is
    /// disabled.
    pub log: Option<Value>,
}

impl Review {
    const fn unchanged(verdict: Verdict) -> Self {
        Self {
            verdict,
            force_prompt: false,
            log: None,
        }
    }
}

/// Review one hook verdict.
pub fn review(
    verdict: Verdict,
    command: &str,
    settings: &JevSettings,
    env: &Env<'_>,
    transport: &dyn Transport,
) -> Review {
    if !settings.enabled {
        return Review::unchanged(verdict);
    }
    let Ok(nodes) = BashParser::new().and_then(|mut p| p.parse(command)) else {
        return skipped(verdict, "rippy could not parse the command");
    };
    let shape = Shape::of(command, &nodes);
    let kind = match eligibility::check(&verdict, &shape) {
        Ok(kind) => kind,
        Err(why) => return skipped(verdict, &why),
    };
    if let Err(problem) = settings.validate() {
        return unavailable(verdict, &problem, json!({ "kind": kind.as_str() }));
    }
    let Some(api_key) = (env.var)(&settings.api_key_env).filter(|k| !k.is_empty()) else {
        let problem = format!("${} is not set", settings.api_key_env);
        return unavailable(verdict, &problem, json!({ "kind": kind.as_str() }));
    };
    let path_var = (env.var)("PATH");
    let places = Places {
        project_root: Places::project_root(env.cwd),
        home: env.home.clone(),
        path_var: path_var.as_deref(),
    };
    let sanitized = shape.sanitized();
    let facts = facts::collect(
        &shape,
        &sanitized,
        &facts::Where {
            cwd: env.cwd,
            places: &places,
            lookup: env.var,
        },
        settings.context.as_deref(),
    );
    if facts::names_project_program(&facts) {
        return skipped(verdict, "a program resolves inside the project");
    }
    let state = request::state(
        &sanitized,
        request::uncertainty(kind),
        kind.as_str(),
        &facts,
    );
    let log = json!({
        "kind": kind.as_str(),
        "question_set": request::QUESTION_SET_VERSION,
        "state": state,
    });
    consult(verdict, log, settings, &api_key, transport)
}

/// Send one request for the state already in `log`, and apply the answer.
fn consult(
    verdict: Verdict,
    mut log: Value,
    settings: &JevSettings,
    api_key: &str,
    transport: &dyn Transport,
) -> Review {
    let body = request::body(&settings.model, &log["state"]);
    if body.to_string().len() > MAX_BODY_BYTES {
        return unavailable(verdict, "command too large to review", log);
    }
    let started = Instant::now();
    let timeout = Duration::from_millis(settings.timeout_ms);
    let response = transport.post(&settings.endpoint, api_key, &body, timeout);
    log["latency_ms"] = json!(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX));
    let response = match response {
        Ok(r) => r,
        Err(problem) => return unavailable(verdict, &problem, log),
    };
    log["answers"] = response["answers"].clone();
    let answers = match Answers::parse(&response["answers"]) {
        Ok(a) => a,
        Err(problem) => {
            return unavailable(verdict, &format!("malformed response: {problem}"), log);
        }
    };
    let model = response["model"]
        .as_str()
        .filter(|m| is_model_id(m))
        .unwrap_or(&settings.model)
        .to_owned();
    let outcome = policy::decide(&answers, settings);
    log["model"] = json!(model);
    log["outcome"] = json!(outcome.label());
    let (verdict, force_prompt) = apply(verdict, &outcome, &model, settings);
    Review {
        verdict,
        force_prompt,
        log: Some(log),
    }
}

fn skipped(verdict: Verdict, why: &str) -> Review {
    Review {
        verdict,
        force_prompt: false,
        log: Some(json!({ "skipped": why })),
    }
}

fn unavailable(mut verdict: Verdict, problem: &str, mut log: Value) -> Review {
    verdict.reason = format!("{} (jev unavailable: {problem})", verdict.reason);
    log["unavailable"] = json!(problem);
    Review {
        verdict,
        force_prompt: false,
        log: Some(log),
    }
}

/// Whether a response's model id is safe to echo into a reason.
fn is_model_id(model: &str) -> bool {
    !model.is_empty()
        && model.len() <= 80
        && model
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '/' | ':' | '~'))
}

fn apply(verdict: Verdict, outcome: &Outcome, model: &str, s: &JevSettings) -> (Verdict, bool) {
    let resolved = verdict.resolved_command.clone();
    let tag = format!("{model} {}", request::QUESTION_SET_VERSION);
    let asked = |reason: String| Verdict::ask(reason).with_optional_resolution(resolved.clone());
    match outcome {
        Outcome::Approve { effect, confidence } => {
            let reason = AllowReason::Model {
                model: tag,
                summary: format!(
                    "{}, conf {confidence:.2} >= {:.2}",
                    effect.as_str(),
                    s.min_confidence
                ),
            };
            (
                Verdict::allow(reason).with_optional_resolution(resolved),
                false,
            )
        }
        Outcome::Exfiltration { probability } => {
            let reason = format!(
                "⚠ jev: possible exfiltration (p={probability:.2}, {tag}) — {}",
                verdict.reason
            );
            (asked(reason), true)
        }
        Outcome::Steered { probability } => {
            let reason = format!(
                "{} (jev: the command text tries to steer its classification, \
                 p={probability:.2}, {tag})",
                verdict.reason
            );
            (asked(reason), true)
        }
        Outcome::Keep {
            effect,
            confidence,
            because,
        } => {
            let mut kept = verdict;
            kept.reason = format!(
                "{} (jev: {}, conf {confidence:.2}; kept: {because}; {tag})",
                kept.reason,
                effect.as_str()
            );
            (kept, false)
        }
    }
}

#[cfg(test)]
#[path = "review_tests.rs"]
mod tests;
