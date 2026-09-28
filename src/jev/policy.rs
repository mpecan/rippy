//! Turns Jev's answers into an outcome. Pure and deterministic: the thresholds
//! come from [`JevSettings`], and nothing here touches the network.
//! See docs/jev.md#policy.

use serde_json::Value;

use crate::jev_settings::{Effect, JevSettings};

/// Probability of `network_send` or `download_execute` at which the ask is
/// escalated regardless of the exfiltration noul.
const NETWORK_EFFECT_THRESHOLD: f64 = 0.5;

/// Largest probability on `destructive` an approval tolerates, whatever the
/// chosen effect: a split answer is not a confident one.
const MAX_DESTRUCTIVE: f64 = 0.2;

/// Jev's answers to the question set, validated.
#[derive(Debug, Clone, PartialEq)]
pub struct Answers {
    pub effect: Effect,
    pub confidence: f64,
    /// The probability Jev put on the effect it chose.
    pub chosen: f64,
    pub destructive: f64,
    pub network_send: f64,
    pub download_execute: f64,
    pub exfiltration: f64,
    pub writes_outside_project: f64,
    pub reads_secrets: f64,
    pub irreversible: f64,
    pub self_referential: f64,
}

impl Answers {
    /// Parse the `answers` object of a System One response.
    ///
    /// # Errors
    ///
    /// Returns a description when an answer is missing, of the wrong type, or
    /// not a probability. A malformed response never approves anything.
    pub fn parse(answers: &Value) -> Result<Self, String> {
        let effect_answer = &answers["effect"];
        let choice = effect_answer["choice"]
            .as_str()
            .ok_or("missing effect.choice")?;
        let effect = Effect::parse(choice).ok_or_else(|| format!("unknown effect {choice:?}"))?;
        let option = |name: &str| probability(&effect_answer["probabilities"][name], name);
        Ok(Self {
            effect,
            confidence: probability(&effect_answer["confidence"], "effect.confidence")?,
            chosen: option(effect.as_str())?,
            destructive: option(Effect::Destructive.as_str())?,
            network_send: option(Effect::NetworkSend.as_str())?,
            download_execute: option(Effect::DownloadExecute.as_str())?,
            exfiltration: noul(answers, "exfiltration")?,
            writes_outside_project: noul(answers, "writes_outside_project")?,
            reads_secrets: noul(answers, "reads_secrets")?,
            irreversible: noul(answers, "irreversible")?,
            self_referential: noul(answers, "self_referential")?,
        })
    }
}

fn noul(answers: &Value, id: &str) -> Result<f64, String> {
    probability(&answers[id]["noul"], id)
}

fn probability(value: &Value, name: &str) -> Result<f64, String> {
    value
        .as_f64()
        .filter(|p| (0.0..=1.0).contains(p))
        .ok_or_else(|| format!("{name} is not a probability"))
}

/// What the answers mean for an uncertain ask.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// Local data may leave the machine: keep asking, warn, never defer.
    Exfiltration { probability: f64 },
    /// The command text argues for its own classification: keep asking,
    /// never defer, and do not trust the other answers.
    Steered { probability: f64 },
    /// Confident, approvable, and every risk gate passed.
    Approve { effect: Effect, confidence: f64 },
    /// Keep the ask, annotated with what Jev saw and the gate that held it.
    Keep {
        effect: Effect,
        confidence: f64,
        because: String,
    },
}

impl Outcome {
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Exfiltration { .. } => "exfiltration",
            Self::Steered { .. } => "steered",
            Self::Approve { .. } => "approve",
            Self::Keep { .. } => "keep",
        }
    }
}

/// Decide. The checks run in a fixed order and the first match wins, so an
/// exfiltration or steering signal is never outweighed by a confident effect.
#[must_use]
pub fn decide(a: &Answers, s: &JevSettings) -> Outcome {
    if a.exfiltration >= s.exfiltration_threshold
        || a.network_send >= NETWORK_EFFECT_THRESHOLD
        || a.download_execute >= NETWORK_EFFECT_THRESHOLD
    {
        let probability = a.exfiltration.max(a.network_send).max(a.download_execute);
        return Outcome::Exfiltration { probability };
    }
    if a.self_referential >= s.steer_threshold {
        return Outcome::Steered {
            probability: a.self_referential,
        };
    }
    let (effect, confidence) = (a.effect, a.confidence);
    let gates = [
        (
            s.allow_effects.contains(&effect) && effect.is_approvable(),
            format!("{} is not an allowed effect", effect.as_str()),
        ),
        (
            confidence >= s.min_confidence,
            format!("confidence {confidence:.2} < {:.2}", s.min_confidence),
        ),
        (
            a.chosen >= s.min_confidence,
            format!(
                "p({}) {:.2} < {:.2}",
                effect.as_str(),
                a.chosen,
                s.min_confidence
            ),
        ),
        (
            a.destructive < MAX_DESTRUCTIVE,
            format!("destructive {:.2}", a.destructive),
        ),
        (
            a.irreversible < s.max_irreversible,
            format!("irreversible {:.2}", a.irreversible),
        ),
        (
            a.writes_outside_project < s.max_writes_outside,
            format!("writes outside project {:.2}", a.writes_outside_project),
        ),
        (
            a.reads_secrets < s.max_reads_secrets,
            format!("reads secrets {:.2}", a.reads_secrets),
        ),
    ];
    match gates.into_iter().find(|(passed, _)| !passed) {
        None => Outcome::Approve { effect, confidence },
        Some((_, because)) => Outcome::Keep {
            effect,
            confidence,
            because,
        },
    }
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod tests;
