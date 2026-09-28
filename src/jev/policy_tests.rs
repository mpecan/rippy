#![allow(clippy::unwrap_used)]

use serde_json::json;

use super::*;

/// A confident, clean read-only answer: approved under the defaults.
fn clean() -> Answers {
    Answers {
        effect: Effect::ReadOnly,
        confidence: 0.97,
        network_send: 0.0,
        download_execute: 0.0,
        exfiltration: 0.05,
        writes_outside_project: 0.05,
        reads_secrets: 0.05,
        irreversible: 0.03,
        self_referential: 0.05,
    }
}

fn settings() -> JevSettings {
    JevSettings::default()
}

#[test]
fn clean_read_only_is_approved() {
    assert_eq!(
        decide(&clean(), &settings()),
        Outcome::Approve {
            effect: Effect::ReadOnly,
            confidence: 0.97
        }
    );
}

#[test]
fn exfiltration_at_threshold_escalates() {
    let a = Answers {
        exfiltration: 0.5,
        ..clean()
    };
    assert_eq!(
        decide(&a, &settings()),
        Outcome::Exfiltration { probability: 0.5 }
    );
    let a = Answers {
        exfiltration: 0.49,
        ..clean()
    };
    assert!(matches!(decide(&a, &settings()), Outcome::Approve { .. }));
}

#[test]
fn network_effects_escalate_even_without_the_exfiltration_noul() {
    for a in [
        Answers {
            network_send: 0.5,
            ..clean()
        },
        Answers {
            download_execute: 0.6,
            ..clean()
        },
    ] {
        assert!(matches!(
            decide(&a, &settings()),
            Outcome::Exfiltration { .. }
        ));
    }
}

#[test]
fn exfiltration_wins_over_steering() {
    let a = Answers {
        exfiltration: 0.9,
        self_referential: 0.99,
        ..clean()
    };
    assert!(matches!(
        decide(&a, &settings()),
        Outcome::Exfiltration { .. }
    ));
}

#[test]
fn steering_at_threshold_is_not_trusted() {
    let a = Answers {
        self_referential: 0.3,
        ..clean()
    };
    assert_eq!(
        decide(&a, &settings()),
        Outcome::Steered { probability: 0.3 }
    );
}

#[test]
fn confidence_below_minimum_keeps() {
    let a = Answers {
        confidence: 0.89,
        ..clean()
    };
    assert!(matches!(decide(&a, &settings()), Outcome::Keep { .. }));
    let a = Answers {
        confidence: 0.9,
        ..clean()
    };
    assert!(matches!(decide(&a, &settings()), Outcome::Approve { .. }));
}

#[test]
fn each_risk_gate_blocks_approval_at_its_maximum() {
    for a in [
        Answers {
            irreversible: 0.2,
            ..clean()
        },
        Answers {
            writes_outside_project: 0.3,
            ..clean()
        },
        Answers {
            reads_secrets: 0.3,
            ..clean()
        },
    ] {
        assert!(
            matches!(decide(&a, &settings()), Outcome::Keep { .. }),
            "{a:?}"
        );
    }
}

#[test]
fn local_change_needs_opt_in() {
    let a = Answers {
        effect: Effect::LocalChange,
        ..clean()
    };
    assert!(matches!(decide(&a, &settings()), Outcome::Keep { .. }));
    let opted_in = JevSettings {
        allow_effects: vec![Effect::ReadOnly, Effect::LocalChange],
        ..settings()
    };
    assert!(matches!(decide(&a, &opted_in), Outcome::Approve { .. }));
}

// Validation rejects these in config, but the policy must not rely on it.
#[test]
fn destructive_is_never_approved_even_if_listed() {
    let a = Answers {
        effect: Effect::Destructive,
        ..clean()
    };
    let s = JevSettings {
        allow_effects: vec![Effect::Destructive],
        ..settings()
    };
    assert!(matches!(decide(&a, &s), Outcome::Keep { .. }));
}

fn response() -> serde_json::Value {
    json!({
        "effect": {
            "type": "choice",
            "choice": "read_only",
            "probabilities": {
                "read_only": 0.97, "remote_read": 0.01, "local_change": 0.01,
                "destructive": 0.0, "network_send": 0.01, "download_execute": 0.0
            },
            "confidence": 0.95
        },
        "exfiltration": { "type": "noul", "noul": 0.04 },
        "writes_outside_project": { "type": "noul", "noul": 0.05 },
        "reads_secrets": { "type": "noul", "noul": 0.03 },
        "irreversible": { "type": "noul", "noul": 0.02 },
        "self_referential": { "type": "noul", "noul": 0.06 }
    })
}

#[test]
fn parses_a_system_one_response() {
    let a = Answers::parse(&response()).unwrap();
    assert_eq!(a.effect, Effect::ReadOnly);
    assert!((a.confidence - 0.95).abs() < f64::EPSILON);
    assert!((a.network_send - 0.01).abs() < f64::EPSILON);
    assert!((a.reads_secrets - 0.03).abs() < f64::EPSILON);
}

#[test]
fn malformed_responses_are_rejected() {
    let mut missing = response();
    missing.as_object_mut().unwrap().remove("reads_secrets");
    assert!(
        Answers::parse(&missing)
            .unwrap_err()
            .contains("reads_secrets")
    );

    let mut unknown = response();
    unknown["effect"]["choice"] = json!("reboot");
    assert!(Answers::parse(&unknown).is_err());

    let mut out_of_range = response();
    out_of_range["exfiltration"]["noul"] = json!(1.5);
    assert!(Answers::parse(&out_of_range).is_err());

    let mut stringly = response();
    stringly["effect"]["confidence"] = json!("0.99");
    assert!(Answers::parse(&stringly).is_err());

    assert!(Answers::parse(&json!(null)).is_err());
}
