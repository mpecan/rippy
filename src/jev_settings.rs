//! The `[jev]` config section. Always compiled so a default build can recognise
//! the section and say it has no Jev support; only the `jev` feature acts on it.
//! See docs/jev.md#configuration.

use serde::Deserialize;

/// The effect classes Jev chooses between. Approval is only ever possible for
/// the ones listed in [`JevSettings::allow_effects`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    ReadOnly,
    RemoteRead,
    LocalChange,
    Destructive,
    NetworkSend,
    DownloadExecute,
}

impl Effect {
    /// Every effect, in the order the question set offers them.
    pub const ALL: [Self; 6] = [
        Self::ReadOnly,
        Self::RemoteRead,
        Self::LocalChange,
        Self::Destructive,
        Self::NetworkSend,
        Self::DownloadExecute,
    ];

    /// The option key sent to and returned by Jev.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::RemoteRead => "remote_read",
            Self::LocalChange => "local_change",
            Self::Destructive => "destructive",
            Self::NetworkSend => "network_send",
            Self::DownloadExecute => "download_execute",
        }
    }

    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|e| e.as_str() == name)
    }

    /// Whether this effect may ever be listed in `allow-effects`.
    #[must_use]
    pub const fn is_approvable(self) -> bool {
        matches!(self, Self::ReadOnly | Self::RemoteRead | Self::LocalChange)
    }
}

/// Settings for Jev-assisted review. Honoured only from the global config or
/// the `--config` override, never from a project config.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct JevSettings {
    pub enabled: bool,
    /// A System One endpoint: the hosted API of either provider, or a proxy.
    pub endpoint: String,
    pub model: String,
    /// Name of the environment variable holding the API key. The key itself is
    /// never read from a config file.
    pub api_key_env: String,
    pub timeout_ms: u64,
    pub allow_effects: Vec<Effect>,
    /// Minimum `effect` confidence for an approval.
    pub min_confidence: f64,
    /// `exfiltration` probability at or above which the ask is escalated.
    pub exfiltration_threshold: f64,
    /// `self_referential` probability at or above which Jev is not trusted.
    pub steer_threshold: f64,
    /// Maximum `irreversible` probability for an approval.
    pub max_irreversible: f64,
    /// Maximum `writes_outside_project` probability for an approval.
    pub max_writes_outside: f64,
    /// Maximum `reads_secrets` probability for an approval.
    pub max_reads_secrets: f64,
    /// Optional description of this machine's environment, sent as a fact.
    pub context: Option<String>,
}

impl Default for JevSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: "https://openrouter.ai/api/v1/systemone".to_owned(),
            model: "jev-1.13".to_owned(),
            api_key_env: "OPENROUTER_API_KEY".to_owned(),
            timeout_ms: 2000,
            allow_effects: vec![Effect::ReadOnly],
            min_confidence: 0.9,
            exfiltration_threshold: 0.5,
            steer_threshold: 0.3,
            max_irreversible: 0.2,
            max_writes_outside: 0.3,
            max_reads_secrets: 0.3,
            context: None,
        }
    }
}

impl JevSettings {
    /// Reject settings that would make the feature unsafe or meaningless. A
    /// problem here keeps every ask untouched; it never fails the hook.
    ///
    /// # Errors
    ///
    /// Returns a human-readable description of the first problem found.
    pub fn validate(&self) -> Result<(), String> {
        if !endpoint_is_allowed(&self.endpoint) {
            return Err(format!(
                "endpoint must be https:// (http:// only for localhost): {}",
                self.endpoint
            ));
        }
        if let Some(bad) = self.allow_effects.iter().find(|e| !e.is_approvable()) {
            return Err(format!("allow-effects may not include {}", bad.as_str()));
        }
        let thresholds = [
            ("min-confidence", self.min_confidence),
            ("exfiltration-threshold", self.exfiltration_threshold),
            ("steer-threshold", self.steer_threshold),
            ("max-irreversible", self.max_irreversible),
            ("max-writes-outside", self.max_writes_outside),
            ("max-reads-secrets", self.max_reads_secrets),
        ];
        if let Some((name, value)) = thresholds.iter().find(|(_, v)| !(0.0..=1.0).contains(v)) {
            return Err(format!("{name} must be between 0 and 1, got {value}"));
        }
        if self.timeout_ms == 0 {
            return Err("timeout-ms must be positive".to_owned());
        }
        Ok(())
    }
}

fn endpoint_is_allowed(endpoint: &str) -> bool {
    if endpoint.starts_with("https://") {
        return true;
    }
    let Some(rest) = endpoint.strip_prefix("http://") else {
        return false;
    };
    let host = rest.split(['/', '?']).next().unwrap_or("");
    let host = host.rsplit_once(':').map_or(host, |(h, port)| {
        if port.chars().all(|c| c.is_ascii_digit()) {
            h
        } else {
            host
        }
    });
    matches!(host, "localhost" | "127.0.0.1" | "[::1]")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid_and_disabled() {
        let s = JevSettings::default();
        assert!(!s.enabled);
        assert_eq!(s.allow_effects, [Effect::ReadOnly]);
        assert_eq!(s.validate(), Ok(()));
    }

    #[test]
    fn http_only_for_loopback() {
        for ok in [
            "https://openrouter.ai/api/v1/systemone",
            "http://localhost:8080/v1/systemone",
            "http://127.0.0.1:9/x",
            "http://[::1]:9/x",
        ] {
            assert!(endpoint_is_allowed(ok), "{ok}");
        }
        for bad in [
            "http://openrouter.ai/api/v1/systemone",
            "http://localhost.evil.com/x",
            "http://127.0.0.1.evil.com:80/x",
            "http://localhost:1@evil.example/x",
            "http://127.0.0.1:80@evil.example/",
            "http://[::1]:9@evil.example/",
            "ftp://localhost/x",
            "openrouter.ai",
        ] {
            assert!(!endpoint_is_allowed(bad), "{bad}");
        }
    }

    #[test]
    fn dangerous_effects_cannot_be_approvable() {
        let s = JevSettings {
            allow_effects: vec![Effect::ReadOnly, Effect::Destructive],
            ..JevSettings::default()
        };
        assert!(s.validate().unwrap_err().contains("destructive"));
        let s = JevSettings {
            allow_effects: vec![Effect::NetworkSend],
            ..JevSettings::default()
        };
        assert!(s.validate().is_err());
    }

    #[test]
    fn thresholds_must_be_probabilities() {
        let s = JevSettings {
            min_confidence: 1.5,
            ..JevSettings::default()
        };
        assert!(s.validate().unwrap_err().contains("min-confidence"));
        let s = JevSettings {
            exfiltration_threshold: f64::NAN,
            ..JevSettings::default()
        };
        assert!(s.validate().is_err());
    }

    #[test]
    fn every_threshold_must_be_a_probability() {
        type Set = fn(&mut JevSettings, f64);
        let setters: [(&str, Set); 6] = [
            ("min-confidence", |s, v| {
                s.min_confidence = v;
            }),
            ("exfiltration-threshold", |s, v| {
                s.exfiltration_threshold = v;
            }),
            ("steer-threshold", |s, v| {
                s.steer_threshold = v;
            }),
            ("max-irreversible", |s, v| {
                s.max_irreversible = v;
            }),
            ("max-writes-outside", |s, v| {
                s.max_writes_outside = v;
            }),
            ("max-reads-secrets", |s, v| {
                s.max_reads_secrets = v;
            }),
        ];
        for (name, set) in setters {
            for bad in [-0.1, 1.1, f64::NAN] {
                let mut s = JevSettings::default();
                set(&mut s, bad);
                assert!(s.validate().unwrap_err().contains(name), "{name}={bad}");
            }
        }
    }

    #[test]
    fn timeout_must_be_positive() {
        let s = JevSettings {
            timeout_ms: 0,
            ..JevSettings::default()
        };
        assert!(s.validate().unwrap_err().contains("timeout-ms"));
    }

    #[test]
    fn effect_names_round_trip() {
        for e in Effect::ALL {
            assert_eq!(Effect::parse(e.as_str()), Some(e));
        }
        assert_eq!(Effect::parse("reboot"), None);
    }

    #[test]
    fn parses_kebab_case_and_rejects_unknown_keys() {
        let s: JevSettings = toml::from_str(
            "enabled = true\n\
             allow-effects = [\"read_only\", \"local_change\"]\n\
             min-confidence = 0.95",
        )
        .unwrap();
        assert!(s.enabled);
        assert_eq!(s.allow_effects, [Effect::ReadOnly, Effect::LocalChange]);
        assert!(toml::from_str::<JevSettings>("min_confidance = 0.5").is_err());
    }
}
