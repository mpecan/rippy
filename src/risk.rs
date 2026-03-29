//! Risk classification for command groups.

use serde::Serialize;

use crate::allowlists;

const CRITICAL_COMMANDS: &[&str] = &[
    "sudo",
    "su",
    "doas",
    "eval",
    "exec",
    "source",
    "chmod",
    "chown",
    "chgrp",
    "mkfs",
    "dd",
    "fdisk",
    "iptables",
    "systemctl",
    "service",
];

const HIGH_COMMANDS: &[&str] = &[
    "rm", "rmdir", "mv", "cp", "install", "docker", "podman", "kubectl", "pip", "pip3", "npm",
    "yarn", "pnpm", "gem", "curl", "wget", "ssh", "scp", "rsync", "kill", "killall", "pkill",
    "mount", "umount",
];

/// Read-only subcommands of tools that are otherwise medium/high risk.
const SAFE_SUBCOMMANDS: &[&str] = &[
    "git status",
    "git log",
    "git diff",
    "git show",
    "git branch",
    "git remote",
    "git stash list",
    "git tag",
    "docker ps",
    "docker images",
    "docker inspect",
    "cargo check",
    "cargo test",
    "cargo clippy",
    "cargo fmt",
    "cargo build",
    "cargo doc",
    "npm test",
    "npm run",
    "kubectl get",
    "kubectl describe",
];

/// Risk level for a suggested rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// Classify a command group key into a risk level.
#[must_use]
pub fn classify(group_key: &str) -> RiskLevel {
    // Check safe subcommands first (e.g. "docker ps" is low even though "docker" is high).
    if SAFE_SUBCOMMANDS.contains(&group_key) {
        return RiskLevel::Low;
    }

    let cmd = group_key.split_whitespace().next().unwrap_or("");

    if CRITICAL_COMMANDS.contains(&cmd) {
        return RiskLevel::Critical;
    }
    if HIGH_COMMANDS.contains(&cmd) {
        return RiskLevel::High;
    }
    if allowlists::is_simple_safe(cmd) {
        return RiskLevel::Low;
    }
    RiskLevel::Medium
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn critical_commands() {
        assert_eq!(classify("sudo"), RiskLevel::Critical);
        assert_eq!(classify("eval"), RiskLevel::Critical);
        assert_eq!(classify("chmod"), RiskLevel::Critical);
    }

    #[test]
    fn high_commands() {
        assert_eq!(classify("rm"), RiskLevel::High);
        assert_eq!(classify("docker"), RiskLevel::High);
        assert_eq!(classify("curl"), RiskLevel::High);
        assert_eq!(classify("npm"), RiskLevel::High);
    }

    #[test]
    fn low_simple_safe() {
        assert_eq!(classify("ls"), RiskLevel::Low);
        assert_eq!(classify("cat"), RiskLevel::Low);
        assert_eq!(classify("grep"), RiskLevel::Low);
    }

    #[test]
    fn low_safe_subcommands() {
        assert_eq!(classify("git status"), RiskLevel::Low);
        assert_eq!(classify("git log"), RiskLevel::Low);
        assert_eq!(classify("cargo test"), RiskLevel::Low);
        assert_eq!(classify("docker ps"), RiskLevel::Low);
    }

    #[test]
    fn medium_default() {
        assert_eq!(classify("make"), RiskLevel::Medium);
        assert_eq!(classify("git push"), RiskLevel::Medium);
        assert_eq!(classify("unknown-tool"), RiskLevel::Medium);
    }
}
