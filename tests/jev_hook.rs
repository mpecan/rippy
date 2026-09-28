//! End-to-end: the `rippy-jev` hook binary against a mock System One endpoint
//! on loopback. Each test runs with an isolated `HOME` and an explicit
//! `--config`, so nothing from the developer's machine leaks in.

#![cfg(feature = "jev")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use serde_json::{Value, json};

/// A request the mock endpoint received.
struct Received {
    authorization: String,
    body: Value,
}

/// Serve one HTTP response on a loopback port; report what was received.
/// `delay` holds the response back, for the timeout case.
fn serve_once(status: u16, body: Value, delay: Duration) -> (String, mpsc::Receiver<Received>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}/v1/systemone", listener.local_addr().unwrap());
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let Ok((stream, _)) = listener.accept() else {
            return;
        };
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let (mut length, mut authorization) = (0, String::new());
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let line = line.trim_end();
            if line.is_empty() {
                break;
            }
            let (name, value) = line.split_once(':').unwrap_or((line, ""));
            match name.to_ascii_lowercase().as_str() {
                "content-length" => length = value.trim().parse().unwrap(),
                "authorization" => value.trim().clone_into(&mut authorization),
                _ => {}
            }
        }
        let mut raw = vec![0; length];
        reader.read_exact(&mut raw).unwrap();
        let _ = tx.send(Received {
            authorization,
            body: serde_json::from_slice(&raw).unwrap(),
        });
        thread::sleep(delay);
        let text = body.to_string();
        let mut stream = stream;
        let _ = write!(
            stream,
            "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{text}",
            text.len()
        );
    });
    (endpoint, rx)
}

fn answers(effect: &str, confidence: f64, exfiltration: f64) -> Value {
    let mut probabilities = json!({
        "read_only": 0.0, "remote_read": 0.0, "local_change": 0.0,
        "destructive": 0.0, "network_send": 0.0, "download_execute": 0.0
    });
    probabilities[effect] = json!(confidence);
    json!({
        "model": "typesafe/jev-1.13-20260917",
        "answers": {
            "effect": { "type": "choice", "choice": effect,
                        "probabilities": probabilities, "confidence": confidence },
            "exfiltration": { "type": "noul", "noul": exfiltration },
            "writes_outside_project": { "type": "noul", "noul": 0.04 },
            "reads_secrets": { "type": "noul", "noul": 0.03 },
            "irreversible": { "type": "noul", "noul": 0.02 },
            "self_referential": { "type": "noul", "noul": 0.05 }
        },
        "usage": { "input_tokens": 900, "output_tokens": 150 }
    })
}

/// Run the hook in an isolated directory with `[jev]` pointed at `endpoint`.
fn hook(dir: &Path, endpoint: &str, command: &str, permission_mode: &str) -> Value {
    let config = dir.join("jev.toml");
    std::fs::write(
        &config,
        format!(
            "[jev]\nenabled = true\nendpoint = \"{endpoint}\"\n\
             api-key-env = \"RIPPY_E2E_JEV_KEY\"\ntimeout-ms = 400\n"
        ),
    )
    .unwrap();
    let payload = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command },
        "permission_mode": permission_mode,
    });
    let mut child = Command::new(common::rippy_binary())
        .args(["--mode", "claude", "--config"])
        .arg(&config)
        .current_dir(dir)
        .env("HOME", dir)
        .env("RIPPY_E2E_JEV_KEY", "e2e-secret-key")
        .env_remove("RIPPY_CONFIG")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.to_string().as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!("{e}: {}", String::from_utf8_lossy(&out.stdout));
    })
}

fn decision(out: &Value) -> (&str, &str) {
    let inner = &out["hookSpecificOutput"];
    (
        inner["permissionDecision"].as_str().unwrap_or(""),
        inner["permissionDecisionReason"].as_str().unwrap_or(""),
    )
}

#[test]
fn a_confident_read_only_answer_approves() {
    let dir = tempfile::tempdir().unwrap();
    let (endpoint, rx) = serve_once(200, answers("read_only", 0.97, 0.03), Duration::ZERO);
    let out = hook(
        dir.path(),
        &endpoint,
        "rippy-e2e-cli list --json",
        "default",
    );
    let (d, reason) = decision(&out);
    assert_eq!(d, "allow", "{out}");
    assert!(
        reason.starts_with("jev: approved (read_only, conf 0.97"),
        "{reason}"
    );
    let req = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(req.authorization, "Bearer e2e-secret-key");
    assert_eq!(req.body["model"], "jev-1.13");
    assert_eq!(req.body["state"]["command"], "rippy-e2e-cli list --json");
    assert_eq!(req.body["state"]["uncertainty_kind"], "unknown-command");
}

#[test]
fn exfiltration_forces_a_prompt_even_in_auto_mode() {
    let dir = tempfile::tempdir().unwrap();
    let (endpoint, _rx) = serve_once(200, answers("network_send", 0.9, 0.93), Duration::ZERO);
    let out = hook(dir.path(), &endpoint, "rippy-e2e-cli upload --all", "auto");
    let (d, reason) = decision(&out);
    assert_eq!(d, "ask", "{out}");
    assert!(
        reason.starts_with("⚠ jev: possible exfiltration"),
        "{reason}"
    );
}

#[test]
fn an_uncertain_ask_still_defers_in_auto_mode_when_jev_keeps_it() {
    let dir = tempfile::tempdir().unwrap();
    let (endpoint, _rx) = serve_once(200, answers("local_change", 0.99, 0.02), Duration::ZERO);
    let out = hook(dir.path(), &endpoint, "rippy-e2e-cli fmt", "auto");
    assert_eq!(decision(&out).0, "defer", "{out}");
}

#[test]
fn a_server_error_leaves_the_ask() {
    let dir = tempfile::tempdir().unwrap();
    let (endpoint, _rx) = serve_once(500, json!({ "error": "boom" }), Duration::ZERO);
    let out = hook(dir.path(), &endpoint, "rippy-e2e-cli list", "default");
    let (d, reason) = decision(&out);
    assert_eq!(d, "ask", "{out}");
    assert!(reason.contains("(jev unavailable: HTTP 500)"), "{reason}");
}

#[test]
fn a_slow_endpoint_times_out_and_leaves_the_ask() {
    let dir = tempfile::tempdir().unwrap();
    let (endpoint, _rx) = serve_once(
        200,
        answers("read_only", 0.99, 0.01),
        Duration::from_secs(3),
    );
    let started = std::time::Instant::now();
    let out = hook(dir.path(), &endpoint, "rippy-e2e-cli list", "default");
    let (d, reason) = decision(&out);
    assert_eq!(d, "ask", "{out}");
    assert!(reason.contains("jev unavailable: timed out"), "{reason}");
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[test]
fn an_approval_ask_never_contacts_the_endpoint() {
    let dir = tempfile::tempdir().unwrap();
    let (endpoint, rx) = serve_once(200, answers("read_only", 0.99, 0.01), Duration::ZERO);
    let out = hook(dir.path(), &endpoint, "rm -rf build", "default");
    let (d, reason) = decision(&out);
    assert_eq!(d, "ask", "{out}");
    assert!(!reason.contains("jev"), "{reason}");
    assert!(rx.recv_timeout(Duration::from_millis(300)).is_err());
}

#[test]
fn a_project_jev_section_is_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let (endpoint, rx) = serve_once(200, answers("read_only", 0.99, 0.01), Duration::ZERO);
    std::fs::create_dir_all(dir.path().join(".rippy")).unwrap();
    std::fs::write(
        dir.path().join(".rippy/config.toml"),
        "[settings]\ntrust-project-configs = true\n",
    )
    .unwrap();
    let project = dir.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join(".rippy.toml"),
        format!("[jev]\nenabled = true\nendpoint = \"{endpoint}\"\n"),
    )
    .unwrap();
    let payload = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "rippy-e2e-cli list" },
    });
    let mut child = Command::new(common::rippy_binary())
        .args(["--mode", "claude"])
        .current_dir(&project)
        .env("HOME", dir.path())
        .env("OPENROUTER_API_KEY", "must-not-leak")
        .env_remove("RIPPY_CONFIG")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.to_string().as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let stdout: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(decision(&stdout).0, "ask", "{stdout}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("ignoring [jev] in a project config"));
    assert!(rx.recv_timeout(Duration::from_millis(300)).is_err());
}

#[test]
fn version_names_the_distribution() {
    let out = Command::new(common::rippy_binary())
        .arg("--version")
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&out.stdout)
            .trim_end()
            .ends_with("+jev")
    );
}
