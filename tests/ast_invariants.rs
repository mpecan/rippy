//! AST-integrity invariants for rippy's rable wrapper.
//!
//! These tests assert structural properties of the parsed AST, not verdicts.
//! They exist to catch regressions where a future rable bump silently
//! restructures the tree (e.g., a substitution body that was a structured
//! `Command` becomes an opaque `Word`) in a way rippy's analyzer walker
//! wouldn't notice, because the verdict might still look right for the
//! specific inputs the integration suite happens to cover.
//!
//! Added during the rable 0.1.13 → 0.1.15 upgrade to lock in the fixes from
//! rable issues #26 (heredoc paren tracking) and #29/#30/#31 (fork-and-merge
//! parsing of `$(...)`, `` `...` ``, and `<(...)` / `>(...)`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

use rable::{Node, NodeKind};
use rippy_cli::ast;
use rippy_cli::parser::BashParser;

fn parse(source: &str) -> Vec<Node> {
    let mut parser = BashParser::new().expect("BashParser::new is infallible");
    parser
        .parse(source)
        .unwrap_or_else(|e| panic!("parse failed for {source:?}: {e}"))
}

/// Depth-first walk, calling `visit` on every node in the tree.
fn walk<'a>(node: &'a Node, visit: &mut dyn FnMut(&'a Node)) {
    visit(node);
    match &node.kind {
        NodeKind::Command {
            words, redirects, ..
        } => {
            for w in words {
                walk(w, visit);
            }
            for r in redirects {
                walk(r, visit);
            }
        }
        NodeKind::Pipeline { commands, .. } => {
            for c in commands {
                walk(c, visit);
            }
        }
        NodeKind::List { items } => {
            for item in items {
                walk(&item.command, visit);
            }
        }
        NodeKind::If {
            condition,
            then_body,
            else_body,
            redirects,
        } => {
            walk(condition, visit);
            walk(then_body, visit);
            if let Some(eb) = else_body.as_deref() {
                walk(eb, visit);
            }
            for r in redirects {
                walk(r, visit);
            }
        }
        NodeKind::While {
            condition,
            body,
            redirects,
        }
        | NodeKind::Until {
            condition,
            body,
            redirects,
        } => {
            walk(condition, visit);
            walk(body, visit);
            for r in redirects {
                walk(r, visit);
            }
        }
        NodeKind::For {
            body, redirects, ..
        }
        | NodeKind::ForArith {
            body, redirects, ..
        }
        | NodeKind::Select {
            body, redirects, ..
        }
        | NodeKind::BraceGroup { body, redirects }
        | NodeKind::Subshell { body, redirects } => {
            walk(body, visit);
            for r in redirects {
                walk(r, visit);
            }
        }
        NodeKind::CommandSubstitution { command, .. }
        | NodeKind::ProcessSubstitution { command, .. } => {
            walk(command, visit);
        }
        NodeKind::Negation { pipeline } | NodeKind::Time { pipeline, .. } => {
            walk(pipeline, visit);
        }
        NodeKind::Word { parts, .. } => {
            for p in parts {
                walk(p, visit);
            }
        }
        NodeKind::Redirect { target, .. } => {
            walk(target, visit);
        }
        _ => {}
    }
}

fn tree_contains(nodes: &[Node], pred: &dyn Fn(&Node) -> bool) -> bool {
    let mut found = false;
    for n in nodes {
        walk(n, &mut |node| {
            if pred(node) {
                found = true;
            }
        });
    }
    found
}

// ---------------------------------------------------------------------------
// Invariant 1: every source-level expansion produces an expansion node.
//
// Catches future regressions where a rable bump drops a substitution into a
// raw `Word` without decomposing it into parts. `is_expansion_node` is the
// single source of truth rippy's analyzer uses to decide whether to Ask, so
// a substitution that fails this check silently bypasses the Ask floor.
// ---------------------------------------------------------------------------

#[test]
fn every_source_level_expansion_produces_expansion_node() {
    // Pairs of (input, short description) — all must produce at least one
    // node where `is_expansion_node` is true somewhere in the AST.
    let cases: &[&str] = &[
        "echo $(whoami)",
        "echo `whoami`",
        "cat <(echo hi)",
        "echo ${HOME}",
        "echo $((1 + 1))",
        "echo ${#v}",
        "echo ${!r}",
        "echo $'hello\\n'",
        "echo $\"hello\"",
        "echo {a,b,c}",
    ];
    for src in cases {
        let nodes = parse(src);
        let has_expansion = tree_contains(&nodes, &|n| ast::is_expansion_node(&n.kind));
        assert!(
            has_expansion,
            "expected an expansion node in the AST for {src:?}, found none"
        );
    }
}

// ---------------------------------------------------------------------------
// Invariant 2: heredoc in cmdsub produces a quoted HereDoc node.
//
// Direct lock for rable issue #26 — pre-0.1.14 the HereDoc node could be
// silently dropped when the body contained an unmatched `(`. Tests both the
// clean case and the previously-buggy unmatched-paren case, asserting both
// produce an AST containing a HereDoc with the expected content.
// ---------------------------------------------------------------------------

#[test]
fn heredoc_in_cmdsub_produces_quoted_heredoc_node() {
    // Each case: (source, substring that must appear in the HereDoc.content).
    // We use a `contains`-check rather than exact equality because rable's
    // content-trimming semantics (trailing newline, tab stripping for `<<-`,
    // etc.) are incidental to the invariant we're pinning — what matters is
    // that the dangerous-token-containing body is visible as quoted heredoc
    // data, not that the bytes match exactly. This stays robust across
    // future rable content-normalization tweaks.
    let cases: &[(&str, &str)] = &[
        // Clean case — always worked.
        ("$(cat <<'EOF'\nx\nEOF\n)", "x"),
        // Unmatched-paren case — the rable #26 regression fixture. Pre-0.1.14
        // this could drop the HereDoc entirely.
        ("$(cat <<'EOF'\nfoo\n(bar\nEOF\n)", "(bar"),
    ];
    for (src, expected_substring) in cases {
        let nodes = parse(src);
        let found = tree_contains(&nodes, &|n| {
            matches!(
                &n.kind,
                NodeKind::HereDoc { quoted: true, content, .. }
                    if content.contains(expected_substring)
            )
        });
        assert!(
            found,
            "expected quoted HereDoc with content containing {expected_substring:?} in AST for {src:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Invariant 3: substitution bodies are structured, not raw words.
//
// Pre-fork-and-merge (before rable 0.1.15), a substitution body that tripped
// up the char-level paren balancer could end up as an opaque `Word` containing
// the raw source text. Post-fix, the real grammar parses the body, so the
// inner `command` of a CommandSubstitution / ProcessSubstitution is always
// a structured node (a Command, Pipeline, List, etc.) — not a bare Word.
// ---------------------------------------------------------------------------

#[test]
fn substitution_body_is_structured_not_raw_word() {
    let cases: &[&str] = &[
        "echo $(echo hi)",
        "echo `echo hi`",
        "cat <(echo hi)",
        "cat >(echo hi)",
    ];
    for src in cases {
        let nodes = parse(src);
        let mut checked = 0_usize;
        for root in &nodes {
            walk(root, &mut |n| {
                let inner = match &n.kind {
                    NodeKind::CommandSubstitution { command, .. }
                    | NodeKind::ProcessSubstitution { command, .. } => Some(command.as_ref()),
                    _ => None,
                };
                if let Some(body) = inner {
                    checked += 1;
                    assert!(
                        !matches!(body.kind, NodeKind::Word { .. }),
                        "substitution body was a raw Word (expected structured Command) for {src:?}"
                    );
                }
            });
        }
        assert!(
            checked > 0,
            "expected at least one substitution node in the AST for {src:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Invariant 4: `has_expansions` agrees with a textual scan for simple inputs.
//
// The AST walker (`has_expansions`) and the textual-scan fallback
// (`has_shell_expansion_pattern` at src/ast.rs:150, invoked when `Word.parts`
// is empty) must not disagree on inputs that don't contain expansions at all,
// and must agree on trivial `$()`/backtick/`${}`/`$VAR` presence.
//
// Catches a class of regression where 0.1.15 populates `Word.parts` where
// 0.1.13 left them empty (or vice versa) and shifts detection semantics.
// ---------------------------------------------------------------------------

#[test]
fn has_expansions_agrees_on_simple_inputs() {
    // (input, expected has_expansions for the first top-level node)
    let cases: &[(&str, bool)] = &[
        // No expansions.
        ("echo hello", false),
        ("ls -la /tmp", false),
        ("cat file.txt", false),
        // Expansions.
        ("echo $(whoami)", true),
        ("echo `whoami`", true),
        ("echo ${HOME}", true),
        ("echo $HOME", true),
    ];
    for (src, expected) in cases {
        let nodes = parse(src);
        assert!(!nodes.is_empty(), "parse produced no nodes for {src:?}");
        let actual = ast::has_expansions(&nodes[0]);
        assert_eq!(
            actual, *expected,
            "has_expansions({src:?}) = {actual}, expected {expected}"
        );
    }
}
