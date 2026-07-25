//! Metamorphic "never fail open" proptests (issue #168).
//!
//! Invariants 1-7 from the issue, each over a *generated* command grammar
//! rather than a fixed cross-product of curated strings. Invariant 8 (the
//! resolver `Literal` invariant) lives in-crate at `src/resolve_proptests.rs`
//! because `resolve::WordResolution` is crate-private.
//!
//! See docs/fuzzing.md.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod metamorphic;

use proptest::prelude::*;
use proptest::strategy::ValueTree;
use proptest::test_runner::TestRunner;
use rippy_cli::verdict::Decision;

use metamorphic::analyzer::isolated_analyzer;
use metamorphic::grammar::{
    Arg, CmdSpec, FLAGS, HANDLER_FORMS, INERT_ENV, Leaf, MAX_ARGS, MAX_STAGES, Op, Redirect,
    SAFE_LEAVES, Stage, TOKEN_ALPHABET, from_bytes, normalize_token, word_from_bytes,
};
use metamorphic::invariants;

fn arb_token() -> impl Strategy<Value = String> {
    prop::collection::vec(prop::sample::select(TOKEN_ALPHABET), 1..=8)
        .prop_map(|bytes| normalize_token(&String::from_utf8_lossy(&bytes)))
}

fn arb_arg() -> impl Strategy<Value = Arg> {
    prop_oneof![
        arb_token().prop_map(Arg::Bare),
        (0..FLAGS.len()).prop_map(Arg::Flag),
        arb_token().prop_map(Arg::Path),
        arb_token().prop_map(Arg::SingleQuoted),
        arb_token().prop_map(Arg::DoubleQuoted),
        Just(Arg::Glob),
    ]
}

fn arb_leaf() -> impl Strategy<Value = Leaf> {
    prop_oneof![
        3 => (0..SAFE_LEAVES.len()).prop_map(Leaf::Simple),
        1 => (0..HANDLER_FORMS.len(), 0..8usize)
            .prop_map(|(base, sub)| Leaf::Handler { base, sub }),
    ]
}

fn arb_redirect() -> impl Strategy<Value = Option<Redirect>> {
    prop_oneof![
        6 => Just(None),
        1 => arb_token().prop_map(|t| Some(Redirect::Out(t))),
        1 => arb_token().prop_map(|t| Some(Redirect::Append(t))),
    ]
}

fn arb_stage() -> impl Strategy<Value = Stage> {
    (
        prop::option::weighted(0.25, 0..INERT_ENV.len()),
        prop::option::weighted(
            0.25,
            prop::sample::select(rippy_cli::allowlists::all_wrappers()),
        ),
        arb_leaf(),
        prop::collection::vec(arb_arg(), 0..=MAX_ARGS),
        arb_redirect(),
    )
        .prop_map(|(env_prefix, wrapper, leaf, args, redirect)| Stage {
            env_prefix,
            wrapper,
            leaf,
            args,
            redirect,
        })
}

fn arb_op() -> impl Strategy<Value = Op> {
    prop_oneof![Just(Op::Semi), Just(Op::And), Just(Op::Or), Just(Op::Pipe)]
}

fn arb_spec() -> impl Strategy<Value = CmdSpec> {
    prop::collection::vec(arb_stage(), 1..=MAX_STAGES).prop_flat_map(|stages| {
        let n = stages.len() - 1;
        prop::collection::vec(arb_op(), n).prop_map(move |ops| CmdSpec {
            stages: stages.clone(),
            ops,
        })
    })
}

macro_rules! invariant_test {
    ($name:ident, $cases:expr, $invariant:path) => {
        invariant_test!($name, $cases, $invariant, |_: &CmdSpec| false);
    };
    ($name:ident, $cases:expr, $invariant:path, $skip:expr) => {
        proptest! {
            #![proptest_config(ProptestConfig {
                cases: $cases,
                max_shrink_iters: 256,
                .. ProptestConfig::default()
            })]

            #[test]
            fn $name(spec in arb_spec()) {
                let skip: fn(&CmdSpec) -> bool = $skip;
                prop_assume!(!skip(&spec));
                let mut analyzer = isolated_analyzer();
                let base = invariants::decide(&mut analyzer, &spec.render());
                if let Err(violation) = $invariant(&mut analyzer, &spec, &base) {
                    prop_assert!(false, "{violation}");
                }
            }
        }
    };
}

invariant_test!(suffix_injection_never_allows, 64, invariants::suffix_inject);
invariant_test!(
    prefix_injection_never_allows,
    128,
    invariants::prefix_inject
);
invariant_test!(
    redirect_injection_never_allows,
    128,
    invariants::redirect_inject
);
invariant_test!(
    expansion_substitution_gated_on_dynamic_arg_safe,
    48,
    invariants::expansion_substitution
);
invariant_test!(
    env_prefix_injection_never_allows,
    96,
    invariants::env_prefix_inject
);
invariant_test!(wrapper_monotonicity, 64, invariants::wrapper_monotonicity);
invariant_test!(
    resolution_never_less_restrictive,
    128,
    invariants::resolution_monotonic
);

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        max_shrink_iters: 256,
        .. ProptestConfig::default()
    })]

    /// The grammar is the trusted base of every invariant: if it emitted an
    /// unbalanced quote or a stray operator, the transforms would be measuring
    /// the generator's bugs instead of rippy's behavior.
    #[test]
    fn grammar_renders_shell_inert(spec in arb_spec()) {
        let rendered = spec.render();
        prop_assert!(!rendered.is_empty());
        prop_assert!(!rendered.contains('\n') && !rendered.contains('\0'));
        prop_assert!(!rendered.contains("$(") && !rendered.contains('`'));
        prop_assert!(!rendered.contains("<<"));
        prop_assert_eq!(rendered.matches('\'').count() % 2, 0);
        prop_assert_eq!(rendered.matches('"').count() % 2, 0);
        prop_assert!(!rendered.trim_end().ends_with(['&', '|', ';']));
    }

    /// Every rendered spec must reach the analyzer, not the parse-error path.
    #[test]
    fn grammar_is_always_analyzable(spec in arb_spec()) {
        let mut analyzer = isolated_analyzer();
        let rendered = spec.render();
        prop_assert!(
            analyzer.analyze(&rendered).is_ok(),
            "generated command failed to parse: {:?}",
            rendered
        );
    }

    /// The byte decoder used by the libfuzzer target must produce the same
    /// shell-inert, analyzable shapes as the proptest strategies.
    #[test]
    fn byte_decoder_renders_analyzable_specs(data in prop::collection::vec(any::<u8>(), 0..96)) {
        let mut analyzer = isolated_analyzer();
        let rendered = from_bytes(&data).render();
        prop_assert!(
            analyzer.analyze(&rendered).is_ok(),
            "decoded command failed to parse: {:?}",
            rendered
        );
    }

    /// Invariant 8's libfuzzer input generator: the words it emits must parse,
    /// otherwise the deep run would only ever exercise the parse-error path.
    #[test]
    fn word_generator_emits_parseable_words(data in prop::collection::vec(any::<u8>(), 0..16)) {
        let word = word_from_bytes(&data);
        let mut parser = rippy_cli::parser::BashParser::new().unwrap();
        prop_assert!(
            parser.parse(&format!("cat {word}")).is_ok(),
            "generated word does not parse: {:?}",
            word
        );
    }
}

/// Regression pin for #181: unwrapping a wrapper used to discard the outer
/// node's redirects, so every shape below was auto-approved. The generated
/// grammar cannot reach the bare-`timeout`, empty-args, nesting and heredoc
/// forms, so they are enumerated here.
#[test]
fn wrapper_must_not_drop_the_redirect_guard() {
    let mut analyzer = isolated_analyzer();
    for cmd in [
        "nice ls > /etc/passwd",
        "nohup ls > /etc/passwd",
        "strace ls > /etc/passwd",
        "ltrace ls > /etc/passwd",
        "command echo pwned > /etc/sudoers",
        "builtin echo x >> /etc/hosts",
        "timeout ls > /etc/passwd",
        "timeout 5 ls > /etc/passwd",
        "nice ls > /etc/passwd; echo done",
        "nice nohup ls > /etc/passwd",
        "nice > /etc/passwd",
        "nice cat <<EOF\n$(id)\nEOF",
    ] {
        let verdict = invariants::decide(&mut analyzer, cmd);
        assert!(
            verdict.decision >= Decision::Ask,
            "{cmd:?} was auto-approved ({})",
            verdict.reason
        );
    }
}

/// Guards against the invariants going vacuous: if a generator drifted into
/// producing commands that already Ask, "injecting danger never Allows" would
/// hold trivially and catch nothing.
fn assert_mostly_allowed(generator: &str, rendered: &[String]) {
    let mut analyzer = isolated_analyzer();
    let allowed = rendered
        .iter()
        .filter(|cmd| invariants::decide(&mut analyzer, cmd).decision == Decision::Allow)
        .count();
    assert!(
        allowed * 2 >= rendered.len(),
        "{generator}: only {allowed}/{} generated commands were Allow — the metamorphic \
         invariants would be near-vacuous",
        rendered.len()
    );
}

/// `arb_spec` is what the seven invariant proptests sample, so it is the
/// distribution that has to stay mostly-`Allow`.
#[test]
fn proptest_generator_is_mostly_allowed() {
    let strategy = arb_spec();
    let mut runner = TestRunner::deterministic();
    let rendered: Vec<String> = (0..400)
        .map(|_| {
            strategy
                .new_tree(&mut runner)
                .expect("arb_spec generates a value")
                .current()
                .render()
        })
        .collect();
    assert_mostly_allowed("arb_spec", &rendered);
}

/// The byte decoder has its own weights, so the libfuzzer target needs its own
/// anti-vacuity guard.
#[test]
fn byte_decoder_generator_is_mostly_allowed() {
    let rendered: Vec<String> = (0..400u64)
        .map(|i| {
            let seed: Vec<u8> = (0..64u64)
                .map(|j| {
                    u8::try_from((i.wrapping_mul(2_654_435_761) + j * 40_503) >> 7 & 0xff).unwrap()
                })
                .collect();
            from_bytes(&seed).render()
        })
        .collect();
    assert_mostly_allowed("grammar::from_bytes", &rendered);
}
