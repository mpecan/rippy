//! A generated command grammar for the metamorphic harness.
//!
//! The space is structural: up to three pipeline stages, each optionally
//! carrying an env prefix, a wrapper, a leaf drawn from the ~200-entry
//! `SIMPLE_SAFE` set or a handler form, up to four generated argument tokens,
//! and a redirect. Rendering is shell-inert by construction — tokens come from
//! an alphabet that contains no quote, operator, expansion or newline
//! character, so a rendered spec can never accidentally *be* the injection the
//! invariants are trying to detect.

use std::sync::LazyLock;

use rippy_cli::allowlists;

pub(crate) static SAFE_LEAVES: LazyLock<Vec<&'static str>> =
    LazyLock::new(allowlists::all_simple_safe);

/// Handler-backed commands paired with read-only subcommand forms, so the
/// grammar reaches the handler dispatch path and not only `SIMPLE_SAFE`.
pub(crate) const HANDLER_FORMS: &[(&str, &[&str])] = &[
    ("git", &["status", "log", "diff", "branch", "show"]),
    ("docker", &["ps", "images", "version", "logs c1"]),
    ("cargo", &["build", "check", "test", "fmt"]),
    ("npm", &["ls", "test", "run build"]),
    ("kubectl", &["get pods", "version", "describe pod p1"]),
];

/// Flag spellings a generated argument may take. Curated rather than generated
/// character-by-character: a random `-` prefix would otherwise synthesize real
/// destructive flags (`--delete`, `-exec`) and turn every invariant into a
/// report about the flag rather than about the transform under test.
pub(crate) const FLAGS: &[&str] = &["-l", "-a", "-n", "-v", "-h", "--color", "--all", "-la"];

/// Environment prefixes that are inert by name, used to reach the assignment
/// path without tripping the dangerous-name guard the transforms rely on.
pub(crate) const INERT_ENV: &[(&str, &str)] =
    &[("FOO", "bar"), ("LANG", "C"), ("MYVAR", "1"), ("TZ", "UTC")];

pub(crate) const TOKEN_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789._-";

pub(crate) const MAX_STAGES: usize = 3;
pub(crate) const MAX_ARGS: usize = 4;
pub(crate) const MAX_TOKEN_LEN: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Leaf {
    Simple(usize),
    Handler { base: usize, sub: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Arg {
    Bare(String),
    Flag(usize),
    Path(String),
    SingleQuoted(String),
    DoubleQuoted(String),
    Glob,
    /// Verbatim text injected by a transform; never produced by generation.
    Raw(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Op {
    Semi,
    And,
    Or,
    Pipe,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Redirect {
    Out(String),
    Append(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Stage {
    pub(crate) env_prefix: Option<usize>,
    pub(crate) wrapper: Option<&'static str>,
    pub(crate) leaf: Leaf,
    pub(crate) args: Vec<Arg>,
    pub(crate) redirect: Option<Redirect>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CmdSpec {
    pub(crate) stages: Vec<Stage>,
    pub(crate) ops: Vec<Op>,
}

impl Op {
    pub(crate) const fn separator(self) -> &'static str {
        match self {
            Self::Semi => "; ",
            Self::And => " && ",
            Self::Or => " || ",
            Self::Pipe => " | ",
        }
    }
}

impl Leaf {
    pub(crate) fn name(&self) -> &'static str {
        match *self {
            Self::Simple(i) => SAFE_LEAVES[i % SAFE_LEAVES.len()],
            Self::Handler { base, .. } => HANDLER_FORMS[base % HANDLER_FORMS.len()].0,
        }
    }

    fn render(&self) -> String {
        match *self {
            Self::Simple(_) => self.name().to_string(),
            Self::Handler { base, sub } => {
                let (name, subs) = HANDLER_FORMS[base % HANDLER_FORMS.len()];
                format!("{name} {}", subs[sub % subs.len()])
            }
        }
    }
}

impl Arg {
    fn render(&self) -> String {
        match self {
            Self::Bare(s) | Self::Raw(s) => s.clone(),
            Self::Flag(i) => FLAGS[i % FLAGS.len()].to_string(),
            Self::Path(s) => format!("/tmp/{s}"),
            Self::SingleQuoted(s) => format!("'{s}'"),
            Self::DoubleQuoted(s) => format!("\"{s}\""),
            Self::Glob => "*.txt".to_string(),
        }
    }
}

impl Stage {
    fn render(&self) -> String {
        let mut out = String::new();
        if let Some(i) = self.env_prefix {
            let (k, v) = INERT_ENV[i % INERT_ENV.len()];
            out.push_str(k);
            out.push('=');
            out.push_str(v);
            out.push(' ');
        }
        if let Some(w) = self.wrapper {
            out.push_str(w);
            out.push(' ');
            if w == "timeout" {
                out.push_str("5 ");
            }
        }
        out.push_str(&self.leaf.render());
        for arg in &self.args {
            out.push(' ');
            out.push_str(&arg.render());
        }
        match &self.redirect {
            Some(Redirect::Out(p)) => {
                out.push_str(" > /tmp/");
                out.push_str(p);
            }
            Some(Redirect::Append(p)) => {
                out.push_str(" >> /tmp/");
                out.push_str(p);
            }
            None => {}
        }
        out
    }
}

impl CmdSpec {
    pub(crate) fn render(&self) -> String {
        let mut out = self.stages[0].render();
        for (i, stage) in self.stages.iter().enumerate().skip(1) {
            let op = self.ops.get(i - 1).copied().unwrap_or(Op::Semi);
            out.push_str(op.separator());
            out.push_str(&stage.render());
        }
        out
    }

    /// The command name a transform at `stage` is acting on — the *inner* leaf,
    /// which is what the dynamic-argument gate is keyed on even when a wrapper
    /// is present.
    pub(crate) fn leaf_name(&self, stage: usize) -> &'static str {
        self.stages[stage].leaf.name()
    }

    /// `(stage, arg)` coordinates of every argument token a transform may
    /// replace.
    pub(crate) fn arg_positions(&self) -> Vec<(usize, usize)> {
        let mut positions = Vec::new();
        for (si, stage) in self.stages.iter().enumerate() {
            for ai in 0..stage.args.len() {
                positions.push((si, ai));
            }
        }
        positions
    }

    pub(crate) fn with_arg_replaced(&self, stage: usize, arg: usize, text: &str) -> Self {
        let mut clone = self.clone();
        clone.stages[stage].args[arg] = Arg::Raw(text.to_string());
        clone
    }
}

/// Bounded byte decoder used by the libfuzzer target, so coverage feedback can
/// steer the same structural space the proptests sample randomly.
pub(crate) fn from_bytes(data: &[u8]) -> CmdSpec {
    let mut r = Reader { data, pos: 0 };
    let stage_count = 1 + usize::from(r.byte()) % MAX_STAGES;
    let stages: Vec<Stage> = (0..stage_count).map(|_| decode_stage(&mut r)).collect();
    let ops = (0..stage_count.saturating_sub(1))
        .map(|_| match r.byte() % 4 {
            0 => Op::Semi,
            1 => Op::And,
            2 => Op::Or,
            _ => Op::Pipe,
        })
        .collect();
    CmdSpec { stages, ops }
}

fn decode_stage(r: &mut Reader<'_>) -> Stage {
    let env_prefix = r.byte().is_multiple_of(4).then(|| usize::from(r.byte()));
    let wrappers = allowlists::all_wrappers();
    let wrapper = r
        .byte()
        .is_multiple_of(4)
        .then(|| wrappers[usize::from(r.byte()) % wrappers.len()]);
    let leaf = if r.byte().is_multiple_of(3) {
        let base = usize::from(r.byte()) % HANDLER_FORMS.len();
        Leaf::Handler {
            base,
            sub: usize::from(r.byte()),
        }
    } else {
        Leaf::Simple(usize::from(r.byte()) % SAFE_LEAVES.len())
    };
    let arg_count = usize::from(r.byte()) % (MAX_ARGS + 1);
    let args = (0..arg_count).map(|_| decode_arg(r)).collect();
    let redirect = match r.byte() % 8 {
        0 => Some(Redirect::Out(r.token())),
        1 => Some(Redirect::Append(r.token())),
        _ => None,
    };
    Stage {
        env_prefix,
        wrapper,
        leaf,
        args,
        redirect,
    }
}

fn decode_arg(r: &mut Reader<'_>) -> Arg {
    match r.byte() % 6 {
        0 => Arg::Bare(r.token()),
        1 => Arg::Flag(usize::from(r.byte())),
        2 => Arg::Path(r.token()),
        3 => Arg::SingleQuoted(r.token()),
        4 => Arg::DoubleQuoted(r.token()),
        _ => Arg::Glob,
    }
}

/// Expansion fragments invariant 8 is stated over: a resolved `Literal` must
/// never still contain one of these.
///
/// `"`id`"` is listed alongside the bare `` `id` `` because rable keeps a
/// double-quoted backtick as one literal word part rather than lifting it to a
/// `CommandSubstitution`, so the two forms exercise entirely different code
/// paths and only the bare one was covered before #202.
pub(crate) const EXPANSION_LEAVES: &[&str] = &[
    "$(id)", "`id`", "\"`id`\"", "<(id)", ">(id)", "$HOME", "$1", "$@", "safe",
];

/// Build an expansion-bearing word from raw bytes, for the libfuzzer version of
/// invariant 8. Nesting is capped at three levels and `$"…"` is skipped when the
/// payload already contains a `"`, which would close the string early and emit a
/// malformed word instead of a nested expansion.
pub(crate) fn word_from_bytes(data: &[u8]) -> String {
    let mut r = Reader { data, pos: 0 };
    let mut word = EXPANSION_LEAVES[usize::from(r.byte()) % EXPANSION_LEAVES.len()].to_string();
    for _ in 0..3 {
        word = match r.byte() % 5 {
            0 => format!("${{U:-{word}}}"),
            1 => format!("${{U-{word}}}"),
            2 => format!("${{U:+{word}}}"),
            3 if !word.contains('"') => format!("$\"{word}\""),
            _ => word,
        };
    }
    word
}

/// Force the first character to be alphanumeric: a leading `-` would make a
/// bare token parse as a flag, which reports on flag handling rather than on
/// the transform under test.
pub(crate) fn normalize_token(raw: &str) -> String {
    let mut chars: Vec<char> = raw.chars().filter(char::is_ascii).collect();
    if chars.is_empty() {
        return "a".to_string();
    }
    if !chars[0].is_ascii_alphanumeric() {
        chars[0] = 'a';
    }
    chars.into_iter().collect()
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn byte(&mut self) -> u8 {
        let b = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos = self.pos.saturating_add(1);
        b
    }

    fn token(&mut self) -> String {
        let len = 1 + usize::from(self.byte()) % MAX_TOKEN_LEN;
        let raw: String = (0..len)
            .map(|_| {
                let b = self.byte();
                char::from(TOKEN_ALPHABET[usize::from(b) % TOKEN_ALPHABET.len()])
            })
            .collect();
        normalize_token(&raw)
    }
}
