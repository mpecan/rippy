//! Read-only tools with options that run a program or write a file. Each was on
//! the simple-safe allowlist, which approved it whatever its flags:
//! `rg --pre CMD`, `man -P CMD` and `fzf --preview CMD` run `CMD`,
//! `less +'!CMD'` runs `CMD` at start-up, `tree -o FILE` and `xxd IN OUT`
//! write a file, and `arch CMD` runs `CMD`.
//!
//! Options are read with [`scan_argv`], so every getopt spelling counts: a
//! cluster (`man -aP cmd`), a glued value (`tree -oFILE`), `--name=value`, an
//! abbreviated long name (`less --log-f=FILE`), and every occurrence.
//! See docs/security-invariants.md#guarded-readers.

use super::getopt::{Argv, OptionSpec, scan_argv};
use super::{AllowEntry, Classification, Handler, HandlerContext};
use crate::verdict::AllowReason;

pub(crate) static GUARDED_READER_HANDLER: GuardedReaderHandler = GuardedReaderHandler;

pub(crate) struct GuardedReaderHandler;

/// What a guarded tool's options and operands can do.
struct Guard {
    names: &'static [&'static str],
    /// The tool's value-taking options, so clusters decode correctly.
    spec: OptionSpec<'static>,
    /// Options that run a program: `(short letters, long names)`.
    exec: (&'static str, &'static [&'static str]),
    /// Options whose value is a file the tool writes.
    write: (&'static str, &'static [&'static str]),
    /// Operand positions that are output files (`xxd IN OUT`, `uniq IN OUT`).
    output_operands: &'static [usize],
    /// Special rules beyond options.
    rule: Rule,
}

#[derive(PartialEq, Eq)]
enum Rule {
    None,
    /// less/more `+CMD`: `!` runs a shell command and `|` pipes to one.
    StartupCommand,
    /// Any operand is a program the tool runs (`arch CMD`, `ldd BIN`).
    OperandsRun,
    /// A first operand of `cache` rebuilds bat's cache from a directory.
    BatCache,
}

const NO_OPTIONS: (&str, &[&str]) = ("", &[]);

const fn spec(
    value_shorts: &'static str,
    value_longs: &'static [&'static str],
) -> OptionSpec<'static> {
    OptionSpec {
        value_shorts,
        optional_shorts: "",
        value_longs,
    }
}

const GUARDS: &[Guard] = &[
    Guard {
        names: &["rg"],
        spec: spec(
            "eEfgmMtTABCjrd",
            &[
                "pre",
                "pre-glob",
                "hostname-bin",
                "hyperlink-format",
                "glob",
                "iglob",
                "type",
                "type-not",
                "type-add",
                "regexp",
                "file",
                "max-count",
                "context",
                "after-context",
                "before-context",
                "encoding",
                "threads",
                "max-columns",
                "replace",
                "max-depth",
                "sort",
                "sortr",
                "color",
                "colors",
                "ignore-file",
                "engine",
                "max-filesize",
            ],
        ),
        exec: ("", &["pre", "hostname-bin"]),
        write: NO_OPTIONS,
        output_operands: &[],
        rule: Rule::None,
    },
    Guard {
        names: &["ag"],
        spec: spec(
            "ABCGgmp",
            &["pager", "depth", "file-search-regex", "max-count"],
        ),
        exec: ("", &["pager"]),
        write: NO_OPTIONS,
        output_operands: &[],
        rule: Rule::None,
    },
    Guard {
        names: &["man"],
        spec: spec(
            "CMPSemrLRHp",
            &[
                "pager",
                "html",
                "config-file",
                "manpath",
                "sections",
                "encoding",
            ],
        ),
        exec: ("PHC", &["pager", "html", "config-file"]),
        write: NO_OPTIONS,
        output_operands: &[],
        rule: Rule::None,
    },
    Guard {
        names: &["bat"],
        spec: spec(
            "lHrm",
            &[
                "pager",
                "language",
                "theme",
                "style",
                "map-syntax",
                "line-range",
                "highlight-line",
                "file-name",
                "tabs",
                "wrap",
                "terminal-width",
                "color",
            ],
        ),
        exec: ("", &["pager", "generate-config-file"]),
        write: NO_OPTIONS,
        output_operands: &[],
        rule: Rule::BatCache,
    },
    Guard {
        names: &["fzf"],
        spec: spec(
            "qdnf",
            &[
                "preview",
                "bind",
                "with-shell",
                "listen",
                "listen-unsafe",
                "history",
                "query",
                "delimiter",
                "nth",
                "with-nth",
                "height",
                "prompt",
                "header",
                "preview-window",
            ],
        ),
        exec: (
            "",
            &["preview", "bind", "with-shell", "listen", "listen-unsafe"],
        ),
        write: ("", &["history"]),
        output_operands: &[],
        rule: Rule::None,
    },
    Guard {
        names: &["tree"],
        spec: spec(
            "oLPIH",
            &["charset", "filelimit", "timefmt", "sort", "output"],
        ),
        exec: ("R", &[]),
        write: ("o", &["output"]),
        output_operands: &[],
        rule: Rule::None,
    },
    Guard {
        names: &["less", "more"],
        spec: spec(
            "bhjkoOpPtTxyzD#",
            &[
                "log-file",
                "LOG-FILE",
                "lesskey-file",
                "lesskey-src",
                "lesskey-content",
                "tag",
                "tag-file",
                "pattern",
                "prompt",
                "tabs",
            ],
        ),
        exec: ("k", &["lesskey-file", "lesskey-src", "lesskey-content"]),
        write: ("oO", &["log-file", "LOG-FILE"]),
        output_operands: &[],
        rule: Rule::StartupCommand,
    },
    Guard {
        names: &["xxd"],
        spec: spec("cglosn", &[]),
        exec: NO_OPTIONS,
        write: NO_OPTIONS,
        output_operands: &[1],
        rule: Rule::None,
    },
    Guard {
        names: &["uniq"],
        spec: spec("fsw", &["skip-fields", "skip-chars", "check-chars"]),
        exec: NO_OPTIONS,
        write: NO_OPTIONS,
        output_operands: &[1],
        rule: Rule::None,
    },
    Guard {
        names: &["shuf", "iconv", "info", "base64"],
        spec: spec(
            "oinftdb",
            &[
                "output",
                "input-range",
                "head-count",
                "from-code",
                "to-code",
            ],
        ),
        exec: NO_OPTIONS,
        write: ("o", &["output"]),
        output_operands: &[],
        rule: Rule::None,
    },
    Guard {
        names: &["cloc", "scc"],
        spec: spec("", &["extract-with", "out", "report-file", "output", "sql"]),
        exec: ("", &["extract-with"]),
        write: ("", &["out", "report-file", "output", "sql"]),
        output_operands: &[],
        rule: Rule::None,
    },
    Guard {
        names: &["arch", "ldd"],
        spec: spec("", &[]),
        exec: NO_OPTIONS,
        write: NO_OPTIONS,
        output_operands: &[],
        rule: Rule::OperandsRun,
    },
];

impl Guard {
    /// Why this invocation must ask, if it runs something.
    fn runs(&self, name: &str, argv: &Argv<'_>) -> Option<String> {
        let (shorts, longs) = self.exec;
        if let Some(option) = argv.first(shorts, longs) {
            return Some(format!("{name} {option} (runs a program)"));
        }
        let first = argv.operands.first().copied();
        let startup_shell = argv
            .operands
            .iter()
            .any(|o| o.starts_with('+') && (o.contains('!') || o.contains('|')));
        match self.rule {
            Rule::StartupCommand if startup_shell => {
                Some(format!("{name} +! (runs a shell command)"))
            }
            Rule::OperandsRun if first.is_some() => Some(format!("{name} (runs its operand)")),
            Rule::BatCache if first == Some("cache") => {
                Some("bat cache (builds from files)".into())
            }
            _ => None,
        }
    }

    /// Every file this invocation writes; `-` is standard output.
    fn targets(&self, argv: &Argv<'_>) -> Vec<String> {
        let (shorts, longs) = self.write;
        let mut targets = argv.values(shorts, longs);
        targets.extend(
            self.output_operands
                .iter()
                .filter_map(|&i| argv.operands.get(i).copied()),
        );
        targets
            .into_iter()
            .filter(|t| *t != "-")
            .map(str::to_owned)
            .collect()
    }

    fn surface(&self) -> String {
        let (exec_s, exec_l) = self.exec;
        let mut parts = Vec::new();
        if !exec_s.is_empty() || !exec_l.is_empty() {
            parts.push(format!("no {} (runs a program)", spell(exec_s, exec_l)));
        }
        match self.rule {
            Rule::StartupCommand => parts.push("no +CMD containing ! or |".to_owned()),
            Rule::OperandsRun => parts.push("no operand (it is run)".to_owned()),
            Rule::BatCache => parts.push("not the cache subcommand".to_owned()),
            Rule::None => {}
        }
        let (write_s, write_l) = self.write;
        if !write_s.is_empty() || !write_l.is_empty() || !self.output_operands.is_empty() {
            parts.push("every output file runs the redirect pipeline".to_owned());
        }
        parts.join("; ")
    }
}

fn spell(shorts: &str, longs: &[&str]) -> String {
    shorts
        .chars()
        .map(|c| format!("-{c}"))
        .chain(longs.iter().map(|l| format!("--{l}")))
        .collect::<Vec<_>>()
        .join("/")
}

impl Handler for GuardedReaderHandler {
    fn commands(&self) -> &[&str] {
        &[
            "rg", "ag", "man", "bat", "fzf", "tree", "less", "more", "xxd", "uniq", "shuf",
            "iconv", "info", "base64", "cloc", "scc", "arch", "ldd",
        ]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        let name = ctx.command_name;
        let Some(guard) = GUARDS.iter().find(|g| g.names.contains(&name)) else {
            return Classification::Ask(format!("{name} (unknown guarded reader)"));
        };
        let argv = scan_argv(ctx.args, &guard.spec);
        if let Some(reason) = guard.runs(name, &argv) {
            return Classification::Ask(reason);
        }
        let reason = AllowReason::handler(format!("{name} is safe"));
        let targets = guard.targets(&argv);
        if targets.is_empty() {
            Classification::Allow(reason)
        } else {
            Classification::WithRedirects(reason, targets)
        }
    }

    fn allow_surface(&self) -> Vec<AllowEntry> {
        GUARDS
            .iter()
            .flat_map(|g| {
                let guard = g.surface();
                g.names
                    .iter()
                    .map(move |n| AllowEntry::guarded(*n, guard.clone()))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_list_every_guarded_name() {
        let mut listed: Vec<&str> = GuardedReaderHandler.commands().to_vec();
        let mut guarded: Vec<&str> = GUARDS
            .iter()
            .flat_map(|g| g.names.iter().copied())
            .collect();
        listed.sort_unstable();
        guarded.sort_unstable();
        assert_eq!(listed, guarded);
    }
}
