//! Read-only tools with an option that runs a program or writes a file. Each
//! was on the simple-safe allowlist, which approved it whatever its flags:
//! `rg --pre CMD` pipes every searched file through `CMD`, `man -P CMD` and
//! `bat --pager CMD` page through `CMD`, `fzf --preview CMD` runs `CMD`,
//! `less +'!CMD'` runs `CMD` at start-up, and `tree -o FILE` writes `FILE`.

use super::{AllowEntry, Classification, Handler, HandlerContext};
use crate::verdict::AllowReason;

pub(crate) static GUARDED_READER_HANDLER: GuardedReaderHandler = GuardedReaderHandler;

pub(crate) struct GuardedReaderHandler;

/// A read-only tool and the options that make it do more.
struct Guard {
    command: &'static str,
    /// Options that run a program, in any spelling.
    exec: &'static [&'static str],
    /// Options whose value is a file the tool writes.
    write: &'static [&'static str],
}

const GUARDS: &[Guard] = &[
    Guard {
        command: "rg",
        exec: &["--pre"],
        write: &[],
    },
    Guard {
        command: "ag",
        exec: &["--pager"],
        write: &[],
    },
    Guard {
        command: "man",
        exec: &["-P", "--pager", "-H", "--html"],
        write: &[],
    },
    Guard {
        command: "bat",
        exec: &["--pager"],
        write: &[],
    },
    Guard {
        command: "fzf",
        exec: &["--preview", "--bind", "--with-shell"],
        write: &[],
    },
    Guard {
        command: "tree",
        exec: &[],
        write: &["-o"],
    },
    Guard {
        command: "less",
        exec: &[],
        write: &["-o", "-O", "--log-file", "--LOG-FILE"],
    },
];

/// How an argument spells a flag.
#[derive(Debug, PartialEq, Eq)]
enum Spelling<'a> {
    /// The flag alone; any value is the next word.
    Bare,
    /// `--flag=v` or a glued short `-Fv`.
    WithValue(&'a str),
}

/// Whether `arg` is `flag` in any spelling.
fn matches_flag<'a>(arg: &'a str, flag: &str) -> Option<Spelling<'a>> {
    if arg == flag {
        return Some(Spelling::Bare);
    }
    if flag.starts_with("--") {
        return arg
            .strip_prefix(flag)
            .and_then(|r| r.strip_prefix('='))
            .map(Spelling::WithValue);
    }
    (flag.len() == 2 && arg.len() > 2 && arg.starts_with(flag))
        .then(|| Spelling::WithValue(&arg[2..]))
}

/// `less +CMD`: a start-up command. `+F`, `+G` and `+/pattern` only move the
/// view; `!` runs a shell command and `|` pipes to one.
fn less_runs_shell(args: &[String]) -> bool {
    args.iter()
        .any(|a| a.starts_with('+') && (a.contains('!') || a.contains('|')))
}

impl Handler for GuardedReaderHandler {
    fn commands(&self) -> &[&str] {
        &["rg", "ag", "man", "bat", "fzf", "tree", "less", "hyperfine"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        let name = ctx.command_name;
        if name == "hyperfine" {
            return Classification::Ask("hyperfine (runs the commands it benchmarks)".into());
        }
        if name == "less" && less_runs_shell(ctx.args) {
            return Classification::Ask("less +! (runs a shell command)".into());
        }
        let Some(guard) = GUARDS.iter().find(|g| g.command == name) else {
            return Classification::Ask(format!("{name} (unknown guarded reader)"));
        };
        for (i, arg) in ctx.args.iter().enumerate() {
            if let Some(flag) = guard.exec.iter().find(|f| matches_flag(arg, f).is_some()) {
                return Classification::Ask(format!("{name} {flag} (runs a program)"));
            }
            for flag in guard.write {
                if let Some(spelling) = matches_flag(arg, flag) {
                    let target = match spelling {
                        Spelling::WithValue(v) => Some(v.to_owned()),
                        Spelling::Bare => ctx.args.get(i + 1).cloned(),
                    };
                    let Some(target) = target else {
                        return Classification::Ask(format!("{name} {flag} (no target)"));
                    };
                    return Classification::WithRedirects(
                        AllowReason::handler(format!("{name} is safe")),
                        vec![target],
                    );
                }
            }
        }
        Classification::Allow(AllowReason::handler(format!("{name} is safe")))
    }

    fn allow_surface(&self) -> Vec<AllowEntry> {
        GUARDS
            .iter()
            .map(|g| {
                let mut parts = Vec::new();
                if !g.exec.is_empty() {
                    parts.push(format!("no {} (runs a program)", g.exec.join("/")));
                }
                if g.command == "less" {
                    parts.push("no +CMD containing ! or | (runs a shell command)".to_owned());
                }
                if !g.write.is_empty() {
                    parts.push(format!(
                        "a {} target runs the redirect pipeline",
                        g.write.join("/")
                    ));
                }
                AllowEntry::guarded(g.command, parts.join("; "))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_spellings() {
        assert_eq!(matches_flag("--pre", "--pre"), Some(Spelling::Bare));
        assert_eq!(
            matches_flag("--pre=sh", "--pre"),
            Some(Spelling::WithValue("sh"))
        );
        assert_eq!(matches_flag("--pre-glob", "--pre"), None);
        assert_eq!(
            matches_flag("-Pless", "-P"),
            Some(Spelling::WithValue("less"))
        );
        assert_eq!(matches_flag("-o", "-o"), Some(Spelling::Bare));
        assert_eq!(matches_flag("--output", "-o"), None);
    }

    #[test]
    fn less_start_up_commands() {
        let args = |a: &[&str]| a.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert!(less_runs_shell(&args(&["+!id", "f"])));
        assert!(less_runs_shell(&args(&["+|sh", "f"])));
        assert!(!less_runs_shell(&args(&["+F", "log"])));
        assert!(!less_runs_shell(&args(&["+/error", "log"])));
    }
}
