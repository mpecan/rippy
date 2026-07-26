use std::collections::HashSet;
use std::sync::LazyLock;

/// Commands known to be safe (read-only, no side effects).
/// Ported from Dippy's `SIMPLE_SAFE` frozenset.
static SIMPLE_SAFE: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from([
        // File viewing
        "cat",
        "head",
        "tail",
        "less",
        "more",
        "bat",
        "hexdump",
        "strings",
        "xxd",
        "od",
        // Compressed file viewing
        "zcat",
        "bzcat",
        "xzcat",
        "zstdcat",
        // Binary analysis
        "nm",
        "objdump",
        "readelf",
        "ldd",
        "otool",
        "size",
        "file",
        // Directory listing
        "ls",
        "tree",
        "exa",
        "eza",
        "lsd",
        // File info
        "stat",
        "wc",
        "du",
        "df",
        // Text processing (read-only)
        "grep",
        "rg",
        "ag",
        "diff",
        "cut",
        "tr",
        // sort has a dedicated handler (handles -o output flag)
        "uniq",
        "paste",
        "join",
        "comm",
        "fold",
        "fmt",
        "nl",
        "column",
        "expand",
        "unexpand",
        "rev",
        "tac",
        "shuf",
        // Encoding/hashing
        "base64",
        "base32",
        "md5sum",
        "sha1sum",
        "sha256sum",
        "sha512sum",
        "cksum",
        "sum",
        // Search (find, fd, env, sort, yq have dedicated handlers — not in this list)
        "locate",
        "which",
        "whereis",
        "type",
        "whence",
        // System info
        "whoami",
        "hostname",
        "uname",
        "id",
        "groups",
        "uptime",
        "pwd",
        "date",
        // env has a dedicated handler (can delegate inner commands)
        "printenv",
        "locale",
        // Process info
        "ps",
        "top",
        "htop",
        "lsof",
        "vmstat",
        "iostat",
        "free",
        "pgrep",
        // Network info (read-only)
        "ping",
        "dig",
        "nslookup",
        "traceroute",
        "tracepath",
        "netstat",
        "ss",
        // ifconfig and ip have dedicated handlers
        "host",
        "getent",
        // Help/docs
        "man",
        "info",
        "whatis",
        "apropos",
        "tldr",
        "help",
        // Shell builtins (safe)
        "echo",
        "printf",
        "true",
        "false",
        "test",
        "[",
        ":",
        // Path manipulation
        "basename",
        "dirname",
        "realpath",
        "readlink",
        // Math
        "bc",
        "expr",
        "seq",
        // Misc read-only
        "tty",
        "stty",
        "tput",
        "yes",
        "sleep",
        // Version/capabilities
        "nproc",
        "getconf",
        "arch",
        "lsb_release",
        // Modern CLI tools
        "jq",
        // yq has a dedicated handler (handles -i inplace)
        "fzf",
        "tokei",
        "cloc",
        "scc",
        "hyperfine",
        // Encoding
        "iconv",
        // dos2unix/unix2dos have a dedicated handler (rewrite the named file in place by default)
        // Disk/fs info
        "mount",
        "findmnt",
        "lsblk",
        "blkid",
        // dmesg has a dedicated handler (clear flags)
    ])
});

/// `SIMPLE_SAFE` commands whose behavior *can* depend dangerously on an
/// argument value, so they must NOT be auto-allowed when an argument is a
/// set-but-unknown (attacker-influenceable) value such as a loop variable or a
/// glob match:
///
/// - pagers that can spawn a subshell (`!cmd`, `v`) or run an input
///   preprocessor (`LESSOPEN`): `less`, `more`, `man`, `info`
/// - interactive finders that execute a preview/bind command from an argument:
///   `fzf`
/// - commands that change system/terminal state from their argument: `mount`,
///   `stty`
///
/// They remain safe with *literal* arguments (still resolved and re-analyzed via
/// the normal path), but the dynamic-argument relaxation excludes them.
static DYNAMIC_ARG_UNSAFE: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| HashSet::from(["less", "more", "man", "info", "fzf", "mount", "stty"]));

/// Commands that wrap other commands — analyze the inner command instead.
static WRAPPER_COMMANDS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from([
        "time", "timeout", "nice", "strace", "ltrace", "nohup", "command", "builtin",
    ])
});

/// Help/version flags the analyzer honors when one of them is a command's sole
/// argument — the whole `AllowReason::HelpFlag` surface.
///
/// Deliberately excludes `-h`/`-V`: commands overload them (`docker -h` is
/// `--hostname`), so a lone short flag keeps asking.
pub const SOLE_HELP_FLAGS: &[&str] = &["--help", "--version"];

/// Check if a command is in the simple-safe allowlist.
#[must_use]
pub fn is_simple_safe(cmd: &str) -> bool {
    SIMPLE_SAFE.contains(cmd)
}

/// Check if a command is a wrapper (should analyze inner command).
#[must_use]
pub fn is_wrapper(cmd: &str) -> bool {
    WRAPPER_COMMANDS.contains(cmd)
}

/// `timeout` flags that consume the following word as their value.
const TIMEOUT_VALUE_FLAGS: &[&str] = &["-k", "--kill-after", "-s", "--signal"];

/// `timeout` flags that stand alone.
const TIMEOUT_FLAGS: &[&str] = &["--preserve-status", "--foreground", "-v", "--verbose"];

/// The argv a wrapper actually executes, with the wrapper's own options removed.
///
/// Only `timeout` and `nice` put options in front of the command; every other
/// wrapper is passed through untouched on purpose. Both fall back to the whole
/// argv when the grammar does not match, which keeps the stray word as the
/// command name and so Asks. See docs/security-invariants.md#wrapper-redirects.
#[must_use]
pub fn wrapper_inner_args<'a>(cmd: &str, args: &'a [String]) -> &'a [String] {
    match cmd {
        "timeout" => timeout_inner_args(args).unwrap_or(args),
        "nice" => nice_inner_args(args).unwrap_or(args),
        _ => args,
    }
}

/// `nice [-n N | --adjustment=N | -N] COMMAND …`. Without this, `nice -n 10 ls`
/// read `-n` as the command and Asked on an ordinary safe invocation.
fn nice_inner_args(args: &[String]) -> Option<&[String]> {
    let mut i = 0;
    while let Some(arg) = args.get(i).map(String::as_str) {
        if arg == "-n" || arg == "--adjustment" {
            i += 2;
        } else if arg.starts_with("--adjustment=") || is_nice_adjustment(arg) {
            i += 1;
        } else {
            break;
        }
    }
    args.get(i..).filter(|rest| !rest.is_empty())
}

/// A bare adjustment such as `-10` or `-+5`, which `nice` accepts in place of
/// `-n 10`. A flag like `-n` is not one, so it still consumes its value.
fn is_nice_adjustment(arg: &str) -> bool {
    arg.strip_prefix('-').is_some_and(|rest| {
        let digits = rest.strip_prefix('+').unwrap_or(rest);
        !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
    })
}

/// `None` when the argv does not match GNU timeout's grammar, which keeps the
/// caller on the fail-closed path of treating the stray word as the command.
fn timeout_inner_args(args: &[String]) -> Option<&[String]> {
    let mut i = 0;
    while let Some(arg) = args.get(i).map(String::as_str) {
        if TIMEOUT_VALUE_FLAGS.contains(&arg) {
            i += 2;
        } else if TIMEOUT_FLAGS.contains(&arg) || is_timeout_joined_value(arg) {
            i += 1;
        } else {
            break;
        }
    }
    if is_timeout_duration(args.get(i)?) {
        args.get(i + 1..)
    } else {
        None
    }
}

fn is_timeout_joined_value(arg: &str) -> bool {
    arg.starts_with("--kill-after=")
        || arg.starts_with("--signal=")
        || (arg.len() > 2 && (arg.starts_with("-k") || arg.starts_with("-s")))
}

fn is_timeout_duration(arg: &str) -> bool {
    let body = arg.strip_suffix(['s', 'm', 'h', 'd']).unwrap_or(arg);
    body.starts_with(|c: char| c.is_ascii_digit())
        && body.bytes().all(|b| b.is_ascii_digit() || b == b'.')
}

/// Check if a command is safe to auto-allow even when one of its arguments is a
/// set-but-unknown (dynamic) value.
///
/// This is the `SIMPLE_SAFE` set minus the commands whose behavior can depend
/// dangerously on an argument value (`DYNAMIC_ARG_UNSAFE` — pagers, `fzf`,
/// `mount`, `stty`).
#[must_use]
pub fn is_dynamic_arg_safe(cmd: &str) -> bool {
    is_simple_safe(cmd) && !DYNAMIC_ARG_UNSAFE.contains(cmd)
}

/// Number of commands in the simple-safe allowlist.
#[must_use]
pub fn simple_safe_count() -> usize {
    SIMPLE_SAFE.len()
}

/// Number of commands in the wrapper allowlist.
#[must_use]
pub fn wrapper_count() -> usize {
    WRAPPER_COMMANDS.len()
}

/// Return all simple-safe commands, sorted alphabetically.
#[must_use]
pub fn all_simple_safe() -> Vec<&'static str> {
    let mut cmds: Vec<_> = SIMPLE_SAFE.iter().copied().collect();
    cmds.sort_unstable();
    cmds
}

/// Return the `SIMPLE_SAFE` commands excluded from the dynamic-argument
/// relaxation, sorted alphabetically.
#[must_use]
pub fn all_dynamic_arg_unsafe() -> Vec<&'static str> {
    let mut cmds: Vec<_> = DYNAMIC_ARG_UNSAFE.iter().copied().collect();
    cmds.sort_unstable();
    cmds
}

/// Return all wrapper commands, sorted alphabetically.
#[must_use]
pub fn all_wrappers() -> Vec<&'static str> {
    let mut cmds: Vec<_> = WRAPPER_COMMANDS.iter().copied().collect();
    cmds.sort_unstable();
    cmds
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_safe_commands() {
        assert!(is_simple_safe("cat"));
        assert!(is_simple_safe("ls"));
        assert!(is_simple_safe("grep"));
        assert!(is_simple_safe("whoami"));
        assert!(is_simple_safe("jq"));
    }

    #[test]
    fn unknown_commands_not_safe() {
        assert!(!is_simple_safe("rm"));
        assert!(!is_simple_safe("sudo"));
        assert!(!is_simple_safe("arbitrary_command"));
    }

    #[test]
    fn wrapper_commands() {
        assert!(is_wrapper("time"));
        assert!(is_wrapper("timeout"));
        assert!(is_wrapper("nice"));
        assert!(is_wrapper("nohup"));
        assert!(!is_wrapper("cat"));
    }

    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| (*w).to_owned()).collect()
    }

    /// A wrapper with no modelled option grammar keeps its whole argv, so a
    /// leading option is read as the command name and Asks. That fail-closed
    /// default is the point; only `timeout` and `nice` are modelled.
    #[test]
    fn wrappers_without_an_option_grammar_keep_their_whole_argv() {
        let args = argv(&["-n", "10", "ls"]);
        assert_eq!(wrapper_inner_args("strace", &args), args.as_slice());
        assert_eq!(wrapper_inner_args("nohup", &args), args.as_slice());
    }

    #[test]
    fn nice_adjustment_options_are_skipped() {
        assert_eq!(
            wrapper_inner_args("nice", &argv(&["-n", "10", "ls"])),
            argv(&["ls"]).as_slice()
        );
        assert_eq!(
            wrapper_inner_args("nice", &argv(&["-10", "ls", "-la"])),
            argv(&["ls", "-la"]).as_slice()
        );
        assert_eq!(
            wrapper_inner_args("nice", &argv(&["--adjustment=5", "ls"])),
            argv(&["ls"]).as_slice()
        );
        assert_eq!(
            wrapper_inner_args("nice", &argv(&["ls"])),
            argv(&["ls"]).as_slice()
        );
    }

    /// A malformed `nice` falls back to the whole argv rather than yielding an
    /// empty command, so it stays on the Ask path.
    #[test]
    fn incomplete_nice_argv_falls_back_to_the_whole_argv() {
        let args = argv(&["-n"]);
        assert_eq!(wrapper_inner_args("nice", &args), args.as_slice());
    }

    #[test]
    fn timeout_duration_and_options_are_skipped() {
        assert_eq!(
            wrapper_inner_args("timeout", &argv(&["5", "ls", "-la"])),
            argv(&["ls", "-la"]).as_slice()
        );
        assert_eq!(
            wrapper_inner_args("timeout", &argv(&["-s", "KILL", "5", "ls"])),
            argv(&["ls"]).as_slice()
        );
        assert_eq!(
            wrapper_inner_args("timeout", &argv(&["--kill-after=1", "5s", "ls"])),
            argv(&["ls"]).as_slice()
        );
        assert_eq!(
            wrapper_inner_args("timeout", &argv(&["-sKILL", "1.5", "ls"])),
            argv(&["ls"]).as_slice()
        );
        assert!(wrapper_inner_args("timeout", &argv(&["5"])).is_empty());
    }

    #[test]
    fn unparseable_timeout_argv_falls_back_to_the_whole_slice() {
        for words in [
            vec!["ls"],
            vec!["1m30s", "ls"],
            vec!["--bogus", "5", "ls"],
            vec!["-s"],
        ] {
            let args = argv(&words);
            assert_eq!(
                wrapper_inner_args("timeout", &args),
                args.as_slice(),
                "{words:?} must not be reinterpreted"
            );
        }
    }
}
