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
}
