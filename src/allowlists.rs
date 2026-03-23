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
        // Search (find, env, sort, yq have dedicated handlers — not in this list)
        "fd",
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
        "ifconfig",
        "ip",
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
        "dos2unix",
        "unix2dos",
        // Disk/fs info
        "mount",
        "findmnt",
        "lsblk",
        "blkid",
        // Dmesg
        "dmesg",
    ])
});

/// Commands that wrap other commands — analyze the inner command instead.
static WRAPPER_COMMANDS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from([
        "time", "timeout", "nice", "strace", "ltrace", "nohup", "command", "builtin",
    ])
});

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
