use super::SubcommandHandler;

pub static CARGO_HANDLER: SubcommandHandler = SubcommandHandler::new(
    &["cargo"],
    &[
        // Built-in info/query commands
        "help",
        "version",
        "search",
        "info",
        "tree",
        "metadata",
        "read-manifest",
        "locate-project",
        "pkgid",
        "verify-project",
        // Build/test/check (writes only to target/)
        "build",
        "test",
        "bench",
        "check",
        "clippy",
        "fmt",
        "doc",
        "clean",
        "nextest",
        // Dependency management (modifies Cargo.lock / vendor only)
        "fetch",
        "generate-lockfile",
        "update",
        "vendor",
        // Registry auth
        "login",
        "logout",
        "owner",
        // Third-party analysis tools (read-only)
        "audit",
        "deny",
        "expand",
        "outdated",
        "bloat",
        "machete",
        "llvm-lines",
        "udeps",
        "depgraph",
        "msrv",
    ],
    &[
        // Executes arbitrary code
        "run",
        // Publishes / installs (side effects beyond project)
        "publish",
        "install",
        "uninstall",
        // Creates files/directories
        "new",
        "init",
        // Modifies source files
        "fix",
        "add",
        "rm",
        "remove",
        "upgrade",
    ],
    "cargo",
);

pub static BREW_HANDLER: SubcommandHandler = SubcommandHandler::new(
    &["brew"],
    &[
        "list", "ls", "leaves", "info", "desc", "home", "deps", "uses", "search", "doctor",
        "config", "outdated", "missing", "tap-info", "formulae", "casks", "log", "cat", "fetch",
        "docs", "shellenv", "help",
    ],
    &[
        "install",
        "uninstall",
        "upgrade",
        "update",
        "link",
        "unlink",
        "cleanup",
        "tap",
        "untap",
        "pin",
        "unpin",
        "services",
    ],
    "brew",
);

pub static PIP_HANDLER: SubcommandHandler = SubcommandHandler::new(
    &["pip", "pip3"],
    &[
        "list", "freeze", "show", "search", "check", "config", "help", "version", "debug", "cache",
        "index", "inspect", "hash",
    ],
    &["install", "uninstall", "download", "wheel", "lock"],
    "pip",
);

pub static TERRAFORM_HANDLER: SubcommandHandler = SubcommandHandler::new(
    &["terraform", "tf"],
    &[
        "version",
        "help",
        "fmt",
        "validate",
        "plan",
        "show",
        "state",
        "output",
        "graph",
        "providers",
        "console",
        "workspace",
        "get",
        "modules",
        "metadata",
        "test",
        "refresh",
    ],
    &[
        "apply", "destroy", "import", "taint", "untaint", "init", "login", "logout",
    ],
    "terraform",
);

pub static PYTEST_HANDLER: SubcommandHandler = SubcommandHandler::new(
    &["pytest"],
    &["--version", "--help", "--co", "--collect-only"],
    &[],
    "pytest",
);

pub static MAKE_HANDLER: SubcommandHandler = SubcommandHandler::new(
    &["make", "gmake"],
    &[], // make targets are all potentially unsafe
    &[], // everything defaults to ask
    "make",
);

pub static RUSTUP_HANDLER: SubcommandHandler = SubcommandHandler::new(
    &["rustup"],
    &[
        "show",
        "which",
        "doc",
        "man",
        "completions",
        "check",
        "default",
        "target",
        "component",
        "toolchain",
    ],
    &["install", "uninstall", "update", "override", "run", "self"],
    "rustup",
);

pub static OPENSSL_HANDLER: SubcommandHandler = SubcommandHandler::new(
    &["openssl"],
    &["version", "help", "list", "s_client"],
    &[],
    "openssl",
);
