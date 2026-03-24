use super::SubcommandHandler;

pub static CARGO_HANDLER: SubcommandHandler = SubcommandHandler::new(
    &["cargo"],
    &[
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
        "check",
        "clippy",
        "fmt",
        "doc",
        "fetch",
        "generate-lockfile",
        "update",
        "vendor",
        "login",
        "logout",
        "owner",
    ],
    &[
        "build",
        "run",
        "test",
        "bench",
        "publish",
        "install",
        "uninstall",
        "new",
        "init",
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
