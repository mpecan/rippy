use super::{
    Classification, Handler, HandlerContext, get_flag_value, is_sole_help_flag, positional_args,
};

/// Verbs across gcloud/az resource trees that mutate state, checked against
/// the command-path (positional tokens before the first flag). Any match in
/// the path means the command mutates regardless of what the last token is.
const MUTATING_VERBS: &[&str] = &[
    "create", "delete", "update", "set", "add", "remove", "patch", "replace", "deploy", "restart",
    "start", "stop", "reset", "resize", "enable", "disable", "attach", "detach", "import",
    "promote", "rollback", "clear", "purge", "drain", "scale", "migrate", "move", "clone",
    "restore", "rotate", "revoke", "grant", "prune",
];

fn is_mutating_verb(tok: &str) -> bool {
    MUTATING_VERBS.contains(&tok)
        || tok.starts_with("create-")
        || tok.starts_with("delete-")
        || tok.starts_with("set-")
}

/// Positional tokens before the first flag — the actual command path,
/// immune to flag values (`--name list`) or trailing `--format json` being
/// mistaken for part of the path.
fn command_path(args: &[String]) -> Vec<&str> {
    args.iter()
        .map(String::as_str)
        .take_while(|a| !a.starts_with('-'))
        .collect()
}

// kubectl

pub static KUBECTL_HANDLER: KubectlHandler = KubectlHandler;

pub struct KubectlHandler;

const KUBECTL_SAFE: &[&str] = &[
    "get",
    "describe",
    "explain",
    "logs",
    "top",
    "cluster-info",
    "version",
    "api-resources",
    "api-versions",
    "auth",
    "wait",
    "diff",
    "plugin",
    "completion",
    "kustomize",
];

impl Handler for KubectlHandler {
    fn commands(&self) -> &[&str] {
        &["kubectl", "k"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        let sub = ctx.args.first().map_or("", String::as_str);
        let desc = format!("kubectl {sub}");

        if is_sole_help_flag(ctx.args, &["--help", "-h", "--version"]) {
            return Classification::Allow("kubectl help/version".into());
        }

        if sub == "exec" {
            return classify_kubectl_exec(ctx);
        }

        if sub == "config" {
            return classify_kubectl_config(ctx);
        }

        if KUBECTL_SAFE.contains(&sub) {
            Classification::Allow(desc)
        } else {
            Classification::Ask(desc)
        }
    }
}

const KUBECTL_CONFIG_SAFE: &[&str] = &[
    "view",
    "current-context",
    "get-contexts",
    "get-clusters",
    "get-users",
    "get-context",
];

fn classify_kubectl_config(ctx: &HandlerContext) -> Classification {
    let child = ctx.arg(1);
    if KUBECTL_CONFIG_SAFE.contains(&child) {
        Classification::Allow(format!("kubectl config {child}"))
    } else {
        Classification::Ask(format!("kubectl config {child}"))
    }
}

fn classify_kubectl_exec(ctx: &HandlerContext) -> Classification {
    // Extract inner command after --
    if let Some(sep) = ctx.args.iter().position(|a| a == "--") {
        let inner = ctx.args[sep + 1..]
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(" ");
        if !inner.is_empty() {
            return Classification::RecurseRemote(inner);
        }
    }
    Classification::Ask("kubectl exec".into())
}

/// Whether an `--endpoint-url` value points at localhost (localstack/minio
/// style local testing). Anything else redirects a signed AWS request off
/// AWS's servers — a viable SSRF/credential-exfil vector.
fn is_local_endpoint(url: &str) -> bool {
    let after_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    let host = after_scheme.split(['/', ':']).next().unwrap_or_default();
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

// aws

pub static AWS_HANDLER: AwsHandler = AwsHandler;

pub struct AwsHandler;

const AWS_SAFE_PREFIXES: &[&str] = &[
    "describe-",
    "list-",
    "get-",
    "show-",
    "head-",
    "lookup-",
    "filter-",
    "validate-",
    "estimate-",
    "simulate-",
    "generate-",
    "download-",
    "detect-",
    "test-",
    "check-if-",
    "admin-get-",
    "admin-list-",
];

const AWS_SAFE_ACTIONS: &[&str] = &[
    "ls",
    "wait",
    "help",
    "query",
    "scan",
    "tail",
    "receive-message",
    "batch-get-item",
    "transact-get-items",
];

impl Handler for AwsHandler {
    fn commands(&self) -> &[&str] {
        &["aws"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if is_sole_help_flag(ctx.args, &["--help", "--version"]) {
            return Classification::Allow("aws help/version".into());
        }

        if let Some(endpoint) = get_flag_value(ctx.args, &["--endpoint-url"])
            && !is_local_endpoint(&endpoint)
        {
            return Classification::Ask(format!("aws --endpoint-url {endpoint}"));
        }

        let positionals = positional_args(ctx.args);
        let service = positionals.first().copied().unwrap_or_default();
        let action = positionals.get(1).copied().unwrap_or_default();

        // get-login-password prints a registry credential; the `get-` prefix
        // would otherwise mark it safe below.
        if action == "get-login-password" {
            return Classification::Ask(format!("aws {service} {action}"));
        }

        if service == "configure" {
            return if matches!(action, "list" | "list-profiles" | "get" | "") {
                Classification::Allow(format!("aws configure {action}"))
            } else {
                Classification::Ask(format!("aws configure {action}"))
            };
        }

        if service == "sts" {
            let sts_safe = [
                "get-caller-identity",
                "get-session-token",
                "get-access-key-info",
                "decode-authorization-message",
            ];
            if sts_safe.contains(&action) {
                return Classification::Allow(format!("aws sts {action}"));
            }
        }

        if AWS_SAFE_ACTIONS.contains(&action) {
            return Classification::Allow(format!("aws {service} {action}"));
        }

        if AWS_SAFE_PREFIXES.iter().any(|p| action.starts_with(p)) {
            return Classification::Allow(format!("aws {service} {action}"));
        }

        Classification::Ask(format!("aws {service} {action}"))
    }
}

// gcloud

pub static GCLOUD_HANDLER: GcloudHandler = GcloudHandler;

pub struct GcloudHandler;

const GCLOUD_SAFE_KEYWORDS: &[&str] = &[
    "describe",
    "list",
    "get",
    "show",
    "info",
    "status",
    "version",
    "get-credentials",
    "list-tags",
    "read",
    "configurations",
];

impl Handler for GcloudHandler {
    fn commands(&self) -> &[&str] {
        &["gcloud", "gsutil"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if is_sole_help_flag(ctx.args, &["--help", "-h", "--version"]) {
            return Classification::Allow(format!("{} help/version", ctx.command_name));
        }

        if ctx.command_name == "gsutil" {
            let sub = ctx.args.first().map_or("", String::as_str);
            return match sub {
                "ls" | "cat" | "stat" | "du" | "hash" | "version" | "help" => {
                    Classification::Allow(format!("gsutil {sub}"))
                }
                _ => Classification::Ask(format!("gsutil {sub}")),
            };
        }

        // Skip alpha/beta prefixes, then take the command-path (positionals
        // before the first flag) so flag values can't masquerade as the verb.
        let skipped: Vec<String> = ctx
            .args
            .iter()
            .skip_while(|a| matches!(a.as_str(), "alpha" | "beta"))
            .cloned()
            .collect();
        let path = command_path(&skipped);

        if path.iter().any(|tok| is_mutating_verb(tok)) {
            return Classification::Ask(format!("gcloud {}", ctx.args.join(" ")));
        }

        let action = path.last().copied().unwrap_or_default();
        if GCLOUD_SAFE_KEYWORDS.contains(&action) {
            Classification::Allow(format!("gcloud ... {action}"))
        } else {
            Classification::Ask(format!("gcloud {}", ctx.args.join(" ")))
        }
    }
}

// az

pub static AZ_HANDLER: AzHandler = AzHandler;

pub struct AzHandler;

const AZ_SAFE_KEYWORDS: &[&str] = &[
    "show",
    "list",
    "get",
    "exists",
    "query",
    "logs",
    "check-health",
    "download",
    "tail",
];

impl Handler for AzHandler {
    fn commands(&self) -> &[&str] {
        &["az"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if is_sole_help_flag(ctx.args, &["--help", "-h", "--version"]) {
            return Classification::Allow("az help/version".into());
        }

        let path = command_path(ctx.args);

        if path.iter().any(|tok| is_mutating_verb(tok)) {
            return Classification::Ask(format!("az {}", ctx.args.join(" ")));
        }

        let action = path.last().copied().unwrap_or_default();

        if AZ_SAFE_KEYWORDS.contains(&action)
            || action.starts_with("list-")
            || action.starts_with("show-")
            || action.starts_with("get-")
        {
            Classification::Allow(format!("az ... {action}"))
        } else {
            Classification::Ask(format!("az {}", ctx.args.join(" ")))
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    // Pure subcommand->decision cases (kubectl get/apply, aws describe/create) are
    // covered by tests/data/catalog/handlers_containers.toml. The exec test below
    // asserts the RecurseRemote variant, which a command string cannot express.
    #[test]
    fn kubectl_exec_recurses_remote() {
        let args: Vec<String> = vec![
            "exec".into(),
            "mypod".into(),
            "--".into(),
            "cat".into(),
            "/etc/hosts".into(),
        ];
        let result = KUBECTL_HANDLER.classify(&HandlerContext::test("kubectl", &args));
        assert!(matches!(result, Classification::RecurseRemote(cmd) if cmd == "cat /etc/hosts"));
    }
}
