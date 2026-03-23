use super::{Classification, Handler, HandlerContext, has_flag, positional_args};

// ---- kubectl ----

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
    "config",
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

        if has_flag(ctx.args, &["--help", "-h", "--version"]) {
            return Classification::Allow("kubectl help/version".into());
        }

        if sub == "exec" {
            return classify_kubectl_exec(ctx);
        }

        if KUBECTL_SAFE.contains(&sub) {
            Classification::Allow(desc)
        } else {
            Classification::Ask(desc)
        }
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
            return Classification::Recurse(inner);
        }
    }
    Classification::Ask("kubectl exec".into())
}

// ---- aws ----

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
        if has_flag(ctx.args, &["--help", "--version"]) {
            return Classification::Allow("aws help/version".into());
        }

        let positionals = positional_args(ctx.args);
        let service = positionals.first().copied().unwrap_or_default();
        let action = positionals.get(1).copied().unwrap_or_default();

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

// ---- gcloud ----

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
        if has_flag(ctx.args, &["--help", "-h", "--version"]) {
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

        // Skip alpha/beta prefixes
        let args: Vec<&str> = ctx
            .args
            .iter()
            .map(String::as_str)
            .skip_while(|a| matches!(*a, "alpha" | "beta"))
            .collect();

        let action = args.last().copied().unwrap_or_default();

        if GCLOUD_SAFE_KEYWORDS.contains(&action) {
            Classification::Allow(format!("gcloud ... {action}"))
        } else {
            Classification::Ask(format!("gcloud {}", ctx.args.join(" ")))
        }
    }
}

// ---- az ----

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
        if has_flag(ctx.args, &["--help", "-h", "--version"]) {
            return Classification::Allow("az help/version".into());
        }

        let positionals = positional_args(ctx.args);
        let action = positionals.last().copied().unwrap_or_default();

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
