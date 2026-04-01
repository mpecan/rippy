use super::{Classification, Handler, HandlerContext, has_flag};

pub static HELM_HANDLER: HelmHandler = HelmHandler;

pub struct HelmHandler;

const SAFE_SUBCOMMANDS: &[&str] = &[
    "completion",
    "env",
    "get",
    "help",
    "history",
    "lint",
    "list",
    "ls",
    "search",
    "show",
    "inspect",
    "status",
    "template",
    "verify",
    "version",
];

/// Subcommands that are safe with --dry-run, otherwise ask.
const DRY_RUN_SUBCOMMANDS: &[&str] = &["install", "upgrade", "uninstall", "rollback"];

/// Nested subcommands where the second arg determines safety.
const NESTED_SAFE: &[(&str, &[&str])] = &[
    ("dependency", &["list", "update", "build"]),
    ("repo", &["list"]),
    ("plugin", &["list"]),
    ("registry", &[]),
];

impl Handler for HelmHandler {
    fn commands(&self) -> &[&str] {
        &["helm"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if has_flag(ctx.args, &["--help", "-h", "--version"]) {
            return Classification::Allow("helm help/version".into());
        }

        let sub = ctx.subcommand();

        if SAFE_SUBCOMMANDS.contains(&sub) {
            return Classification::Allow(format!("helm {sub}"));
        }

        if DRY_RUN_SUBCOMMANDS.contains(&sub) {
            if has_flag(ctx.args, &["--dry-run"]) {
                return Classification::Allow(format!("helm {sub} --dry-run"));
            }
            return Classification::Ask(format!("helm {sub}"));
        }

        // Nested subcommands: helm dependency list, helm repo list, etc.
        for (parent, safe_actions) in NESTED_SAFE {
            if sub == *parent {
                let action = ctx.arg(1);
                if safe_actions.contains(&action) {
                    return Classification::Allow(format!("helm {sub} {action}"));
                }
                return Classification::Ask(format!("helm {sub} {action}"));
            }
        }

        Classification::Ask(format!("helm {sub}"))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::path::Path;

    use super::*;

    fn ctx(args: &[String]) -> HandlerContext<'_> {
        HandlerContext {
            command_name: "helm",
            args,
            working_directory: Path::new("/tmp"),
            remote: false,
            receives_piped_input: false,
            cd_allowed_dirs: &[],
        }
    }

    #[test]
    fn install_dry_run_allows() {
        let args: Vec<String> = vec![
            "install".into(),
            "myrelease".into(),
            "chart".into(),
            "--dry-run".into(),
        ];
        let result = HELM_HANDLER.classify(&ctx(&args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn install_without_dry_run_asks() {
        let args: Vec<String> = vec!["install".into(), "myrelease".into(), "chart".into()];
        let result = HELM_HANDLER.classify(&ctx(&args));
        assert!(matches!(result, Classification::Ask(_)));
    }

    #[test]
    fn upgrade_dry_run_allows() {
        let args: Vec<String> = vec![
            "upgrade".into(),
            "myrelease".into(),
            "chart".into(),
            "--dry-run".into(),
        ];
        let result = HELM_HANDLER.classify(&ctx(&args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn list_allows() {
        let args: Vec<String> = vec!["list".into()];
        let result = HELM_HANDLER.classify(&ctx(&args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn dependency_list_allows() {
        let args: Vec<String> = vec!["dependency".into(), "list".into()];
        let result = HELM_HANDLER.classify(&ctx(&args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn repo_list_allows() {
        let args: Vec<String> = vec!["repo".into(), "list".into()];
        let result = HELM_HANDLER.classify(&ctx(&args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn repo_add_asks() {
        let args: Vec<String> = vec!["repo".into(), "add".into(), "name".into(), "url".into()];
        let result = HELM_HANDLER.classify(&ctx(&args));
        assert!(matches!(result, Classification::Ask(_)));
    }

    #[test]
    fn plugin_list_allows() {
        let args: Vec<String> = vec!["plugin".into(), "list".into()];
        let result = HELM_HANDLER.classify(&ctx(&args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn rollback_dry_run_allows() {
        let args: Vec<String> = vec![
            "rollback".into(),
            "myrelease".into(),
            "1".into(),
            "--dry-run".into(),
        ];
        let result = HELM_HANDLER.classify(&ctx(&args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn uninstall_asks() {
        let args: Vec<String> = vec!["uninstall".into(), "myrelease".into()];
        let result = HELM_HANDLER.classify(&ctx(&args));
        assert!(matches!(result, Classification::Ask(_)));
    }

    #[test]
    fn help_allows() {
        let args: Vec<String> = vec!["--help".into()];
        let result = HELM_HANDLER.classify(&ctx(&args));
        assert!(matches!(result, Classification::Allow(_)));
    }
}
