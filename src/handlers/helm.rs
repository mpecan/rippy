use super::{
    AllowEntry, Classification, Handler, HandlerContext, has_flag, is_sole_help_flag, surface,
};
use crate::verdict::AllowReason;

pub(crate) static HELM_HANDLER: HelmHandler = HelmHandler;

pub(crate) struct HelmHandler;

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
        if is_sole_help_flag(ctx.args, &["--help", "-h", "--version"]) {
            return Classification::Allow(AllowReason::handler("helm help/version"));
        }

        let sub = ctx.subcommand();

        if SAFE_SUBCOMMANDS.contains(&sub) {
            return Classification::Allow(AllowReason::handler(format!("helm {sub}")));
        }

        if DRY_RUN_SUBCOMMANDS.contains(&sub) {
            if has_flag(ctx.args, &["--dry-run"]) {
                return Classification::Allow(AllowReason::handler(format!(
                    "helm {sub} --dry-run"
                )));
            }
            return Classification::Ask(format!("helm {sub}"));
        }

        // Nested subcommands: helm dependency list, helm repo list, etc.
        for (parent, safe_actions) in NESTED_SAFE {
            if sub == *parent {
                let action = ctx.arg(1);
                if safe_actions.contains(&action) {
                    return Classification::Allow(AllowReason::handler(format!(
                        "helm {sub} {action}"
                    )));
                }
                return Classification::Ask(format!("helm {sub} {action}"));
            }
        }

        Classification::Ask(format!("helm {sub}"))
    }

    fn allow_surface(&self) -> Vec<AllowEntry> {
        let mut entries = surface::subcommands("helm", SAFE_SUBCOMMANDS);
        entries.extend(surface::guarded_subcommands(
            "helm",
            DRY_RUN_SUBCOMMANDS,
            "--dry-run present",
        ));
        for (parent, safe_actions) in NESTED_SAFE {
            entries.extend(surface::subcommands(
                &format!("helm {parent}"),
                safe_actions,
            ));
        }
        entries.push(AllowEntry::guarded(
            "helm --help|-h|--version",
            "sole argument",
        ));
        entries
    }
}

// Behavioral coverage lives in tests/data/catalog/handlers_containers.toml — every
// helm case is a pure command->decision mapping with no injected state, so it is
// exercised through the real parse+analyze pipeline rather than white-box here.
