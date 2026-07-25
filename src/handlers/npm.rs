use super::{
    AllowEntry, Classification, Handler, HandlerContext, has_flag, is_sole_help_flag, surface,
};
use crate::verdict::AllowReason;

pub(crate) static NPM_HANDLER: NpmHandler = NpmHandler;

pub(crate) struct NpmHandler;

const SAFE: &[&str] = &[
    "list",
    "ls",
    "ll",
    "la",
    "info",
    "show",
    "view",
    "search",
    "outdated",
    "help",
    "docs",
    "whoami",
    "ping",
    "explain",
    "why",
    "fund",
    "doctor",
    "licenses",
    "completion",
    "diff",
    "find-dupes",
    "query",
    "stars",
    "sbom",
];

/// `npm config` children that only read.
const NPM_CONFIG_SAFE: &[&str] = &["list", "ls", "get"];

/// `npm cache` children that only read.
const NPM_CACHE_SAFE: &[&str] = &["ls", "list"];

// All non-safe commands default to Ask, so no explicit ASK list needed.

impl Handler for NpmHandler {
    fn commands(&self) -> &[&str] {
        &["npm", "npx", "yarn", "pnpm", "bun"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        let sub = ctx.args.first().map_or("", String::as_str);
        let desc = format!("{} {sub}", ctx.command_name);

        if is_sole_help_flag(ctx.args, &["--help", "-h", "--version", "-v"]) {
            return Classification::Allow(AllowReason::handler(format!(
                "{} help/version",
                ctx.command_name
            )));
        }

        // npx always asks (runs arbitrary packages)
        if ctx.command_name == "npx" {
            return Classification::Ask(format!("npx {sub}"));
        }

        if sub == "run" {
            // npm run with no script name or --list is safe
            if ctx.args.len() <= 1 || has_flag(ctx.args, &["--list"]) {
                return Classification::Allow(AllowReason::handler(format!(
                    "{} run (list)",
                    ctx.command_name
                )));
            }
            return Classification::Ask(desc);
        }

        if sub == "config" || sub == "c" {
            return classify_config(ctx);
        }

        if sub == "cache" {
            return classify_cache(ctx);
        }

        if sub == "audit" {
            if has_flag(&ctx.args[1..], &["fix"]) {
                return Classification::Ask(format!("{} audit fix", ctx.command_name));
            }
            return Classification::Allow(AllowReason::handler(format!(
                "{} audit",
                ctx.command_name
            )));
        }

        if SAFE.contains(&sub) {
            Classification::Allow(AllowReason::handler(desc))
        } else {
            Classification::Ask(desc)
        }
    }

    fn allow_surface(&self) -> Vec<AllowEntry> {
        // `npx` always asks; every entry below is for npm/yarn/pnpm/bun.
        let mut entries = surface::subcommands("npm", SAFE);
        entries.extend(surface::subcommands("npm config", NPM_CONFIG_SAFE));
        entries.extend(surface::subcommands("npm c", NPM_CONFIG_SAFE));
        entries.extend(surface::subcommands("npm cache", NPM_CACHE_SAFE));
        entries.push(AllowEntry::guarded(
            "npm run",
            "no script name, or --list present",
        ));
        entries.push(AllowEntry::guarded("npm audit", "no `fix` operand"));
        entries.push(AllowEntry::guarded(
            "npm --help|-h|--version|-v",
            "sole argument",
        ));
        entries
    }
}

fn classify_config(ctx: &HandlerContext) -> Classification {
    let sub = ctx.args.get(1).map_or("", String::as_str);
    if NPM_CONFIG_SAFE.contains(&sub) {
        Classification::Allow(AllowReason::handler(format!(
            "{} config {sub}",
            ctx.command_name
        )))
    } else {
        Classification::Ask(format!("{} config {sub}", ctx.command_name))
    }
}

fn classify_cache(ctx: &HandlerContext) -> Classification {
    let sub = ctx.args.get(1).map_or("", String::as_str);
    if NPM_CACHE_SAFE.contains(&sub) {
        Classification::Allow(AllowReason::handler(format!(
            "{} cache {sub}",
            ctx.command_name
        )))
    } else {
        Classification::Ask(format!("{} cache {sub}", ctx.command_name))
    }
}
