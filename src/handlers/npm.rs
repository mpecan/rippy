use super::{Classification, Handler, HandlerContext, has_flag};

pub static NPM_HANDLER: NpmHandler = NpmHandler;

pub struct NpmHandler;

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
    "pack",
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

// All non-safe commands default to Ask, so no explicit ASK list needed.

impl Handler for NpmHandler {
    fn commands(&self) -> &[&str] {
        &["npm", "npx", "yarn", "pnpm", "bun"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        let sub = ctx.args.first().map_or("", String::as_str);
        let desc = format!("{} {sub}", ctx.command_name);

        if has_flag(ctx.args, &["--help", "-h", "--version", "-v"]) {
            return Classification::Allow(format!("{} help/version", ctx.command_name));
        }

        // npx always asks (runs arbitrary packages)
        if ctx.command_name == "npx" {
            return Classification::Ask(format!("npx {sub}"));
        }

        if sub == "run" {
            // npm run with no script name or --list is safe
            if ctx.args.len() <= 1 || has_flag(ctx.args, &["--list"]) {
                return Classification::Allow(format!("{} run (list)", ctx.command_name));
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
            return Classification::Allow(format!("{} audit", ctx.command_name));
        }

        if SAFE.contains(&sub) {
            Classification::Allow(desc)
        } else {
            Classification::Ask(desc)
        }
    }
}

fn classify_config(ctx: &HandlerContext) -> Classification {
    let sub = ctx.args.get(1).map_or("", String::as_str);
    match sub {
        "list" | "ls" | "get" => {
            Classification::Allow(format!("{} config {sub}", ctx.command_name))
        }
        _ => Classification::Ask(format!("{} config {sub}", ctx.command_name)),
    }
}

fn classify_cache(ctx: &HandlerContext) -> Classification {
    let sub = ctx.args.get(1).map_or("", String::as_str);
    match sub {
        "ls" | "list" => Classification::Allow(format!("{} cache {sub}", ctx.command_name)),
        _ => Classification::Ask(format!("{} cache {sub}", ctx.command_name)),
    }
}
