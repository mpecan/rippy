use super::{Classification, Handler, HandlerContext, has_flag};

pub static DOCKER_HANDLER: DockerHandler = DockerHandler;

pub struct DockerHandler;

const SAFE: &[&str] = &[
    "version", "help", "info", "ps", "images", "image", "inspect", "logs", "stats", "top", "port",
    "diff", "history", "search", "events", "system", "network", "volume", "config", "context",
];

// All non-safe commands default to Ask, so no explicit ASK list needed.

impl Handler for DockerHandler {
    fn commands(&self) -> &[&str] {
        &["docker", "docker-compose", "podman", "podman-compose"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        let sub = ctx.args.first().map_or("", String::as_str);
        let desc = format!("{} {sub}", ctx.command_name);

        if has_flag(ctx.args, &["--help", "-h", "--version"]) {
            return Classification::Allow(format!("{} help/version", ctx.command_name));
        }

        if sub == "exec" {
            return classify_exec(ctx);
        }

        if sub == "compose" || ctx.command_name.ends_with("-compose") {
            return classify_compose(ctx);
        }

        if SAFE.contains(&sub) {
            Classification::Allow(desc)
        } else {
            Classification::Ask(desc)
        }
    }
}

fn classify_exec(ctx: &HandlerContext) -> Classification {
    // Extract inner command after exec flags and container name
    let args = &ctx.args[1..]; // skip "exec"
    let mut i = 0;
    let mut found_container = false;
    while i < args.len() {
        let arg = &args[i];
        if arg.starts_with('-') {
            // Skip flags (some take values)
            if matches!(
                arg.as_str(),
                "-e" | "--env" | "-u" | "--user" | "-w" | "--workdir"
            ) {
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        if !found_container {
            found_container = true;
            i += 1;
            continue;
        }
        // Everything after container name is the inner command
        let inner = args[i..]
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(" ");
        return Classification::Recurse(inner);
    }
    Classification::Ask("docker exec".into())
}

fn classify_compose(ctx: &HandlerContext) -> Classification {
    const COMPOSE_SAFE: &[&str] = &[
        "ps", "logs", "config", "images", "ls", "top", "version", "port", "events",
    ];

    let sub = if ctx.command_name.ends_with("-compose") {
        ctx.args.first().map_or("", String::as_str)
    } else {
        // docker compose <sub>
        ctx.args.get(1).map_or("", String::as_str)
    };

    if COMPOSE_SAFE.contains(&sub) {
        Classification::Allow(format!("compose {sub}"))
    } else {
        Classification::Ask(format!("compose {sub}"))
    }
}
