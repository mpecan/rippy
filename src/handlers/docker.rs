use super::{Classification, Handler, HandlerContext, get_flag_value, is_sole_help_flag};

pub(crate) static DOCKER_HANDLER: DockerHandler = DockerHandler;

pub(crate) struct DockerHandler;

const SAFE: &[&str] = &[
    "version", "help", "info", "ps", "images", "inspect", "logs", "stats", "top", "port", "diff",
    "history", "search", "events",
];

/// Management nouns whose action verb, not the noun, determines safety
/// (`docker image rm` mutates; `docker image ls` reads).
const GROUPED_NOUNS: &[&str] = &["image", "system", "network", "volume", "config", "context"];

/// Read-only actions across the grouped management nouns.
const GROUP_SAFE_ACTIONS: &[&str] = &[
    "ls", "list", "inspect", "df", "history", "events", "info", "show",
];

// All non-safe commands default to Ask, so no explicit ASK list needed.

impl Handler for DockerHandler {
    fn commands(&self) -> &[&str] {
        &["docker", "docker-compose", "podman", "podman-compose"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        let sub = ctx.args.first().map_or("", String::as_str);
        let desc = format!("{} {sub}", ctx.command_name);

        if is_sole_help_flag(ctx.args, &["--help", "-h", "--version"]) {
            return Classification::Allow(format!("{} help/version", ctx.command_name));
        }

        if sub == "exec" {
            return classify_exec(ctx);
        }

        if sub == "compose" || ctx.command_name.ends_with("-compose") {
            return classify_compose(ctx);
        }

        // export/save: safe to stdout, but -o/--output writes to file
        if sub == "export" || sub == "save" {
            return classify_export_save(ctx, sub);
        }

        if GROUPED_NOUNS.contains(&sub) {
            return classify_grouped_noun(ctx, sub);
        }

        if SAFE.contains(&sub) {
            Classification::Allow(desc)
        } else {
            Classification::Ask(desc)
        }
    }
}

fn classify_grouped_noun(ctx: &HandlerContext, noun: &str) -> Classification {
    let action = ctx.args.get(1).map_or("", String::as_str);
    let desc = format!("{} {noun} {action}", ctx.command_name);
    if GROUP_SAFE_ACTIONS.contains(&action) {
        Classification::Allow(desc)
    } else {
        Classification::Ask(desc)
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
        return Classification::RecurseRemote(inner);
    }
    Classification::Ask("docker exec".into())
}

fn classify_export_save(ctx: &HandlerContext, sub: &str) -> Classification {
    if let Some(output) = get_flag_value(ctx.args, &["-o", "--output"]) {
        return Classification::WithRedirects(
            crate::verdict::Decision::Allow,
            format!("{} {sub} with output file", ctx.command_name),
            vec![output],
        );
    }
    Classification::Allow(format!("{} {sub} (stdout)", ctx.command_name))
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

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn docker_exec_recurses_remote() {
        let args: Vec<String> = vec![
            "exec".into(),
            "mycontainer".into(),
            "ls".into(),
            "-la".into(),
        ];
        let result = DOCKER_HANDLER.classify(&HandlerContext::test("docker", &args));
        assert!(matches!(result, Classification::RecurseRemote(cmd) if cmd == "ls -la"));
    }

    #[test]
    fn docker_exec_with_flags() {
        let args: Vec<String> = vec![
            "exec".into(),
            "-it".into(),
            "-u".into(),
            "root".into(),
            "mycontainer".into(),
            "bash".into(),
        ];
        let result = DOCKER_HANDLER.classify(&HandlerContext::test("docker", &args));
        assert!(matches!(result, Classification::RecurseRemote(cmd) if cmd == "bash"));
    }

    // Pure subcommand->decision cases (compose ps/up, run, save/export to stdout,
    // safe subcommands) are covered by tests/data/catalog/handlers_containers.toml.
    // The tests below assert non-decision Classification variants (RecurseRemote,
    // WithRedirects) that a command string cannot express.
    #[test]
    fn docker_save_output_file() {
        let args: Vec<String> = vec![
            "save".into(),
            "-o".into(),
            "/tmp/image.tar".into(),
            "myimage".into(),
        ];
        let result = DOCKER_HANDLER.classify(&HandlerContext::test("docker", &args));
        assert!(matches!(result, Classification::WithRedirects(..)));
    }

    #[test]
    fn docker_export_stdout_allows() {
        let args: Vec<String> = vec!["export".into(), "container".into()];
        let result = DOCKER_HANDLER.classify(&HandlerContext::test("docker", &args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn docker_export_output_file() {
        let args: Vec<String> = vec![
            "export".into(),
            "--output".into(),
            "/tmp/container.tar".into(),
            "container".into(),
        ];
        let result = DOCKER_HANDLER.classify(&HandlerContext::test("docker", &args));
        assert!(matches!(result, Classification::WithRedirects(..)));
    }
}
