use super::{Classification, Handler, HandlerContext, get_flag_value, has_flag};

pub static GH_HANDLER: GhHandler = GhHandler;

pub struct GhHandler;

const SAFE_ACTIONS: &[&str] = &[
    "view", "list", "status", "diff", "checks", "search", "download", "watch", "verify", "logs",
    "ports",
];

const UNSAFE_METHODS: &[&str] = &["POST", "PUT", "DELETE", "PATCH"];

impl Handler for GhHandler {
    fn commands(&self) -> &[&str] {
        &["gh"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if has_flag(ctx.args, &["--help", "-h", "--version"]) {
            return Classification::Allow("gh help/version".into());
        }

        let sub = ctx.subcommand();

        match sub {
            "api" => classify_api(ctx),
            // Top-level safe commands
            "status" | "browse" | "search" | "completion" | "help" => {
                Classification::Allow(format!("gh {sub}"))
            }
            // Resource commands — classify by action (second arg)
            "pr" | "issue" | "release" | "repo" | "run" | "workflow" | "gist" | "project"
            | "label" | "codespace" | "secret" | "variable" => classify_resource(ctx, sub),
            _ => Classification::Ask(format!("gh {sub}")),
        }
    }
}

fn classify_api(ctx: &HandlerContext) -> Classification {
    if let Some(method) = get_flag_value(ctx.args, &["-X", "--method"])
        && UNSAFE_METHODS.contains(&method.to_uppercase().as_str())
    {
        return Classification::Ask(format!("gh api -X {method}"));
    }

    // Check for GraphQL mutation in field arguments
    for (i, arg) in ctx.args.iter().enumerate() {
        if matches!(arg.as_str(), "-f" | "--raw-field" | "--field")
            && let Some(val) = ctx.args.get(i + 1)
            && val.contains("mutation")
        {
            return Classification::Ask("gh api (GraphQL mutation)".into());
        }
    }

    // --input reads from a file — we can't inspect its contents, so ask
    if has_flag(ctx.args, &["--input"]) {
        return Classification::Ask("gh api (--input, cannot verify contents)".into());
    }

    Classification::Allow("gh api (GET)".into())
}

fn classify_resource(ctx: &HandlerContext, resource: &str) -> Classification {
    let action = ctx.arg(1);

    if action.is_empty() {
        return Classification::Ask(format!("gh {resource}"));
    }

    if SAFE_ACTIONS.contains(&action) {
        Classification::Allow(format!("gh {resource} {action}"))
    } else {
        Classification::Ask(format!("gh {resource} {action}"))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::path::Path;

    use super::*;

    fn ctx(args: &[String]) -> HandlerContext<'_> {
        HandlerContext {
            command_name: "gh",
            args,
            working_directory: Path::new("/tmp"),
            remote: false,
        }
    }

    // gh api tests
    #[test]
    fn api_get_allows() {
        let args: Vec<String> = vec!["api".into(), "repos/owner/repo".into()];
        let result = GH_HANDLER.classify(&ctx(&args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn api_post_asks() {
        let args: Vec<String> = vec![
            "api".into(),
            "-X".into(),
            "POST".into(),
            "repos/owner/repo/issues".into(),
        ];
        let result = GH_HANDLER.classify(&ctx(&args));
        assert!(matches!(result, Classification::Ask(_)));
    }

    #[test]
    fn api_delete_asks() {
        let args: Vec<String> = vec![
            "api".into(),
            "--method".into(),
            "DELETE".into(),
            "repos/owner/repo".into(),
        ];
        let result = GH_HANDLER.classify(&ctx(&args));
        assert!(matches!(result, Classification::Ask(_)));
    }

    #[test]
    fn api_graphql_mutation_asks() {
        let args: Vec<String> = vec![
            "api".into(),
            "graphql".into(),
            "-f".into(),
            "query=mutation { addStar(input: {}) { clientMutationId } }".into(),
        ];
        let result = GH_HANDLER.classify(&ctx(&args));
        assert!(matches!(result, Classification::Ask(_)));
    }

    #[test]
    fn api_graphql_query_allows() {
        let args: Vec<String> = vec![
            "api".into(),
            "graphql".into(),
            "-f".into(),
            "query={ repository(owner: \"o\", name: \"r\") { name } }".into(),
        ];
        let result = GH_HANDLER.classify(&ctx(&args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn api_input_file_asks() {
        let args: Vec<String> = vec![
            "api".into(),
            "graphql".into(),
            "--input".into(),
            "query.graphql".into(),
        ];
        let result = GH_HANDLER.classify(&ctx(&args));
        assert!(matches!(result, Classification::Ask(_)));
    }

    // gh pr tests
    #[test]
    fn pr_view_allows() {
        let args: Vec<String> = vec!["pr".into(), "view".into(), "123".into()];
        let result = GH_HANDLER.classify(&ctx(&args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn pr_create_asks() {
        let args: Vec<String> = vec!["pr".into(), "create".into()];
        let result = GH_HANDLER.classify(&ctx(&args));
        assert!(matches!(result, Classification::Ask(_)));
    }

    #[test]
    fn pr_list_allows() {
        let args: Vec<String> = vec!["pr".into(), "list".into()];
        let result = GH_HANDLER.classify(&ctx(&args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn pr_merge_asks() {
        let args: Vec<String> = vec!["pr".into(), "merge".into(), "123".into()];
        let result = GH_HANDLER.classify(&ctx(&args));
        assert!(matches!(result, Classification::Ask(_)));
    }

    #[test]
    fn issue_create_asks() {
        let args: Vec<String> = vec!["issue".into(), "create".into()];
        let result = GH_HANDLER.classify(&ctx(&args));
        assert!(matches!(result, Classification::Ask(_)));
    }

    #[test]
    fn issue_view_allows() {
        let args: Vec<String> = vec!["issue".into(), "view".into(), "42".into()];
        let result = GH_HANDLER.classify(&ctx(&args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    // Top-level commands
    #[test]
    fn status_allows() {
        let args: Vec<String> = vec!["status".into()];
        let result = GH_HANDLER.classify(&ctx(&args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn help_allows() {
        let args: Vec<String> = vec!["--help".into()];
        let result = GH_HANDLER.classify(&ctx(&args));
        assert!(matches!(result, Classification::Allow(_)));
    }
}
