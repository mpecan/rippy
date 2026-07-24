use super::{Classification, Handler, HandlerContext, get_flag_value, is_sole_help_flag};

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
        if is_sole_help_flag(ctx.args, &["--help", "-h", "--version"]) {
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

    // --input reads from a file — try to inspect contents
    if let Some(path) = get_flag_value(ctx.args, &["--input"]) {
        if let Some(content) = ctx.read_file(&path) {
            return if is_graphql_mutation(&content) {
                Classification::Ask("gh api --input (GraphQL mutation)".into())
            } else {
                Classification::Allow("gh api --input (query)".into())
            };
        }
        return Classification::Ask("gh api (--input, cannot verify contents)".into());
    }

    Classification::Allow("gh api (GET)".into())
}

/// Check if a GraphQL document contains a mutation operation.
fn is_graphql_mutation(content: &str) -> bool {
    // Look for "mutation" as a top-level keyword (not inside a string or comment)
    content
        .split_whitespace()
        .any(|word| word.eq_ignore_ascii_case("mutation") || word.starts_with("mutation{"))
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

    use super::*;

    // Pure gh command->decision cases (api GET/POST/DELETE/mutation/missing-input,
    // pr/issue actions, status, help) are covered by
    // tests/data/catalog/handlers_text_system.toml. Retained below: the GraphQL
    // *query* Allow (the shell parser mangles the `{`-containing arg in the
    // pipeline, so the handler-level Allow is only observable here) and the two
    // --input read_file content tests.

    // gh api tests

    #[test]
    fn api_graphql_query_allows() {
        let args: Vec<String> = vec![
            "api".into(),
            "graphql".into(),
            "-f".into(),
            "query={ repository(owner: \"o\", name: \"r\") { name } }".into(),
        ];
        let result = GH_HANDLER.classify(&HandlerContext::test("gh", &args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    // gh pr tests

    // Top-level commands

    #[test]
    fn api_input_query_file_allows() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("query.graphql"),
            "{ repository(owner: \"o\", name: \"r\") { name } }",
        )
        .unwrap();
        let args: Vec<String> = vec![
            "api".into(),
            "graphql".into(),
            "--input".into(),
            "query.graphql".into(),
        ];
        let ctx = HandlerContext {
            working_directory: dir.path(),
            ..HandlerContext::test("gh", &args)
        };
        let result = GH_HANDLER.classify(&ctx);
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn api_input_mutation_file_asks() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("mutate.graphql"),
            "mutation { addStar(input: {}) { clientMutationId } }",
        )
        .unwrap();
        let args: Vec<String> = vec![
            "api".into(),
            "graphql".into(),
            "--input".into(),
            "mutate.graphql".into(),
        ];
        let ctx = HandlerContext {
            working_directory: dir.path(),
            ..HandlerContext::test("gh", &args)
        };
        let result = GH_HANDLER.classify(&ctx);
        assert!(matches!(result, Classification::Ask(_)));
    }
}
