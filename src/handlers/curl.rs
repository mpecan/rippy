use super::{Classification, Handler, HandlerContext, get_flag_value, has_flag};

pub static CURL_HANDLER: CurlHandler = CurlHandler;

pub struct CurlHandler;

const DATA_FLAGS: &[&str] = &[
    "-d",
    "--data",
    "--data-raw",
    "--data-binary",
    "--data-urlencode",
    "--data-ascii",
    "-F",
    "--form",
    "-T",
    "--upload-file",
    "--json",
];

const UNSAFE_METHODS: &[&str] = &["POST", "PUT", "DELETE", "PATCH"];

impl Handler for CurlHandler {
    fn commands(&self) -> &[&str] {
        &["curl"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if has_flag(ctx.args, &["--help", "-h", "--version", "-V"]) {
            return Classification::Allow("curl help/version".into());
        }

        // Data flags mean a write request
        if has_flag(ctx.args, DATA_FLAGS) {
            return Classification::Ask("curl with data (write request)".into());
        }

        // Explicit unsafe method
        if let Some(method) = get_flag_value(ctx.args, &["-X", "--request"])
            && UNSAFE_METHODS.contains(&method.to_uppercase().as_str())
        {
            return Classification::Ask(format!("curl -X {method}"));
        }

        // -K/--config
        if has_flag(ctx.args, &["-K", "--config"]) {
            return Classification::Ask("curl --config".into());
        }

        // -o/--output: report redirect targets
        if let Some(output) = get_flag_value(ctx.args, &["-o", "--output"]) {
            return Classification::WithRedirects(
                crate::verdict::Decision::Allow,
                "curl with output file".into(),
                vec![output],
            );
        }

        Classification::Allow("curl (GET request)".into())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::path::Path;

    use super::*;

    fn ctx<'a>(args: &'a [String], cmd: &'a str) -> HandlerContext<'a> {
        HandlerContext {
            command_name: cmd,
            args,
            working_directory: Path::new("/tmp"),
            remote: false,
            receives_piped_input: false,
            cd_allowed_dirs: &[],
        }
    }

    #[test]
    fn curl_get_allows() {
        let args: Vec<String> = vec!["https://example.com".into()];
        let result = CURL_HANDLER.classify(&ctx(&args, "curl"));
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn curl_data_asks() {
        let args: Vec<String> = vec!["-d".into(), "foo=bar".into(), "https://example.com".into()];
        let result = CURL_HANDLER.classify(&ctx(&args, "curl"));
        assert!(matches!(result, Classification::Ask(reason) if reason.contains("data")));
    }

    #[test]
    fn curl_output_file() {
        let args: Vec<String> = vec![
            "-o".into(),
            "output.html".into(),
            "https://example.com".into(),
        ];
        let result = CURL_HANDLER.classify(&ctx(&args, "curl"));
        assert!(matches!(result, Classification::WithRedirects(_, _, _)));
    }

    #[test]
    fn curl_post_method_asks() {
        let args: Vec<String> = vec!["-X".into(), "POST".into(), "https://example.com".into()];
        let result = CURL_HANDLER.classify(&ctx(&args, "curl"));
        assert!(matches!(result, Classification::Ask(_)));
    }

    #[test]
    fn curl_help_allows() {
        let args: Vec<String> = vec!["--help".into()];
        let result = CURL_HANDLER.classify(&ctx(&args, "curl"));
        assert!(matches!(result, Classification::Allow(_)));
    }
}
