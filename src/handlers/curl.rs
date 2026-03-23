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
