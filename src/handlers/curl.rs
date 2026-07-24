use super::{
    Classification, Handler, HandlerContext, get_flag_value, has_flag, has_flag_or_prefixed,
    is_sole_help_flag,
};

pub(crate) static CURL_HANDLER: CurlHandler = CurlHandler;

pub(crate) struct CurlHandler;

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

/// curl short-flag characters that combine with `-O`/`-J` in the common
/// "download and save" idiom (`curl -fsSLO url`).
///
/// curl clusters single-dash boolean short options into one token, so
/// `-O`/`-J` can appear glued inside a cluster (`-fsSLO`, `-sJO`) rather than
/// as their own token, bypassing an exact-match check. This list is
/// intentionally narrow (booleans only) so a cluster containing a
/// value-taking short flag (`-X`, `-A`, ...) is never misread as a bundle.
const CURL_BOOLEAN_CLUSTER_FLAGS: &[char] = &[
    'f', 's', 'S', 'L', 'k', 'v', 'i', 'g', 'q', 'n', 'N', '#', '0', '1', '2', '3', '4', '6', 'O',
    'J',
];

/// Detect `-O`/`-J` glued inside a boolean short-option cluster (`-fsSLO`).
fn has_bundled_write_flag(args: &[String]) -> bool {
    args.iter().any(|a| {
        a.starts_with('-')
            && !a.starts_with("--")
            && a.len() > 1
            && a.chars()
                .skip(1)
                .all(|c| CURL_BOOLEAN_CLUSTER_FLAGS.contains(&c))
            && a.chars().skip(1).any(|c| c == 'O' || c == 'J')
    })
}

impl Handler for CurlHandler {
    fn commands(&self) -> &[&str] {
        &["curl"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if is_sole_help_flag(ctx.args, &["--help", "-h", "--version", "-V"]) {
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

        // Server-named-write flags: the filename is server-controlled, so we
        // can't emit a redirect target — fail closed rather than Allow.
        if has_flag(
            ctx.args,
            &[
                "-O",
                "--remote-name",
                "--remote-name-all",
                "-J",
                "--remote-header-name",
            ],
        ) || has_flag_or_prefixed(ctx.args, &["--output-dir"])
            || has_bundled_write_flag(ctx.args)
        {
            return Classification::Ask("curl with server-named output (write request)".into());
        }

        Classification::Allow("curl (GET request)".into())
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    // curl GET/-d/-X POST/--help command->decision cases are covered by
    // tests/data/catalog/handlers_text_system.toml. This test asserts the
    // WithRedirects variant for `-o`, which a command string cannot express.
    #[test]
    fn curl_output_file() {
        let args: Vec<String> = vec![
            "-o".into(),
            "output.html".into(),
            "https://example.com".into(),
        ];
        let result = CURL_HANDLER.classify(&HandlerContext::test("curl", &args));
        assert!(matches!(result, Classification::WithRedirects(_, _, _)));
    }
}
