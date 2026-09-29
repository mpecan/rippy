use super::{AllowEntry, Classification, Handler, HandlerContext, is_sole_help_flag};
use crate::verdict::AllowReason;

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
    "--form-string",
];

/// Methods that only read. Any other `-X` (POST, PUT, DELETE, and `WebDAV`'s
/// `MKCOL`, `MOVE`, `COPY`, `PROPPATCH`, …) may change the server.
const READ_METHODS: &[&str] = &["GET", "HEAD", "OPTIONS"];

/// Short options that take a value, as the rest of their token (`-o/path`,
/// `-d@file`) or the next word. Every other short option is a boolean that may
/// be clustered with others (`-fsSLO`).
const VALUE_SHORT: &[char] = &[
    'A', 'b', 'c', 'C', 'd', 'D', 'e', 'E', 'F', 'H', 'K', 'm', 'o', 'P', 'Q', 'r', 'T', 't', 'u',
    'U', 'w', 'x', 'X', 'y', 'Y', 'z',
];

/// Long options that take the next word as their value (they also accept
/// `--name=value`).
const VALUE_LONG: &[&str] = &[
    "--data",
    "--data-raw",
    "--data-binary",
    "--data-urlencode",
    "--data-ascii",
    "--form",
    "--upload-file",
    "--json",
    "--request",
    "--config",
    "--output",
    "--output-dir",
    "--dump-header",
    "--cookie-jar",
    "--trace",
    "--trace-ascii",
    "--stderr",
    "--libcurl",
    "--header",
    "--user",
    "--user-agent",
    "--cookie",
    "--referer",
    "--url",
    "--proxy",
    "--form-string",
    "--etag-save",
    "--etag-compare",
    "--hsts",
    "--alt-svc",
    "--write-out",
    "--quote",
    "--cacert",
    "--cert",
    "--key",
    "--connect-timeout",
    "--max-time",
    "--retry",
    "--range",
    "--resolve",
    "--interface",
    "--limit-rate",
    "--proxy-user",
    "--oauth2-bearer",
    "--unix-socket",
    "--max-filesize",
    "--data-urlencode",
];

/// Options whose value is a local file curl writes.
const WRITE_TARGETS: &[&str] = &[
    "-o",
    "--output",
    "-D",
    "--dump-header",
    "-c",
    "--cookie-jar",
    "--trace",
    "--trace-ascii",
    "--stderr",
    "--libcurl",
    "--etag-save",
    "--hsts",
    "--alt-svc",
];

/// Options that write a file whose name the server chooses.
const SERVER_NAMED_WRITES: &[&str] = &[
    "-O",
    "--remote-name",
    "--remote-name-all",
    "-J",
    "--remote-header-name",
    "--output-dir",
];

/// curl 8.3+ accepts `--expand-NAME` for every long option, with variables
/// expanded in its value: `--expand-output FILE` is `--output FILE`.
fn canonical(arg: &str) -> String {
    arg.strip_prefix("--expand-")
        .map_or_else(|| arg.to_owned(), |rest| format!("--{rest}"))
}

/// Every option in curl's argv as `(flag, value)`, in any spelling: `-o v`,
/// `-ov`, a cluster ending in a value flag (`-sSo v`), `--output v` and
/// `--output=v`. Matching whole words alone let `-d@/etc/passwd`, `-XPOST`
/// and `--request=DELETE` pass as a GET.
fn options(args: &[String]) -> Vec<(String, Option<String>)> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(raw) = args.get(i) {
        i += 1;
        if raw == "--" {
            break;
        }
        let arg = &canonical(raw);
        if let Some(long) = arg.strip_prefix("--") {
            if let Some((name, value)) = long.split_once('=') {
                out.push((format!("--{name}"), Some(value.to_owned())));
            } else if VALUE_LONG.contains(&arg.as_str()) {
                out.push((arg.to_owned(), args.get(i).cloned()));
                i += 1;
            } else {
                out.push((arg.to_owned(), None));
            }
        } else if arg.len() > 1 && arg.starts_with('-') {
            for (pos, c) in arg.char_indices().skip(1) {
                if !VALUE_SHORT.contains(&c) {
                    out.push((format!("-{c}"), None));
                    continue;
                }
                let rest = &arg[pos + c.len_utf8()..];
                let value = if rest.is_empty() {
                    i += 1;
                    args.get(i - 1).cloned()
                } else {
                    Some(rest.to_owned())
                };
                out.push((format!("-{c}"), value));
                break;
            }
        }
    }
    out
}

impl Handler for CurlHandler {
    fn commands(&self) -> &[&str] {
        &["curl"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if is_sole_help_flag(ctx.args, &["--help", "-h", "--version", "-V"]) {
            return Classification::Allow(AllowReason::handler("curl help/version"));
        }
        let opts = options(ctx.args);
        let has = |names: &[&str]| opts.iter().any(|(f, _)| names.contains(&f.as_str()));

        if has(DATA_FLAGS) {
            return Classification::Ask("curl with data (write request)".into());
        }
        let method = opts
            .iter()
            .find(|(f, _)| f == "-X" || f == "--request")
            .and_then(|(_, v)| v.clone());
        if let Some(method) = method
            && !READ_METHODS.contains(&method.to_uppercase().as_str())
        {
            return Classification::Ask(format!("curl -X {method}"));
        }
        if has(&["-Q", "--quote"]) {
            return Classification::Ask("curl --quote (runs server commands)".into());
        }
        // curl 8.3+ writes `%output{FILE}` in a write-out format to FILE.
        let writes_out = opts.iter().any(|(f, v)| {
            (f == "-w" || f == "--write-out")
                && v.as_deref().is_some_and(|v| v.contains("%output{"))
        });
        if writes_out {
            return Classification::Ask("curl --write-out %output (writes a file)".into());
        }
        if has(&["-K", "--config"]) {
            return Classification::Ask("curl --config".into());
        }
        // The filename is server-controlled, so no redirect target can be
        // checked: fail closed rather than Allow.
        if has(SERVER_NAMED_WRITES) {
            return Classification::Ask("curl with server-named output (write request)".into());
        }
        let targets: Vec<String> = opts
            .iter()
            .filter(|(f, _)| WRITE_TARGETS.contains(&f.as_str()))
            .filter_map(|(_, v)| v.clone())
            .filter(|v| v != "-")
            .collect();
        if !targets.is_empty() {
            return Classification::WithRedirects(
                AllowReason::handler("curl with output file"),
                targets,
            );
        }
        Classification::Allow(AllowReason::handler("curl (GET request)"))
    }

    fn allow_surface(&self) -> Vec<AllowEntry> {
        vec![
            AllowEntry::guarded("curl --help|-h|--version|-V", "sole argument"),
            AllowEntry::guarded(
                "curl <url>",
                format!(
                    "no request body flag ({}), -X/--request only {}, no -K/--config, \
                     no -Q/--quote, no --write-out %output, no \
                     server-named output flag ({}), in any spelling (glued, clustered or \
                     --name=value); a local write target ({}) runs the redirect pipeline",
                    DATA_FLAGS.join(" "),
                    READ_METHODS.join("/"),
                    SERVER_NAMED_WRITES.join(" "),
                    WRITE_TARGETS.join(" "),
                ),
            ),
        ]
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
        assert!(matches!(result, Classification::WithRedirects(..)));
    }
}
