use super::{
    AllowEntry, Classification, Handler, HandlerContext, SubcommandHandler, has_flag,
    has_flag_or_prefixed, is_sole_help_flag, positional_args,
};
use crate::verdict::AllowReason;

/// tar long options that spawn an external program (RCE regardless of archive
/// flags used).
///
/// A denylist is used here rather than an allowlist because tar has dozens of
/// benign flags (`-z`/`-j`/`-v`/`-f`/`-C`) that an allowlist would over-restrict.
const TAR_PROGRAM_EXEC_LONG: &[&str] = &[
    "--use-compress-program",
    "--to-command",
    "--checkpoint-action",
    "--rmt-command",
    "--info-script",
    "--new-volume-script",
];

/// Long options that are exact spellings of inert tar options while also being a
/// proper prefix of a [`TAR_PROGRAM_EXEC_LONG`] entry.
///
/// `getopt_long` resolves an exact match before it considers prefixes, so
/// `--checkpoint=1000` is the progress counter, not an abbreviation of
/// `--checkpoint-action`.
const TAR_INERT_EXEC_PREFIXES: &[&str] = &["--checkpoint"];

/// tar short options that spawn an external program.
const TAR_EXEC_SHORT: &[char] = &['I', 'F'];

/// tar short options that take a value, which getopt reads from the rest of the
/// cluster when it is non-empty (`-tfFoo.tar` selects the file `Foo.tar`).
///
/// Scanning a cluster stops at the first of these: everything after it is a
/// value, so letters there are not options.
const TAR_SHORT_WITH_VALUE: &[char] = &[
    'b', 'C', 'f', 'F', 'g', 'H', 'I', 'K', 'L', 'N', 'T', 'V', 'X',
];

// tar

pub(crate) static TAR_HANDLER: TarHandler = TarHandler;

pub(crate) struct TarHandler;

impl Handler for TarHandler {
    fn commands(&self) -> &[&str] {
        &["tar"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        let mut class = Self::classify_archive_op(ctx);
        // A spawned program is a risk on top of the archive operation, not instead of it (#198).
        for program in Self::to_command_programs(ctx.args) {
            class = Classification::RecurseAtLeast(program, Box::new(class));
        }
        class
    }

    fn allow_surface(&self) -> Vec<AllowEntry> {
        vec![AllowEntry::guarded(
            "tar -t|--list",
            "no flag that runs an external program (-I, -F, --use-compress-program, \
             --to-command, --checkpoint-action, --rmt-command, --info-script, \
             --new-volume-script, or any prefix abbreviation of those long options)",
        )]
    }
}

impl TarHandler {
    /// The verdict for the archive operation itself, independent of any program
    /// `--to-command` spawns.
    fn classify_archive_op(ctx: &HandlerContext) -> Classification {
        if ctx.args.iter().any(|a| runs_external_program(a)) {
            return Classification::Ask("tar (runs external program)".into());
        }
        if has_flag(ctx.args, &["-t", "--list"]) {
            return Classification::Allow(AllowReason::handler("tar (list)"));
        }
        Classification::Ask("tar (create/extract)".into())
    }

    /// The program handed to each `--to-command`, in both the spaced and the
    /// `=`-glued spelling and under any prefix abbreviation.
    ///
    /// Every occurrence is returned, not the first: tar's *last* `--to-command`
    /// is the one it runs, and an earlier one has already run for the members
    /// before it, so judging one and ignoring the rest judges the wrong program.
    fn to_command_programs(args: &[String]) -> Vec<String> {
        let mut programs = Vec::new();
        let mut i = 0;
        while i < args.len() {
            let (name, glued) = split_long_option(&args[i]);
            if name.is_some_and(|n| "--to-command".starts_with(n)) {
                if let Some(value) = glued {
                    programs.push(value.to_owned());
                } else if let Some(value) = args.get(i + 1) {
                    programs.push(value.clone());
                    i += 1;
                }
            }
            i += 1;
        }
        programs
    }
}

/// Splits a long option into its name and its `=`-glued value. The name is
/// `None` for anything that is not a long option, bare `--` included.
fn split_long_option(arg: &str) -> (Option<&str>, Option<&str>) {
    if !arg.starts_with("--") || arg.len() == 2 {
        return (None, None);
    }
    arg.split_once('=')
        .map_or((Some(arg), None), |(name, value)| (Some(name), Some(value)))
}

/// Whether a token selects one of tar's program-spawning options.
fn runs_external_program(arg: &str) -> bool {
    split_long_option(arg)
        .0
        .map_or_else(|| cluster_has_exec_short(arg), is_exec_long_option)
}

/// GNU tar (argp/`getopt_long`) accepts *any prefix* of a long option, so matching
/// exact spellings cannot work: `--use-c` really does select
/// `--use-compress-program` (#198). A spelling is an exec option when a known
/// exec option starts with it. An ambiguous prefix makes real tar exit with an
/// error, so treating it as the exec option it could name costs nothing.
fn is_exec_long_option(name: &str) -> bool {
    !TAR_INERT_EXEC_PREFIXES.contains(&name)
        && TAR_PROGRAM_EXEC_LONG.iter().any(|f| f.starts_with(name))
}

/// Scans a short-option cluster (`-xIf`, `-Ish`) for an exec option.
fn cluster_has_exec_short(arg: &str) -> bool {
    let Some(cluster) = arg.strip_prefix('-') else {
        return false;
    };
    for c in cluster.chars() {
        if TAR_EXEC_SHORT.contains(&c) {
            return true;
        }
        // Everything after a value-taking option is that value, not more options.
        if TAR_SHORT_WITH_VALUE.contains(&c) {
            return false;
        }
    }
    false
}

// wget

pub(crate) static WGET_HANDLER: WgetHandler = WgetHandler;

pub(crate) struct WgetHandler;

impl Handler for WgetHandler {
    fn commands(&self) -> &[&str] {
        &["wget"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if has_flag(ctx.args, &["--spider"]) {
            return Classification::Allow(AllowReason::handler("wget --spider"));
        }
        if is_sole_help_flag(ctx.args, &["--help", "-h", "--version", "-V"]) {
            return Classification::Allow(AllowReason::handler("wget help/version"));
        }
        Classification::Ask("wget (download)".into())
    }

    fn allow_surface(&self) -> Vec<AllowEntry> {
        vec![
            AllowEntry::new("wget --spider"),
            AllowEntry::guarded("wget --help|-h|--version|-V", "sole argument"),
        ]
    }
}

// gzip

pub(crate) static GZIP_HANDLER: SubcommandHandler = SubcommandHandler::new(
    &["gzip", "gunzip"],
    &["--stdout", "-c", "--list", "-l", "--test", "-t"],
    &[],
    "gzip",
);

// unzip
//
// Unlike 7z, unzip takes its mode as a FLAG (`-l` list, `-t` test), not a bare
// subcommand verb — `unzip l archive.zip` is not a real invocation. See #190.

pub(crate) static UNZIP_HANDLER: UnzipHandler = UnzipHandler;

pub(crate) struct UnzipHandler;

impl Handler for UnzipHandler {
    fn commands(&self) -> &[&str] {
        &["unzip"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if is_sole_help_flag(ctx.args, &["--help", "-h", "--version", "-V"]) {
            return Classification::Allow(AllowReason::handler("unzip help/version"));
        }
        if has_leading_unzip_mode_flag(ctx.args) {
            return Classification::Allow(AllowReason::handler("unzip (list/test)"));
        }
        Classification::Ask("unzip (extract)".into())
    }

    fn allow_surface(&self) -> Vec<AllowEntry> {
        let guard = "flag appears in the option run before the archive operand";
        vec![
            AllowEntry::guarded("unzip --help|-h|--version|-V", "sole argument"),
            AllowEntry::guarded("unzip -l", guard),
            AllowEntry::guarded("unzip -t", guard),
            AllowEntry::guarded("unzip -v", guard),
            AllowEntry::guarded("unzip -Z", guard),
        ]
    }
}

/// unzip mode letters that make the invocation read-only: list, test, verbose
/// list and zipinfo mode.
const UNZIP_MODE_LETTERS: &[char] = &['l', 't', 'v', 'Z'];

/// unzip letters whose value may be glued to them (`-dlogs`, `-Psecret`), so the
/// rest of the token is data rather than more clustered flags.
const UNZIP_VALUE_LETTERS: &[char] = &['d', 'O', 'I', 'P'];

/// Whether a read-only mode flag appears in the option run that precedes the
/// archive operand, which is the only place unzip treats it as an option: words
/// after the archive are member filespecs, so a trailing `-l` is consumed as a
/// (non-matching) member name while the rest of argv still extracts (#190).
fn has_leading_unzip_mode_flag(args: &[String]) -> bool {
    let mut skip_value = false;
    for arg in args {
        if skip_value {
            skip_value = false;
            continue;
        }
        if arg.starts_with("--") {
            return false; // unknown long option: fail closed
        }
        let Some(letters) = arg.strip_prefix('-') else {
            return false; // the archive operand ends the option run
        };
        for (i, ch) in letters.char_indices() {
            if UNZIP_MODE_LETTERS.contains(&ch) {
                return true;
            }
            if UNZIP_VALUE_LETTERS.contains(&ch) {
                skip_value = i + ch.len_utf8() == letters.len();
                break;
            }
        }
    }
    false
}

// 7z / 7za / 7zr / 7zz — bare subcommand verbs (`7z l archive.7z`), unlike unzip.

pub(crate) static SEVENZIP_HANDLER: SubcommandHandler = SubcommandHandler::new(
    &["7z", "7za", "7zr", "7zz"],
    &["l", "t"],                // list and test
    &["x", "e", "a", "d", "u"], // extract, add, delete, update
    "7z",
);

// mktemp

pub(crate) static MKTEMP_HANDLER: MktempHandler = MktempHandler;

pub(crate) struct MktempHandler;

impl Handler for MktempHandler {
    fn commands(&self) -> &[&str] {
        &["mktemp"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if has_flag(ctx.args, &["-u"]) {
            return Classification::Allow(AllowReason::handler("mktemp -u (dry run)"));
        }
        Classification::Ask("mktemp".into())
    }

    fn allow_surface(&self) -> Vec<AllowEntry> {
        vec![AllowEntry::new("mktemp -u")]
    }
}

// tee

pub(crate) static TEE_HANDLER: TeeHandler = TeeHandler;

pub(crate) struct TeeHandler;

impl Handler for TeeHandler {
    fn commands(&self) -> &[&str] {
        &["tee"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        let files: Vec<&str> = ctx
            .args
            .iter()
            .filter(|a| !a.starts_with('-'))
            .map(String::as_str)
            .collect();
        if files.is_empty() {
            return Classification::Allow(AllowReason::handler("tee (stdout only)"));
        }
        Classification::WithRedirects(
            AllowReason::handler("tee"),
            files.iter().map(|f| (*f).to_owned()).collect(),
        )
    }

    fn allow_surface(&self) -> Vec<AllowEntry> {
        vec![AllowEntry::guarded(
            "tee",
            "no file operand; file operands run the redirect pipeline",
        )]
    }
}

// sort

pub(crate) static SORT_HANDLER: SortHandler = SortHandler;

pub(crate) struct SortHandler;

impl Handler for SortHandler {
    fn commands(&self) -> &[&str] {
        &["sort"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if let Some(pos) = ctx.args.iter().position(|a| a == "-o" || a == "--output")
            && let Some(file) = ctx.args.get(pos + 1)
        {
            return Classification::WithRedirects(
                AllowReason::handler("sort -o"),
                vec![file.clone()],
            );
        }
        if let Some(file) = attached_output_value(ctx.args) {
            return Classification::WithRedirects(AllowReason::handler("sort -o"), vec![file]);
        }
        if has_flag_or_prefixed(ctx.args, &["-o", "--output"]) {
            return Classification::Ask("sort (output target not extractable)".into());
        }
        Classification::Allow(AllowReason::handler("sort"))
    }

    fn allow_surface(&self) -> Vec<AllowEntry> {
        vec![AllowEntry::guarded(
            "sort",
            "no -o/--output; with one, the target runs the redirect pipeline",
        )]
    }
}

/// Extract the path from an attached `sort` output flag: `--output=path` or `-oPATH`.
fn attached_output_value(args: &[String]) -> Option<String> {
    for arg in args {
        if let Some(path) = arg.strip_prefix("--output=") {
            return Some(path.to_owned());
        }
        if let Some(path) = arg.strip_prefix("-o")
            && !path.is_empty()
        {
            return Some(path.to_owned());
        }
    }
    None
}

// open

pub(crate) static OPEN_HANDLER: OpenHandler = OpenHandler;

pub(crate) struct OpenHandler;

impl Handler for OpenHandler {
    fn commands(&self) -> &[&str] {
        &["open"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if has_flag(ctx.args, &["-R"]) {
            return Classification::Allow(AllowReason::handler("open -R (reveal)"));
        }
        Classification::Ask("open".into())
    }

    fn allow_surface(&self) -> Vec<AllowEntry> {
        vec![AllowEntry::new("open -R")]
    }
}

// yq

pub(crate) static YQ_HANDLER: YqHandler = YqHandler;

pub(crate) struct YqHandler;

impl Handler for YqHandler {
    fn commands(&self) -> &[&str] {
        &["yq"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if has_flag(ctx.args, &["-i", "--inplace"]) {
            return Classification::Ask("yq -i (in-place)".into());
        }
        Classification::Allow(AllowReason::handler("yq (filter)"))
    }

    fn allow_surface(&self) -> Vec<AllowEntry> {
        vec![AllowEntry::guarded("yq <filter>", "no -i/--inplace")]
    }
}

// dos2unix / unix2dos
//
// Both rewrite the named file in place by default; #187. The genuinely
// read-only forms are info mode, help/version, and `-n` new-file mode, whose
// output path is routed through the redirect safety pipeline rather than
// trusted outright.

pub(crate) static DOS2UNIX_HANDLER: Dos2UnixHandler = Dos2UnixHandler;

pub(crate) struct Dos2UnixHandler;

impl Handler for Dos2UnixHandler {
    fn commands(&self) -> &[&str] {
        &["dos2unix", "unix2dos"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if is_sole_help_flag(ctx.args, &["--help", "-h", "--version", "-V"]) {
            return Classification::Allow(AllowReason::handler(format!(
                "{} help/version",
                ctx.command_name
            )));
        }
        if has_flag_or_prefixed(ctx.args, &["-i", "--info"]) {
            return Classification::Allow(AllowReason::handler(format!(
                "{} --info (no conversion)",
                ctx.command_name
            )));
        }
        if has_flag(ctx.args, &["-n", "--newfile"]) {
            return classify_newfile(ctx);
        }
        if positional_args(ctx.args).is_empty() {
            return Classification::Allow(AllowReason::handler(format!(
                "{} (stdin/stdout filter)",
                ctx.command_name
            )));
        }
        Classification::Ask(format!("{} (in-place conversion)", ctx.command_name))
    }

    fn allow_surface(&self) -> Vec<AllowEntry> {
        vec![
            AllowEntry::guarded("dos2unix --help|-h|--version|-V", "sole argument"),
            AllowEntry::new("dos2unix --info"),
            AllowEntry::guarded(
                "dos2unix -n <in> <out>",
                "even number of file operands (in/out pairs); each output path runs the \
                 redirect pipeline",
            ),
            AllowEntry::guarded("dos2unix", "no file operand (stdin/stdout filter)"),
        ]
    }
}

/// Classify `-n`/`--newfile` mode: positional operands must form (in, out)
/// pairs. Each output path is routed through the redirect safety pipeline
/// rather than trusted outright.
fn classify_newfile(ctx: &HandlerContext) -> Classification {
    let files = dos2unix_file_operands(ctx.args);
    if files.is_empty() || !files.len().is_multiple_of(2) {
        return Classification::Ask(format!("{} -n (unpaired file operands)", ctx.command_name));
    }
    let outputs: Vec<String> = files
        .iter()
        .skip(1)
        .step_by(2)
        .map(|f| (*f).to_owned())
        .collect();
    Classification::WithRedirects(
        AllowReason::handler(format!("{} -n (new-file mode)", ctx.command_name)),
        outputs,
    )
}

/// dos2unix options that consume the following word, which is therefore a value
/// and not a file operand.
const DOS2UNIX_VALUE_FLAGS: &[&str] = &["-c", "--convmode", "-D", "--display-enc"];

/// Split argv into file operands for `-n` pairing. `positional_args` would count
/// the value of a flag such as `-c mac` as a file and make the pair count odd.
fn dos2unix_file_operands(args: &[String]) -> Vec<&str> {
    let mut files = Vec::new();
    let mut skip_value = false;
    for arg in args {
        if skip_value {
            skip_value = false;
        } else if arg.starts_with('-') {
            skip_value = DOS2UNIX_VALUE_FLAGS.contains(&arg.as_str());
        } else {
            files.push(arg.as_str());
        }
    }
    files
}

// Behavioral coverage (tar list/extract, wget, mktemp, open, yq, unzip, dos2unix) lives in
// tests/data/catalog/handlers_text_system.toml — pure command->decision mappings
// exercised through the real parse+analyze pipeline. The tee/sort `-o` redirect
// paths return WithRedirects and are covered by redirect integration tests.
