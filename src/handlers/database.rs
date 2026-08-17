use super::getopt::{OptionName, OptionSpec, scan_options};
use super::{
    AllowEntry, Classification, Handler, HandlerContext, has_flag, is_sole_help_flag,
    positional_args,
};
use crate::sql::classify_sql;
use crate::verdict::AllowReason;

/// Guard shared by every inline-SQL entry: the statement itself decides.
const READ_ONLY_SQL: &str = "statement classified read-only by src/sql.rs";

/// Guard for the file-borne variant, which additionally has to be readable.
const READ_ONLY_SQL_FILE: &str =
    "file readable from the working directory and classified read-only by src/sql.rs";

// psql

pub(crate) static PSQL_HANDLER: PsqlHandler = PsqlHandler;

pub(crate) struct PsqlHandler;

/// psql's value-taking options. `-c`/`-f` are what gets classified; the rest
/// are declared so their operand is not itself read as an option — without
/// `-o`, `psql -o -copy.out` looks like a glued `-c opy.out` (#199).
const PSQL_OPTIONS: OptionSpec = OptionSpec {
    value_shorts: "cdfFhLoPpRTUv",
    optional_shorts: "",
    value_longs: &[
        "command",
        "dbname",
        "field-separator",
        "file",
        "host",
        "log-file",
        "output",
        "port",
        "pset",
        "record-separator",
        "set",
        "table-attr",
        "username",
        "variable",
    ],
};

impl Handler for PsqlHandler {
    fn commands(&self) -> &[&str] {
        &["psql"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if is_sole_help_flag(ctx.args, &["--help", "-?", "--version", "-V"]) {
            return Classification::Allow(AllowReason::handler("psql help/version"));
        }
        let sql = scan_options(ctx.args, &PSQL_OPTIONS)
            .into_iter()
            .filter_map(|(name, value)| psql_sql_option(ctx, &name, value))
            .reduce(least_safe);
        if let Some(classification) = sql {
            return classification;
        }
        // After the SQL scan: `psql -l -c "DROP TABLE t"` still runs the DROP.
        if has_flag(ctx.args, &["--list", "-l"]) {
            return Classification::Allow(AllowReason::handler("psql list databases"));
        }
        Classification::Ask("psql (interactive)".into())
    }

    fn allow_surface(&self) -> Vec<AllowEntry> {
        vec![
            AllowEntry::guarded("psql --help|-?|--version|-V", "sole argument"),
            AllowEntry::guarded("psql --list|-l", "no -c/-f statement to run"),
            AllowEntry::guarded("psql -c|--command <sql>", READ_ONLY_SQL),
            AllowEntry::guarded("psql -f|--file <path>", READ_ONLY_SQL_FILE),
        ]
    }
}

/// Classify one psql option occurrence, or `None` if it carries no SQL.
fn psql_sql_option(ctx: &HandlerContext, name: &OptionName, value: &str) -> Option<Classification> {
    if name.is('c', &["command"]) {
        return Some(classify_sql_command("psql", value));
    }
    if !name.is('f', &["file"]) {
        return None;
    }
    Some(ctx.read_file(value).map_or_else(
        || Classification::Ask("psql -f (file execution)".into()),
        |sql| classify_sql_command("psql -f", &sql),
    ))
}

// mysql

pub(crate) static MYSQL_HANDLER: MysqlHandler = MysqlHandler;

pub(crate) struct MysqlHandler;

/// mysql's value-taking options. `-p` is listed as optional-valued because its
/// password only attaches when glued: a required `-p` would eat the `-e` after
/// a bare one and hide the statement entirely.
const MYSQL_OPTIONS: OptionSpec = OptionSpec {
    value_shorts: "DePSuh",
    optional_shorts: "p",
    value_longs: &[
        "database",
        "default-character-set",
        "execute",
        "host",
        "port",
        "protocol",
        "socket",
        "user",
    ],
};

impl Handler for MysqlHandler {
    fn commands(&self) -> &[&str] {
        &["mysql"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if is_sole_help_flag(ctx.args, &["--help", "--version", "-V"]) {
            return Classification::Allow(AllowReason::handler("mysql help/version"));
        }
        scan_options(ctx.args, &MYSQL_OPTIONS)
            .into_iter()
            .filter(|(name, _)| name.is('e', &["execute"]))
            .map(|(_, sql)| classify_sql_command("mysql", sql))
            .reduce(least_safe)
            .unwrap_or_else(|| Classification::Ask("mysql (interactive)".into()))
    }

    fn allow_surface(&self) -> Vec<AllowEntry> {
        vec![
            AllowEntry::guarded("mysql --help|--version|-V", "sole argument"),
            AllowEntry::guarded("mysql -e|--execute <sql>", READ_ONLY_SQL),
        ]
    }
}

// sqlite3

pub(crate) static SQLITE3_HANDLER: Sqlite3Handler = Sqlite3Handler;

pub(crate) struct Sqlite3Handler;

impl Handler for Sqlite3Handler {
    fn commands(&self) -> &[&str] {
        &["sqlite3"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if is_sole_help_flag(ctx.args, &["--help", "-help", "--version"]) {
            return Classification::Allow(AllowReason::handler("sqlite3 help/version"));
        }
        if has_flag(ctx.args, &["-readonly", "-safe"]) {
            return Classification::Allow(AllowReason::handler("sqlite3 (readonly mode)"));
        }
        // Look for SQL after the database file argument
        let positionals = positional_args(ctx.args);
        if let Some(sql) = positionals.get(1) {
            return classify_sql_command("sqlite3", sql);
        }
        Classification::Ask("sqlite3 (interactive)".into())
    }

    fn allow_surface(&self) -> Vec<AllowEntry> {
        vec![
            AllowEntry::guarded("sqlite3 --help|-help|--version", "sole argument"),
            AllowEntry::new("sqlite3 -readonly|-safe"),
            AllowEntry::guarded("sqlite3 <database> <sql>", READ_ONLY_SQL),
        ]
    }
}

fn classify_sql_command(tool: &str, sql: &str) -> Classification {
    classification_for(tool, classify_sql(sql))
}

/// Keep the least safe of two classifications, since a client runs every
/// statement it is given: an inline `SELECT` must not launder the `DROP` in a
/// later `-c`, nor the script named by `-f` (#199).
///
/// Each occurrence is classified on its own rather than joined with `;`: a
/// statement ending in a `--` line comment would otherwise swallow the one
/// appended after it. Ties keep the first, so the reason names the earliest
/// offending statement.
fn least_safe(a: Classification, b: Classification) -> Classification {
    match (&a, &b) {
        (Classification::Allow(_), Classification::Ask(_) | Classification::Deny(_))
        | (Classification::Ask(_), Classification::Deny(_)) => b,
        _ => a,
    }
}

fn classification_for(tool: &str, read_only: Option<bool>) -> Classification {
    match read_only {
        Some(true) => {
            Classification::Allow(AllowReason::handler(format!("{tool} (read-only SQL)")))
        }
        Some(false) => Classification::Ask(format!("{tool} (write SQL)")),
        None => Classification::Ask(format!("{tool} (ambiguous SQL)")),
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used)]
mod tests {

    use super::*;

    // Inline-SQL command->decision cases (psql -c, psql -l, mysql -e, sqlite3
    // -readonly) are covered by tests/data/catalog/handlers_text_system.toml. The
    // `-f` tests below classify SQL read from a real file via read_file.
    #[test]
    fn psql_f_readonly_allows() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("query.sql"), "SELECT * FROM users;").unwrap();
        let args: Vec<String> = vec!["-f".into(), "query.sql".into()];
        let ctx = HandlerContext {
            working_directory: dir.path(),
            ..HandlerContext::test("psql", &args)
        };
        let result = PSQL_HANDLER.classify(&ctx);
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn psql_f_write_asks() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("migrate.sql"), "DROP TABLE users;").unwrap();
        let args: Vec<String> = vec!["-f".into(), "migrate.sql".into()];
        let ctx = HandlerContext {
            working_directory: dir.path(),
            ..HandlerContext::test("psql", &args)
        };
        let result = PSQL_HANDLER.classify(&ctx);
        assert!(matches!(result, Classification::Ask(_)));
    }

    #[test]
    fn psql_f_missing_file_asks() {
        let dir = tempfile::tempdir().unwrap();
        let args: Vec<String> = vec!["-f".into(), "missing.sql".into()];
        let ctx = HandlerContext {
            working_directory: dir.path(),
            ..HandlerContext::test("psql", &args)
        };
        let result = PSQL_HANDLER.classify(&ctx);
        assert!(matches!(result, Classification::Ask(_)));
    }

    /// Classify a psql run against a real SQL file in a temp working directory.
    fn classify_with_file(file: &str, sql: &str, args: &[&str]) -> Classification {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(file), sql).unwrap();
        let args: Vec<String> = args.iter().map(|a| (*a).to_string()).collect();
        let ctx = HandlerContext {
            working_directory: dir.path(),
            ..HandlerContext::test("psql", &args)
        };
        PSQL_HANDLER.classify(&ctx)
    }

    /// #199 follow-up: a readable script is the case a command string alone
    /// cannot reach, and it is where cross-flag laundering pays off — the
    /// leading `-c SELECT` must not approve the DROP the script runs.
    #[test]
    fn psql_c_does_not_launder_a_write_in_the_f_script() {
        let result = classify_with_file(
            "drop.sql",
            "DROP TABLE users;",
            &["-c", "SELECT 1", "-f", "drop.sql"],
        );
        assert!(matches!(result, Classification::Ask(_)), "{result:?}");
    }

    #[test]
    fn psql_c_and_a_read_only_f_script_stay_allowed() {
        let result = classify_with_file(
            "query.sql",
            "SELECT * FROM users;",
            &["-c", "SELECT 1", "-f", "query.sql"],
        );
        assert!(matches!(result, Classification::Allow(_)), "{result:?}");
    }

    /// The same laundering through a cluster: `-Atf drop.sql` is `-A -t -f`.
    #[test]
    fn psql_reads_the_f_script_named_by_a_cluster() {
        let result = classify_with_file(
            "drop.sql",
            "DROP TABLE users;",
            &["-c", "SELECT 1", "-Atf", "drop.sql"],
        );
        assert!(matches!(result, Classification::Ask(_)), "{result:?}");
    }
}
