use super::{
    AllowEntry, Classification, Handler, HandlerContext, get_all_flag_values, get_flag_value,
    has_flag, is_sole_help_flag, positional_args,
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

impl Handler for PsqlHandler {
    fn commands(&self) -> &[&str] {
        &["psql"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if is_sole_help_flag(ctx.args, &["--help", "-?", "--version", "-V"]) {
            return Classification::Allow(AllowReason::handler("psql help/version"));
        }
        if has_flag(ctx.args, &["--list", "-l"]) {
            return Classification::Allow(AllowReason::handler("psql list databases"));
        }
        // -c SQL
        if let Some(result) = classify_sql_commands("psql", ctx.args, &["-c", "--command"]) {
            return result;
        }
        // -f file — try to read and classify the SQL
        if let Some(path) = get_flag_value(ctx.args, &["-f", "--file"]) {
            if let Some(sql) = ctx.read_file(&path) {
                return classify_sql_command("psql -f", &sql);
            }
            return Classification::Ask("psql -f (file execution)".into());
        }
        Classification::Ask("psql (interactive)".into())
    }

    fn allow_surface(&self) -> Vec<AllowEntry> {
        vec![
            AllowEntry::guarded("psql --help|-?|--version|-V", "sole argument"),
            AllowEntry::new("psql --list|-l"),
            AllowEntry::guarded("psql -c|--command <sql>", READ_ONLY_SQL),
            AllowEntry::guarded("psql -f|--file <path>", READ_ONLY_SQL_FILE),
        ]
    }
}

// mysql

pub(crate) static MYSQL_HANDLER: MysqlHandler = MysqlHandler;

pub(crate) struct MysqlHandler;

impl Handler for MysqlHandler {
    fn commands(&self) -> &[&str] {
        &["mysql"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if is_sole_help_flag(ctx.args, &["--help", "--version", "-V"]) {
            return Classification::Allow(AllowReason::handler("mysql help/version"));
        }
        if let Some(result) = classify_sql_commands("mysql", ctx.args, &["-e", "--execute"]) {
            return result;
        }
        Classification::Ask("mysql (interactive)".into())
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

/// Classify every occurrence of a cumulative SQL flag and keep the least safe
/// outcome, since the client runs all of them (#199).
///
/// Each occurrence is classified on its own instead of being joined with `;`:
/// a statement ending in a `--` line comment would otherwise swallow the
/// statement appended after it.
fn classify_sql_commands(tool: &str, args: &[String], flags: &[&str]) -> Option<Classification> {
    let least_safe = get_all_flag_values(args, flags)
        .iter()
        .map(|sql| classify_sql(sql))
        .reduce(|a, b| match (a, b) {
            (Some(false), _) | (_, Some(false)) => Some(false),
            (None, _) | (_, None) => None,
            _ => Some(true),
        })?;
    Some(classification_for(tool, least_safe))
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
}
