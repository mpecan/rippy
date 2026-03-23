use super::{Classification, Handler, HandlerContext, get_flag_value, has_flag, positional_args};
use crate::sql::classify_sql;

// ---- psql ----

pub static PSQL_HANDLER: PsqlHandler = PsqlHandler;

pub struct PsqlHandler;

impl Handler for PsqlHandler {
    fn commands(&self) -> &[&str] {
        &["psql"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if has_flag(ctx.args, &["--help", "-?", "--version", "-V"]) {
            return Classification::Allow("psql help/version".into());
        }
        if has_flag(ctx.args, &["--list", "-l"]) {
            return Classification::Allow("psql list databases".into());
        }
        // -c SQL
        if let Some(sql) = get_flag_value(ctx.args, &["-c", "--command"]) {
            return classify_sql_command("psql", &sql);
        }
        // -f file
        if has_flag(ctx.args, &["-f", "--file"]) {
            return Classification::Ask("psql -f (file execution)".into());
        }
        Classification::Ask("psql (interactive)".into())
    }
}

// ---- mysql ----

pub static MYSQL_HANDLER: MysqlHandler = MysqlHandler;

pub struct MysqlHandler;

impl Handler for MysqlHandler {
    fn commands(&self) -> &[&str] {
        &["mysql"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if has_flag(ctx.args, &["--help", "--version", "-V"]) {
            return Classification::Allow("mysql help/version".into());
        }
        if let Some(sql) = get_flag_value(ctx.args, &["-e", "--execute"]) {
            return classify_sql_command("mysql", &sql);
        }
        Classification::Ask("mysql (interactive)".into())
    }
}

// ---- sqlite3 ----

pub static SQLITE3_HANDLER: Sqlite3Handler = Sqlite3Handler;

pub struct Sqlite3Handler;

impl Handler for Sqlite3Handler {
    fn commands(&self) -> &[&str] {
        &["sqlite3"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if has_flag(ctx.args, &["--help", "-help", "--version"]) {
            return Classification::Allow("sqlite3 help/version".into());
        }
        if has_flag(ctx.args, &["-readonly", "-safe"]) {
            return Classification::Allow("sqlite3 (readonly mode)".into());
        }
        // Look for SQL after the database file argument
        let positionals = positional_args(ctx.args);
        if let Some(sql) = positionals.get(1) {
            return classify_sql_command("sqlite3", sql);
        }
        Classification::Ask("sqlite3 (interactive)".into())
    }
}

fn classify_sql_command(tool: &str, sql: &str) -> Classification {
    match classify_sql(sql) {
        Some(true) => Classification::Allow(format!("{tool} (read-only SQL)")),
        Some(false) => Classification::Ask(format!("{tool} (write SQL)")),
        None => Classification::Ask(format!("{tool} (ambiguous SQL)")),
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
        }
    }

    #[test]
    fn psql_readonly_sql_allows() {
        let args: Vec<String> = vec!["-c".into(), "SELECT * FROM users".into()];
        let result = PSQL_HANDLER.classify(&ctx(&args, "psql"));
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn psql_write_sql_asks() {
        let args: Vec<String> = vec!["-c".into(), "DELETE FROM users".into()];
        let result = PSQL_HANDLER.classify(&ctx(&args, "psql"));
        assert!(matches!(result, Classification::Ask(_)));
    }

    #[test]
    fn psql_list_allows() {
        let args: Vec<String> = vec!["-l".into()];
        let result = PSQL_HANDLER.classify(&ctx(&args, "psql"));
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn mysql_select_allows() {
        let args: Vec<String> = vec!["-e".into(), "SELECT 1".into()];
        let result = MYSQL_HANDLER.classify(&ctx(&args, "mysql"));
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn mysql_insert_asks() {
        let args: Vec<String> = vec!["-e".into(), "INSERT INTO users VALUES (1)".into()];
        let result = MYSQL_HANDLER.classify(&ctx(&args, "mysql"));
        assert!(matches!(result, Classification::Ask(_)));
    }

    #[test]
    fn sqlite3_readonly_allows() {
        let args: Vec<String> = vec!["-readonly".into(), "test.db".into()];
        let result = SQLITE3_HANDLER.classify(&ctx(&args, "sqlite3"));
        assert!(matches!(result, Classification::Allow(_)));
    }
}
