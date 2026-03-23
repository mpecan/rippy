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
