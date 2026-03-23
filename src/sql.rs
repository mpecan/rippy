/// Classify a SQL statement as read-only, write, or ambiguous.
///
/// Returns:
/// - `Some(true)` — read-only (SELECT, SHOW, DESCRIBE, EXPLAIN)
/// - `Some(false)` — write (INSERT, UPDATE, DELETE, CREATE, DROP, etc.)
/// - `None` — ambiguous, multiple statements, or unrecognizable
#[must_use]
pub fn classify_sql(sql: &str) -> Option<bool> {
    let cleaned = strip_comments(sql);
    let trimmed = cleaned.trim();

    if trimmed.is_empty() {
        return None;
    }

    // Check for multiple statements (semicolons outside quotes)
    let statements: Vec<&str> = split_statements(trimmed);
    if statements.len() > 1 {
        // All must be read-only for the whole thing to be read-only
        let results: Vec<Option<bool>> = statements.iter().copied().map(classify_single).collect();
        if results.iter().any(Option::is_none) {
            return None;
        }
        return Some(results.iter().all(|r| *r == Some(true)));
    }

    classify_single(trimmed)
}

/// Classify a single SQL statement.
fn classify_single(sql: &str) -> Option<bool> {
    let trimmed = sql.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Strip leading CTE: WITH ... AS (...) — look at the final statement
    let main_stmt = skip_cte(trimmed);
    let upper = main_stmt.to_uppercase();

    // Find the first keyword
    let first_word = upper.split_whitespace().next()?;

    match first_word {
        "SELECT" => {
            // SELECT INTO is a write operation
            if contains_keyword(&upper, "INTO")
                && !contains_keyword(&upper, "INTO OUTFILE")
                && is_select_into(&upper)
            {
                Some(false)
            } else {
                Some(true)
            }
        }
        "SHOW" | "DESCRIBE" | "DESC" | "EXPLAIN" | "PRAGMA" | "TABLE" => Some(true),
        "WITH" => {
            // CTE not fully stripped — try to find the main statement
            None
        }
        "INSERT" | "UPDATE" | "DELETE" | "CREATE" | "DROP" | "ALTER" | "TRUNCATE" | "REPLACE"
        | "MERGE" | "GRANT" | "REVOKE" | "RENAME" | "UPSERT" | "VACUUM" | "REINDEX" | "ANALYZE" => {
            Some(false)
        }
        _ => None,
    }
}

/// Check if the SELECT statement has an INTO clause that makes it a write.
fn is_select_into(upper_sql: &str) -> bool {
    // Simple heuristic: look for SELECT ... INTO ... FROM
    // but not INTO OUTFILE or INTO DUMPFILE
    upper_sql.find(" INTO ").is_some_and(|into_pos| {
        let after_into = &upper_sql[into_pos + 6..];
        let next_word = after_into.split_whitespace().next().unwrap_or("");
        !matches!(next_word, "OUTFILE" | "DUMPFILE")
    })
}

/// Strip SQL comments (-- line comments and /* */ block comments).
fn strip_comments(sql: &str) -> String {
    let mut result = String::with_capacity(sql.len());
    let bytes = sql.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    let mut in_single_quote = false;
    let mut in_double_quote = false;

    while i < len {
        if in_single_quote {
            result.push(bytes[i] as char);
            if bytes[i] == b'\'' {
                in_single_quote = false;
            }
            i += 1;
        } else if in_double_quote {
            result.push(bytes[i] as char);
            if bytes[i] == b'"' {
                in_double_quote = false;
            }
            i += 1;
        } else if bytes[i] == b'\'' {
            in_single_quote = true;
            result.push('\'');
            i += 1;
        } else if bytes[i] == b'"' {
            in_double_quote = true;
            result.push('"');
            i += 1;
        } else if i + 1 < len && bytes[i] == b'-' && bytes[i + 1] == b'-' {
            // Line comment — skip to end of line
            while i < len && bytes[i] != b'\n' {
                i += 1;
            }
        } else if i + 1 < len && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            // Block comment — skip to */
            i += 2;
            while i + 1 < len && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i += 2; // skip */
        } else {
            result.push(bytes[i] as char);
            i += 1;
        }
    }
    result
}

/// Split SQL on semicolons, respecting quotes.
fn split_statements(sql: &str) -> Vec<&str> {
    let mut stmts = Vec::new();
    let mut start = 0;
    let bytes = sql.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    let mut in_single_quote = false;
    let mut in_double_quote = false;

    while i < len {
        if in_single_quote {
            if bytes[i] == b'\'' {
                in_single_quote = false;
            }
        } else if in_double_quote {
            if bytes[i] == b'"' {
                in_double_quote = false;
            }
        } else if bytes[i] == b'\'' {
            in_single_quote = true;
        } else if bytes[i] == b'"' {
            in_double_quote = true;
        } else if bytes[i] == b';' {
            let stmt = sql[start..i].trim();
            if !stmt.is_empty() {
                stmts.push(stmt);
            }
            start = i + 1;
        }
        i += 1;
    }

    let last = sql[start..].trim();
    if !last.is_empty() {
        stmts.push(last);
    }
    stmts
}

/// Skip a leading CTE (WITH ... AS (...)) and return the main statement.
fn skip_cte(sql: &str) -> &str {
    let upper = sql.to_uppercase();
    if !upper.starts_with("WITH ") {
        return sql;
    }

    // Find the last matching closing paren, then look for the main keyword
    let mut depth = 0i32;
    let mut last_close = 0;
    for (i, ch) in sql.chars().enumerate() {
        if ch == '(' {
            depth += 1;
        } else if ch == ')' {
            depth -= 1;
            if depth == 0 {
                last_close = i;
            }
        }
    }

    if last_close > 0 && last_close + 1 < sql.len() {
        let after = sql[last_close + 1..].trim();
        // Skip optional comma for chained CTEs, then return the main statement
        let after = after.strip_prefix(',').map_or(after, str::trim);
        if after.to_uppercase().starts_with("SELECT")
            || after.to_uppercase().starts_with("INSERT")
            || after.to_uppercase().starts_with("UPDATE")
            || after.to_uppercase().starts_with("DELETE")
        {
            return after;
        }
    }

    sql
}

/// Check if a keyword appears in the SQL (case-insensitive, word boundary).
fn contains_keyword(upper_sql: &str, keyword: &str) -> bool {
    upper_sql.contains(keyword)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_is_readonly() {
        assert_eq!(classify_sql("SELECT * FROM users"), Some(true));
        assert_eq!(classify_sql("select id from orders"), Some(true));
    }

    #[test]
    fn show_describe_are_readonly() {
        assert_eq!(classify_sql("SHOW TABLES"), Some(true));
        assert_eq!(classify_sql("DESCRIBE users"), Some(true));
        assert_eq!(classify_sql("EXPLAIN SELECT 1"), Some(true));
    }

    #[test]
    fn write_statements() {
        assert_eq!(classify_sql("INSERT INTO users VALUES (1)"), Some(false));
        assert_eq!(classify_sql("UPDATE users SET name='x'"), Some(false));
        assert_eq!(classify_sql("DELETE FROM users"), Some(false));
        assert_eq!(classify_sql("CREATE TABLE t (id INT)"), Some(false));
        assert_eq!(classify_sql("DROP TABLE users"), Some(false));
        assert_eq!(classify_sql("ALTER TABLE users ADD col INT"), Some(false));
        assert_eq!(classify_sql("TRUNCATE TABLE users"), Some(false));
    }

    #[test]
    fn select_into_is_write() {
        assert_eq!(
            classify_sql("SELECT * INTO new_table FROM users"),
            Some(false)
        );
    }

    #[test]
    fn cte_with_select() {
        assert_eq!(
            classify_sql("WITH cte AS (SELECT 1) SELECT * FROM cte"),
            Some(true)
        );
    }

    #[test]
    fn multi_statement_all_readonly() {
        assert_eq!(classify_sql("SELECT 1; SELECT 2"), Some(true));
    }

    #[test]
    fn multi_statement_mixed() {
        assert_eq!(classify_sql("SELECT 1; DELETE FROM users"), Some(false));
    }

    #[test]
    fn comments_stripped() {
        assert_eq!(classify_sql("-- comment\nSELECT 1"), Some(true));
        assert_eq!(classify_sql("/* block */ SELECT 1"), Some(true));
    }

    #[test]
    fn empty_is_ambiguous() {
        assert_eq!(classify_sql(""), None);
        assert_eq!(classify_sql("   "), None);
    }

    #[test]
    fn exec_is_ambiguous() {
        assert_eq!(classify_sql("EXEC sp_something"), None);
    }
}
