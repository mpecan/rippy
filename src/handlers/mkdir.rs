use std::path::Path;

use super::{Classification, Handler, HandlerContext, is_within_scope, normalize_path};

pub static MKDIR_HANDLER: MkdirHandler = MkdirHandler;

pub struct MkdirHandler;

/// Flags that take a value argument (skip both flag and value).
const VALUE_FLAGS: &[&str] = &["-m", "--mode"];

impl Handler for MkdirHandler {
    fn commands(&self) -> &[&str] {
        &["mkdir"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if ctx.remote {
            return Classification::Ask("mkdir in remote context".into());
        }

        let normalized_cwd = normalize_path(ctx.working_directory);
        let mut i = 0;
        let mut has_targets = false;

        while i < ctx.args.len() {
            let arg = &ctx.args[i];

            // Skip flags
            if arg.starts_with('-') {
                if VALUE_FLAGS.contains(&arg.as_str()) {
                    i += 1; // skip the value too
                }
                i += 1;
                continue;
            }

            has_targets = true;

            // Can't statically resolve
            if arg.contains('$') || arg.contains('`') {
                return Classification::Ask("mkdir with variable expansion".into());
            }

            if arg.starts_with('~') {
                return Classification::Ask(format!("mkdir in home directory ({arg})"));
            }

            let resolved = if Path::new(arg.as_str()).is_absolute() {
                normalize_path(Path::new(arg.as_str()))
            } else {
                normalize_path(&ctx.working_directory.join(arg.as_str()))
            };

            if !is_within_scope(&resolved, &normalized_cwd, ctx.cd_allowed_dirs) {
                return Classification::Ask(format!("mkdir outside allowed scope ({arg})"));
            }

            i += 1;
        }

        if has_targets {
            Classification::Allow("mkdir within allowed scope".into())
        } else {
            Classification::Ask("mkdir (no directory specified)".into())
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn mk_ctx<'a>(args: &'a [String], cwd: &'a Path) -> HandlerContext<'a> {
        HandlerContext {
            command_name: "mkdir",
            args,
            working_directory: cwd,
            remote: false,
            receives_piped_input: false,
            cd_allowed_dirs: &[],
        }
    }

    fn mk_ctx_with_allowed<'a>(
        args: &'a [String],
        cwd: &'a Path,
        allowed: &'a [PathBuf],
    ) -> HandlerContext<'a> {
        HandlerContext {
            command_name: "mkdir",
            args,
            working_directory: cwd,
            remote: false,
            receives_piped_input: false,
            cd_allowed_dirs: allowed,
        }
    }

    fn is_allow(c: &Classification) -> bool {
        matches!(c, Classification::Allow(_))
    }

    fn is_ask(c: &Classification) -> bool {
        matches!(c, Classification::Ask(_))
    }

    #[test]
    fn mkdir_relative_allows() {
        let cwd = PathBuf::from("/project");
        let args = ["-p".to_string(), "src/new_dir".to_string()];
        assert!(is_allow(&MKDIR_HANDLER.classify(&mk_ctx(&args, &cwd))));
    }

    #[test]
    fn mkdir_absolute_in_project_allows() {
        let cwd = PathBuf::from("/project");
        let args = ["/project/build".to_string()];
        assert!(is_allow(&MKDIR_HANDLER.classify(&mk_ctx(&args, &cwd))));
    }

    #[test]
    fn mkdir_tmp_allows() {
        let cwd = PathBuf::from("/project");
        let args = ["-p".to_string(), "/tmp/build-output".to_string()];
        assert!(is_allow(&MKDIR_HANDLER.classify(&mk_ctx(&args, &cwd))));
    }

    #[test]
    fn mkdir_outside_project_asks() {
        let cwd = PathBuf::from("/project");
        let args = ["/etc/new_dir".to_string()];
        assert!(is_ask(&MKDIR_HANDLER.classify(&mk_ctx(&args, &cwd))));
    }

    #[test]
    fn mkdir_config_allowed_dir() {
        let cwd = PathBuf::from("/project");
        let allowed = vec![PathBuf::from("/opt/repos")];
        let args = ["-p".to_string(), "/opt/repos/new-project".to_string()];
        assert!(is_allow(
            &MKDIR_HANDLER.classify(&mk_ctx_with_allowed(&args, &cwd, &allowed))
        ));
    }

    #[test]
    fn mkdir_variable_expansion_asks() {
        let cwd = PathBuf::from("/project");
        let args = ["$HOME/new_dir".to_string()];
        assert!(is_ask(&MKDIR_HANDLER.classify(&mk_ctx(&args, &cwd))));
    }

    #[test]
    fn mkdir_tilde_asks() {
        let cwd = PathBuf::from("/project");
        let args = ["~/new_dir".to_string()];
        assert!(is_ask(&MKDIR_HANDLER.classify(&mk_ctx(&args, &cwd))));
    }

    #[test]
    fn mkdir_no_args_asks() {
        let cwd = PathBuf::from("/project");
        assert!(is_ask(&MKDIR_HANDLER.classify(&mk_ctx(&[], &cwd))));
    }

    #[test]
    fn mkdir_flags_only_asks() {
        let cwd = PathBuf::from("/project");
        let args = ["-p".to_string()];
        assert!(is_ask(&MKDIR_HANDLER.classify(&mk_ctx(&args, &cwd))));
    }

    #[test]
    fn mkdir_mode_flag_skipped() {
        let cwd = PathBuf::from("/project");
        let args = ["-m".to_string(), "755".to_string(), "src/build".to_string()];
        assert!(is_allow(&MKDIR_HANDLER.classify(&mk_ctx(&args, &cwd))));
    }

    #[test]
    fn mkdir_multiple_dirs_all_safe() {
        let cwd = PathBuf::from("/project");
        let args = ["-p".to_string(), "src/a".to_string(), "src/b".to_string()];
        assert!(is_allow(&MKDIR_HANDLER.classify(&mk_ctx(&args, &cwd))));
    }

    #[test]
    fn mkdir_multiple_dirs_one_unsafe() {
        let cwd = PathBuf::from("/project");
        let args = ["-p".to_string(), "src/a".to_string(), "/etc/b".to_string()];
        assert!(is_ask(&MKDIR_HANDLER.classify(&mk_ctx(&args, &cwd))));
    }

    #[test]
    fn mkdir_remote_asks() {
        let cwd = PathBuf::from("/project");
        let args = ["src/dir".to_string()];
        let ctx = HandlerContext {
            command_name: "mkdir",
            args: &args,
            working_directory: &cwd,
            remote: true,
            receives_piped_input: false,
            cd_allowed_dirs: &[],
        };
        assert!(is_ask(&MKDIR_HANDLER.classify(&ctx)));
    }

    #[test]
    fn mkdir_dotdot_escape_asks() {
        let cwd = PathBuf::from("/project");
        let args = ["-p".to_string(), "../../etc/evil".to_string()];
        assert!(is_ask(&MKDIR_HANDLER.classify(&mk_ctx(&args, &cwd))));
    }
}
