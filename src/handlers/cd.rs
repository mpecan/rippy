use std::path::Path;

use super::{Classification, Handler, HandlerContext, is_within_scope, normalize_path};

pub static CD_HANDLER: CdHandler = CdHandler;

pub struct CdHandler;

/// `cd` option flags that take no value and don't change the destination.
const CD_KNOWN_FLAGS: &[&str] = &["-L", "-P", "-e", "-@"];

/// Skip leading `cd` option tokens (and a `--` terminator) to find the real
/// destination. Returns `None` (fail closed) if a leading flag is not one of
/// the known no-op flags, since an unrecognized flag could shift or consume
/// the destination in ways this handler can't reason about.
fn resolve_target(args: &[String]) -> Option<&String> {
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--" {
            return args.get(i + 1);
        }
        if arg == "-" || !arg.starts_with('-') {
            return Some(arg);
        }
        if !CD_KNOWN_FLAGS.contains(&arg.as_str()) {
            return None;
        }
        i += 1;
    }
    None
}

impl Handler for CdHandler {
    fn commands(&self) -> &[&str] {
        &["cd", "pushd", "popd"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if ctx.command_name == "popd" {
            return Classification::Ask("popd (unknown destination)".into());
        }

        if ctx.remote {
            return Classification::Ask(format!("{} in remote context", ctx.command_name));
        }

        if ctx.args.is_empty() {
            return Classification::Ask(format!("{} (goes to home directory)", ctx.command_name));
        }

        let Some(target) = resolve_target(ctx.args) else {
            return Classification::Ask(format!("{} (unknown flag)", ctx.command_name));
        };

        if target == "-" {
            return Classification::Allow(format!("{} - (previous directory)", ctx.command_name));
        }

        // Can't statically resolve the destination
        if target.contains('$') || target.contains('`') {
            return Classification::Ask(format!("{} with variable expansion", ctx.command_name));
        }

        if target.starts_with('~') {
            return Classification::Ask(format!("{} to home directory", ctx.command_name));
        }

        let resolved = if Path::new(target).is_absolute() {
            normalize_path(Path::new(target))
        } else {
            normalize_path(&ctx.working_directory.join(target))
        };

        let normalized_cwd = normalize_path(ctx.working_directory);
        if is_within_scope(&resolved, &normalized_cwd, ctx.safe_scopes) {
            Classification::Allow(format!("{} within allowed scope", ctx.command_name))
        } else {
            Classification::Ask(format!("{} to {target}", ctx.command_name))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn is_allow(c: &Classification) -> bool {
        matches!(c, Classification::Allow(_))
    }

    fn is_ask(c: &Classification) -> bool {
        matches!(c, Classification::Ask(_))
    }

    // cd with no args

    #[test]
    fn cd_no_args_asks() {
        let cwd = PathBuf::from("/project");
        let ctx = HandlerContext {
            working_directory: &cwd,
            ..HandlerContext::test("cd", &[])
        };
        assert!(is_ask(&CD_HANDLER.classify(&ctx)));
    }

    // cd -

    #[test]
    fn cd_dash_allows() {
        let cwd = PathBuf::from("/project");
        let args = ["-".to_string()];
        let ctx = HandlerContext {
            working_directory: &cwd,
            ..HandlerContext::test("cd", &args)
        };
        assert!(is_allow(&CD_HANDLER.classify(&ctx)));
    }

    // cd ~

    #[test]
    fn cd_tilde_asks() {
        let cwd = PathBuf::from("/project");
        let args = ["~".to_string()];
        let ctx = HandlerContext {
            working_directory: &cwd,
            ..HandlerContext::test("cd", &args)
        };
        assert!(is_ask(&CD_HANDLER.classify(&ctx)));
    }

    #[test]
    fn cd_tilde_subdir_asks() {
        let cwd = PathBuf::from("/project");
        let args = ["~/Documents".to_string()];
        let ctx = HandlerContext {
            working_directory: &cwd,
            ..HandlerContext::test("cd", &args)
        };
        assert!(is_ask(&CD_HANDLER.classify(&ctx)));
    }

    // variable expansion

    #[test]
    fn cd_variable_asks() {
        let cwd = PathBuf::from("/project");
        let args = ["$HOME".to_string()];
        let ctx = HandlerContext {
            working_directory: &cwd,
            ..HandlerContext::test("cd", &args)
        };
        assert!(is_ask(&CD_HANDLER.classify(&ctx)));
    }

    #[test]
    fn cd_command_substitution_asks() {
        let cwd = PathBuf::from("/project");
        let args = ["$(pwd)".to_string()];
        let ctx = HandlerContext {
            working_directory: &cwd,
            ..HandlerContext::test("cd", &args)
        };
        assert!(is_ask(&CD_HANDLER.classify(&ctx)));
    }

    #[test]
    fn cd_backtick_asks() {
        let cwd = PathBuf::from("/project");
        let args = ["`pwd`".to_string()];
        let ctx = HandlerContext {
            working_directory: &cwd,
            ..HandlerContext::test("cd", &args)
        };
        assert!(is_ask(&CD_HANDLER.classify(&ctx)));
    }

    // relative paths within project

    #[test]
    fn cd_relative_subdir_allows() {
        let cwd = PathBuf::from("/project");
        let args = ["src".to_string()];
        let ctx = HandlerContext {
            working_directory: &cwd,
            ..HandlerContext::test("cd", &args)
        };
        assert!(is_allow(&CD_HANDLER.classify(&ctx)));
    }

    #[test]
    fn cd_relative_nested_allows() {
        let cwd = PathBuf::from("/project");
        let args = ["src/handlers".to_string()];
        let ctx = HandlerContext {
            working_directory: &cwd,
            ..HandlerContext::test("cd", &args)
        };
        assert!(is_allow(&CD_HANDLER.classify(&ctx)));
    }

    #[test]
    fn cd_dot_allows() {
        let cwd = PathBuf::from("/project");
        let args = [".".to_string()];
        let ctx = HandlerContext {
            working_directory: &cwd,
            ..HandlerContext::test("cd", &args)
        };
        assert!(is_allow(&CD_HANDLER.classify(&ctx)));
    }

    #[test]
    fn cd_dotdot_from_subdir_asks() {
        // CWD is a subdir — going up escapes the working_directory
        let cwd = PathBuf::from("/project/src");
        let args = ["..".to_string()];
        let ctx = HandlerContext {
            working_directory: &cwd,
            ..HandlerContext::test("cd", &args)
        };
        assert!(is_ask(&CD_HANDLER.classify(&ctx)));
    }

    // relative paths escaping project

    #[test]
    fn cd_dotdot_from_root_asks() {
        let cwd = PathBuf::from("/project");
        let args = ["..".to_string()];
        let ctx = HandlerContext {
            working_directory: &cwd,
            ..HandlerContext::test("cd", &args)
        };
        assert!(is_ask(&CD_HANDLER.classify(&ctx)));
    }

    #[test]
    fn cd_relative_escape_asks() {
        let cwd = PathBuf::from("/project");
        let args = ["../../etc".to_string()];
        let ctx = HandlerContext {
            working_directory: &cwd,
            ..HandlerContext::test("cd", &args)
        };
        assert!(is_ask(&CD_HANDLER.classify(&ctx)));
    }

    // absolute paths

    #[test]
    fn cd_absolute_within_project_allows() {
        let cwd = PathBuf::from("/project");
        let args = ["/project/src".to_string()];
        let ctx = HandlerContext {
            working_directory: &cwd,
            ..HandlerContext::test("cd", &args)
        };
        assert!(is_allow(&CD_HANDLER.classify(&ctx)));
    }

    #[test]
    fn cd_absolute_outside_project_asks() {
        let cwd = PathBuf::from("/project");
        let args = ["/etc".to_string()];
        let ctx = HandlerContext {
            working_directory: &cwd,
            ..HandlerContext::test("cd", &args)
        };
        assert!(is_ask(&CD_HANDLER.classify(&ctx)));
    }

    // safe directories

    #[test]
    fn cd_tmp_allows() {
        let cwd = PathBuf::from("/project");
        let args = ["/tmp".to_string()];
        let ctx = HandlerContext {
            working_directory: &cwd,
            ..HandlerContext::test("cd", &args)
        };
        assert!(is_allow(&CD_HANDLER.classify(&ctx)));
    }

    #[test]
    fn cd_tmp_subdir_allows() {
        let cwd = PathBuf::from("/project");
        let args = ["/tmp/build-output".to_string()];
        let ctx = HandlerContext {
            working_directory: &cwd,
            ..HandlerContext::test("cd", &args)
        };
        assert!(is_allow(&CD_HANDLER.classify(&ctx)));
    }

    #[test]
    fn cd_var_tmp_allows() {
        let cwd = PathBuf::from("/project");
        let args = ["/var/tmp".to_string()];
        let ctx = HandlerContext {
            working_directory: &cwd,
            ..HandlerContext::test("cd", &args)
        };
        assert!(is_allow(&CD_HANDLER.classify(&ctx)));
    }

    // config-allowed directories

    #[test]
    fn cd_to_config_allowed_dir_allows() {
        let cwd = PathBuf::from("/project");
        let args = ["/opt/repos/other-project".to_string()];
        let allowed = vec![PathBuf::from("/opt/repos")];
        let ctx = HandlerContext {
            working_directory: &cwd,
            safe_scopes: &allowed,
            ..HandlerContext::test("cd", &args)
        };
        assert!(is_allow(&CD_HANDLER.classify(&ctx)));
    }

    #[test]
    fn cd_to_config_allowed_exact_allows() {
        let cwd = PathBuf::from("/project");
        let args = ["/opt/repos".to_string()];
        let allowed = vec![PathBuf::from("/opt/repos")];
        let ctx = HandlerContext {
            working_directory: &cwd,
            safe_scopes: &allowed,
            ..HandlerContext::test("cd", &args)
        };
        assert!(is_allow(&CD_HANDLER.classify(&ctx)));
    }

    #[test]
    fn cd_outside_config_allowed_asks() {
        let cwd = PathBuf::from("/project");
        let args = ["/etc".to_string()];
        let allowed = vec![PathBuf::from("/opt/repos")];
        let ctx = HandlerContext {
            working_directory: &cwd,
            safe_scopes: &allowed,
            ..HandlerContext::test("cd", &args)
        };
        assert!(is_ask(&CD_HANDLER.classify(&ctx)));
    }

    #[test]
    fn cd_relative_resolves_into_allowed_parent() {
        // CWD is within an allowed parent — relative cd that stays within is ok
        let cwd = PathBuf::from("/opt/repos/project-a");
        let args = ["../project-b".to_string()];
        let allowed = vec![PathBuf::from("/opt/repos")];
        let ctx = HandlerContext {
            working_directory: &cwd,
            safe_scopes: &allowed,
            ..HandlerContext::test("cd", &args)
        };
        assert!(is_allow(&CD_HANDLER.classify(&ctx)));
    }

    #[test]
    fn cd_multiple_allowed_dirs() {
        let cwd = PathBuf::from("/project");
        let allowed = vec![
            PathBuf::from("/opt/repos"),
            PathBuf::from("/home/user/work"),
        ];

        let args = ["/opt/repos/foo".to_string()];
        let ctx = HandlerContext {
            working_directory: &cwd,
            safe_scopes: &allowed,
            ..HandlerContext::test("cd", &args)
        };
        assert!(is_allow(&CD_HANDLER.classify(&ctx)));

        let args = ["/home/user/work/bar".to_string()];
        let ctx = HandlerContext {
            working_directory: &cwd,
            safe_scopes: &allowed,
            ..HandlerContext::test("cd", &args)
        };
        assert!(is_allow(&CD_HANDLER.classify(&ctx)));

        let args = ["/home/user/personal".to_string()];
        let ctx = HandlerContext {
            working_directory: &cwd,
            safe_scopes: &allowed,
            ..HandlerContext::test("cd", &args)
        };
        assert!(is_ask(&CD_HANDLER.classify(&ctx)));
    }

    // leading option flags shifting the destination

    #[test]
    fn cd_dash_p_outside_scope_asks() {
        let cwd = PathBuf::from("/project");
        let args = ["-P".to_string(), "/etc".to_string()];
        let ctx = HandlerContext {
            working_directory: &cwd,
            ..HandlerContext::test("cd", &args)
        };
        assert!(is_ask(&CD_HANDLER.classify(&ctx)));
    }

    #[test]
    fn cd_dash_p_within_scope_allows() {
        let cwd = PathBuf::from("/project");
        let args = ["-P".to_string(), "src".to_string()];
        let ctx = HandlerContext {
            working_directory: &cwd,
            ..HandlerContext::test("cd", &args)
        };
        assert!(is_allow(&CD_HANDLER.classify(&ctx)));
    }

    #[test]
    fn cd_double_dash_outside_scope_asks() {
        let cwd = PathBuf::from("/project");
        let args = ["--".to_string(), "/etc".to_string()];
        let ctx = HandlerContext {
            working_directory: &cwd,
            ..HandlerContext::test("cd", &args)
        };
        assert!(is_ask(&CD_HANDLER.classify(&ctx)));
    }

    #[test]
    fn cd_double_dash_within_scope_allows() {
        let cwd = PathBuf::from("/project");
        let args = ["--".to_string(), "src".to_string()];
        let ctx = HandlerContext {
            working_directory: &cwd,
            ..HandlerContext::test("cd", &args)
        };
        assert!(is_allow(&CD_HANDLER.classify(&ctx)));
    }

    #[test]
    fn cd_unknown_flag_asks() {
        let cwd = PathBuf::from("/project");
        let args = ["-Z".to_string(), "src".to_string()];
        let ctx = HandlerContext {
            working_directory: &cwd,
            ..HandlerContext::test("cd", &args)
        };
        assert!(is_ask(&CD_HANDLER.classify(&ctx)));
    }

    // pushd

    #[test]
    fn pushd_within_project_allows() {
        let cwd = PathBuf::from("/project");
        let args = ["src".to_string()];
        let ctx = HandlerContext {
            working_directory: &cwd,
            ..HandlerContext::test("pushd", &args)
        };
        assert!(is_allow(&CD_HANDLER.classify(&ctx)));
    }

    #[test]
    fn pushd_outside_project_asks() {
        let cwd = PathBuf::from("/project");
        let args = ["/etc".to_string()];
        let ctx = HandlerContext {
            working_directory: &cwd,
            ..HandlerContext::test("pushd", &args)
        };
        assert!(is_ask(&CD_HANDLER.classify(&ctx)));
    }

    #[test]
    fn pushd_tmp_allows() {
        let cwd = PathBuf::from("/project");
        let args = ["/tmp".to_string()];
        let ctx = HandlerContext {
            working_directory: &cwd,
            ..HandlerContext::test("pushd", &args)
        };
        assert!(is_allow(&CD_HANDLER.classify(&ctx)));
    }

    #[test]
    fn pushd_to_config_allowed_allows() {
        let cwd = PathBuf::from("/project");
        let args = ["/opt/repos/other".to_string()];
        let allowed = vec![PathBuf::from("/opt/repos")];
        let ctx = HandlerContext {
            working_directory: &cwd,
            safe_scopes: &allowed,
            ..HandlerContext::test("pushd", &args)
        };
        assert!(is_allow(&CD_HANDLER.classify(&ctx)));
    }

    // popd

    #[test]
    fn popd_asks() {
        let cwd = PathBuf::from("/project");
        let ctx = HandlerContext {
            working_directory: &cwd,
            ..HandlerContext::test("popd", &[])
        };
        assert!(is_ask(&CD_HANDLER.classify(&ctx)));
    }

    // remote mode

    #[test]
    fn cd_remote_asks() {
        let cwd = PathBuf::from("/project");
        let args = ["src".to_string()];
        let ctx = HandlerContext {
            working_directory: &cwd,
            remote: true,
            ..HandlerContext::test("cd", &args)
        };
        assert!(is_ask(&CD_HANDLER.classify(&ctx)));
    }

    // normalize_path

    #[test]
    fn normalize_resolves_dotdot() {
        assert_eq!(
            normalize_path(Path::new("/a/b/../c")),
            PathBuf::from("/a/c")
        );
    }

    #[test]
    fn normalize_resolves_dot() {
        assert_eq!(normalize_path(Path::new("/a/./b")), PathBuf::from("/a/b"));
    }

    #[test]
    fn normalize_multiple_dotdot() {
        assert_eq!(
            normalize_path(Path::new("/a/b/c/../../d")),
            PathBuf::from("/a/d")
        );
    }
}
