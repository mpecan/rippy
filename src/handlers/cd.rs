use std::path::Path;

use super::{Classification, Handler, HandlerContext, is_within_scope, normalize_path};

pub static CD_HANDLER: CdHandler = CdHandler;

pub struct CdHandler;

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

        let target = &ctx.args[0];

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
        if is_within_scope(&resolved, &normalized_cwd, ctx.cd_allowed_dirs) {
            Classification::Allow(format!("{} within allowed scope", ctx.command_name))
        } else {
            Classification::Ask(format!("{} to {target}", ctx.command_name))
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn mk_ctx<'a>(cmd: &'a str, args: &'a [String], cwd: &'a Path) -> HandlerContext<'a> {
        HandlerContext {
            command_name: cmd,
            args,
            working_directory: cwd,
            remote: false,
            receives_piped_input: false,
            cd_allowed_dirs: &[],
        }
    }

    fn mk_ctx_with_allowed<'a>(
        cmd: &'a str,
        args: &'a [String],
        cwd: &'a Path,
        allowed: &'a [PathBuf],
    ) -> HandlerContext<'a> {
        HandlerContext {
            command_name: cmd,
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

    // ---- cd with no args ----

    #[test]
    fn cd_no_args_asks() {
        let cwd = PathBuf::from("/project");
        let ctx = mk_ctx("cd", &[], &cwd);
        assert!(is_ask(&CD_HANDLER.classify(&ctx)));
    }

    // ---- cd - ----

    #[test]
    fn cd_dash_allows() {
        let cwd = PathBuf::from("/project");
        let args = ["-".to_string()];
        let ctx = mk_ctx("cd", &args, &cwd);
        assert!(is_allow(&CD_HANDLER.classify(&ctx)));
    }

    // ---- cd ~ ----

    #[test]
    fn cd_tilde_asks() {
        let cwd = PathBuf::from("/project");
        let args = ["~".to_string()];
        let ctx = mk_ctx("cd", &args, &cwd);
        assert!(is_ask(&CD_HANDLER.classify(&ctx)));
    }

    #[test]
    fn cd_tilde_subdir_asks() {
        let cwd = PathBuf::from("/project");
        let args = ["~/Documents".to_string()];
        let ctx = mk_ctx("cd", &args, &cwd);
        assert!(is_ask(&CD_HANDLER.classify(&ctx)));
    }

    // ---- variable expansion ----

    #[test]
    fn cd_variable_asks() {
        let cwd = PathBuf::from("/project");
        let args = ["$HOME".to_string()];
        let ctx = mk_ctx("cd", &args, &cwd);
        assert!(is_ask(&CD_HANDLER.classify(&ctx)));
    }

    #[test]
    fn cd_command_substitution_asks() {
        let cwd = PathBuf::from("/project");
        let args = ["$(pwd)".to_string()];
        let ctx = mk_ctx("cd", &args, &cwd);
        assert!(is_ask(&CD_HANDLER.classify(&ctx)));
    }

    #[test]
    fn cd_backtick_asks() {
        let cwd = PathBuf::from("/project");
        let args = ["`pwd`".to_string()];
        let ctx = mk_ctx("cd", &args, &cwd);
        assert!(is_ask(&CD_HANDLER.classify(&ctx)));
    }

    // ---- relative paths within project ----

    #[test]
    fn cd_relative_subdir_allows() {
        let cwd = PathBuf::from("/project");
        let args = ["src".to_string()];
        let ctx = mk_ctx("cd", &args, &cwd);
        assert!(is_allow(&CD_HANDLER.classify(&ctx)));
    }

    #[test]
    fn cd_relative_nested_allows() {
        let cwd = PathBuf::from("/project");
        let args = ["src/handlers".to_string()];
        let ctx = mk_ctx("cd", &args, &cwd);
        assert!(is_allow(&CD_HANDLER.classify(&ctx)));
    }

    #[test]
    fn cd_dot_allows() {
        let cwd = PathBuf::from("/project");
        let args = [".".to_string()];
        let ctx = mk_ctx("cd", &args, &cwd);
        assert!(is_allow(&CD_HANDLER.classify(&ctx)));
    }

    #[test]
    fn cd_dotdot_from_subdir_asks() {
        // CWD is a subdir — going up escapes the working_directory
        let cwd = PathBuf::from("/project/src");
        let args = ["..".to_string()];
        let ctx = mk_ctx("cd", &args, &cwd);
        assert!(is_ask(&CD_HANDLER.classify(&ctx)));
    }

    // ---- relative paths escaping project ----

    #[test]
    fn cd_dotdot_from_root_asks() {
        let cwd = PathBuf::from("/project");
        let args = ["..".to_string()];
        let ctx = mk_ctx("cd", &args, &cwd);
        assert!(is_ask(&CD_HANDLER.classify(&ctx)));
    }

    #[test]
    fn cd_relative_escape_asks() {
        let cwd = PathBuf::from("/project");
        let args = ["../../etc".to_string()];
        let ctx = mk_ctx("cd", &args, &cwd);
        assert!(is_ask(&CD_HANDLER.classify(&ctx)));
    }

    // ---- absolute paths ----

    #[test]
    fn cd_absolute_within_project_allows() {
        let cwd = PathBuf::from("/project");
        let args = ["/project/src".to_string()];
        let ctx = mk_ctx("cd", &args, &cwd);
        assert!(is_allow(&CD_HANDLER.classify(&ctx)));
    }

    #[test]
    fn cd_absolute_outside_project_asks() {
        let cwd = PathBuf::from("/project");
        let args = ["/etc".to_string()];
        let ctx = mk_ctx("cd", &args, &cwd);
        assert!(is_ask(&CD_HANDLER.classify(&ctx)));
    }

    // ---- safe directories ----

    #[test]
    fn cd_tmp_allows() {
        let cwd = PathBuf::from("/project");
        let args = ["/tmp".to_string()];
        let ctx = mk_ctx("cd", &args, &cwd);
        assert!(is_allow(&CD_HANDLER.classify(&ctx)));
    }

    #[test]
    fn cd_tmp_subdir_allows() {
        let cwd = PathBuf::from("/project");
        let args = ["/tmp/build-output".to_string()];
        let ctx = mk_ctx("cd", &args, &cwd);
        assert!(is_allow(&CD_HANDLER.classify(&ctx)));
    }

    #[test]
    fn cd_var_tmp_allows() {
        let cwd = PathBuf::from("/project");
        let args = ["/var/tmp".to_string()];
        let ctx = mk_ctx("cd", &args, &cwd);
        assert!(is_allow(&CD_HANDLER.classify(&ctx)));
    }

    // ---- config-allowed directories ----

    #[test]
    fn cd_to_config_allowed_dir_allows() {
        let cwd = PathBuf::from("/project");
        let args = ["/opt/repos/other-project".to_string()];
        let allowed = vec![PathBuf::from("/opt/repos")];
        let ctx = mk_ctx_with_allowed("cd", &args, &cwd, &allowed);
        assert!(is_allow(&CD_HANDLER.classify(&ctx)));
    }

    #[test]
    fn cd_to_config_allowed_exact_allows() {
        let cwd = PathBuf::from("/project");
        let args = ["/opt/repos".to_string()];
        let allowed = vec![PathBuf::from("/opt/repos")];
        let ctx = mk_ctx_with_allowed("cd", &args, &cwd, &allowed);
        assert!(is_allow(&CD_HANDLER.classify(&ctx)));
    }

    #[test]
    fn cd_outside_config_allowed_asks() {
        let cwd = PathBuf::from("/project");
        let args = ["/etc".to_string()];
        let allowed = vec![PathBuf::from("/opt/repos")];
        let ctx = mk_ctx_with_allowed("cd", &args, &cwd, &allowed);
        assert!(is_ask(&CD_HANDLER.classify(&ctx)));
    }

    #[test]
    fn cd_relative_resolves_into_allowed_parent() {
        // CWD is within an allowed parent — relative cd that stays within is ok
        let cwd = PathBuf::from("/opt/repos/project-a");
        let args = ["../project-b".to_string()];
        let allowed = vec![PathBuf::from("/opt/repos")];
        let ctx = mk_ctx_with_allowed("cd", &args, &cwd, &allowed);
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
        let ctx = mk_ctx_with_allowed("cd", &args, &cwd, &allowed);
        assert!(is_allow(&CD_HANDLER.classify(&ctx)));

        let args = ["/home/user/work/bar".to_string()];
        let ctx = mk_ctx_with_allowed("cd", &args, &cwd, &allowed);
        assert!(is_allow(&CD_HANDLER.classify(&ctx)));

        let args = ["/home/user/personal".to_string()];
        let ctx = mk_ctx_with_allowed("cd", &args, &cwd, &allowed);
        assert!(is_ask(&CD_HANDLER.classify(&ctx)));
    }

    // ---- pushd ----

    #[test]
    fn pushd_within_project_allows() {
        let cwd = PathBuf::from("/project");
        let args = ["src".to_string()];
        let ctx = mk_ctx("pushd", &args, &cwd);
        assert!(is_allow(&CD_HANDLER.classify(&ctx)));
    }

    #[test]
    fn pushd_outside_project_asks() {
        let cwd = PathBuf::from("/project");
        let args = ["/etc".to_string()];
        let ctx = mk_ctx("pushd", &args, &cwd);
        assert!(is_ask(&CD_HANDLER.classify(&ctx)));
    }

    #[test]
    fn pushd_tmp_allows() {
        let cwd = PathBuf::from("/project");
        let args = ["/tmp".to_string()];
        let ctx = mk_ctx("pushd", &args, &cwd);
        assert!(is_allow(&CD_HANDLER.classify(&ctx)));
    }

    #[test]
    fn pushd_to_config_allowed_allows() {
        let cwd = PathBuf::from("/project");
        let args = ["/opt/repos/other".to_string()];
        let allowed = vec![PathBuf::from("/opt/repos")];
        let ctx = mk_ctx_with_allowed("pushd", &args, &cwd, &allowed);
        assert!(is_allow(&CD_HANDLER.classify(&ctx)));
    }

    // ---- popd ----

    #[test]
    fn popd_asks() {
        let cwd = PathBuf::from("/project");
        let ctx = mk_ctx("popd", &[], &cwd);
        assert!(is_ask(&CD_HANDLER.classify(&ctx)));
    }

    // ---- remote mode ----

    #[test]
    fn cd_remote_asks() {
        let cwd = PathBuf::from("/project");
        let args = ["src".to_string()];
        let ctx = HandlerContext {
            command_name: "cd",
            args: &args,
            working_directory: &cwd,
            remote: true,
            receives_piped_input: false,
            cd_allowed_dirs: &[],
        };
        assert!(is_ask(&CD_HANDLER.classify(&ctx)));
    }

    // ---- normalize_path ----

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
