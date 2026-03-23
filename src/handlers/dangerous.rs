use super::{Classification, Handler, HandlerContext};

/// Handler for dangerous shell builtins and privilege escalation commands.
pub static DANGEROUS_BUILTINS_HANDLER: DangerousBuiltinsHandler = DangerousBuiltinsHandler;

pub struct DangerousBuiltinsHandler;

impl Handler for DangerousBuiltinsHandler {
    fn commands(&self) -> &[&str] {
        &["eval", "exec", "source"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        Classification::Ask(format!("{} (executes arbitrary code)", ctx.command_name))
    }
}

/// Handler for privilege escalation commands.
pub static SUDO_HANDLER: SudoHandler = SudoHandler;

pub struct SudoHandler;

impl Handler for SudoHandler {
    fn commands(&self) -> &[&str] {
        &["sudo", "su", "doas"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        Classification::Ask(format!("{} (privilege escalation)", ctx.command_name))
    }
}

/// Handler for remote execution commands.
pub static SSH_HANDLER: SshHandler = SshHandler;

pub struct SshHandler;

impl Handler for SshHandler {
    fn commands(&self) -> &[&str] {
        &["ssh", "scp", "rsync"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        Classification::Ask(format!("{} (remote execution/transfer)", ctx.command_name))
    }
}

/// Handler for script interpreters (similar to python handler).
pub static INTERPRETER_HANDLER: InterpreterHandler = InterpreterHandler;

pub struct InterpreterHandler;

impl Handler for InterpreterHandler {
    fn commands(&self) -> &[&str] {
        &["perl", "ruby", "node", "deno", "lua"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if super::has_flag(ctx.args, &["--version", "-v", "--help", "-h"]) {
            return Classification::Allow(format!("{} version/help", ctx.command_name));
        }
        Classification::Ask(format!("{} (script execution)", ctx.command_name))
    }
}

/// Handler for system package managers.
pub static PACKAGE_MANAGER_HANDLER: PackageManagerHandler = PackageManagerHandler;

pub struct PackageManagerHandler;

impl Handler for PackageManagerHandler {
    fn commands(&self) -> &[&str] {
        &[
            "apt", "apt-get", "dpkg", "dnf", "yum", "pacman", "snap", "flatpak",
        ]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        Classification::Ask(format!("{} (system package management)", ctx.command_name))
    }
}
