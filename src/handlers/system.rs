use super::{Classification, Handler, HandlerContext, has_flag};

// fd

pub static FD_HANDLER: FdHandler = FdHandler;

pub struct FdHandler;

impl Handler for FdHandler {
    fn commands(&self) -> &[&str] {
        &["fd"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        // -x/--exec and -X/--exec-batch delegate inner commands
        for (i, arg) in ctx.args.iter().enumerate() {
            if matches!(arg.as_str(), "-x" | "--exec" | "-X" | "--exec-batch") {
                let inner: Vec<&str> = ctx.args[i + 1..]
                    .iter()
                    .take_while(|a| a.as_str() != ";")
                    .map(String::as_str)
                    .collect();
                if inner.is_empty() {
                    return Classification::Ask("fd exec (no command)".into());
                }
                return Classification::Recurse(inner.join(" "));
            }
        }
        Classification::Allow("fd (search only)".into())
    }
}

// dmesg

pub static DMESG_HANDLER: DmesgHandler = DmesgHandler;

pub struct DmesgHandler;

impl Handler for DmesgHandler {
    fn commands(&self) -> &[&str] {
        &["dmesg"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if has_flag(ctx.args, &["-c", "-C", "--clear"]) {
            return Classification::Ask("dmesg (clear kernel ring buffer)".into());
        }
        Classification::Allow("dmesg (read)".into())
    }
}

// ip

pub static IP_HANDLER: IpHandler = IpHandler;

pub struct IpHandler;

const IP_MUTATION_ACTIONS: &[&str] = &["add", "del", "delete", "change", "set", "flush", "replace"];

impl Handler for IpHandler {
    fn commands(&self) -> &[&str] {
        &["ip"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        // ip <object> <action> — check if action is a mutation. `-f`/`-family`
        // takes a value, so skip it and its value too or the object/action
        // indexes shift and a mutation can hide behind them.
        let mut positionals: Vec<&str> = Vec::new();
        let mut skip_next = false;
        for arg in ctx.args {
            if skip_next {
                skip_next = false;
                continue;
            }
            if arg == "-f" || arg == "-family" {
                skip_next = true;
                continue;
            }
            if !arg.starts_with('-') {
                positionals.push(arg);
            }
        }

        let action = positionals.get(1).copied().unwrap_or_default();
        if IP_MUTATION_ACTIONS.contains(&action) {
            Classification::Ask(format!(
                "ip {} {action}",
                positionals.first().unwrap_or(&"")
            ))
        } else {
            Classification::Allow(format!("ip {} (read)", positionals.first().unwrap_or(&"")))
        }
    }
}

// ifconfig

pub static IFCONFIG_HANDLER: IfconfigHandler = IfconfigHandler;

pub struct IfconfigHandler;

impl Handler for IfconfigHandler {
    fn commands(&self) -> &[&str] {
        &["ifconfig"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        // >1 positional arg (beyond an interface name) means a config change.
        let positional_count = ctx.args.iter().filter(|a| !a.starts_with('-')).count();
        if positional_count <= 1 {
            Classification::Allow("ifconfig (view)".into())
        } else {
            Classification::Ask("ifconfig (modify interface)".into())
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {

    use super::*;

    // fd search and all dmesg/ip/ifconfig command->decision cases are covered by
    // tests/data/catalog/handlers_text_system.toml. The fd `-x`/`--exec-batch`
    // tests below assert the Recurse variant and exact inner-command extraction.
    #[test]
    fn fd_exec_recurses() {
        let args: Vec<String> = vec!["-x".into(), "rm".into()];
        let result = FD_HANDLER.classify(&HandlerContext::test("fd", &args));
        assert!(matches!(result, Classification::Recurse(cmd) if cmd == "rm"));
    }

    #[test]
    fn fd_exec_no_command_asks() {
        let args: Vec<String> = vec!["-x".into()];
        let result = FD_HANDLER.classify(&HandlerContext::test("fd", &args));
        assert!(matches!(result, Classification::Ask(_)));
    }

    #[test]
    fn fd_exec_batch_recurses() {
        let args: Vec<String> = vec!["--exec-batch".into(), "grep".into(), "pattern".into()];
        let result = FD_HANDLER.classify(&HandlerContext::test("fd", &args));
        assert!(matches!(result, Classification::Recurse(cmd) if cmd == "grep pattern"));
    }
}
