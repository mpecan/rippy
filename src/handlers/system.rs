use super::{Classification, Handler, HandlerContext, has_flag};

// ---- fd ----

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

// ---- dmesg ----

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

// ---- ip ----

pub static IP_HANDLER: IpHandler = IpHandler;

pub struct IpHandler;

const IP_MUTATION_ACTIONS: &[&str] = &["add", "del", "delete", "change", "set", "flush", "replace"];

impl Handler for IpHandler {
    fn commands(&self) -> &[&str] {
        &["ip"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        // ip <object> <action> — check if action is a mutation
        let positionals: Vec<&str> = ctx
            .args
            .iter()
            .filter(|a| !a.starts_with('-'))
            .map(String::as_str)
            .collect();

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

// ---- ifconfig ----

pub static IFCONFIG_HANDLER: IfconfigHandler = IfconfigHandler;

pub struct IfconfigHandler;

impl Handler for IfconfigHandler {
    fn commands(&self) -> &[&str] {
        &["ifconfig"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        // ≤1 positional arg (just interface name or nothing) = viewing
        // >1 positional arg = modifying
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

    // fd tests
    #[test]
    fn fd_search_allows() {
        let args: Vec<String> = vec!["-e".into(), "rs".into()];
        let result = FD_HANDLER.classify(&ctx(&args, "fd"));
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn fd_exec_recurses() {
        let args: Vec<String> = vec!["-x".into(), "rm".into()];
        let result = FD_HANDLER.classify(&ctx(&args, "fd"));
        assert!(matches!(result, Classification::Recurse(cmd) if cmd == "rm"));
    }

    #[test]
    fn fd_exec_batch_recurses() {
        let args: Vec<String> = vec!["--exec-batch".into(), "grep".into(), "pattern".into()];
        let result = FD_HANDLER.classify(&ctx(&args, "fd"));
        assert!(matches!(result, Classification::Recurse(cmd) if cmd == "grep pattern"));
    }

    // dmesg tests
    #[test]
    fn dmesg_read_allows() {
        let args: Vec<String> = vec![];
        let result = DMESG_HANDLER.classify(&ctx(&args, "dmesg"));
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn dmesg_clear_asks() {
        let args: Vec<String> = vec!["-c".into()];
        let result = DMESG_HANDLER.classify(&ctx(&args, "dmesg"));
        assert!(matches!(result, Classification::Ask(_)));
    }

    #[test]
    fn dmesg_clear_long_asks() {
        let args: Vec<String> = vec!["--clear".into()];
        let result = DMESG_HANDLER.classify(&ctx(&args, "dmesg"));
        assert!(matches!(result, Classification::Ask(_)));
    }

    // ip tests
    #[test]
    fn ip_addr_show_allows() {
        let args: Vec<String> = vec!["addr".into(), "show".into()];
        let result = IP_HANDLER.classify(&ctx(&args, "ip"));
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn ip_addr_add_asks() {
        let args: Vec<String> = vec!["addr".into(), "add".into(), "10.0.0.1/24".into()];
        let result = IP_HANDLER.classify(&ctx(&args, "ip"));
        assert!(matches!(result, Classification::Ask(_)));
    }

    #[test]
    fn ip_route_flush_asks() {
        let args: Vec<String> = vec!["route".into(), "flush".into()];
        let result = IP_HANDLER.classify(&ctx(&args, "ip"));
        assert!(matches!(result, Classification::Ask(_)));
    }

    #[test]
    fn ip_link_allows() {
        let args: Vec<String> = vec!["link".into(), "show".into()];
        let result = IP_HANDLER.classify(&ctx(&args, "ip"));
        assert!(matches!(result, Classification::Allow(_)));
    }

    // ifconfig tests
    #[test]
    fn ifconfig_bare_allows() {
        let args: Vec<String> = vec![];
        let result = IFCONFIG_HANDLER.classify(&ctx(&args, "ifconfig"));
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn ifconfig_interface_allows() {
        let args: Vec<String> = vec!["eth0".into()];
        let result = IFCONFIG_HANDLER.classify(&ctx(&args, "ifconfig"));
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn ifconfig_modify_asks() {
        let args: Vec<String> = vec!["eth0".into(), "down".into()];
        let result = IFCONFIG_HANDLER.classify(&ctx(&args, "ifconfig"));
        assert!(matches!(result, Classification::Ask(_)));
    }

    #[test]
    fn ifconfig_set_ip_asks() {
        let args: Vec<String> = vec![
            "eth0".into(),
            "10.0.0.1".into(),
            "netmask".into(),
            "255.255.255.0".into(),
        ];
        let result = IFCONFIG_HANDLER.classify(&ctx(&args, "ifconfig"));
        assert!(matches!(result, Classification::Ask(_)));
    }
}
