use super::{Classification, Handler, HandlerContext, has_flag};

pub static ANSIBLE_HANDLER: AnsibleHandler = AnsibleHandler;

pub struct AnsibleHandler;

impl Handler for AnsibleHandler {
    fn commands(&self) -> &[&str] {
        &[
            "ansible",
            "ansible-playbook",
            "ansible-vault",
            "ansible-galaxy",
            "ansible-config",
            "ansible-inventory",
            "ansible-doc",
            "ansible-lint",
        ]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        match ctx.command_name {
            "ansible-doc" => Classification::Allow("ansible-doc (read-only)".into()),
            "ansible-lint" => Classification::Allow("ansible-lint (read-only)".into()),
            "ansible" => classify_ansible(ctx),
            "ansible-playbook" => classify_playbook(ctx),
            "ansible-vault" => classify_vault(ctx),
            "ansible-galaxy" => classify_galaxy(ctx),
            "ansible-config" => classify_config(ctx),
            "ansible-inventory" => classify_inventory(ctx),
            _ => Classification::Ask(format!("{} (unknown ansible command)", ctx.command_name)),
        }
    }
}

fn classify_ansible(ctx: &HandlerContext) -> Classification {
    if has_flag(ctx.args, &["--check", "-C", "--list-hosts"]) {
        Classification::Allow("ansible dry-run/inspection".into())
    } else {
        Classification::Ask("ansible (may modify targets)".into())
    }
}

fn classify_playbook(ctx: &HandlerContext) -> Classification {
    if has_flag(
        ctx.args,
        &[
            "--check",
            "-C",
            "--syntax-check",
            "--list-hosts",
            "--list-tasks",
            "--list-tags",
        ],
    ) {
        Classification::Allow("ansible-playbook dry-run/inspection".into())
    } else {
        Classification::Ask("ansible-playbook (may modify targets)".into())
    }
}

fn classify_vault(ctx: &HandlerContext) -> Classification {
    if ctx.subcommand() == "view" {
        Classification::Allow("ansible-vault view (read-only)".into())
    } else {
        Classification::Ask(format!(
            "ansible-vault {} (may modify vault)",
            ctx.subcommand()
        ))
    }
}

fn classify_galaxy(ctx: &HandlerContext) -> Classification {
    match ctx.subcommand() {
        "list" | "search" | "info" => {
            Classification::Allow(format!("ansible-galaxy {} (read-only)", ctx.subcommand()))
        }
        sub => Classification::Ask(format!("ansible-galaxy {sub} (may modify roles)")),
    }
}

fn classify_config(ctx: &HandlerContext) -> Classification {
    match ctx.subcommand() {
        "list" | "dump" | "view" => {
            Classification::Allow(format!("ansible-config {} (read-only)", ctx.subcommand()))
        }
        sub => Classification::Ask(format!("ansible-config {sub}")),
    }
}

fn classify_inventory(ctx: &HandlerContext) -> Classification {
    if has_flag(ctx.args, &["--list", "--graph", "--host"]) {
        Classification::Allow("ansible-inventory (read-only query)".into())
    } else {
        Classification::Ask("ansible-inventory".into())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::path::Path;

    use super::*;

    fn ctx<'a>(cmd: &'a str, args: &'a [String]) -> HandlerContext<'a> {
        HandlerContext {
            command_name: cmd,
            args,
            working_directory: Path::new("/tmp"),
            remote: false,
            receives_piped_input: false,
            cd_allowed_dirs: &[],
        }
    }

    // ansible-doc: always allow
    #[test]
    fn ansible_doc_allows() {
        let args = vec!["module_name".into()];
        let result = ANSIBLE_HANDLER.classify(&ctx("ansible-doc", &args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    // ansible-lint: always allow
    #[test]
    fn ansible_lint_allows() {
        let args = vec!["playbook.yml".into()];
        let result = ANSIBLE_HANDLER.classify(&ctx("ansible-lint", &args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    // ansible --check
    #[test]
    fn ansible_check_allows() {
        let args = vec!["all".into(), "-m".into(), "ping".into(), "--check".into()];
        let result = ANSIBLE_HANDLER.classify(&ctx("ansible", &args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    // ansible -C (short flag)
    #[test]
    fn ansible_short_check_allows() {
        let args = vec!["all".into(), "-m".into(), "ping".into(), "-C".into()];
        let result = ANSIBLE_HANDLER.classify(&ctx("ansible", &args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    // ansible --list-hosts
    #[test]
    fn ansible_list_hosts_allows() {
        let args = vec!["all".into(), "--list-hosts".into()];
        let result = ANSIBLE_HANDLER.classify(&ctx("ansible", &args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    // ansible without safe flags → ask
    #[test]
    fn ansible_without_flags_asks() {
        let args = vec!["all".into(), "-m".into(), "shell".into()];
        let result = ANSIBLE_HANDLER.classify(&ctx("ansible", &args));
        assert!(matches!(result, Classification::Ask(_)));
    }

    // ansible-playbook --check
    #[test]
    fn playbook_check_allows() {
        let args = vec!["site.yml".into(), "--check".into()];
        let result = ANSIBLE_HANDLER.classify(&ctx("ansible-playbook", &args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    // ansible-playbook --syntax-check
    #[test]
    fn playbook_syntax_check_allows() {
        let args = vec!["site.yml".into(), "--syntax-check".into()];
        let result = ANSIBLE_HANDLER.classify(&ctx("ansible-playbook", &args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    // ansible-playbook --list-tasks
    #[test]
    fn playbook_list_tasks_allows() {
        let args = vec!["site.yml".into(), "--list-tasks".into()];
        let result = ANSIBLE_HANDLER.classify(&ctx("ansible-playbook", &args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    // ansible-playbook --list-tags
    #[test]
    fn playbook_list_tags_allows() {
        let args = vec!["site.yml".into(), "--list-tags".into()];
        let result = ANSIBLE_HANDLER.classify(&ctx("ansible-playbook", &args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    // ansible-playbook without safe flags → ask
    #[test]
    fn playbook_without_flags_asks() {
        let args = vec!["site.yml".into()];
        let result = ANSIBLE_HANDLER.classify(&ctx("ansible-playbook", &args));
        assert!(matches!(result, Classification::Ask(_)));
    }

    // ansible-vault view → allow
    #[test]
    fn vault_view_allows() {
        let args = vec!["view".into(), "secrets.yml".into()];
        let result = ANSIBLE_HANDLER.classify(&ctx("ansible-vault", &args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    // ansible-vault encrypt → ask
    #[test]
    fn vault_encrypt_asks() {
        let args = vec!["encrypt".into(), "secrets.yml".into()];
        let result = ANSIBLE_HANDLER.classify(&ctx("ansible-vault", &args));
        assert!(matches!(result, Classification::Ask(_)));
    }

    // ansible-galaxy list → allow
    #[test]
    fn galaxy_list_allows() {
        let args = vec!["list".into()];
        let result = ANSIBLE_HANDLER.classify(&ctx("ansible-galaxy", &args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    // ansible-galaxy search → allow
    #[test]
    fn galaxy_search_allows() {
        let args = vec!["search".into(), "nginx".into()];
        let result = ANSIBLE_HANDLER.classify(&ctx("ansible-galaxy", &args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    // ansible-galaxy install → ask
    #[test]
    fn galaxy_install_asks() {
        let args = vec!["install".into(), "geerlingguy.docker".into()];
        let result = ANSIBLE_HANDLER.classify(&ctx("ansible-galaxy", &args));
        assert!(matches!(result, Classification::Ask(_)));
    }

    // ansible-config list → allow
    #[test]
    fn config_list_allows() {
        let args = vec!["list".into()];
        let result = ANSIBLE_HANDLER.classify(&ctx("ansible-config", &args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    // ansible-config dump → allow
    #[test]
    fn config_dump_allows() {
        let args = vec!["dump".into()];
        let result = ANSIBLE_HANDLER.classify(&ctx("ansible-config", &args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    // ansible-config init → ask
    #[test]
    fn config_init_asks() {
        let args = vec!["init".into()];
        let result = ANSIBLE_HANDLER.classify(&ctx("ansible-config", &args));
        assert!(matches!(result, Classification::Ask(_)));
    }

    // ansible-inventory --list → allow
    #[test]
    fn inventory_list_allows() {
        let args = vec!["--list".into()];
        let result = ANSIBLE_HANDLER.classify(&ctx("ansible-inventory", &args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    // ansible-inventory --graph → allow
    #[test]
    fn inventory_graph_allows() {
        let args = vec!["--graph".into()];
        let result = ANSIBLE_HANDLER.classify(&ctx("ansible-inventory", &args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    // ansible-inventory --host → allow
    #[test]
    fn inventory_host_allows() {
        let args = vec!["--host".into(), "webserver1".into()];
        let result = ANSIBLE_HANDLER.classify(&ctx("ansible-inventory", &args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    // ansible-inventory without flags → ask
    #[test]
    fn inventory_without_flags_asks() {
        let args: Vec<String> = vec!["-i".into(), "hosts".into()];
        let result = ANSIBLE_HANDLER.classify(&ctx("ansible-inventory", &args));
        assert!(matches!(result, Classification::Ask(_)));
    }

    // ansible-playbook -C (short flag)
    #[test]
    fn playbook_short_check_allows() {
        let args = vec!["site.yml".into(), "-C".into()];
        let result = ANSIBLE_HANDLER.classify(&ctx("ansible-playbook", &args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    // ansible-playbook --list-hosts
    #[test]
    fn playbook_list_hosts_allows() {
        let args = vec!["site.yml".into(), "--list-hosts".into()];
        let result = ANSIBLE_HANDLER.classify(&ctx("ansible-playbook", &args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    // ansible-galaxy info → allow
    #[test]
    fn galaxy_info_allows() {
        let args = vec!["info".into(), "geerlingguy.docker".into()];
        let result = ANSIBLE_HANDLER.classify(&ctx("ansible-galaxy", &args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    // ansible-config view → allow
    #[test]
    fn config_view_allows() {
        let args = vec!["view".into()];
        let result = ANSIBLE_HANDLER.classify(&ctx("ansible-config", &args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    // ansible-vault no subcommand → ask
    #[test]
    fn vault_no_subcommand_asks() {
        let args: Vec<String> = vec![];
        let result = ANSIBLE_HANDLER.classify(&ctx("ansible-vault", &args));
        assert!(matches!(result, Classification::Ask(_)));
    }

    // ansible-galaxy no subcommand → ask
    #[test]
    fn galaxy_no_subcommand_asks() {
        let args: Vec<String> = vec![];
        let result = ANSIBLE_HANDLER.classify(&ctx("ansible-galaxy", &args));
        assert!(matches!(result, Classification::Ask(_)));
    }

    // ansible-config no subcommand → ask
    #[test]
    fn config_no_subcommand_asks() {
        let args: Vec<String> = vec![];
        let result = ANSIBLE_HANDLER.classify(&ctx("ansible-config", &args));
        assert!(matches!(result, Classification::Ask(_)));
    }
}
