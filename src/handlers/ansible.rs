use super::{Classification, Handler, HandlerContext, get_flag_value, has_flag};

/// Extensions that indicate a static inventory file rather than a dynamic
/// (executable) inventory script.
const STATIC_INVENTORY_EXTENSIONS: &[&str] = &[".ini", ".yaml", ".yml", ".json"];

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
    if !has_flag(ctx.args, &["--list", "--graph", "--host"]) {
        return Classification::Ask("ansible-inventory".into());
    }
    if let Some(inventory) = get_flag_value(ctx.args, &["-i", "--inventory"])
        && !STATIC_INVENTORY_EXTENSIONS
            .iter()
            .any(|ext| inventory.ends_with(ext))
    {
        return Classification::Ask("ansible-inventory (dynamic inventory script)".into());
    }
    Classification::Allow("ansible-inventory (read-only query)".into())
}

// Behavioral coverage lives in tests/data/catalog/handlers_containers.toml — every
// ansible-family case is a pure command->decision mapping with no injected state,
// so it runs through the real parse+analyze pipeline rather than white-box here.
