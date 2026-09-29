//! Which short flags carry a credential depends on the program: `-p` is a
//! password to `sshpass` and `docker login`, a port to `docker run` and
//! `redis-cli`, and a directory flag to `mkdir`.

use super::words::Rules;

/// One program whose short flags take a credential.
struct Program {
    names: &'static [&'static str],
    /// Only after this subcommand (`docker login`, not `docker run`).
    subcommand: Option<&'static str>,
    /// Flags whose next word is the credential.
    spaced: &'static [&'static str],
    /// Flags with the credential glued on (`-phunter2`).
    attached: &'static [&'static str],
    /// Long flags that are this program's credential (`curl --user a:b`).
    long: &'static [&'static str],
    /// The first operand after the subcommand is itself the credential
    /// (`vault login TOKEN`).
    operand: bool,
}

const PROGRAMS: &[Program] = &[
    Program {
        names: &["curl"],
        subcommand: None,
        spaced: &["-u"],
        attached: &["-u"],
        long: &["--user", "--proxy-user"],
        operand: false,
    },
    Program {
        names: &["sshpass"],
        subcommand: None,
        spaced: &["-p"],
        attached: &["-p"],
        long: &[],
        operand: false,
    },
    Program {
        // `mysql -p db` prompts: only a glued value is a password.
        names: &["mysql", "mysqldump", "mysqladmin", "mariadb"],
        subcommand: None,
        spaced: &[],
        attached: &["-p"],
        long: &[],
        operand: false,
    },
    Program {
        names: &["mongo", "mongosh"],
        subcommand: None,
        spaced: &["-p"],
        attached: &[],
        long: &[],
        operand: false,
    },
    Program {
        names: &["zip"],
        subcommand: None,
        spaced: &["-P"],
        attached: &[],
        long: &[],
        operand: false,
    },
    Program {
        names: &["redis-cli"],
        subcommand: None,
        spaced: &["-a"],
        attached: &[],
        long: &[],
        operand: false,
    },
    Program {
        names: &[
            "docker", "podman", "nerdctl", "helm", "buildah", "skopeo", "oras", "az",
        ],
        subcommand: Some("login"),
        spaced: &["-p"],
        attached: &[],
        long: &[],
        operand: false,
    },
    Program {
        names: &["vault"],
        subcommand: Some("login"),
        spaced: &[],
        attached: &[],
        long: &[],
        operand: true,
    },
];

/// What one command (a pipeline stage or list item) has shown so far.
#[derive(Default, Clone)]
pub(super) struct Context {
    program: Option<&'static Program>,
    in_subcommand: bool,
}

impl Context {
    /// Read `word`: the program it names, or the subcommand it enters.
    pub(super) fn see(&mut self, word: &str) {
        if let Some(program) = self.program {
            self.in_subcommand |= program.subcommand == Some(word);
            return;
        }
        let name = word.rsplit('/').next().unwrap_or(word);
        self.program = PROGRAMS.iter().find(|p| p.names.contains(&name));
    }

    fn active(&self) -> Option<&'static Program> {
        self.program
            .filter(|p| p.subcommand.is_none() || self.in_subcommand)
    }

    /// The history rules for the words that follow.
    pub(super) fn rules(&self) -> Rules {
        let program = self.active();
        Rules {
            spaced_short: program.map_or(&[], |p| p.spaced),
            attached_short: program.map_or(&[], |p| p.attached),
            long: program.map_or(&[], |p| p.long),
            history: true,
        }
    }

    /// Whether the word after `word` is a credential operand
    /// (`vault login TOKEN`).
    pub(super) fn marks_next(&self, word: &str) -> bool {
        self.active()
            .is_some_and(|p| p.operand && p.subcommand == Some(word))
    }
}
