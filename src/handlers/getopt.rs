//! A getopt-shaped scan of argv for handlers that must see every occurrence of
//! a value-carrying option.
//!
//! The token-matching helpers in the parent module (`get_flag_value`,
//! `has_flag`) miss two spellings getopt accepts and users write: a short
//! option clustered behind boolean ones (`psql -Atc SQL` is `-A -t -c SQL`),
//! and a value glued to its letter (`-cSQL`). Scanning every token as a
//! possible flag instead is worse — it re-reads an option's *operand* as a
//! flag, so `psql -o -copy.out` looks like a glued `-c opy.out` (#199).
//!
//! Both hinge on the one fact a flag list cannot carry: which options take a
//! value. That is what an [`OptionSpec`] declares.

/// The value-taking options of one command; every letter and name not listed
/// is boolean, which is what makes a cluster decodable.
pub(crate) struct OptionSpec<'a> {
    /// Short letters that require a value, whether separate (`-c SQL`), glued
    /// (`-cSQL`) or last in a cluster (`-Atc SQL`).
    pub(crate) value_shorts: &'a str,
    /// Short letters whose value is optional. getopt attaches one only when it
    /// is glued (`mysql -psecret`); declaring such a letter as required would
    /// make a bare `-p` swallow the `-e` after it.
    pub(crate) optional_shorts: &'a str,
    /// Long names (without `--`) that take a *separate* value. The
    /// `--name=value` spelling needs no declaration: it is self-delimiting.
    pub(crate) value_longs: &'a [&'a str],
}

/// One option occurrence found by [`scan_options`], in the spelling used.
pub(crate) enum OptionName<'a> {
    Short(char),
    Long(&'a str),
}

impl OptionName<'_> {
    /// Whether this occurrence names the given option in either spelling.
    ///
    /// A long name matches by prefix because `getopt_long` accepts any
    /// unambiguous abbreviation (`psql --comm=SQL` runs the SQL). Accepting an
    /// ambiguous abbreviation too costs at most a prompt; rejecting one would
    /// let an unclassified statement through.
    pub(crate) fn is(&self, short: char, longs: &[&str]) -> bool {
        match *self {
            Self::Short(letter) => letter == short,
            Self::Long(name) => longs.iter().any(|long| long.starts_with(name)),
        }
    }
}

/// Every value-carrying option occurrence in `args`, in argv order.
///
/// Boolean options are not reported — a caller only ever asks about the value.
pub(crate) fn scan_options<'a>(
    args: &'a [String],
    spec: &OptionSpec,
) -> Vec<(OptionName<'a>, &'a str)> {
    let mut found = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        if arg == "--" {
            break;
        }
        i += if let Some(name) = arg.strip_prefix("--") {
            scan_long(name, args.get(i + 1), spec, &mut found)
        } else if let Some(cluster) = arg.strip_prefix('-').filter(|c| !c.is_empty()) {
            scan_cluster(cluster, args.get(i + 1), spec, &mut found)
        } else {
            1
        };
    }
    found
}

/// Scan one `--…` token; returns how many argv tokens it consumed.
fn scan_long<'a>(
    arg: &'a str,
    next: Option<&'a String>,
    spec: &OptionSpec,
    found: &mut Vec<(OptionName<'a>, &'a str)>,
) -> usize {
    if let Some((name, value)) = arg.split_once('=') {
        found.push((OptionName::Long(name), value));
        return 1;
    }
    if !spec.value_longs.iter().any(|long| long.starts_with(arg)) {
        return 1;
    }
    next.map_or(1, |value| {
        found.push((OptionName::Long(arg), value.as_str()));
        2
    })
}

/// Scan one short-option cluster; returns how many argv tokens it consumed.
///
/// The first value-taking letter ends the cluster: everything after it is that
/// option's value, which is why the command letter has to be written last.
fn scan_cluster<'a>(
    cluster: &'a str,
    next: Option<&'a String>,
    spec: &OptionSpec,
    found: &mut Vec<(OptionName<'a>, &'a str)>,
) -> usize {
    for (offset, letter) in cluster.char_indices() {
        let rest = &cluster[offset + letter.len_utf8()..];
        if spec.value_shorts.contains(letter) {
            if !rest.is_empty() {
                found.push((OptionName::Short(letter), rest));
                return 1;
            }
            let Some(value) = next else { return 1 };
            found.push((OptionName::Short(letter), value.as_str()));
            return 2;
        }
        if spec.optional_shorts.contains(letter) {
            if !rest.is_empty() {
                found.push((OptionName::Short(letter), rest));
            }
            return 1;
        }
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: OptionSpec = OptionSpec {
        value_shorts: "co",
        optional_shorts: "p",
        value_longs: &["command", "output"],
    };

    fn scan(args: &[&str]) -> Vec<(String, String)> {
        let owned: Vec<String> = args.iter().map(|a| (*a).to_string()).collect();
        scan_options(&owned, &SPEC)
            .into_iter()
            .map(|(name, value)| {
                let name = match name {
                    OptionName::Short(c) => format!("-{c}"),
                    OptionName::Long(l) => format!("--{l}"),
                };
                (name, value.to_string())
            })
            .collect()
    }

    #[test]
    fn cluster_gives_its_value_to_the_last_letter() {
        assert_eq!(scan(&["-Atc", "SQL"]), [("-c".into(), "SQL".into())]);
    }

    #[test]
    fn an_operand_is_not_rescanned_as_a_flag() {
        assert_eq!(
            scan(&["-o", "-copy.out", "-c", "SQL"]),
            [
                ("-o".into(), "-copy.out".into()),
                ("-c".into(), "SQL".into()),
            ]
        );
    }

    #[test]
    fn optional_value_attaches_only_when_glued() {
        assert_eq!(
            scan(&["-p", "-c", "SQL"]),
            [("-c".into(), "SQL".into())],
            "a bare optional-value letter must not eat the next token"
        );
        assert_eq!(scan(&["-psecret"]), [("-p".into(), "secret".into())]);
    }

    #[test]
    fn long_forms_and_abbreviations() {
        assert_eq!(
            scan(&["--command=SQL"]),
            [("--command".into(), "SQL".into())]
        );
        assert_eq!(
            scan(&["--command", "SQL"]),
            [("--command".into(), "SQL".into())]
        );
        assert_eq!(scan(&["--comm", "SQL"]), [("--comm".into(), "SQL".into())]);
        assert!(OptionName::Long("comm").is('c', &["command"]));
    }

    #[test]
    fn double_dash_ends_option_scanning() {
        assert!(scan(&["--", "-c", "SQL"]).is_empty());
    }

    #[test]
    fn a_trailing_value_letter_with_no_operand_yields_nothing() {
        assert!(scan(&["-c"]).is_empty());
    }
}
