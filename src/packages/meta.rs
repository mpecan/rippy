//! Lazy-cached display metadata (`tagline`, `shield`) for built-in packages,
//! sourced from each package's embedded TOML `[meta]` section.
//!
//! This is the single source of truth for the strings shown by
//! `rippy profile list` / `rippy profile show`. `Package::name()` is
//! deliberately *not* routed through here — the enum variant is the
//! authoritative identity (`review`, `develop`, `autopilot`).
//!
//! See also [`super::custom::load_custom_package_from_path`], which performs
//! the same `[meta]` read for user-defined packages at discovery time. The
//! built-in path uses a `OnceLock` cache because the TOML source is static;
//! the custom path reads fresh because user files may change between runs.

use std::sync::OnceLock;

use super::Package;

/// Display metadata for a built-in package.
#[derive(Default)]
pub(super) struct BuiltinMeta {
    pub tagline: String,
    pub shield: String,
}

/// Parse the `[meta]` section out of a package's embedded TOML source.
///
/// Returns `BuiltinMeta::default()` (empty strings) if the TOML can't be
/// parsed or has no `[meta]` table. Embedded TOMLs can't fail at runtime
/// once the build succeeds; `builtin_meta_non_empty` (below) catches
/// accidental removal of `[meta]` in CI.
fn parse(source: &str) -> BuiltinMeta {
    toml::from_str::<crate::toml_config::TomlConfig>(source)
        .ok()
        .and_then(|c| c.meta)
        .map(|m| BuiltinMeta {
            tagline: m.tagline.unwrap_or_default(),
            shield: m.shield.unwrap_or_default(),
        })
        .unwrap_or_default()
}

/// Return the cached `BuiltinMeta` for a built-in package.
///
/// Each built-in variant has its own `OnceLock` so the embedded TOML is
/// parsed at most once per variant per process. The `Custom` arm returns
/// an empty default — `Package::tagline()` / `Package::shield()` never
/// route custom packages through here, but the fallback keeps this function
/// total in case a future caller does.
pub(super) fn builtin_meta(package: &Package) -> &'static BuiltinMeta {
    match package {
        Package::Review => {
            static M: OnceLock<BuiltinMeta> = OnceLock::new();
            M.get_or_init(|| parse(super::REVIEW_TOML))
        }
        Package::Develop => {
            static M: OnceLock<BuiltinMeta> = OnceLock::new();
            M.get_or_init(|| parse(super::DEVELOP_TOML))
        }
        Package::Autopilot => {
            static M: OnceLock<BuiltinMeta> = OnceLock::new();
            M.get_or_init(|| parse(super::AUTOPILOT_TOML))
        }
        Package::Custom(_) => {
            static EMPTY: OnceLock<BuiltinMeta> = OnceLock::new();
            EMPTY.get_or_init(BuiltinMeta::default)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::packages::package_toml;

    #[test]
    fn builtin_meta_matches_toml() {
        // The whole point of #118: `tagline()` / `shield()` must come from
        // the embedded TOML, not from a second hardcoded location. Parse
        // each TOML directly and confirm the runtime getter agrees.
        for pkg in Package::all() {
            let source = package_toml(pkg);
            let config: crate::toml_config::TomlConfig = toml::from_str(source).unwrap();
            let Some(meta) = config.meta else {
                panic!("built-in packages must have [meta] section");
            };

            assert_eq!(
                pkg.tagline(),
                meta.tagline.as_deref().unwrap_or(""),
                "{pkg} tagline should be sourced from [meta] tagline in TOML"
            );
            assert_eq!(
                pkg.shield(),
                meta.shield.as_deref().unwrap_or(""),
                "{pkg} shield should be sourced from [meta] shield in TOML"
            );
        }
    }

    #[test]
    fn builtin_meta_non_empty() {
        // Catches silent regressions where someone deletes `[meta]` from
        // a built-in TOML: the `OnceLock` fallback would return empty
        // strings without this assertion, and `rippy profile list` would
        // render blank.
        for pkg in Package::all() {
            assert!(
                !pkg.tagline().is_empty(),
                "{pkg} tagline must not be empty — [meta] tagline missing from TOML?"
            );
            assert!(
                !pkg.shield().is_empty(),
                "{pkg} shield must not be empty — [meta] shield missing from TOML?"
            );
        }
    }
}
