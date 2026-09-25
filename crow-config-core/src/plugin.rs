//! What a plugin is, what it can do, and what it needs.
//!
//! Plugins come in three kinds:
//!
//! - **config**: a file format (hosts, sshd_config, ...). Has a grammar.
//! - **provider**: talks to an outside service. Its `category` names the
//!   contract it implements (`provider.hosts`, `provider.dns`, ...), and its
//!   `capabilities` say which parts of that contract it supports.
//! - **module**: a bundle of functionality built on other plugins. It never
//!   names a specific provider; it declares `[[requires]]` on categories and
//!   capabilities, and it is active only while [`satisfies`] says so.
//!
//! ```toml
//! [plugin]
//! name = "paas"
//! kind = "module"
//!
//! [[requires]]
//! category = "provider.dns"
//! capabilities = ["records.write"]
//! min = 1
//! ```

use serde::{Deserialize, Serialize};

use crate::schema::PluginManifest;

/// The kind of a plugin. Manifests without one are `config` plugins.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginKind {
    #[default]
    Config,
    Provider,
    Module,
}

impl std::fmt::Display for PluginKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Config => "config",
            Self::Provider => "provider",
            Self::Module => "module",
        })
    }
}

/// Well-known categories and the capabilities each one defines. A category
/// is a contract: plugins in it implement the same interface, so anything
/// built on the category works with every one of them.
pub mod categories {
    /// File formats (hosts, sshd_config, pg_hba.conf, ufw rules).
    pub const CONFIG_FORMAT: &str = "config.format";
    /// Where servers come from (Linode, UpCloud, ...).
    pub const PROVIDER_HOSTS: &str = "provider.hosts";
    /// Where DNS records live (Cloudflare, Bunny.net, ...).
    pub const PROVIDER_DNS: &str = "provider.dns";

    /// Every well-known category with its capability vocabulary.
    pub const KNOWN: &[(&str, &[&str])] = &[
        (CONFIG_FORMAT, &[]),
        (PROVIDER_HOSTS, &["instances.list", "instances.power", "snapshots", "firewall.read"]),
        (PROVIDER_DNS, &["zones.list", "records.read", "records.write"]),
    ];

    /// The capabilities `category` defines, if it's a well-known one.
    pub fn capabilities(category: &str) -> Option<&'static [&'static str]> {
        KNOWN.iter().find(|(c, _)| *c == category).map(|(_, caps)| *caps)
    }
}

/// A module's need for plugins of one category.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Requirement {
    pub category: String,
    /// Capabilities a plugin must have all of to count.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// How many such plugins are needed.
    #[serde(default = "one")]
    pub min: u32,
}

fn one() -> u32 {
    1
}

impl Requirement {
    /// Whether `plugin` counts towards this requirement.
    pub fn accepts(&self, plugin: &PluginManifest) -> bool {
        plugin.plugin.category.as_deref() == Some(self.category.as_str())
            && self.capabilities.iter().all(|c| plugin.has_capability(c))
    }
}

/// A plugin in the right category that still doesn't count, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NearMiss {
    pub plugin: String,
    pub lacking: Vec<String>,
}

/// An unmet requirement: what was needed, how many were found, and which
/// plugins came close.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Missing {
    pub requirement: Requirement,
    pub found: u32,
    pub near_misses: Vec<NearMiss>,
}

impl std::fmt::Display for Missing {
    /// e.g. "needs 1 provider.dns plugin with records.write (found 0; bunny lacks records.write)"
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let r = &self.requirement;
        write!(f, "needs {} {} plugin{}", r.min, r.category, if r.min == 1 { "" } else { "s" })?;
        if !r.capabilities.is_empty() {
            write!(f, " with {}", r.capabilities.join(", "))?;
        }
        write!(f, " (found {}", self.found)?;
        for m in &self.near_misses {
            write!(f, "; {} lacks {}", m.plugin, m.lacking.join(", "))?;
        }
        write!(f, ")")
    }
}

/// Checks `requirements` against the plugins that are available (installed
/// and, where that matters to the host, configured). `Ok` means a module
/// with these requirements can run.
pub fn satisfies<'a>(requirements: &[Requirement], available: impl IntoIterator<Item = &'a PluginManifest> + Clone) -> Result<(), Vec<Missing>> {
    let missing: Vec<Missing> = requirements
        .iter()
        .filter_map(|r| {
            let in_category = available.clone().into_iter().filter(|p| p.plugin.category.as_deref() == Some(r.category.as_str()));
            let (mut found, mut near_misses) = (0, Vec::new());
            for p in in_category {
                let lacking: Vec<String> = r.capabilities.iter().filter(|c| !p.has_capability(c)).cloned().collect();
                if lacking.is_empty() {
                    found += 1;
                } else {
                    near_misses.push(NearMiss { plugin: p.plugin.name.clone(), lacking });
                }
            }
            (found < r.min).then(|| Missing { requirement: r.clone(), found, near_misses })
        })
        .collect();
    if missing.is_empty() { Ok(()) } else { Err(missing) }
}

/// Plugins from `known` (e.g. every plugin Crow ships) that would satisfy
/// `requirement`, for "install or configure one of these" hints.
pub fn candidates<'a>(requirement: &Requirement, known: impl IntoIterator<Item = &'a PluginManifest>) -> Vec<&'a str> {
    known.into_iter().filter(|p| requirement.accepts(p)).map(|p| p.plugin.name.as_str()).collect()
}

/// A problem with a manifest's plugin declaration.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    #[error("config plugin '{0}' needs a grammar")]
    MissingGrammar(String),
    #[error("provider plugin '{0}' needs a category")]
    MissingCategory(String),
    #[error("module '{0}' declares no requirements")]
    ModuleWithoutRequirements(String),
    #[error("only modules declare requirements, but '{0}' is a {1} plugin")]
    RequirementsOnNonModule(String, PluginKind),
    #[error("'{0}' isn't a valid category (lowercase words joined by dots, e.g. provider.dns)")]
    BadCategory(String),
    #[error("a requirement on {0} has min = 0, which is always met")]
    ZeroMin(String),
}

/// Lowercase ASCII words (letters, digits, `_`) joined by single dots.
pub fn is_valid_category(s: &str) -> bool {
    !s.is_empty() && s.split('.').all(|w| !w.is_empty() && w.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(toml: &str) -> PluginManifest {
        PluginManifest::from_toml_str(toml).unwrap()
    }

    fn provider(name: &str, category: &str, caps: &[&str]) -> PluginManifest {
        let caps = caps.iter().map(|c| format!("\"{c}\"")).collect::<Vec<_>>().join(", ");
        manifest(&format!("[plugin]\nname = \"{name}\"\nkind = \"provider\"\ncategory = \"{category}\"\ncapabilities = [{caps}]\n"))
    }

    fn paas() -> PluginManifest {
        manifest(
            r#"
[plugin]
name = "paas"
kind = "module"

[[requires]]
category = "provider.dns"
capabilities = ["records.write"]

[[requires]]
category = "provider.hosts"
capabilities = ["instances.list"]
min = 1
"#,
        )
    }

    #[test]
    fn old_manifests_are_config_plugins_without_a_category() {
        let m = manifest("[plugin]\nname = \"hosts\"\ngrammar = \"hosts-line-grammar\"\n\n[shape]\nkind = \"key_value_list\"\n");
        assert_eq!(m.plugin.kind, PluginKind::Config);
        assert_eq!(m.plugin.category, None);
        assert!(m.plugin.capabilities.is_empty() && m.requires.is_empty());
        assert_eq!(m.validate(), Ok(()));
    }

    #[test]
    fn a_module_is_satisfied_by_any_plugins_of_the_right_categories() {
        let module = paas();
        assert_eq!(module.validate(), Ok(()));
        assert_eq!(module.requires[0].min, 1, "min defaults to 1");
        let cloudflare = provider("cloudflare", "provider.dns", &["zones.list", "records.read", "records.write"]);
        let linode = provider("linode", "provider.hosts", &["instances.list", "instances.power", "snapshots"]);
        assert_eq!(satisfies(&module.requires, [&cloudflare, &linode]), Ok(()));
        let bunny = provider("bunny", "provider.dns", &["zones.list", "records.read", "records.write"]);
        let upcloud = provider("upcloud", "provider.hosts", &["instances.list", "instances.power"]);
        assert_eq!(satisfies(&module.requires, [&bunny, &upcloud]), Ok(()), "a different pair works just the same");
    }

    #[test]
    fn a_missing_category_is_reported() {
        let module = paas();
        let linode = provider("linode", "provider.hosts", &["instances.list"]);
        let missing = satisfies(&module.requires, [&linode]).unwrap_err();
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].requirement.category, "provider.dns");
        assert_eq!(missing[0].found, 0);
        assert_eq!(missing[0].to_string(), "needs 1 provider.dns plugin with records.write (found 0)");
    }

    #[test]
    fn a_plugin_lacking_the_capability_is_a_near_miss() {
        let module = paas();
        let read_only = provider("bunny", "provider.dns", &["zones.list", "records.read"]);
        let linode = provider("linode", "provider.hosts", &["instances.list"]);
        let missing = satisfies(&module.requires, [&read_only, &linode]).unwrap_err();
        assert_eq!(missing[0].near_misses, vec![NearMiss { plugin: "bunny".into(), lacking: vec!["records.write".into()] }]);
        assert_eq!(missing[0].to_string(), "needs 1 provider.dns plugin with records.write (found 0; bunny lacks records.write)");
    }

    #[test]
    fn min_counts_plugins() {
        let r = vec![Requirement { category: "provider.hosts".into(), capabilities: vec![], min: 2 }];
        let a = provider("linode", "provider.hosts", &[]);
        let b = provider("upcloud", "provider.hosts", &[]);
        assert_eq!(satisfies(&r, [&a]).unwrap_err()[0].found, 1);
        assert_eq!(satisfies(&r, [&a, &b]), Ok(()));
    }

    #[test]
    fn candidates_lists_plugins_that_would_do() {
        let module = paas();
        let known = [
            provider("cloudflare", "provider.dns", &["records.write"]),
            provider("readonly-dns", "provider.dns", &["records.read"]),
            provider("linode", "provider.hosts", &["instances.list"]),
        ];
        assert_eq!(candidates(&module.requires[0], &known), vec!["cloudflare"]);
    }

    #[test]
    fn declarations_are_validated() {
        let no_category = manifest("[plugin]\nname = \"x\"\nkind = \"provider\"\n");
        assert_eq!(no_category.validate(), Err(vec![ManifestError::MissingCategory("x".into())]));
        let no_grammar = manifest("[plugin]\nname = \"x\"\n");
        assert_eq!(no_grammar.validate(), Err(vec![ManifestError::MissingGrammar("x".into())]));
        let bare_module = manifest("[plugin]\nname = \"m\"\nkind = \"module\"\n");
        assert_eq!(bare_module.validate(), Err(vec![ManifestError::ModuleWithoutRequirements("m".into())]));
        let bad = manifest("[plugin]\nname = \"x\"\nkind = \"provider\"\ncategory = \"Provider..DNS\"\n\n[[requires]]\ncategory = \"provider.dns\"\nmin = 0\n");
        assert_eq!(
            bad.validate(),
            Err(vec![
                ManifestError::BadCategory("Provider..DNS".into()),
                ManifestError::RequirementsOnNonModule("x".into(), PluginKind::Provider),
                ManifestError::ZeroMin("provider.dns".into()),
            ])
        );
    }

    #[test]
    fn unknown_capabilities_are_flagged_but_allowed() {
        let p = provider("linode", "provider.hosts", &["instances.list", "teleport"]);
        assert_eq!(p.validate(), Ok(()));
        assert_eq!(p.unknown_capabilities(), vec!["teleport"]);
        let custom = provider("x", "provider.queue", &["anything"]);
        assert!(custom.unknown_capabilities().is_empty(), "no vocabulary to check a custom category against");
    }
}
