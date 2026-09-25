use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;

use crate::secret::SecretValue;
use crate::plugin::{categories, is_valid_category, ManifestError, PluginKind, Requirement};

/// High-level generic widget kinds that a config format can request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WidgetKind {
    RuleTable,
    KeyValueList,
    BlockTree,
    TogglePanel,
}

impl std::fmt::Display for WidgetKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RuleTable => write!(f, "rule_table"),
            Self::KeyValueList => write!(f, "key_value_list"),
            Self::BlockTree => write!(f, "block_tree"),
            Self::TogglePanel => write!(f, "toggle_panel"),
        }
    }
}

/// Primitive and semantic types for fields.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldType {
    IpAddress,
    String,
    StringList,
    Enum,
    Cidr,
    Bool,
    Path,
    Port,
    /// A whole number, optionally bounded by the field's `min` / `max`.
    Integer,
    /// A credential (API token, password). Its value never appears in IR,
    /// `Debug` output, serialized edits or error messages; see
    /// [`crate::secret`].
    Secret,
    #[serde(untagged)]
    Other(std::borrow::Cow<'static, str>),
}

/// Risk classification for enum options and configuration choices.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Recommended,
    Caution,
    Weak,
    NeverOnProd,
    Deny,
    #[serde(untagged)]
    Other(String),
}

/// An option for enum fields with human labels and risk metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnumOption {
    pub value: String,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk: Option<RiskLevel>,
}

/// Field definition within a plugin manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldDef {
    /// The field's key. Settings manifests may call it `key`.
    #[serde(alias = "key")]
    pub name: String,
    /// A human name for the field, where the key isn't one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(rename = "type")]
    pub field_type: FieldType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docs_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<EnumOption>>,
    /// Section a UI lists this field under (e.g. "Authentication"). Fields
    /// without one go under a catch-all section.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// The value the program uses when the field isn't set in the file, so
    /// a UI can show the effective setting (e.g. OpenSSH's defaults).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    /// Bounds for `integer` fields, inclusive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<i64>,
}

/// External validation command specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorDef {
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl ValidatorDef {
    /// Renders the validation command replacing template placeholders `{param}`.
    pub fn render_command(&self, params: &HashMap<String, String>) -> String {
        let mut cmd = self.command.clone();
        for (key, val) in params {
            let placeholder = format!("{{{}}}", key);
            cmd = cmd.replace(&placeholder, val);
        }
        cmd
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginMeta {
    pub name: String,
    /// How the plugin is named to people ("UpCloud" for `upcloud`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// The file grammar. Config plugins have one; providers and modules,
    /// whose settings live in the host app's store, don't.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grammar: Option<String>,
    #[serde(default)]
    pub kind: PluginKind,
    /// The contract the plugin implements (e.g. `provider.dns`); see
    /// [`crate::plugin::categories`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// Which parts of the category's contract the plugin supports. Hosts
    /// offer only the actions a plugin declares here.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
}

/// How a UI lays out the document. Settings manifests can leave it out and
/// get a plain key/value list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShapeMeta {
    pub kind: WidgetKind,
    #[serde(default)]
    pub order_sensitive: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order_note: Option<String>,
}

impl Default for ShapeMeta {
    fn default() -> Self {
        Self { kind: WidgetKind::KeyValueList, order_sensitive: false, order_note: None }
    }
}

/// A complete plugin manifest describing format schema, shape, and validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginManifest {
    pub plugin: PluginMeta,
    #[serde(default)]
    pub shape: ShapeMeta,
    /// The fields. Settings manifests (providers, modules) write them as
    /// `[[settings]]`.
    #[serde(default, alias = "settings")]
    pub fields: Vec<FieldDef>,
    #[serde(default)]
    pub validators: Vec<ValidatorDef>,
    /// What a module needs from other plugins; see [`crate::plugin::satisfies`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<Requirement>,
}

impl PluginManifest {
    pub fn from_toml_str(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }

    pub fn find_field(&self, name: &str) -> Option<&FieldDef> {
        self.fields.iter().find(|f| f.name == name)
    }

    /// The display name, else the plugin name.
    pub fn display_name(&self) -> &str {
        self.plugin.display_name.as_deref().unwrap_or(&self.plugin.name)
    }

    pub fn has_capability(&self, capability: &str) -> bool {
        self.plugin.capabilities.iter().any(|c| c == capability)
    }

    /// Checks the plugin declaration: kind, grammar, category, requirements.
    pub fn validate(&self) -> Result<(), Vec<ManifestError>> {
        let (name, meta) = (&self.plugin.name, &self.plugin);
        let mut errors = Vec::new();
        match meta.kind {
            PluginKind::Config if meta.grammar.is_none() => errors.push(ManifestError::MissingGrammar(name.clone())),
            PluginKind::Provider if meta.category.is_none() => errors.push(ManifestError::MissingCategory(name.clone())),
            PluginKind::Module if self.requires.is_empty() => errors.push(ManifestError::ModuleWithoutRequirements(name.clone())),
            _ => {}
        }
        if let Some(c) = meta.category.as_ref().filter(|c| !is_valid_category(c)) {
            errors.push(ManifestError::BadCategory(c.clone()));
        }
        if meta.kind != PluginKind::Module && !self.requires.is_empty() {
            errors.push(ManifestError::RequirementsOnNonModule(name.clone(), meta.kind));
        }
        errors.extend(self.requires.iter().filter(|r| r.min == 0).map(|r| ManifestError::ZeroMin(r.category.clone())));
        if errors.is_empty() { Ok(()) } else { Err(errors) }
    }

    /// Declared capabilities that the plugin's (well-known) category doesn't
    /// define. They're allowed, but usually a typo.
    pub fn unknown_capabilities(&self) -> Vec<&str> {
        let Some(known) = self.plugin.category.as_deref().and_then(categories::capabilities) else { return Vec::new() };
        self.plugin.capabilities.iter().map(String::as_str).filter(|c| !known.contains(c)).collect()
    }
}

/// Validates a secret. Error messages name the field, never the value.
pub fn validate_secret(field_def: &FieldDef, value: &SecretValue) -> Result<(), String> {
    check_secret(field_def, value.expose())
}

fn check_secret(field_def: &FieldDef, s: &str) -> Result<(), String> {
    if s.is_empty() && field_def.required == Some(true) {
        return Err(format!("Field '{}' can't be empty", field_def.name));
    }
    if s.chars().any(char::is_control) {
        return Err(format!("Field '{}' contains control characters (a stray line break?)", field_def.name));
    }
    Ok(())
}

/// Validates a candidate value against its field definition.
pub fn validate_field_value(field_def: &FieldDef, value: &serde_json::Value) -> Result<(), String> {
    if value.is_null() {
        if field_def.required == Some(true) {
            return Err(format!("Field '{}' is required", field_def.name));
        }
        return Ok(());
    }

    match &field_def.field_type {
        FieldType::IpAddress => {
            let s = value
                .as_str()
                .ok_or_else(|| format!("Field '{}' must be an IP address string", field_def.name))?;
            IpAddr::from_str(s)
                .map_err(|e| format!("Invalid IP address '{}': {}", s, e))?;
        }
        FieldType::Port => {
            let port_num = if let Some(n) = value.as_u64() {
                n
            } else if let Some(s) = value.as_str() {
                s.parse::<u64>()
                    .map_err(|_| format!("Invalid port number '{}'", s))?
            } else {
                return Err(format!("Field '{}' must be a port number", field_def.name));
            };
            if port_num == 0 || port_num > 65535 {
                return Err(format!("Port number {} is out of range (1-65535)", port_num));
            }
        }
        FieldType::Cidr => {
            let s = value
                .as_str()
                .ok_or_else(|| format!("Field '{}' must be a CIDR string", field_def.name))?;
            let parts: Vec<&str> = s.split('/').collect();
            if parts.len() != 2 {
                return Err(format!("Invalid CIDR format '{}', expected ip/prefix", s));
            }
            let ip = IpAddr::from_str(parts[0])
                .map_err(|e| format!("Invalid CIDR IP '{}': {}", parts[0], e))?;
            let prefix: u32 = parts[1]
                .parse()
                .map_err(|_| format!("Invalid CIDR prefix '{}'", parts[1]))?;
            let max_prefix = match ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            if prefix > max_prefix {
                return Err(format!("CIDR prefix /{} exceeds maximum /{}", prefix, max_prefix));
            }
        }
        FieldType::Bool => {
            if !value.is_boolean() {
                if let Some(s) = value.as_str() {
                    let s_lower = s.to_ascii_lowercase();
                    if !["yes", "no", "true", "false", "on", "off", "1", "0"].contains(&s_lower.as_str()) {
                        return Err(format!("Field '{}' must be a boolean", field_def.name));
                    }
                } else {
                    return Err(format!("Field '{}' must be a boolean", field_def.name));
                }
            }
        }
        FieldType::StringList => {
            let arr = value
                .as_array()
                .ok_or_else(|| format!("Field '{}' must be a list of strings", field_def.name))?;
            for item in arr {
                if !item.is_string() {
                    return Err(format!("Field '{}' items must be strings", field_def.name));
                }
            }
            if field_def.required == Some(true) && arr.is_empty() {
                return Err(format!("Field '{}' requires at least one entry", field_def.name));
            }
        }
        FieldType::Enum => {
            let s = value
                .as_str()
                .ok_or_else(|| format!("Field '{}' must be a string", field_def.name))?;
            if let Some(opts) = &field_def.options {
                if !opts.iter().any(|opt| opt.value == s) {
                    let valid_vals: Vec<&str> = opts.iter().map(|o| o.value.as_str()).collect();
                    return Err(format!(
                        "Invalid value '{}' for field '{}'. Allowed options: {:?}",
                        s, field_def.name, valid_vals
                    ));
                }
            }
        }
        FieldType::Integer => {
            let n = value
                .as_i64()
                .or_else(|| value.as_str().and_then(|s| s.trim().parse().ok()))
                .ok_or_else(|| format!("Field '{}' must be a whole number", field_def.name))?;
            if let Some(min) = field_def.min.filter(|m| n < *m) {
                return Err(format!("Field '{}' must be at least {min}", field_def.name));
            }
            if let Some(max) = field_def.max.filter(|m| n > *m) {
                return Err(format!("Field '{}' must be at most {max}", field_def.name));
            }
        }
        FieldType::Secret => {
            let s = value.as_str().ok_or_else(|| format!("Field '{}' must be text", field_def.name))?;
            check_secret(field_def, s)?;
        }
        FieldType::String | FieldType::Path | FieldType::Other(_) => {
            if !value.is_string() {
                return Err(format!("Field '{}' must be a string", field_def.name));
            }
        }
    }

    Ok(())
}
