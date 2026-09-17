use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;

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
    pub name: String,
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
    pub grammar: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShapeMeta {
    pub kind: WidgetKind,
    #[serde(default)]
    pub order_sensitive: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order_note: Option<String>,
}

/// A complete plugin manifest describing format schema, shape, and validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginManifest {
    pub plugin: PluginMeta,
    pub shape: ShapeMeta,
    #[serde(default)]
    pub fields: Vec<FieldDef>,
    #[serde(default)]
    pub validators: Vec<ValidatorDef>,
}

impl PluginManifest {
    pub fn from_toml_str(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }

    pub fn find_field(&self, name: &str) -> Option<&FieldDef> {
        self.fields.iter().find(|f| f.name == name)
    }
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
        FieldType::String | FieldType::Path | FieldType::Other(_) => {
            if !value.is_string() {
                return Err(format!("Field '{}' must be a string", field_def.name));
            }
        }
    }

    Ok(())
}
