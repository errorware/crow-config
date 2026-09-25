//! Settings that live in the host app's store instead of a file.
//!
//! A provider's API token or default region has no config file behind it.
//! The same manifest fields (types, options, `default`, `group`, `help`)
//! describe it, and a [`SettingsDocument`] turns them into the same
//! [`ConfigDocumentIr`] a file produces, so one renderer shows both.
//!
//! The core does no I/O. The host hands in the stored values, applies
//! [`SettingsEdit`]s, and persists each validated [`SettingsChange`] that
//! comes back. Secrets are never held: the document only knows whether one
//! is set, and a [`SettingsChange::StoreSecret`] carries the value straight
//! to the host's vault.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::Value;

use crate::cst::SourceSpan;
use crate::edit::{EditError, EditOp};
use crate::ir::{ConfigDocumentIr, FieldIr, RowIr, ShapeIr};
use crate::schema::{validate_field_value, validate_secret, FieldDef, FieldType, PluginManifest};
use crate::secret::{secret_state, SecretValue};

/// The IR widget name of a settings row.
pub const SETTING_WIDGET: &str = "setting";

/// An edit requested by a UI.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum SettingsEdit {
    Set { key: String, value: Value },
    Unset { key: String },
    SetSecret { key: String, value: SecretValue },
    ClearSecret { key: String },
}

/// A validated change for the host to persist.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum SettingsChange {
    /// Store `value` under `key`.
    Set { key: String, value: Value },
    /// Remove `key`; the field falls back to its default.
    Unset { key: String },
    /// Put `value` in the vault under `key`. Never write it anywhere else.
    StoreSecret { key: String, value: SecretValue },
    /// Remove the secret under `key` from the vault.
    DeleteSecret { key: String },
}

/// A plugin's settings, bound to values the host supplied.
#[derive(Debug, Clone)]
pub struct SettingsDocument<'m> {
    manifest: &'m PluginManifest,
    values: BTreeMap<String, Value>,
    secrets_set: BTreeSet<String>,
}

impl<'m> SettingsDocument<'m> {
    /// Binds `manifest` to stored `values` and the keys of the secrets the
    /// vault holds. Keys the manifest doesn't define are ignored (stale
    /// settings from an older plugin version), and so is any value handed in
    /// for a secret field, beyond noting that it's set.
    pub fn new(manifest: &'m PluginManifest, values: impl IntoIterator<Item = (String, Value)>, secrets_set: impl IntoIterator<Item = String>) -> Self {
        let mut doc = Self { manifest, values: BTreeMap::new(), secrets_set: BTreeSet::new() };
        for key in secrets_set {
            if doc.field(&key).is_some_and(is_secret) {
                doc.secrets_set.insert(key);
            }
        }
        for (key, value) in values {
            match doc.field(&key) {
                Some(def) if is_secret(def) => {
                    doc.secrets_set.insert(key);
                }
                Some(_) if !value.is_null() => {
                    doc.values.insert(key, value);
                }
                _ => {}
            }
        }
        doc
    }

    pub fn manifest(&self) -> &'m PluginManifest {
        self.manifest
    }

    fn field(&self, key: &str) -> Option<&'m FieldDef> {
        self.manifest.find_field(key)
    }

    /// The stored value of a plain field, if set.
    pub fn value(&self, key: &str) -> Option<&Value> {
        self.values.get(key)
    }

    /// The value in effect: the stored one, else the manifest's default.
    pub fn effective(&self, key: &str) -> Option<Value> {
        self.values.get(key).cloned().or_else(|| self.field(key)?.default.clone().map(Value::String))
    }

    pub fn is_secret_set(&self, key: &str) -> bool {
        self.secrets_set.contains(key)
    }

    /// Required fields with no value, stored or default. Empty means the
    /// plugin is fully configured.
    pub fn missing_required(&self) -> Vec<&'m str> {
        self.manifest
            .fields
            .iter()
            .filter(|f| f.required == Some(true))
            .filter(|f| if is_secret(f) { !self.is_secret_set(&f.name) } else { self.effective(&f.name).is_none() })
            .map(|f| f.name.as_str())
            .collect()
    }

    /// One row per field, in manifest order. Secret fields carry
    /// `{"set": bool}` instead of a value.
    pub fn to_ir(&self) -> ConfigDocumentIr {
        let rows = self
            .manifest
            .fields
            .iter()
            .enumerate()
            .map(|(i, def)| {
                let mut row = RowIr::new(def.name.clone(), SETTING_WIDGET, SourceSpan::new(i + 1, i + 1));
                let value = if is_secret(def) { secret_state(self.is_secret_set(&def.name)) } else { self.values.get(&def.name).cloned().unwrap_or(Value::Null) };
                let mut field = FieldIr::new(def.name.clone(), def.field_type.clone(), value.clone());
                field.options = def.options.clone();
                field.help = def.help.clone();
                field.docs_source = def.docs_source.clone();
                if !is_secret(def) && !value.is_null() {
                    field = match validate_field_value(def, &value) {
                        Ok(()) => field.with_validity(true),
                        Err(e) => field.with_error(e),
                    };
                }
                row.fields.push(field);
                row
            })
            .collect();
        ConfigDocumentIr {
            plugin_name: self.manifest.plugin.name.clone(),
            shape: ShapeIr { kind: self.manifest.shape.kind, order_sensitive: self.manifest.shape.order_sensitive, order_note: self.manifest.shape.order_note.clone() },
            rows,
        }
    }

    /// Validates `edit`, updates the document, and returns the change to
    /// persist. On error nothing changes.
    pub fn apply(&mut self, edit: SettingsEdit) -> Result<SettingsChange, EditError> {
        let manifest = self.manifest;
        let key = match &edit {
            SettingsEdit::Set { key, .. } | SettingsEdit::Unset { key } | SettingsEdit::SetSecret { key, .. } | SettingsEdit::ClearSecret { key } => key.clone(),
        };
        let def = self.field(&key).ok_or_else(|| EditError::FieldNotFound(key.clone(), manifest.plugin.name.clone()))?;
        match (edit, is_secret(def)) {
            (SettingsEdit::Set { value, .. }, false) if value.is_null() => self.apply(SettingsEdit::Unset { key }),
            (SettingsEdit::Set { value, .. }, false) => {
                validate_field_value(def, &value).map_err(|message| EditError::InvalidValue { field: key.clone(), message })?;
                self.values.insert(key.clone(), value.clone());
                Ok(SettingsChange::Set { key, value })
            }
            (SettingsEdit::Unset { .. }, false) => {
                if def.required == Some(true) && def.default.is_none() {
                    return Err(EditError::InvalidValue { field: key, message: "is required and has no default".into() });
                }
                self.values.remove(&key);
                Ok(SettingsChange::Unset { key })
            }
            (SettingsEdit::SetSecret { value, .. }, true) => {
                validate_secret(def, &value).map_err(|message| EditError::InvalidValue { field: key.clone(), message })?;
                self.secrets_set.insert(key.clone());
                Ok(SettingsChange::StoreSecret { key, value })
            }
            (SettingsEdit::ClearSecret { .. } | SettingsEdit::Unset { .. }, true) => {
                if def.required == Some(true) {
                    return Err(EditError::InvalidValue { field: key, message: "is required; replace it instead of clearing it".into() });
                }
                self.secrets_set.remove(&key);
                Ok(SettingsChange::DeleteSecret { key })
            }
            (SettingsEdit::Set { .. }, true) => Err(EditError::Unsupported(format!("'{key}' is a secret; set it with SetSecret so the value never passes through plain JSON"))),
            (SettingsEdit::SetSecret { .. } | SettingsEdit::ClearSecret { .. }, false) => Err(EditError::Unsupported(format!("'{key}' isn't a secret field"))),
        }
    }

    /// Applies a generic [`EditOp`], so a renderer written for file
    /// documents works here too. Rows are keyed by field name:
    /// `UpdateField` sets, `DeleteRow` unsets; rows can't be inserted or
    /// moved. Secret fields refuse `UpdateField`, since its value is plain JSON.
    pub fn apply_op(&mut self, op: &EditOp) -> Result<SettingsChange, EditError> {
        match op {
            EditOp::UpdateField { row_id, field_name, new_value } => {
                if row_id != field_name {
                    return Err(EditError::FieldNotFound(field_name.clone(), row_id.clone()));
                }
                self.apply(SettingsEdit::Set { key: row_id.clone(), value: new_value.clone() })
            }
            EditOp::DeleteRow { row_id } => self.apply(SettingsEdit::Unset { key: row_id.clone() }),
            EditOp::InsertRow { .. } | EditOp::MoveRow { .. } => Err(EditError::Unsupported("settings have one row per field; rows can't be added or moved".into())),
        }
    }
}

fn is_secret(def: &FieldDef) -> bool {
    def.field_type == FieldType::Secret
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const LINODE: &str = r#"
[plugin]
name = "linode"
kind = "provider"
category = "provider.hosts"
capabilities = ["instances.list", "instances.power", "snapshots"]

[[settings]]
key = "api_token"
label = "API token"
type = "secret"
required = true
help = "A personal access token with Linodes read/write."

[[settings]]
key = "default_region"
label = "Default region"
type = "string"
default = "eu-central"

[[settings]]
key = "page_size"
type = "port"
"#;

    fn manifest() -> PluginManifest {
        PluginManifest::from_toml_str(LINODE).unwrap()
    }

    #[test]
    fn a_settings_only_manifest_parses_without_grammar_or_shape() {
        let m = manifest();
        assert_eq!(m.validate(), Ok(()));
        assert_eq!(m.plugin.grammar, None);
        assert_eq!(m.shape.kind, crate::schema::WidgetKind::KeyValueList);
        let token = m.find_field("api_token").unwrap();
        assert_eq!((token.label.as_deref(), &token.field_type), (Some("API token"), &FieldType::Secret));
    }

    #[test]
    fn renders_one_row_per_setting_with_secret_state_not_value() {
        let m = manifest();
        let doc = SettingsDocument::new(&m, [("page_size".to_string(), json!(100))], ["api_token".to_string()]);
        let ir = doc.to_ir();
        assert_eq!(ir.rows.iter().map(|r| r.row_id.as_str()).collect::<Vec<_>>(), ["api_token", "default_region", "page_size"]);
        assert_eq!(ir.rows[0].fields[0].value, json!({"set": true}));
        assert_eq!(ir.rows[1].fields[0].value, Value::Null, "unset: the renderer shows the default");
        assert_eq!(doc.effective("default_region"), Some(json!("eu-central")));
        assert_eq!(ir.rows[2].fields[0].valid, Some(true));
        assert!(doc.missing_required().is_empty());
    }

    #[test]
    fn edits_are_validated_and_returned_for_the_host_to_store() {
        let m = manifest();
        let mut doc = SettingsDocument::new(&m, [], []);
        assert_eq!(doc.missing_required(), vec!["api_token"]);

        let change = doc.apply(SettingsEdit::Set { key: "default_region".into(), value: json!("us-east") }).unwrap();
        assert_eq!(change, SettingsChange::Set { key: "default_region".into(), value: json!("us-east") });
        assert_eq!(doc.value("default_region"), Some(&json!("us-east")));

        let bad = doc.apply(SettingsEdit::Set { key: "page_size".into(), value: json!(70000) }).unwrap_err();
        assert!(matches!(bad, EditError::InvalidValue { .. }), "{bad}");
        assert_eq!(doc.value("page_size"), None, "a rejected edit changes nothing");

        assert_eq!(doc.apply(SettingsEdit::Unset { key: "default_region".into() }).unwrap(), SettingsChange::Unset { key: "default_region".into() });
        assert!(matches!(doc.apply(SettingsEdit::Set { key: "nope".into(), value: json!(1) }), Err(EditError::FieldNotFound(..))));
    }

    #[test]
    fn generic_edit_ops_work_like_on_a_file() {
        let m = manifest();
        let mut doc = SettingsDocument::new(&m, [], []);
        let op = EditOp::UpdateField { row_id: "default_region".into(), field_name: "default_region".into(), new_value: json!("ap-south") };
        assert_eq!(doc.apply_op(&op).unwrap(), SettingsChange::Set { key: "default_region".into(), value: json!("ap-south") });
        assert!(matches!(doc.apply_op(&EditOp::InsertRow { after_row_id: None, fields: Default::default() }), Err(EditError::Unsupported(_))));
    }

    #[test]
    fn secrets_go_to_the_vault_and_nowhere_else() {
        let m = manifest();
        let mut doc = SettingsDocument::new(&m, [], []);
        let token = "lin-SECRET-9f8e7d";

        // Plain JSON can't carry a secret in.
        let err = doc.apply(SettingsEdit::Set { key: "api_token".into(), value: json!(token) }).unwrap_err();
        assert!(!err.to_string().contains(token));
        let op = EditOp::UpdateField { row_id: "api_token".into(), field_name: "api_token".into(), new_value: json!(token) };
        assert!(doc.apply_op(&op).is_err());
        assert!(!doc.is_secret_set("api_token"));

        let edit = SettingsEdit::SetSecret { key: "api_token".into(), value: SecretValue::new(token) };
        let change = doc.apply(edit.clone()).unwrap();
        let SettingsChange::StoreSecret { value, .. } = &change else { panic!("expected StoreSecret, got {change:?}") };
        assert_eq!(value.expose(), token, "the host gets the value to put in its vault");
        assert!(doc.is_secret_set("api_token"));

        // Nothing the host might log, serialize or render contains it.
        let ir = doc.to_ir();
        let surfaces = [
            format!("{edit:?}"),
            format!("{change:?}"),
            serde_json::to_string(&edit).unwrap(),
            serde_json::to_string(&change).unwrap(),
            format!("{doc:?}"),
            format!("{ir:?}"),
            serde_json::to_string(&ir).unwrap(),
        ];
        for s in &surfaces {
            assert!(!s.contains(token), "secret leaked into: {s}");
        }

        // Bad secrets are rejected without echoing them.
        let bad = doc.apply(SettingsEdit::SetSecret { key: "api_token".into(), value: SecretValue::new("abc\ndef-SECRET") }).unwrap_err();
        assert!(!bad.to_string().contains("SECRET"), "{bad}");
        // A required secret can be replaced, not cleared.
        assert!(doc.apply(SettingsEdit::ClearSecret { key: "api_token".into() }).is_err());
    }

    #[test]
    fn stale_keys_and_stray_secret_values_are_dropped_on_load() {
        let m = manifest();
        let doc = SettingsDocument::new(&m, [("old_key".to_string(), json!("x")), ("api_token".to_string(), json!("leaked-into-plain-store"))], []);
        assert_eq!(doc.value("old_key"), None);
        assert!(doc.is_secret_set("api_token"));
        assert!(!format!("{doc:?}").contains("leaked-into-plain-store"));
    }
}
