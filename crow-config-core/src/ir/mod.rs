use crate::cst::SourceSpan;
use crate::schema::{EnumOption, FieldType, WidgetKind};
use serde::{Deserialize, Serialize};

/// The full document View-Binding IR emitted by the engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfigDocumentIr {
    pub plugin_name: String,
    pub shape: ShapeIr,
    pub rows: Vec<RowIr>,
}

/// Shape metadata attached to the IR to inform generic UI renderers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShapeIr {
    pub kind: WidgetKind,
    pub order_sensitive: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order_note: Option<String>,
}

/// A single row in the View-Binding IR.
///
/// Matches the schema required by generic UI renderers:
/// ```json
/// {
///   "row_id": "line-4",
///   "widget": "key_value_list_row",
///   "fields": [
///     { "name": "address", "value": "10.0.4.12", "type": "ip_address", "valid": true },
///     { "name": "hostnames", "value": ["db-primary-01.internal", "db-primary-01"], "type": "string_list" },
///     { "name": "comment", "value": "primary postgres", "type": "string" }
///   ],
///   "source_span": { "start_line": 4, "end_line": 4 }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RowIr {
    pub row_id: String,
    pub widget: String,
    pub fields: Vec<FieldIr>,
    pub source_span: SourceSpan,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_comment_only: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_blank: Option<bool>,
}

impl RowIr {
    pub fn new(row_id: impl Into<String>, widget: impl Into<String>, span: SourceSpan) -> Self {
        Self {
            row_id: row_id.into(),
            widget: widget.into(),
            fields: Vec::new(),
            source_span: span,
            is_comment_only: None,
            is_blank: None,
        }
    }

    pub fn get_field(&self, name: &str) -> Option<&FieldIr> {
        self.fields.iter().find(|f| f.name == name)
    }

    pub fn get_field_mut(&mut self, name: &str) -> Option<&mut FieldIr> {
        self.fields.iter_mut().find(|f| f.name == name)
    }
}

/// A typed field value with optional validation state and metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FieldIr {
    pub name: String,
    pub value: serde_json::Value,
    #[serde(rename = "type")]
    pub field_type: FieldType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<EnumOption>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docs_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help: Option<String>,
}

impl FieldIr {
    pub fn new(name: impl Into<String>, field_type: FieldType, value: serde_json::Value) -> Self {
        Self {
            name: name.into(),
            field_type,
            value,
            valid: None,
            validation_error: None,
            options: None,
            docs_source: None,
            help: None,
        }
    }

    pub fn with_validity(mut self, valid: bool) -> Self {
        self.valid = Some(valid);
        self
    }

    pub fn with_error(mut self, err: impl Into<String>) -> Self {
        self.valid = Some(false);
        self.validation_error = Some(err.into());
        self
    }
}
