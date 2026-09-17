use crate::cst::CstNode;
use crate::ir::ConfigDocumentIr;
use crate::schema::PluginManifest;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("Failed to parse config: {0}")]
    Syntax(String),
}

#[derive(Debug, Error)]
pub enum BindError {
    #[error("Failed to bind CST to IR: {0}")]
    Mapping(String),
}

#[derive(Debug, Error)]
pub enum EditError {
    #[error("Row '{0}' not found")]
    RowNotFound(String),
    #[error("Field '{0}' not found in row '{1}'")]
    FieldNotFound(String, String),
    #[error("Invalid value for field '{field}': {message}")]
    InvalidValue { field: String, message: String },
    #[error("Edit operation unsupported: {0}")]
    Unsupported(String),
}

/// A semantic edit operation on the document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum EditOp {
    UpdateField {
        row_id: String,
        field_name: String,
        new_value: serde_json::Value,
    },
    DeleteRow {
        row_id: String,
    },
    InsertRow {
        after_row_id: Option<String>,
        fields: HashMap<String, serde_json::Value>,
    },
}

/// A format plugin capable of parsing raw text into a CST, binding CST to IR,
/// and applying semantic edits directly to the CST.
pub trait ConfigPlugin: Send + Sync {
    fn manifest(&self) -> &PluginManifest;
    fn parse(&self, text: &str) -> Result<CstNode, ParseError>;
    fn to_ir(&self, cst: &CstNode) -> Result<ConfigDocumentIr, BindError>;
    fn apply_edit(&self, cst: &mut CstNode, op: &EditOp) -> Result<(), EditError>;
}

/// An active in-memory configuration document.
pub struct ConfigDocument<'a> {
    plugin: &'a dyn ConfigPlugin,
    cst: CstNode,
}

impl<'a> ConfigDocument<'a> {
    pub fn parse(plugin: &'a dyn ConfigPlugin, text: &str) -> Result<Self, ParseError> {
        let cst = plugin.parse(text)?;
        Ok(Self { plugin, cst })
    }

    pub fn cst(&self) -> &CstNode {
        &self.cst
    }

    pub fn cst_mut(&mut self) -> &mut CstNode {
        &mut self.cst
    }

    pub fn to_ir(&self) -> Result<ConfigDocumentIr, BindError> {
        self.plugin.to_ir(&self.cst)
    }

    pub fn apply_edit(&mut self, op: &EditOp) -> Result<(), EditError> {
        self.plugin.apply_edit(&mut self.cst, op)
    }

    /// Serializes the CST back into the exact text format.
    pub fn serialize(&self) -> String {
        self.cst.to_string_lossless()
    }
}
