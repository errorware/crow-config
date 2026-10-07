//! INI files: `[section]` headers and `key = value` lines (my.cnf and its
//! conf.d files, smb.conf, php.ini, …). The grammar is systemd's (comments
//! with `#` or `;`, values continued with `\`), without its unit-key help.
//! Lines that aren't `key = value` (flags like `skip-name-resolve`,
//! `!includedir`) are kept as text.

use crow_config_core::cst::CstNode;
use crow_config_core::edit::{BindError, ConfigPlugin, EditError, EditOp, ParseError};
use crow_config_core::ir::ConfigDocumentIr;
use crow_config_core::schema::PluginManifest;
use std::sync::LazyLock;

use crate::systemd::SystemdPlugin;

pub const INI_MANIFEST_TOML: &str = include_str!("../../plugins/ini.toml");

pub static INI_MANIFEST: LazyLock<PluginManifest> = LazyLock::new(|| PluginManifest::from_toml_str(INI_MANIFEST_TOML).expect("Failed to parse embedded ini.toml manifest"));

/// Lossless parser and plugin for INI files.
#[derive(Debug, Clone)]
pub struct IniPlugin {
    manifest: &'static PluginManifest,
    grammar: SystemdPlugin,
}

impl IniPlugin {
    pub fn new() -> Self {
        Self { manifest: &INI_MANIFEST, grammar: SystemdPlugin::new() }
    }
}

impl Default for IniPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigPlugin for IniPlugin {
    fn manifest(&self) -> &PluginManifest {
        self.manifest
    }

    fn parse(&self, text: &str) -> Result<CstNode, ParseError> {
        self.grammar.parse(text)
    }

    fn to_ir(&self, cst: &CstNode) -> Result<ConfigDocumentIr, BindError> {
        let mut ir = self.grammar.to_ir(cst)?;
        // systemd's key help means nothing in a my.cnf.
        for f in ir.rows.iter_mut().flat_map(|r| r.fields.iter_mut()) {
            f.help = None;
            f.options = None;
        }
        ir.plugin_name = self.manifest.plugin.name.clone();
        ir.shape.order_sensitive = self.manifest.shape.order_sensitive;
        ir.shape.order_note = self.manifest.shape.order_note.clone();
        Ok(ir)
    }

    fn apply_edit(&self, cst: &mut CstNode, op: &EditOp) -> Result<(), EditError> {
        self.grammar.apply_edit(cst, op)
    }
}
