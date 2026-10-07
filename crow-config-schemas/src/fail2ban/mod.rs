//! fail2ban's jail files (jail.local, jail.d/*.local): INI where an indented
//! line continues the value above it (logpath, ignoreip, action lists). The
//! grammar is systemd's in that mode; values on several lines are edited in
//! the text view, where their line breaks stay as written.

use crow_config_core::cst::{CstNode, Span, SyntaxKind};
use crow_config_core::edit::{BindError, ConfigPlugin, EditError, EditOp, ParseError};
use crow_config_core::ir::ConfigDocumentIr;
use crow_config_core::schema::{EnumOption, PluginManifest, RiskLevel};
use std::sync::LazyLock;

use crate::systemd::{parse_indented_cst, SystemdPlugin};

pub const FAIL2BAN_MANIFEST_TOML: &str = include_str!("../../plugins/fail2ban.toml");

pub static FAIL2BAN_MANIFEST: LazyLock<PluginManifest> = LazyLock::new(|| PluginManifest::from_toml_str(FAIL2BAN_MANIFEST_TOML).expect("Failed to parse embedded fail2ban.toml manifest"));

type Values = &'static [(&'static str, &'static str, Option<RiskLevel>)];
const TRUE_FALSE: Values = &[("true", "on", None), ("false", "off", None)];

/// The keys a jail usually sets, in the order they're offered: what each
/// does, and its values when it takes a few fixed ones.
const KEYS: &[(&str, &str, Values)] = &[
    ("enabled", "Turns this jail on.", TRUE_FALSE),
    ("port", "The ports banned addresses are blocked on (ssh, http,https, 2222…).", &[]),
    ("filter", "The filter in filter.d that finds failures in the log (the jail's name by default).", &[]),
    ("logpath", "The log files the filter reads (one per line).", &[]),
    (
        "backend",
        "How log changes are noticed.",
        &[("auto", "pick one that works (default)", None), ("systemd", "read the journal instead of files", None), ("pyinotify", "inotify on the files", None), ("polling", "check the files on a timer", None)],
    ),
    ("maxretry", "Failures allowed within findtime before a ban.", &[]),
    ("findtime", "The window failures are counted in (e.g. 10m).", &[]),
    ("bantime", "How long a ban lasts (e.g. 1h; -1 bans for good).", &[]),
    ("bantime.increment", "Bans repeat offenders for longer each time.", TRUE_FALSE),
    ("ignoreip", "Addresses and networks never banned (keep your own here).", &[]),
    ("banaction", "The firewall action that does the banning (iptables-multiport, nftables, ufw, firewallcmd-ipset…).", &[]),
    ("action", "What a ban does (ban only, or ban and mail).", &[]),
    ("destemail", "Where ban mails go, with a mail action.", &[]),
];

/// Keys to suggest for a new line in a jail: (key, what it does, a
/// starting value). [INCLUDES] takes only before/after.
pub fn suggested_keys(section: &str) -> Vec<(&'static str, &'static str, &'static str)> {
    if section.eq_ignore_ascii_case("INCLUDES") {
        return Vec::new();
    }
    KEYS.iter().map(|(k, h, v)| (*k, *h, v.first().map_or("", |o| o.0))).collect()
}

/// Lossless parser and plugin for fail2ban jail files.
#[derive(Debug, Clone)]
pub struct Fail2banPlugin {
    manifest: &'static PluginManifest,
    grammar: SystemdPlugin,
}

impl Fail2banPlugin {
    pub fn new() -> Self {
        Self { manifest: &FAIL2BAN_MANIFEST, grammar: SystemdPlugin::new() }
    }
}

impl Default for Fail2banPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigPlugin for Fail2banPlugin {
    fn manifest(&self) -> &PluginManifest {
        self.manifest
    }

    fn parse(&self, text: &str) -> Result<CstNode, ParseError> {
        Ok(CstNode::rule(SyntaxKind::Document, parse_indented_cst(text), Span::new(0, text.len())))
    }

    fn to_ir(&self, cst: &CstNode) -> Result<ConfigDocumentIr, BindError> {
        let mut ir = self.grammar.to_ir(cst)?;
        for row in &mut ir.rows {
            let multi_line = row.fields.iter().any(|f| f.value.as_str().is_some_and(|v| v.contains('\n')));
            for f in &mut row.fields {
                f.help = None;
                f.options = None;
                if let Some((_, help, values)) = KEYS.iter().find(|(k, _, _)| *k == f.name) {
                    f.help = Some(help.to_string());
                    if !values.is_empty() {
                        f.options = Some(values.iter().map(|(v, l, r)| EnumOption { value: v.to_string(), label: l.to_string(), risk: r.clone() }).collect());
                    }
                }
            }
            if multi_line && row.widget != "scope_row" {
                // The structured editor locks these; the text view keeps the line breaks.
                row.widget = "script_row".into();
                if let Some(f) = row.fields.first_mut() {
                    f.help = Some("On several lines: edited in the text view.".into());
                }
            }
        }
        ir.plugin_name = self.manifest.plugin.name.clone();
        ir.shape.order_sensitive = self.manifest.shape.order_sensitive;
        ir.shape.order_note = self.manifest.shape.order_note.clone();
        Ok(ir)
    }

    fn apply_edit(&self, cst: &mut CstNode, op: &EditOp) -> Result<(), EditError> {
        if let EditOp::UpdateField { row_id, .. } = op {
            let ir = self.to_ir(cst).map_err(|e| EditError::Unsupported(e.to_string()))?;
            if ir.rows.iter().any(|r| &r.row_id == row_id && r.widget == "script_row") {
                return Err(EditError::Unsupported("this value is on several lines; edit it in the text view".into()));
            }
        }
        self.grammar.apply_edit(cst, op)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crow_config_core::edit::ConfigDocument;

    const JAIL: &str = "[DEFAULT]\nbantime = 1h\nignoreip = 127.0.0.1/8\n           10.0.0.0/8\n\n[sshd]\nenabled = true\nport    = ssh\nlogpath = %(sshd_log)s\n  # not part of the value\nbackend = systemd\n";

    #[test]
    fn indented_lines_continue_the_value_and_round_trip() {
        let plugin = Fail2banPlugin::new();
        let mut doc = ConfigDocument::parse(&plugin, JAIL).unwrap();
        assert_eq!(doc.serialize(), JAIL);
        let ir = doc.to_ir().unwrap();
        let row = |name: &str| ir.rows.iter().find(|r| r.fields[0].name == name).unwrap().clone();
        assert_eq!(row("ignoreip").widget, "script_row");
        assert_eq!(row("enabled").fields[0].options.as_ref().map(|o| o.len()), Some(2));
        assert_eq!(row("backend").scope.as_deref(), Some("sshd"));
        assert!(doc.apply_edit(&EditOp::UpdateField { row_id: row("ignoreip").row_id, field_name: "ignoreip".into(), new_value: serde_json::json!("1.2.3.4") }).is_err());
        doc.apply_edit(&EditOp::UpdateField { row_id: row("bantime").row_id, field_name: "bantime".into(), new_value: serde_json::json!("2h") }).unwrap();
        doc.apply_edit(&EditOp::UpdateField { row_id: row("backend").row_id, field_name: "backend".into(), new_value: serde_json::json!("auto") }).unwrap();
        assert_eq!(doc.serialize(), JAIL.replace("bantime = 1h", "bantime = 2h").replace("backend = systemd", "backend = auto"));
    }

    #[test]
    fn includes_take_no_suggestions() {
        assert!(suggested_keys("INCLUDES").is_empty());
        assert_eq!(suggested_keys("sshd")[0], ("enabled", "Turns this jail on.", "true"));
    }
}
