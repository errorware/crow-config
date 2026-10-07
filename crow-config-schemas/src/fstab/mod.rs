//! `/etc/fstab`: one mount per line, six whitespace-separated fields
//! (device, mount point, type, options, dump, pass; the last two optional).
//! `#` starts a comment line.

use crow_config_core::cst::{CstNode, SourceSpan, Span, SyntaxKind};
use crow_config_core::edit::{BindError, ConfigPlugin, EditError, EditOp, ParseError};
use crow_config_core::ir::{ConfigDocumentIr, FieldIr, RowIr, ShapeIr};
use crow_config_core::schema::{FieldType, PluginManifest};
use std::sync::LazyLock;

pub const FSTAB_MANIFEST_TOML: &str = include_str!("../../plugins/fstab.toml");

pub static FSTAB_MANIFEST: LazyLock<PluginManifest> =
    LazyLock::new(|| PluginManifest::from_toml_str(FSTAB_MANIFEST_TOML).expect("Failed to parse embedded fstab.toml manifest"));

/// The fields, in the order they're written.
pub const FIELDS: [&str; 6] = ["device", "mountpoint", "type", "options", "dump", "pass"];

/// Lossless parser and plugin for `/etc/fstab`.
#[derive(Debug, Clone)]
pub struct FstabPlugin {
    manifest: &'static PluginManifest,
}

impl FstabPlugin {
    pub fn new() -> Self {
        Self { manifest: &FSTAB_MANIFEST }
    }
}

impl Default for FstabPlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// One mount, as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    pub device: String,
    pub mountpoint: String,
    pub fstype: String,
    pub options: Vec<String>,
}

impl Mount {
    pub fn has_option(&self, name: &str) -> bool {
        self.options.iter().any(|o| o == name)
    }
}

/// The mounts in an fstab, in order.
pub fn mounts(text: &str) -> Vec<Mount> {
    parse_fstab_cst(text)
        .iter()
        .filter(|n| n.kind() == &SyntaxKind::Entry)
        .map(|n| {
            let f = |name: &str| field_text(n, name).unwrap_or_default().to_string();
            Mount { device: f("device"), mountpoint: f("mountpoint"), fstype: f("type"), options: f("options").split(',').map(str::to_string).collect() }
        })
        .collect()
}

/// Why a mount can stop a boot, if it can: systemd waits for every mount
/// that isn't `nofail` (or `noauto`), and drops to emergency mode when one
/// fails. Network filesystems also need the network first (`_netdev`).
/// `all` is the whole file: a mount from the same device as `/` (another
/// btrfs subvolume, say) can't go missing on its own, so it isn't flagged.
pub fn boot_risk(m: &Mount, all: &[Mount]) -> Option<&'static str> {
    const ESSENTIAL: [&str; 5] = ["/", "/boot", "/boot/efi", "/usr", "/var"];
    const VIRTUAL: [&str; 7] = ["swap", "proc", "sysfs", "tmpfs", "devpts", "devtmpfs", "none"];
    const NETWORK: [&str; 7] = ["nfs", "nfs4", "cifs", "smbfs", "sshfs", "fuse.sshfs", "glusterfs"];
    if m.has_option("noauto") || ESSENTIAL.contains(&m.mountpoint.as_str()) || VIRTUAL.contains(&m.fstype.as_str()) {
        return None;
    }
    if all.iter().any(|o| o.mountpoint == "/" && o.device == m.device) {
        return None;
    }
    let network = NETWORK.contains(&m.fstype.as_str()) || m.device.starts_with("//") || m.device.contains(":/");
    match (network, m.has_option("nofail"), m.has_option("_netdev")) {
        (true, _, false) => Some("a network mount without _netdev: the boot may try it before the network is up"),
        (_, false, _) => Some("without nofail, the server stops booting (emergency mode) if this device is missing"),
        _ => None,
    }
}

impl ConfigPlugin for FstabPlugin {
    fn manifest(&self) -> &PluginManifest {
        self.manifest
    }

    fn parse(&self, text: &str) -> Result<CstNode, ParseError> {
        Ok(CstNode::rule(SyntaxKind::Document, parse_fstab_cst(text), Span::new(0, text.len())))
    }

    fn to_ir(&self, cst: &CstNode) -> Result<ConfigDocumentIr, BindError> {
        let mut rows = Vec::new();
        for (i, node) in cst.children().iter().enumerate() {
            if node.kind() != &SyntaxKind::Entry {
                continue;
            }
            let line = i + 1;
            let mut row = RowIr::new(format!("line-{line}"), "rule_table_row", SourceSpan::single_line(line));
            for name in FIELDS {
                let present = field_text(node, name);
                // dump and pass default to 0 when left out.
                let value = present.map(str::to_string).unwrap_or_else(|| if matches!(name, "dump" | "pass") { "0".into() } else { String::new() });
                let field = FieldIr::new(name, FieldType::String, serde_json::Value::String(value.clone()));
                row.fields.push(match field_problem(name, &value) {
                    Some(p) => field.with_error(p),
                    None => field.with_validity(true),
                });
            }
            rows.push(row);
        }
        Ok(ConfigDocumentIr {
            plugin_name: self.manifest.plugin.name.clone(),
            shape: ShapeIr { kind: self.manifest.shape.kind, order_sensitive: self.manifest.shape.order_sensitive, order_note: self.manifest.shape.order_note.clone() },
            rows,
        })
    }

    fn apply_edit(&self, cst: &mut CstNode, op: &EditOp) -> Result<(), EditError> {
        match op {
            EditOp::UpdateField { row_id, field_name, new_value } => {
                let pos = FIELDS.iter().position(|f| f == field_name).ok_or_else(|| EditError::FieldNotFound(field_name.clone(), row_id.clone()))?;
                let text = clean(field_name, new_value)?;
                let idx = index_of(cst, row_id)?;
                let node = &mut children(cst)?[idx];
                if node.kind() != &SyntaxKind::Entry {
                    return Err(EditError::RowNotFound(row_id.clone()));
                }
                if node.replace_first_token_text(&SyntaxKind::custom(field_name.as_str()), &text) {
                    return Ok(());
                }
                // dump or pass left out: write the missing ones, then this.
                let tokens = node.children_mut().ok_or_else(|| EditError::Unsupported("line is not a rule".into()))?;
                let mut at = tokens.iter().rposition(|t| FIELDS.iter().any(|f| t.kind() == &SyntaxKind::custom(*f))).map_or(0, |i| i + 1);
                let have = tokens.iter().filter(|t| FIELDS.iter().any(|f| t.kind() == &SyntaxKind::custom(*f))).count();
                for missing in &FIELDS[have..=pos] {
                    let value = if *missing == field_name.as_str() { text.clone() } else { "0".to_string() };
                    tokens.insert(at, CstNode::token(SyntaxKind::Whitespace, " ", Span::default()));
                    tokens.insert(at + 1, CstNode::token(SyntaxKind::custom(*missing), value, Span::default()));
                    at += 2;
                }
                Ok(())
            }
            EditOp::DeleteRow { row_id } => {
                let idx = index_of(cst, row_id)?;
                children(cst)?.remove(idx);
                Ok(())
            }
            EditOp::InsertRow { after_row_id, fields } => {
                let mut parts = Vec::new();
                for name in FIELDS {
                    let value = match fields.get(name) {
                        Some(v) => clean(name, v)?,
                        None if name == "options" => "defaults".into(),
                        None if matches!(name, "dump" | "pass") => "0".into(),
                        None => return Err(EditError::InvalidValue { field: name.into(), message: format!("Field '{name}' is required for insertion") }),
                    };
                    parts.push(value);
                }
                let node = parse_line(&format!("{}\n", parts.join("\t")), 0);
                let at = match after_row_id {
                    Some(id) => index_of(cst, id)? + 1,
                    None => children(cst)?.len(),
                };
                insert_node(children(cst)?, at, node);
                Ok(())
            }
            EditOp::MoveRow { row_id, after_row_id, before_row_id } => {
                let idx = index_of(cst, row_id)?;
                let target = match (before_row_id, after_row_id) {
                    (Some(b), _) => Some((index_of(cst, b)?, false)),
                    (None, Some(a)) => Some((index_of(cst, a)?, true)),
                    (None, None) => None,
                };
                let list = children(cst)?;
                let node = list.remove(idx);
                let at = match target {
                    Some((t, after)) => {
                        let t = if t > idx { t - 1 } else { t };
                        if after { t + 1 } else { t }
                    }
                    None => list.len(),
                };
                insert_node(list, at, node);
                Ok(())
            }
        }
    }
}

/// What's wrong with a field's value, if anything.
fn field_problem(field: &str, value: &str) -> Option<&'static str> {
    match field {
        "device" | "mountpoint" | "type" | "options" if value.is_empty() => Some("required"),
        "mountpoint" if value != "none" && !value.starts_with('/') => Some("a mount point is an absolute path, or 'none' for swap"),
        "dump" | "pass" if !value.chars().all(|c| c.is_ascii_digit()) || value.is_empty() => Some("a number (usually 0, 1 or 2)"),
        _ => None,
    }
}

/// A field's new value: one word (spaces are written \040).
fn clean(field: &str, v: &serde_json::Value) -> Result<String, EditError> {
    let invalid = |message: &str| EditError::InvalidValue { field: field.into(), message: message.into() };
    let s = v.as_str().ok_or_else(|| invalid("Expected a string"))?.trim();
    if s.contains(['\n', '\r']) {
        return Err(invalid("must be one line"));
    }
    let s = s.replace(' ', "\\040");
    if let Some(p) = field_problem(field, &s) {
        return Err(invalid(p));
    }
    if s.starts_with('#') {
        return Err(invalid("can't start with #"));
    }
    Ok(s)
}

fn field_text<'a>(node: &'a CstNode, name: &str) -> Option<&'a str> {
    node.children().iter().find(|t| t.kind() == &SyntaxKind::custom(name)).and_then(|t| match t {
        CstNode::Token { text, .. } => Some(text.as_str()),
        CstNode::Rule { .. } => None,
    })
}

fn insert_node(list: &mut Vec<CstNode>, at: usize, node: CstNode) {
    if at > 0 {
        if let Some(prev) = list.get_mut(at - 1) {
            if !ends_with_newline(prev) {
                if let Some(c) = prev.children_mut() {
                    c.push(CstNode::token(SyntaxKind::Newline, "\n", Span::default()));
                }
            }
        }
    }
    list.insert(at.min(list.len()), node);
}

fn ends_with_newline(node: &CstNode) -> bool {
    match node {
        CstNode::Token { text, .. } => text.ends_with('\n'),
        CstNode::Rule { children, .. } => children.last().is_some_and(ends_with_newline),
    }
}

fn children(cst: &mut CstNode) -> Result<&mut Vec<CstNode>, EditError> {
    cst.children_mut().ok_or_else(|| EditError::Unsupported("Root is not a rule".into()))
}

fn index_of(cst: &CstNode, row_id: &str) -> Result<usize, EditError> {
    let n: usize = row_id.strip_prefix("line-").and_then(|n| n.parse().ok()).ok_or_else(|| EditError::RowNotFound(row_id.into()))?;
    (n >= 1 && n <= cst.children().len()).then(|| n - 1).ok_or_else(|| EditError::RowNotFound(row_id.into()))
}

/// One node per line; every byte is kept.
pub fn parse_fstab_cst(input: &str) -> Vec<CstNode> {
    let mut out = Vec::new();
    let mut offset = 0;
    for line in input.split_inclusive('\n') {
        out.push(parse_line(line, offset));
        offset += line.len();
    }
    out
}

fn parse_line(line: &str, base: usize) -> CstNode {
    let span = |s: usize, e: usize| Span::new(base + s, base + e);
    let body_end = line.strip_suffix("\r\n").or_else(|| line.strip_suffix('\n')).map_or(line.len(), str::len);
    let body = &line[..body_end];
    let mut tokens = Vec::new();
    let trimmed = body.trim_start_matches([' ', '\t']);
    let kind = if trimmed.is_empty() {
        if !body.is_empty() {
            tokens.push(CstNode::token(SyntaxKind::Whitespace, body, span(0, body_end)));
        }
        SyntaxKind::BlankLine
    } else if trimmed.starts_with('#') {
        let lead = body.len() - trimmed.len();
        if lead > 0 {
            tokens.push(CstNode::token(SyntaxKind::Whitespace, &body[..lead], span(0, lead)));
        }
        tokens.push(CstNode::token(SyntaxKind::Comment, trimmed, span(lead, body_end)));
        SyntaxKind::CommentLine
    } else {
        // Alternate whitespace and words; words take the field names in order.
        let mut pos = 0;
        let mut word = 0;
        let bytes = body.as_bytes();
        while pos < body_end {
            let start = pos;
            let is_ws = |b: u8| b == b' ' || b == b'\t';
            if is_ws(bytes[pos]) {
                while pos < body_end && is_ws(bytes[pos]) {
                    pos += 1;
                }
                tokens.push(CstNode::token(SyntaxKind::Whitespace, &body[start..pos], span(start, pos)));
            } else {
                while pos < body_end && !is_ws(bytes[pos]) {
                    pos += 1;
                }
                let kind = FIELDS.get(word).map_or(SyntaxKind::Error, |f| SyntaxKind::custom(*f));
                tokens.push(CstNode::token(kind, &body[start..pos], span(start, pos)));
                word += 1;
            }
        }
        // Fewer than four fields, or more than six: not a mount line.
        if (4..=6).contains(&word) { SyntaxKind::Entry } else { SyntaxKind::Error }
    };
    if body_end < line.len() {
        tokens.push(CstNode::token(SyntaxKind::Newline, &line[body_end..], span(body_end, line.len())));
    }
    CstNode::rule(kind, tokens, span(0, line.len()))
}
