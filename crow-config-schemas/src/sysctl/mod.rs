//! `sysctl.conf` and `/etc/sysctl.d/*.conf`: one `key = value` per line.
//!
//! Comments are whole lines starting with `#` or `;` (a `#` after a value is
//! part of the value, as procps reads it). A key may start with `-`: "ignore
//! it if this kernel doesn't have it". Lines without `=` are kept as errors.

use crow_config_core::cst::{CstNode, SourceSpan, Span, SyntaxKind};
use crow_config_core::edit::{BindError, ConfigPlugin, EditError, EditOp, ParseError};
use crow_config_core::ir::{ConfigDocumentIr, FieldIr, RowIr, ShapeIr};
use crow_config_core::schema::{FieldType, PluginManifest};
use std::sync::LazyLock;

pub mod known;

pub const SYSCTL_MANIFEST_TOML: &str = include_str!("../../plugins/sysctl.toml");

pub static SYSCTL_MANIFEST: LazyLock<PluginManifest> =
    LazyLock::new(|| PluginManifest::from_toml_str(SYSCTL_MANIFEST_TOML).expect("Failed to parse embedded sysctl.toml manifest"));

/// The `-` before a key that asks to ignore it when the kernel lacks it.
const IGNORE_MARKER: &str = "ignore_marker";
const EQUALS: &str = "equals";

/// Lossless parser and plugin for sysctl configuration files.
#[derive(Debug, Clone)]
pub struct SysctlPlugin {
    manifest: &'static PluginManifest,
}

impl SysctlPlugin {
    pub fn new() -> Self {
        Self { manifest: &SYSCTL_MANIFEST }
    }
}

impl Default for SysctlPlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Why a key isn't a well-formed sysctl name, if it isn't.
pub fn key_problem(key: &str) -> Option<&'static str> {
    if key.is_empty() {
        return Some("a key is required");
    }
    if key.starts_with(['.', '/']) || key.ends_with(['.', '/']) {
        return Some("a key can't start or end with a separator");
    }
    if !key.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '/' | '_' | '-' | '*')) {
        return Some("a key is letters, digits, '_', '-' and '.' or '/' separators");
    }
    None
}

impl ConfigPlugin for SysctlPlugin {
    fn manifest(&self) -> &PluginManifest {
        self.manifest
    }

    fn parse(&self, text: &str) -> Result<CstNode, ParseError> {
        Ok(CstNode::rule(SyntaxKind::Document, parse_sysctl_cst(text), Span::new(0, text.len())))
    }

    fn to_ir(&self, cst: &CstNode) -> Result<ConfigDocumentIr, BindError> {
        let mut rows = Vec::new();
        for (line_no, line) in lines(cst) {
            if line.kind() != &SyntaxKind::Entry {
                continue;
            }
            let text_of = |kind: &SyntaxKind| line.children().iter().find(|t| t.kind() == kind).and_then(token_text).unwrap_or_default();
            let key = text_of(&SyntaxKind::Key);
            let value = text_of(&SyntaxKind::Value);
            let mut row = RowIr::new(format!("line-{line_no}"), "key_value_list_row", SourceSpan::single_line(line_no));
            let key_field = FieldIr::new("key", FieldType::String, serde_json::Value::String(key.to_string()));
            row.fields.push(match key_problem(key) {
                Some(p) => key_field.with_error(p),
                None => key_field.with_validity(true),
            });
            let mut value_field = FieldIr::new("value", FieldType::String, serde_json::Value::String(value.to_string()));
            // Well-known parameters say what they do, and offer their values.
            if let Some(k) = known::known(key) {
                value_field.help = Some(k.help.to_string());
                value_field.options = k.options();
            }
            row.fields.push(if value.is_empty() { value_field.with_error("a value is required") } else { value_field.with_validity(true) });
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
                let text = clean_value(field_name, new_value)?;
                let idx = index_of(cst, row_id)?;
                let line = &mut children(cst)?[idx];
                if line.kind() != &SyntaxKind::Entry {
                    return Err(EditError::RowNotFound(row_id.clone()));
                }
                let kind = match field_name.as_str() {
                    "key" => SyntaxKind::Key,
                    "value" => SyntaxKind::Value,
                    _ => return Err(EditError::FieldNotFound(field_name.clone(), row_id.clone())),
                };
                if !line.replace_first_token_text(&kind, &text) {
                    return Err(EditError::FieldNotFound(field_name.clone(), row_id.clone()));
                }
                Ok(())
            }
            EditOp::DeleteRow { row_id } => {
                let idx = index_of(cst, row_id)?;
                children(cst)?.remove(idx);
                Ok(())
            }
            EditOp::InsertRow { after_row_id, fields } => {
                let field = |name: &str| fields.get(name).ok_or_else(|| EditError::InvalidValue { field: name.into(), message: format!("Field '{name}' is required for insertion") }).and_then(|v| clean_value(name, v));
                let (key, value) = (field("key")?, field("value")?);
                let line = CstNode::rule(
                    SyntaxKind::Entry,
                    vec![
                        CstNode::token(SyntaxKind::Key, key, Span::default()),
                        CstNode::token(SyntaxKind::Whitespace, " ", Span::default()),
                        CstNode::token(SyntaxKind::custom(EQUALS), "=", Span::default()),
                        CstNode::token(SyntaxKind::Whitespace, " ", Span::default()),
                        CstNode::token(SyntaxKind::Value, value, Span::default()),
                        CstNode::token(SyntaxKind::Newline, "\n", Span::default()),
                    ],
                    Span::default(),
                );
                let at = match after_row_id {
                    Some(id) => index_of(cst, id)? + 1,
                    None => children(cst)?.len(),
                };
                insert_line(children(cst)?, at, line);
                Ok(())
            }
            EditOp::MoveRow { row_id, after_row_id, before_row_id } => {
                let idx = index_of(cst, row_id)?;
                // Find the target before removing, by identity of position.
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
                insert_line(list, at, node);
                Ok(())
            }
        }
    }
}

/// A field's new value as one line of text.
fn clean_value(field: &str, v: &serde_json::Value) -> Result<String, EditError> {
    let invalid = |message: &str| EditError::InvalidValue { field: field.into(), message: message.into() };
    let s = v.as_str().ok_or_else(|| invalid("Expected a string"))?;
    if s.contains(['\n', '\r']) {
        return Err(invalid("must be one line"));
    }
    let s = s.trim();
    match field {
        "key" => {
            if let Some(p) = key_problem(s.trim_start_matches('-')) {
                return Err(invalid(p));
            }
            // A '-' prefix belongs to the marker token, not the key.
            Ok(s.trim_start_matches('-').to_string())
        }
        "value" if s.is_empty() => Err(invalid("a value is required")),
        _ => Ok(s.to_string()),
    }
}

/// Inserts a line at `at`, giving the line before it a newline if it was
/// the last line of a file without one.
fn insert_line(list: &mut Vec<CstNode>, at: usize, line: CstNode) {
    if at > 0 {
        if let Some(prev) = list.get_mut(at - 1) {
            if !ends_with_newline(prev) {
                if let Some(c) = prev.children_mut() {
                    c.push(CstNode::token(SyntaxKind::Newline, "\n", Span::default()));
                }
            }
        }
    }
    list.insert(at.min(list.len()), line);
}

fn ends_with_newline(node: &CstNode) -> bool {
    match node {
        CstNode::Token { text, .. } => text.ends_with('\n'),
        CstNode::Rule { children, .. } => children.last().is_some_and(ends_with_newline),
    }
}

fn token_text(node: &CstNode) -> Option<&str> {
    match node {
        CstNode::Token { text, .. } => Some(text.as_str()),
        CstNode::Rule { .. } => None,
    }
}

fn children(cst: &mut CstNode) -> Result<&mut Vec<CstNode>, EditError> {
    cst.children_mut().ok_or_else(|| EditError::Unsupported("Root is not a rule".into()))
}

/// Lines with their 1-based line numbers.
fn lines(cst: &CstNode) -> impl Iterator<Item = (usize, &CstNode)> {
    cst.children().iter().enumerate().map(|(i, l)| (i + 1, l))
}

/// The index of the line a `line-N` row id names.
fn index_of(cst: &CstNode, row_id: &str) -> Result<usize, EditError> {
    let n: usize = row_id.strip_prefix("line-").and_then(|n| n.parse().ok()).ok_or_else(|| EditError::RowNotFound(row_id.into()))?;
    (n >= 1 && n <= cst.children().len()).then(|| n - 1).ok_or_else(|| EditError::RowNotFound(row_id.into()))
}

/// Splits `input` into one node per line; every byte is kept.
pub fn parse_sysctl_cst(input: &str) -> Vec<CstNode> {
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
    let push = |tokens: &mut Vec<CstNode>, kind: SyntaxKind, s: usize, e: usize| {
        if s < e {
            tokens.push(CstNode::token(kind, &line[s..e], span(s, e)));
        }
    };
    let lead = body.len() - body.trim_start_matches([' ', '\t']).len();
    push(&mut tokens, SyntaxKind::Whitespace, 0, lead);
    let rest = &body[lead..];
    let kind = if rest.is_empty() {
        SyntaxKind::BlankLine
    } else if rest.starts_with(['#', ';']) {
        push(&mut tokens, SyntaxKind::Comment, lead, body_end);
        SyntaxKind::CommentLine
    } else if let Some(eq) = rest.find('=') {
        let mut pos = lead;
        if rest.starts_with('-') {
            push(&mut tokens, SyntaxKind::custom(IGNORE_MARKER), pos, pos + 1);
            pos += 1;
        }
        let eq = lead + eq;
        let key_end = pos + line[pos..eq].trim_end_matches([' ', '\t']).len();
        push(&mut tokens, SyntaxKind::Key, pos, key_end);
        push(&mut tokens, SyntaxKind::Whitespace, key_end, eq);
        push(&mut tokens, SyntaxKind::custom(EQUALS), eq, eq + 1);
        let val_start = eq + 1 + (line[eq + 1..body_end].len() - line[eq + 1..body_end].trim_start_matches([' ', '\t']).len());
        let val_end = val_start + line[val_start..body_end].trim_end_matches([' ', '\t']).len();
        push(&mut tokens, SyntaxKind::Whitespace, eq + 1, val_start);
        // An empty value still gets a token, so it can be edited in place.
        tokens.push(CstNode::token(SyntaxKind::Value, &line[val_start..val_end], span(val_start, val_end)));
        push(&mut tokens, SyntaxKind::Whitespace, val_end, body_end);
        SyntaxKind::Entry
    } else {
        push(&mut tokens, SyntaxKind::Error, lead, body_end);
        SyntaxKind::Error
    };
    push(&mut tokens, SyntaxKind::Newline, body_end, line.len());
    CstNode::rule(kind, tokens, span(0, line.len()))
}
