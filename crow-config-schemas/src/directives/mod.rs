//! Files of one directive per line, `name arguments…`: chrony.conf,
//! ntp.conf and resolv.conf. One grammar; each file type has its own
//! manifest, whose fields hold what its directives do and their values.

use crow_config_core::cst::{CstNode, SourceSpan, Span, SyntaxKind};
use crow_config_core::edit::{BindError, ConfigPlugin, EditError, EditOp, ParseError};
use crow_config_core::ir::{ConfigDocumentIr, FieldIr, RowIr, ShapeIr};
use crow_config_core::schema::{FieldType, PluginManifest};
use std::sync::LazyLock;

pub const CHRONY_MANIFEST_TOML: &str = include_str!("../../plugins/chrony.toml");
pub const NTP_MANIFEST_TOML: &str = include_str!("../../plugins/ntp.toml");
pub const RESOLV_MANIFEST_TOML: &str = include_str!("../../plugins/resolv.toml");

pub static CHRONY_MANIFEST: LazyLock<PluginManifest> = LazyLock::new(|| PluginManifest::from_toml_str(CHRONY_MANIFEST_TOML).expect("Failed to parse embedded chrony.toml manifest"));
pub static NTP_MANIFEST: LazyLock<PluginManifest> = LazyLock::new(|| PluginManifest::from_toml_str(NTP_MANIFEST_TOML).expect("Failed to parse embedded ntp.toml manifest"));
pub static RESOLV_MANIFEST: LazyLock<PluginManifest> = LazyLock::new(|| PluginManifest::from_toml_str(RESOLV_MANIFEST_TOML).expect("Failed to parse embedded resolv.toml manifest"));

/// Line comments: `#` everywhere, `;` in resolv.conf, `!` and `%` in chrony.
const COMMENT: [char; 4] = ['#', ';', '!', '%'];

/// Lossless parser and plugin for one-directive-per-line files.
#[derive(Debug, Clone)]
pub struct DirectivesPlugin {
    manifest: &'static PluginManifest,
}

impl DirectivesPlugin {
    pub fn chrony() -> Self {
        Self { manifest: &CHRONY_MANIFEST }
    }
    pub fn ntp() -> Self {
        Self { manifest: &NTP_MANIFEST }
    }
    pub fn resolv() -> Self {
        Self { manifest: &RESOLV_MANIFEST }
    }

    /// The manifest's directives: (name, what it does, a starting value).
    pub fn suggestions(&self) -> Vec<(&'static str, &'static str, &'static str)> {
        let m: &'static PluginManifest = self.manifest;
        m.fields
            .iter()
            .map(|f| (f.name.as_str(), f.help.as_deref().unwrap_or_default(), f.options.as_ref().and_then(|o| o.first()).map_or("", |o| o.value.as_str())))
            .collect()
    }
}

fn body_of(line: &str) -> &str {
    line.strip_suffix("\r\n").or_else(|| line.strip_suffix('\n')).unwrap_or(line)
}

fn parse_line(text: &str, base: usize) -> CstNode {
    let body_end = body_of(text).len();
    let body = &text[..body_end];
    let mut tokens = Vec::new();
    let mut push = |kind: SyntaxKind, s: usize, e: usize| {
        if s < e {
            tokens.push(CstNode::token(kind, &text[s..e], Span::new(base + s, base + e)));
        }
    };
    let lead = body.len() - body.trim_start_matches([' ', '\t']).len();
    let t = body.trim();
    let kind = if t.is_empty() {
        push(SyntaxKind::Whitespace, 0, body_end);
        SyntaxKind::BlankLine
    } else if t.starts_with(COMMENT) {
        push(SyntaxKind::Whitespace, 0, lead);
        push(SyntaxKind::Comment, lead, body_end);
        SyntaxKind::CommentLine
    } else {
        let name_end = lead + body[lead..].find([' ', '\t']).unwrap_or(body.len() - lead);
        let v_start = name_end + (body[name_end..].len() - body[name_end..].trim_start_matches([' ', '\t']).len());
        let v_end = v_start + body[v_start..].trim_end_matches([' ', '\t']).len();
        push(SyntaxKind::Whitespace, 0, lead);
        push(SyntaxKind::Key, lead, name_end);
        push(SyntaxKind::Whitespace, name_end, v_start);
        push(SyntaxKind::Value, v_start, v_end);
        push(SyntaxKind::Whitespace, v_end, body_end);
        SyntaxKind::Entry
    };
    push(SyntaxKind::Newline, body_end, text.len());
    CstNode::rule(kind, tokens, Span::new(base, base + text.len()))
}

pub fn parse_directives_cst(input: &str) -> Vec<CstNode> {
    let mut offset = 0;
    input
        .split_inclusive('\n')
        .map(|line| {
            let node = parse_line(line, offset);
            offset += line.len();
            node
        })
        .collect()
}

fn tok(node: &CstNode, kind: &SyntaxKind) -> Option<String> {
    node.children().iter().find(|t| t.kind() == kind).and_then(|t| match t {
        CstNode::Token { text, .. } => Some(text.clone()),
        CstNode::Rule { .. } => None,
    })
}

fn children(cst: &mut CstNode) -> Result<&mut Vec<CstNode>, EditError> {
    cst.children_mut().ok_or_else(|| EditError::Unsupported("Root is not a rule".into()))
}

/// Row ids are `line-N`, and every line is one node.
fn index_of(cst: &CstNode, row_id: &str) -> Result<usize, EditError> {
    let n: usize = row_id.strip_prefix("line-").and_then(|n| n.parse().ok()).ok_or_else(|| EditError::RowNotFound(row_id.into()))?;
    (n >= 1 && n <= cst.children().len() && cst.children()[n - 1].kind() == &SyntaxKind::Entry).then(|| n - 1).ok_or_else(|| EditError::RowNotFound(row_id.into()))
}

fn one_line(field: &str, v: &serde_json::Value) -> Result<String, EditError> {
    let s = v.as_str().ok_or_else(|| EditError::InvalidValue { field: field.into(), message: "Expected a string".into() })?;
    if s.contains(['\n', '\r']) {
        return Err(EditError::InvalidValue { field: field.into(), message: "one line".into() });
    }
    Ok(s.trim().to_string())
}

impl ConfigPlugin for DirectivesPlugin {
    fn manifest(&self) -> &PluginManifest {
        self.manifest
    }

    fn parse(&self, text: &str) -> Result<CstNode, ParseError> {
        Ok(CstNode::rule(SyntaxKind::Document, parse_directives_cst(text), Span::new(0, text.len())))
    }

    fn to_ir(&self, cst: &CstNode) -> Result<ConfigDocumentIr, BindError> {
        let mut rows = Vec::new();
        for (i, node) in cst.children().iter().enumerate() {
            if node.kind() != &SyntaxKind::Entry {
                continue;
            }
            let line = i + 1;
            let name = tok(node, &SyntaxKind::Key).unwrap_or_default();
            let value = tok(node, &SyntaxKind::Value).unwrap_or_default();
            let mut row = RowIr::new(format!("line-{line}"), "key_value_row", SourceSpan::single_line(line));
            let mut f = FieldIr::new(name.clone(), FieldType::String, serde_json::Value::String(value)).with_validity(true);
            if let Some(known) = self.manifest.fields.iter().find(|k| k.name == name) {
                f.help = known.help.clone();
                f.options = known.options.clone();
            }
            row.fields.push(f);
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
                let text = one_line(field_name, new_value)?;
                let idx = index_of(cst, row_id)?;
                let node = &mut children(cst)?[idx];
                if tok(node, &SyntaxKind::Key).as_deref() != Some(field_name.as_str()) {
                    return Err(EditError::FieldNotFound(field_name.clone(), row_id.clone()));
                }
                if !node.replace_first_token_text(&SyntaxKind::Value, &text) && !text.is_empty() {
                    // A bare directive (`rtcsync`): add a space and the arguments.
                    let tokens = node.children_mut().ok_or_else(|| EditError::Unsupported("line is not a rule".into()))?;
                    let at = tokens.iter().position(|t| t.kind() == &SyntaxKind::Key).map_or(0, |i| i + 1);
                    tokens.insert(at, CstNode::token(SyntaxKind::Value, text, Span::default()));
                    tokens.insert(at, CstNode::token(SyntaxKind::Whitespace, " ", Span::default()));
                }
                Ok(())
            }
            EditOp::DeleteRow { row_id } => {
                let idx = index_of(cst, row_id)?;
                children(cst)?.remove(idx);
                Ok(())
            }
            EditOp::InsertRow { after_row_id, fields } => {
                let (name, value) = fields.iter().next().ok_or_else(|| EditError::InvalidValue { field: "directive".into(), message: "a directive is required".into() })?;
                if name.is_empty() || name.starts_with(COMMENT) || name.contains(char::is_whitespace) {
                    return Err(EditError::InvalidValue { field: name.clone(), message: "a directive is one word".into() });
                }
                let value = one_line(name, value)?;
                let line = if value.is_empty() { format!("{name}\n") } else { format!("{name} {value}\n") };
                let node = parse_directives_cst(&line).remove(0);
                let at = match after_row_id {
                    Some(id) => index_of(cst, id)? + 1,
                    None => children(cst)?.len(),
                };
                let list = children(cst)?;
                // A last line without its newline gets one before the new line.
                if let Some(prev) = at.checked_sub(1).and_then(|i| list.get_mut(i)) {
                    if !matches!(prev.children().last(), Some(CstNode::Token { kind: SyntaxKind::Newline, .. })) {
                        if let Some(c) = prev.children_mut() {
                            c.push(CstNode::token(SyntaxKind::Newline, "\n", Span::default()));
                        }
                    }
                }
                list.insert(at.min(list.len()), node);
                Ok(())
            }
            EditOp::MoveRow { .. } => Err(EditError::Unsupported("lines are moved in the text view".into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crow_config_core::edit::ConfigDocument;

    const CHRONY: &str = "# Use public servers\npool 2.debian.pool.ntp.org iburst\n! old\nmakestep 1 3\nrtcsync\ndriftfile /var/lib/chrony/chrony.drift";

    #[test]
    fn directives_round_trip_and_edit_in_place() {
        let plugin = DirectivesPlugin::chrony();
        let mut doc = ConfigDocument::parse(&plugin, CHRONY).unwrap();
        assert_eq!(doc.serialize(), CHRONY);
        let ir = doc.to_ir().unwrap();
        let names: Vec<&str> = ir.rows.iter().map(|r| r.fields[0].name.as_str()).collect();
        assert_eq!(names, ["pool", "makestep", "rtcsync", "driftfile"]);
        assert!(ir.rows[1].fields[0].help.is_some(), "makestep explains itself");
        doc.apply_edit(&EditOp::UpdateField { row_id: "line-4".into(), field_name: "makestep".into(), new_value: serde_json::json!("0.5 -1") }).unwrap();
        doc.apply_edit(&EditOp::UpdateField { row_id: "line-5".into(), field_name: "rtcsync".into(), new_value: serde_json::json!("") }).unwrap();
        let fields = [("server".to_string(), serde_json::json!("time.example iburst"))].into_iter().collect();
        doc.apply_edit(&EditOp::InsertRow { after_row_id: Some("line-6".into()), fields }).unwrap();
        doc.apply_edit(&EditOp::DeleteRow { row_id: "line-2".into() }).unwrap();
        assert_eq!(doc.serialize(), "# Use public servers\n! old\nmakestep 0.5 -1\nrtcsync\ndriftfile /var/lib/chrony/chrony.drift\nserver time.example iburst\n");
        assert!(doc.apply_edit(&EditOp::UpdateField { row_id: "line-1".into(), field_name: "x".into(), new_value: serde_json::json!("y") }).is_err(), "comments aren't rows");
    }

    #[test]
    fn resolv_reads_semicolon_comments_and_suggests_its_directives() {
        let plugin = DirectivesPlugin::resolv();
        let doc = ConfigDocument::parse(&plugin, "; generated\nnameserver 1.1.1.1\nsearch lan\n").unwrap();
        assert_eq!(doc.to_ir().unwrap().rows.len(), 2);
        assert!(plugin.suggestions().iter().any(|s| s.0 == "nameserver"));
        assert!(DirectivesPlugin::ntp().suggestions().iter().any(|s| s.0 == "restrict"));
    }
}
