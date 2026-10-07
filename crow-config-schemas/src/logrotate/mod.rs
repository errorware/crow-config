//! logrotate.conf and /etc/logrotate.d/*: global directives, then blocks
//! of directives for a set of log paths (`/var/log/nginx/*.log { ... }`).
//!
//! Each directive is a row named by its keyword (`rotate 14`, or a flag
//! like `compress`); a block's opening line is a scope row holding its log
//! paths, and its directives carry those paths as their scope. Scripts
//! (`postrotate` … `endscript`) are kept as one read-only row.

use crow_config_core::cst::{CstNode, SourceSpan, Span, SyntaxKind};
use crow_config_core::edit::{BindError, ConfigPlugin, EditError, EditOp, ParseError};
use crow_config_core::ir::{ConfigDocumentIr, FieldIr, RowIr, ShapeIr};
use crow_config_core::schema::{FieldType, PluginManifest};
use std::sync::LazyLock;

pub const LOGROTATE_MANIFEST_TOML: &str = include_str!("../../plugins/logrotate.toml");

pub static LOGROTATE_MANIFEST: LazyLock<PluginManifest> =
    LazyLock::new(|| PluginManifest::from_toml_str(LOGROTATE_MANIFEST_TOML).expect("Failed to parse embedded logrotate.toml manifest"));

const OPEN: &str = "block_open";
const CLOSE: &str = "block_close";
const SCRIPT: &str = "script";
const PATHS: &str = "paths";
const SCRIPT_WORDS: [&str; 5] = ["postrotate", "prerotate", "firstaction", "lastaction", "preremove"];

/// The value a flag directive (`compress`) shows.
pub const FLAG_VALUE: &str = "on";

/// What common directives do, for the row's help line.
fn help_for(directive: &str) -> Option<&'static str> {
    Some(match directive {
        "daily" | "weekly" | "monthly" | "yearly" | "hourly" => "How often the logs are rotated.",
        "rotate" => "How many rotated files are kept; older ones are deleted.",
        "compress" => "Rotated files are gzipped.",
        "nocompress" => "Rotated files are left uncompressed.",
        "delaycompress" => "The newest rotated file is compressed one cycle later (for programs that keep writing to it).",
        "missingok" => "A missing log file isn't an error.",
        "nomissingok" => "A missing log file is an error.",
        "notifempty" => "Empty logs aren't rotated.",
        "ifempty" => "Logs are rotated even when empty.",
        "create" => "A new empty log is created after rotating (mode, owner, group).",
        "nocreate" => "No new log file is created after rotating.",
        "copytruncate" => "The log is copied and then truncated in place, for programs that can't reopen it (a few lines can be lost).",
        "size" => "Rotate once the log is bigger than this (100k, 10M, 1G), whatever the schedule.",
        "maxsize" => "Rotate early when the log is bigger than this, even before its schedule.",
        "minsize" => "Don't rotate on schedule unless the log is at least this big.",
        "maxage" => "Rotated files older than this many days are deleted.",
        "dateext" => "Rotated files get a date suffix instead of a number.",
        "dateformat" => "The date suffix's format (with dateext).",
        "olddir" => "Rotated files are moved to this folder.",
        "su" => "The user and group logrotate rotates these logs as.",
        "sharedscripts" => "Scripts run once for all the logs in the block, not once per log.",
        "include" => "Reads more configuration from this file or folder.",
        "postrotate" | "prerotate" | "firstaction" | "lastaction" | "preremove" => "A shell script logrotate runs; edit it in the text view.",
        _ => return None,
    })
}

/// Lossless parser and plugin for logrotate configuration.
#[derive(Debug, Clone)]
pub struct LogrotatePlugin {
    manifest: &'static PluginManifest,
}

impl LogrotatePlugin {
    pub fn new() -> Self {
        Self { manifest: &LOGROTATE_MANIFEST }
    }
}

impl Default for LogrotatePlugin {
    fn default() -> Self {
        Self::new()
    }
}

fn tok(node: &CstNode, kind: &SyntaxKind) -> Option<String> {
    node.children().iter().find(|t| t.kind() == kind).and_then(|t| match t {
        CstNode::Token { text, .. } => Some(text.clone()),
        CstNode::Rule { .. } => None,
    })
}

fn newlines(node: &CstNode) -> usize {
    match node {
        CstNode::Token { text, .. } => text.matches('\n').count(),
        CstNode::Rule { children, .. } => children.iter().map(newlines).sum(),
    }
}

/// Each node with its first line number and the paths of the block it's
/// in (`None` outside blocks; a block's own opening line has its paths).
fn walk(cst: &CstNode) -> Vec<(usize, &CstNode, Option<String>)> {
    let mut out = Vec::new();
    let mut line = 1;
    let mut scope: Option<String> = None;
    for node in cst.children() {
        if node.kind() == &SyntaxKind::custom(OPEN) {
            scope = tok(node, &SyntaxKind::custom(PATHS)).map(|p| p.split_whitespace().collect::<Vec<_>>().join(" "));
        }
        out.push((line, node, scope.clone()));
        if node.kind() == &SyntaxKind::custom(CLOSE) {
            scope = None;
        }
        line += newlines(node).max(1);
    }
    out
}

impl ConfigPlugin for LogrotatePlugin {
    fn manifest(&self) -> &PluginManifest {
        self.manifest
    }

    fn parse(&self, text: &str) -> Result<CstNode, ParseError> {
        Ok(CstNode::rule(SyntaxKind::Document, parse_logrotate_cst(text), Span::new(0, text.len())))
    }

    fn to_ir(&self, cst: &CstNode) -> Result<ConfigDocumentIr, BindError> {
        let mut rows = Vec::new();
        for (line, node, scope) in walk(cst) {
            let span = SourceSpan::new(line, line + newlines(node).saturating_sub(1).max(0));
            let mut row = RowIr::new(format!("line-{line}"), "key_value_row", span);
            row.scope = scope.clone();
            let kind = node.kind();
            if kind == &SyntaxKind::custom(OPEN) {
                row.widget = "scope_row".into();
                let paths = scope.clone().unwrap_or_default();
                row.fields.push(FieldIr::new("logs", FieldType::String, serde_json::Value::String(paths)).with_validity(true));
            } else if kind == &SyntaxKind::custom(SCRIPT) {
                let word = tok(node, &SyntaxKind::Key).unwrap_or_default();
                let body = tok(node, &SyntaxKind::Value).unwrap_or_default();
                let lines: Vec<&str> = body.lines().map(str::trim).filter(|l| !l.is_empty() && *l != "endscript").collect();
                let summary = match lines.as_slice() {
                    [] => "empty".to_string(),
                    [one] => one.to_string(),
                    [first, rest @ ..] => format!("{first} (+{} more line{})", rest.len(), if rest.len() == 1 { "" } else { "s" }),
                };
                row.widget = "script_row".into();
                let mut f = FieldIr::new(word.clone(), FieldType::String, serde_json::Value::String(summary)).with_validity(true);
                f.help = help_for(&word).map(str::to_string);
                row.fields.push(f);
            } else if kind == &SyntaxKind::Entry {
                let word = tok(node, &SyntaxKind::Key).unwrap_or_default();
                let value = tok(node, &SyntaxKind::Value).unwrap_or_else(|| FLAG_VALUE.to_string());
                let mut f = FieldIr::new(word.clone(), FieldType::String, serde_json::Value::String(value)).with_validity(true);
                f.help = help_for(&word).map(str::to_string);
                if word == "include" {
                    row.include = tok(node, &SyntaxKind::Value).map(|v| vec![v]);
                }
                row.fields.push(f);
            } else {
                continue;
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
        let unsupported = |m: &str| EditError::Unsupported(m.to_string());
        match op {
            EditOp::UpdateField { row_id, field_name, new_value } => {
                let text = one_line(field_name, new_value)?;
                let idx = index_of(cst, row_id)?;
                let node = &mut children(cst)?[idx];
                let kind = node.kind().clone();
                if kind == SyntaxKind::custom(OPEN) {
                    if field_name != "logs" || text.is_empty() {
                        return Err(EditError::InvalidValue { field: field_name.clone(), message: "a block needs at least one log path".into() });
                    }
                    node.replace_first_token_text(&SyntaxKind::custom(PATHS), &text);
                    return Ok(());
                }
                if kind == SyntaxKind::custom(SCRIPT) {
                    return Err(unsupported("scripts are edited in the text view"));
                }
                if kind != SyntaxKind::Entry || tok(node, &SyntaxKind::Key).as_deref() != Some(field_name.as_str()) {
                    return Err(EditError::FieldNotFound(field_name.clone(), row_id.clone()));
                }
                if !node.replace_first_token_text(&SyntaxKind::Value, &text) {
                    return Err(unsupported("this directive is a flag: delete it to turn it off"));
                }
                Ok(())
            }
            EditOp::DeleteRow { row_id } => {
                let idx = index_of(cst, row_id)?;
                if children(cst)?[idx].kind() == &SyntaxKind::custom(OPEN) {
                    return Err(unsupported("a block is removed in the text view, with its closing brace"));
                }
                children(cst)?.remove(idx);
                Ok(())
            }
            EditOp::InsertRow { after_row_id, fields } => {
                let (word, value) = fields.iter().next().ok_or_else(|| EditError::InvalidValue { field: "directive".into(), message: "a directive is required".into() })?;
                if !word.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') || word.is_empty() || SCRIPT_WORDS.contains(&word.as_str()) {
                    return Err(EditError::InvalidValue { field: word.clone(), message: "not a directive that can be added here".into() });
                }
                let value = one_line(word, value)?;
                let (at, indent) = match after_row_id {
                    Some(id) => {
                        let idx = index_of(cst, id)?;
                        let inside = walk(cst)[idx].2.is_some() && cst.children()[idx].kind() != &SyntaxKind::custom(CLOSE);
                        (idx + 1, if inside { "    " } else { "" })
                    }
                    None => (children(cst)?.len(), ""),
                };
                let line = if value.is_empty() || value == FLAG_VALUE { format!("{indent}{word}\n") } else { format!("{indent}{word} {value}\n") };
                let node = parse_logrotate_cst(&line).remove(0);
                let list = children(cst)?;
                if at > 0 {
                    if let Some(prev) = list.get_mut(at - 1) {
                        if newlines(prev) == 0 {
                            if let Some(c) = prev.children_mut() {
                                c.push(CstNode::token(SyntaxKind::Newline, "\n", Span::default()));
                            }
                        }
                    }
                }
                list.insert(at.min(list.len()), node);
                Ok(())
            }
            EditOp::MoveRow { .. } => Err(unsupported("logrotate directives aren't ordered; move them in the text view")),
        }
    }
}

fn one_line(field: &str, v: &serde_json::Value) -> Result<String, EditError> {
    let s = v.as_str().ok_or_else(|| EditError::InvalidValue { field: field.into(), message: "Expected a string".into() })?;
    if s.contains(['\n', '\r', '{', '}']) {
        return Err(EditError::InvalidValue { field: field.into(), message: "must be one line, without braces".into() });
    }
    Ok(s.trim().to_string())
}

fn children(cst: &mut CstNode) -> Result<&mut Vec<CstNode>, EditError> {
    cst.children_mut().ok_or_else(|| EditError::Unsupported("Root is not a rule".into()))
}

fn index_of(cst: &CstNode, row_id: &str) -> Result<usize, EditError> {
    let n: usize = row_id.strip_prefix("line-").and_then(|n| n.parse().ok()).ok_or_else(|| EditError::RowNotFound(row_id.into()))?;
    walk(cst).iter().position(|(line, _, _)| *line == n).ok_or_else(|| EditError::RowNotFound(row_id.into()))
}

fn body_of(line: &str) -> &str {
    line.strip_suffix("\r\n").or_else(|| line.strip_suffix('\n')).unwrap_or(line)
}

/// Splits `input` into nodes: comments, blanks, directives, block openings
/// (paths may span lines before the `{`), closings and whole scripts.
/// Every byte is kept.
pub fn parse_logrotate_cst(input: &str) -> Vec<CstNode> {
    let lines: Vec<&str> = input.split_inclusive('\n').collect();
    let mut out = Vec::new();
    let mut offset = 0;
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let t = body_of(line).trim();
        let word = t.split_whitespace().next().unwrap_or_default();
        // A script runs to its endscript.
        if SCRIPT_WORDS.contains(&word) {
            let mut j = i + 1;
            while j < lines.len() && body_of(lines[j]).trim() != "endscript" {
                j += 1;
            }
            let end = (j + 1).min(lines.len());
            let text: String = lines[i..end].concat();
            out.push(script_node(&text, offset));
            offset += text.len();
            i = end;
            continue;
        }
        // Path lines before a `{` (on this line or a later one) open a block.
        let opens_here = t.ends_with('{') && !t.starts_with('#');
        let path_like = (t.starts_with('/') || t.starts_with('"') || t.starts_with('*')) && !t.contains('}');
        if opens_here || path_like {
            let mut j = i;
            while j < lines.len() && !body_of(lines[j]).trim_end().ends_with('{') {
                let tj = body_of(lines[j]).trim();
                if j > i && !(tj.starts_with('/') || tj.starts_with('"') || tj.starts_with('*') || tj.is_empty() || tj == "{") {
                    break;
                }
                j += 1;
            }
            if j < lines.len() && body_of(lines[j]).trim_end().ends_with('{') {
                let text: String = lines[i..=j].concat();
                out.push(open_node(&text, offset));
                offset += text.len();
                i = j + 1;
                continue;
            }
        }
        out.push(line_node(line, offset));
        offset += line.len();
        i += 1;
    }
    out
}

fn script_node(text: &str, base: usize) -> CstNode {
    let first_end = text.find('\n').map_or(text.len(), |i| i + 1);
    let first = &text[..first_end];
    let lead = first.len() - first.trim_start_matches([' ', '\t']).len();
    let word_end = lead + first[lead..].find(|c: char| c.is_whitespace()).unwrap_or(first.len() - lead);
    let mut tokens = Vec::new();
    if lead > 0 {
        tokens.push(CstNode::token(SyntaxKind::Whitespace, &text[..lead], Span::new(base, base + lead)));
    }
    tokens.push(CstNode::token(SyntaxKind::Key, &text[lead..word_end], Span::new(base + lead, base + word_end)));
    // The script body (and endscript) as one value; it's never edited here.
    tokens.push(CstNode::token(SyntaxKind::Value, &text[word_end..], Span::new(base + word_end, base + text.len())));
    CstNode::rule(SyntaxKind::custom(SCRIPT), tokens, Span::new(base, base + text.len()))
}

fn open_node(text: &str, base: usize) -> CstNode {
    // paths, then the brace, then whatever trails it on that line.
    let brace = text.rfind('{').unwrap_or(text.len());
    let lead = text.len() - text.trim_start_matches([' ', '\t']).len();
    let paths_end = lead + text[lead..brace].trim_end().len();
    let mut tokens = Vec::new();
    let mut push = |kind: SyntaxKind, s: usize, e: usize| {
        if s < e {
            tokens.push(CstNode::token(kind, &text[s..e], Span::new(base + s, base + e)));
        }
    };
    push(SyntaxKind::Whitespace, 0, lead);
    push(SyntaxKind::custom(PATHS), lead, paths_end);
    push(SyntaxKind::Whitespace, paths_end, brace);
    push(SyntaxKind::custom("brace"), brace, (brace + 1).min(text.len()));
    push(SyntaxKind::Whitespace, (brace + 1).min(text.len()), text.len());
    CstNode::rule(SyntaxKind::custom(OPEN), tokens, Span::new(base, base + text.len()))
}

fn line_node(line: &str, base: usize) -> CstNode {
    let body_end = body_of(line).len();
    let body = &line[..body_end];
    let mut tokens = Vec::new();
    let mut push = |kind: SyntaxKind, s: usize, e: usize| {
        if s < e {
            tokens.push(CstNode::token(kind, &line[s..e], Span::new(base + s, base + e)));
        }
    };
    let lead = body.len() - body.trim_start_matches([' ', '\t']).len();
    let t = body.trim();
    let kind = if t.is_empty() {
        push(SyntaxKind::Whitespace, 0, body_end);
        SyntaxKind::BlankLine
    } else if t.starts_with('#') {
        push(SyntaxKind::Whitespace, 0, lead);
        push(SyntaxKind::Comment, lead, body_end);
        SyntaxKind::CommentLine
    } else if t == "}" {
        push(SyntaxKind::Whitespace, 0, lead);
        push(SyntaxKind::custom("brace"), lead, lead + 1);
        push(SyntaxKind::Whitespace, lead + 1, body_end);
        SyntaxKind::custom(CLOSE)
    } else {
        push(SyntaxKind::Whitespace, 0, lead);
        let word_end = lead + body[lead..].find([' ', '\t']).unwrap_or(body_end - lead);
        push(SyntaxKind::Key, lead, word_end);
        let v_start = word_end + (body[word_end..].len() - body[word_end..].trim_start_matches([' ', '\t']).len());
        let v_end = v_start + body[v_start..].trim_end_matches([' ', '\t']).len();
        push(SyntaxKind::Whitespace, word_end, v_start);
        push(SyntaxKind::Value, v_start, v_end);
        push(SyntaxKind::Whitespace, v_end, body_end);
        SyntaxKind::Entry
    };
    push(SyntaxKind::Newline, body_end, line.len());
    CstNode::rule(kind, tokens, Span::new(base, base + line.len()))
}
