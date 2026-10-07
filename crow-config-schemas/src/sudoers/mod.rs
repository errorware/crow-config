//! `/etc/sudoers` and `/etc/sudoers.d/*`: rules, `Defaults`, aliases and
//! includes, one row per entry (an entry continues over lines ending in
//! `\`).
//!
//! `#` starts a comment, except `#include`/`#includedir` and `#<uid>` (a
//! user given by number, e.g. `#1001 ALL=(ALL) ALL`).

use crow_config_core::cst::{CstNode, SourceSpan, Span, SyntaxKind};
use crow_config_core::edit::{BindError, ConfigPlugin, EditError, EditOp, ParseError};
use crow_config_core::ir::{ConfigDocumentIr, FieldIr, RowIr, ShapeIr};
use crow_config_core::schema::{FieldType, PluginManifest};
use std::sync::LazyLock;

pub const SUDOERS_MANIFEST_TOML: &str = include_str!("../../plugins/sudoers.toml");

pub static SUDOERS_MANIFEST: LazyLock<PluginManifest> =
    LazyLock::new(|| PluginManifest::from_toml_str(SUDOERS_MANIFEST_TOML).expect("Failed to parse embedded sudoers.toml manifest"));

/// The word that says what an entry is (`Defaults:alice`, `Cmnd_Alias`,
/// `@includedir`); rules have none.
const ENTRY_WORD: &str = "entry_word";
const EQUALS: &str = "equals";

const ALIASES: [&str; 5] = ["User_Alias", "Runas_Alias", "Host_Alias", "Cmnd_Alias", "Cmd_Alias"];
const INCLUDES: [&str; 4] = ["@includedir", "@include", "#includedir", "#include"];

/// Lossless parser and plugin for sudoers files.
#[derive(Debug, Clone)]
pub struct SudoersPlugin {
    manifest: &'static PluginManifest,
}

impl SudoersPlugin {
    pub fn new() -> Self {
        Self { manifest: &SUDOERS_MANIFEST }
    }
}

impl Default for SudoersPlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// What an entry is, from its leading word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Rule,
    Defaults,
    Alias,
    Include,
}

fn kind_of_word(word: &str) -> Kind {
    if INCLUDES.contains(&word) {
        Kind::Include
    } else if ALIASES.contains(&word) {
        Kind::Alias
    } else if word == "Defaults" || word.starts_with("Defaults") && word[8..].starts_with([':', '@', '>', '!']) {
        Kind::Defaults
    } else {
        Kind::Rule
    }
}

/// Why a rule is risky, if it is: what sudo lets it do without a password,
/// in words. `rule` is a rule's right-hand side (`ALL=(ALL) NOPASSWD: ALL`).
/// Rules that ask for the user's password (`%sudo ALL=(ALL:ALL) ALL`) are
/// sudo's normal shape and aren't flagged.
pub fn rule_risk(rule: &str) -> Option<&'static str> {
    let flat: String = rule.split_whitespace().collect::<Vec<_>>().join(" ");
    let nopasswd = flat.contains("NOPASSWD:");
    // The command list is after the last tag or the runas spec.
    let commands = flat.rsplit([':', ')']).next().unwrap_or(&flat).trim();
    let any_command = commands.split(',').any(|c| c.trim() == "ALL");
    match (nopasswd, any_command) {
        (true, true) => Some("any command as root, without a password"),
        (true, false) if commands.split(',').any(|c| matches!(c.split_whitespace().next().and_then(|p| p.rsplit('/').next()), Some("sh" | "bash" | "zsh" | "su" | "vi" | "vim" | "less" | "env"))) => {
            Some("without a password, and a listed command can start a root shell")
        }
        _ => None,
    }
}

impl ConfigPlugin for SudoersPlugin {
    fn manifest(&self) -> &PluginManifest {
        self.manifest
    }

    fn parse(&self, text: &str) -> Result<CstNode, ParseError> {
        Ok(CstNode::rule(SyntaxKind::Document, parse_sudoers_cst(text), Span::new(0, text.len())))
    }

    fn to_ir(&self, cst: &CstNode) -> Result<ConfigDocumentIr, BindError> {
        let mut rows = Vec::new();
        let mut line = 1;
        for node in cst.children() {
            let lines_here = count_newlines(node).max(1);
            if node.kind() == &SyntaxKind::Entry {
                let tok = |kind: &SyntaxKind| node.children().iter().find(|t| t.kind() == kind).and_then(token_text);
                let word = tok(&SyntaxKind::custom(ENTRY_WORD));
                let kind = word.map_or(Kind::Rule, kind_of_word);
                let (kind_label, who) = match kind {
                    Kind::Rule => ("rule".to_string(), tok(&SyntaxKind::Key).unwrap_or_default().to_string()),
                    Kind::Defaults => ("Defaults".to_string(), word.and_then(|w| w.get(9..)).unwrap_or_default().to_string()),
                    Kind::Alias => (word.unwrap_or_default().to_string(), tok(&SyntaxKind::Key).unwrap_or_default().to_string()),
                    Kind::Include => (word.unwrap_or_default().to_string(), String::new()),
                };
                let rule = flatten(tok(&SyntaxKind::Value).unwrap_or_default());
                let mut row = RowIr::new(format!("line-{line}"), "rule_table_row", SourceSpan::new(line, line + count_newlines_in_entry(node)));
                row.fields.push(FieldIr::new("kind", FieldType::String, serde_json::Value::String(kind_label)).with_validity(true));
                if kind != Kind::Include {
                    row.fields.push(FieldIr::new("who", FieldType::String, serde_json::Value::String(who)).with_validity(true));
                }
                let rule_field = FieldIr::new("rule", FieldType::String, serde_json::Value::String(rule.clone()));
                row.fields.push(if rule.is_empty() { rule_field.with_error("this entry is incomplete") } else { rule_field.with_validity(true) });
                rows.push(row);
            }
            line += lines_here;
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
                if node.kind() != &SyntaxKind::Entry {
                    return Err(EditError::RowNotFound(row_id.clone()));
                }
                let word = node.children().iter().find(|t| t.kind() == &SyntaxKind::custom(ENTRY_WORD)).and_then(token_text).map(str::to_string);
                let kind = word.as_deref().map_or(Kind::Rule, kind_of_word);
                match (field_name.as_str(), kind) {
                    ("rule", _) => {
                        if text.is_empty() {
                            return Err(EditError::InvalidValue { field: "rule".into(), message: "a rule can't be empty".into() });
                        }
                        // A multi-line entry becomes one line.
                        if !node.replace_first_token_text(&SyntaxKind::Value, &text) {
                            return Err(EditError::FieldNotFound(field_name.clone(), row_id.clone()));
                        }
                    }
                    ("who", Kind::Defaults) => {
                        let w = word.unwrap_or_default();
                        let sep = w.get(8..9).filter(|s| !s.is_empty()).unwrap_or(":");
                        let new_word = if text.is_empty() { "Defaults".to_string() } else { format!("Defaults{sep}{text}") };
                        node.replace_first_token_text(&SyntaxKind::custom(ENTRY_WORD), &new_word);
                    }
                    ("who", Kind::Rule | Kind::Alias) => {
                        if text.is_empty() || text.contains(char::is_whitespace) && !text.contains(',') {
                            return Err(EditError::InvalidValue { field: "who".into(), message: "who is a user, %group or alias, or a comma-separated list of them".into() });
                        }
                        if !node.replace_first_token_text(&SyntaxKind::Key, &text) {
                            return Err(EditError::FieldNotFound(field_name.clone(), row_id.clone()));
                        }
                    }
                    _ => return Err(EditError::Unsupported(format!("{field_name} can't be changed on this entry"))),
                }
                Ok(())
            }
            EditOp::DeleteRow { row_id } => {
                let idx = index_of(cst, row_id)?;
                children(cst)?.remove(idx);
                Ok(())
            }
            EditOp::InsertRow { after_row_id, fields } => {
                let get = |n: &str| fields.get(n).map(|v| one_line(n, v)).transpose();
                let who = get("who")?.unwrap_or_default();
                let rule = get("rule")?.unwrap_or_default();
                let kind = get("kind")?.unwrap_or_else(|| "rule".into());
                if rule.is_empty() {
                    return Err(EditError::InvalidValue { field: "rule".into(), message: "Field 'rule' is required for insertion".into() });
                }
                let line = match kind.as_str() {
                    "rule" if who.is_empty() => return Err(EditError::InvalidValue { field: "who".into(), message: "a rule needs who it's for".into() }),
                    "rule" => format!("{who} {rule}"),
                    "Defaults" if who.is_empty() => format!("Defaults {rule}"),
                    "Defaults" => format!("Defaults:{who} {rule}"),
                    k if ALIASES.contains(&k) => format!("{k} {who} = {rule}"),
                    k => return Err(EditError::Unsupported(format!("can't insert a {k} entry"))),
                };
                let mut nodes = parse_sudoers_cst(&format!("{line}\n"));
                let node = nodes.remove(0);
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

/// An entry's text with its line continuations joined.
fn flatten(value: &str) -> String {
    value.split("\\\n").map(str::trim).collect::<Vec<_>>().join(" ").trim().to_string()
}

fn one_line(field: &str, v: &serde_json::Value) -> Result<String, EditError> {
    let s = v.as_str().ok_or_else(|| EditError::InvalidValue { field: field.into(), message: "Expected a string".into() })?;
    if s.contains(['\n', '\r']) {
        return Err(EditError::InvalidValue { field: field.into(), message: "must be one line".into() });
    }
    Ok(s.trim().to_string())
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

fn token_text(node: &CstNode) -> Option<&str> {
    match node {
        CstNode::Token { text, .. } => Some(text.as_str()),
        CstNode::Rule { .. } => None,
    }
}

fn count_newlines(node: &CstNode) -> usize {
    match node {
        CstNode::Token { text, .. } => text.matches('\n').count(),
        CstNode::Rule { children, .. } => children.iter().map(count_newlines).sum(),
    }
}

/// Continuation newlines inside an entry (not its final newline).
fn count_newlines_in_entry(node: &CstNode) -> usize {
    node.children().iter().filter(|t| t.kind() != &SyntaxKind::Newline).map(count_newlines).sum()
}

fn children(cst: &mut CstNode) -> Result<&mut Vec<CstNode>, EditError> {
    cst.children_mut().ok_or_else(|| EditError::Unsupported("Root is not a rule".into()))
}

/// The node a `line-N` row id names: the entry starting on line N.
fn index_of(cst: &CstNode, row_id: &str) -> Result<usize, EditError> {
    let n: usize = row_id.strip_prefix("line-").and_then(|n| n.parse().ok()).ok_or_else(|| EditError::RowNotFound(row_id.into()))?;
    let mut line = 1;
    for (i, node) in cst.children().iter().enumerate() {
        if line == n {
            return Ok(i);
        }
        line += count_newlines(node).max(1);
    }
    Err(EditError::RowNotFound(row_id.into()))
}

/// Splits `input` into entries (joining `\` continuations), comments and
/// blank lines; every byte is kept.
pub fn parse_sudoers_cst(input: &str) -> Vec<CstNode> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut lines = input.split_inclusive('\n').peekable();
    while let Some(first) = lines.next() {
        let mut end = start + first.len();
        let mut last = first;
        // A line ending in a backslash continues (comments don't).
        let is_comment = is_comment_line(first);
        while !is_comment && body_of(last).ends_with('\\') {
            match lines.next() {
                Some(next) => {
                    end += next.len();
                    last = next;
                }
                None => break,
            }
        }
        out.push(parse_entry(&input[start..end], start));
        start = end;
    }
    out
}

fn body_of(line: &str) -> &str {
    line.strip_suffix("\r\n").or_else(|| line.strip_suffix('\n')).unwrap_or(line)
}

fn is_comment_line(line: &str) -> bool {
    let t = line.trim_start_matches([' ', '\t']);
    t.starts_with('#') && !INCLUDES.iter().any(|i| t.starts_with(i)) && !t[1..].starts_with(|c: char| c.is_ascii_digit())
}

fn parse_entry(text: &str, base: usize) -> CstNode {
    let span = |s: usize, e: usize| Span::new(base + s, base + e);
    let body_end = body_of(text).len();
    let mut tokens = Vec::new();
    let push = |tokens: &mut Vec<CstNode>, kind: SyntaxKind, s: usize, e: usize| {
        if s < e {
            tokens.push(CstNode::token(kind, &text[s..e], span(s, e)));
        }
    };
    let ws_end = |from: usize| from + text[from..body_end].len() - text[from..body_end].trim_start_matches([' ', '\t']).len();
    let word_end = |from: usize| from + text[from..body_end].find([' ', '\t', '\\', '\n']).unwrap_or(body_end - from);
    let lead = ws_end(0);
    push(&mut tokens, SyntaxKind::Whitespace, 0, lead);
    let kind = if lead == body_end {
        SyntaxKind::BlankLine
    } else if is_comment_line(text) {
        push(&mut tokens, SyntaxKind::Comment, lead, body_end);
        SyntaxKind::CommentLine
    } else {
        let w_end = word_end(lead);
        let word = &text[lead..w_end];
        let value_with_trailing = |tokens: &mut Vec<CstNode>, from: usize| {
            let v_end = from + text[from..body_end].trim_end_matches([' ', '\t']).len();
            push(tokens, SyntaxKind::Value, from, v_end);
            push(tokens, SyntaxKind::Whitespace, v_end, body_end);
        };
        match kind_of_word(word) {
            Kind::Defaults | Kind::Include => {
                push(&mut tokens, SyntaxKind::custom(ENTRY_WORD), lead, w_end);
                let v = ws_end(w_end);
                push(&mut tokens, SyntaxKind::Whitespace, w_end, v);
                value_with_trailing(&mut tokens, v);
            }
            Kind::Alias => {
                push(&mut tokens, SyntaxKind::custom(ENTRY_WORD), lead, w_end);
                let name_start = ws_end(w_end);
                push(&mut tokens, SyntaxKind::Whitespace, w_end, name_start);
                let name_end = name_start + text[name_start..body_end].find(['=', ' ', '\t']).unwrap_or(body_end - name_start);
                push(&mut tokens, SyntaxKind::Key, name_start, name_end);
                let eq = ws_end(name_end);
                push(&mut tokens, SyntaxKind::Whitespace, name_end, eq);
                if text[eq..body_end].starts_with('=') {
                    push(&mut tokens, SyntaxKind::custom(EQUALS), eq, eq + 1);
                    let v = ws_end(eq + 1);
                    push(&mut tokens, SyntaxKind::Whitespace, eq + 1, v);
                    value_with_trailing(&mut tokens, v);
                } else {
                    value_with_trailing(&mut tokens, eq);
                }
            }
            Kind::Rule => {
                // Who: a list like "alice, bob" may have spaces after commas.
                let mut who_end = lead;
                loop {
                    who_end = word_end(who_end);
                    let next = ws_end(who_end);
                    // Only on progress: a ',' right before a '\' would
                    // otherwise loop forever.
                    if text[lead..who_end].ends_with(',') && next < body_end && next > who_end {
                        who_end = next;
                        continue;
                    }
                    break;
                }
                push(&mut tokens, SyntaxKind::Key, lead, who_end);
                let v = ws_end(who_end);
                push(&mut tokens, SyntaxKind::Whitespace, who_end, v);
                value_with_trailing(&mut tokens, v);
            }
        }
        if tokens.iter().any(|t| t.kind() == &SyntaxKind::Value) { SyntaxKind::Entry } else { SyntaxKind::Error }
    };
    push(&mut tokens, SyntaxKind::Newline, body_end, text.len());
    CstNode::rule(kind, tokens, span(0, text.len()))
}
