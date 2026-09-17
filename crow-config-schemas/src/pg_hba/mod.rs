use crow_config_core::cst::{CstNode, SourceSpan, Span, SyntaxKind};
use crow_config_core::edit::{BindError, ConfigPlugin, EditError, EditOp, ParseError};
use crow_config_core::ir::{ConfigDocumentIr, FieldIr, RowIr, ShapeIr};
use crow_config_core::schema::{validate_field_value, FieldType, PluginManifest};
use std::sync::LazyLock;

pub const PG_HBA_MANIFEST_TOML: &str = include_str!("../../plugins/pg_hba.toml");

pub static PG_HBA_MANIFEST: LazyLock<PluginManifest> = LazyLock::new(|| {
    PluginManifest::from_toml_str(PG_HBA_MANIFEST_TOML)
        .expect("Failed to parse embedded pg_hba.toml manifest")
});

/// Lossless parser and plugin for PostgreSQL `pg_hba.conf`.
#[derive(Debug, Clone)]
pub struct PgHbaPlugin {
    manifest: &'static PluginManifest,
}

impl PgHbaPlugin {
    pub fn new() -> Self {
        Self {
            manifest: &PG_HBA_MANIFEST,
        }
    }
}

impl Default for PgHbaPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigPlugin for PgHbaPlugin {
    fn manifest(&self) -> &PluginManifest {
        self.manifest
    }

    fn parse(&self, text: &str) -> Result<CstNode, ParseError> {
        let lines = parse_pg_hba_cst(text);
        let total_span = Span::new(0, text.len());
        Ok(CstNode::rule(SyntaxKind::Document, lines, total_span))
    }

    fn to_ir(&self, cst: &CstNode) -> Result<ConfigDocumentIr, BindError> {
        let mut rows = Vec::new();
        let mut current_line = 1;

        for line_node in cst.children() {
            let line_no = current_line;

            if line_node.kind() == &SyntaxKind::Entry {
                let row_id = format!("line-{}", line_no);
                let mut row = RowIr::new(
                    row_id,
                    "rule_table_row",
                    SourceSpan::single_line(line_no),
                );

                let mut conn_type: Option<String> = None;
                let mut database: Option<String> = None;
                let mut user: Option<String> = None;
                let mut address: Option<String> = None;
                let mut method: Option<String> = None;
                let mut options: Option<String> = None;
                let mut comment_val: Option<String> = None;

                for token in line_node.children() {
                    if let CstNode::Token { kind, text, .. } = token {
                        match kind.as_str() {
                            "type" => conn_type = Some(text.clone()),
                            "database" => database = Some(text.clone()),
                            "user" => user = Some(text.clone()),
                            "address" => address = Some(text.clone()),
                            "method" => method = Some(text.clone()),
                            "options" => options = Some(text.clone()),
                            "comment" => {
                                let trimmed = text.trim_start_matches('#').trim();
                                comment_val = Some(trimmed.to_string());
                            }
                            _ => {}
                        }
                    }
                }

                if let Some(t) = conn_type {
                    let mut type_field = FieldIr::new(
                        "type",
                        FieldType::Enum,
                        serde_json::Value::String(t.clone()),
                    );
                    if let Some(def) = self.manifest.find_field("type") {
                        if validate_field_value(def, &serde_json::Value::String(t)).is_ok() {
                            type_field = type_field.with_validity(true);
                        }
                        type_field.options = def.options.clone();
                    }
                    row.fields.push(type_field);
                }

                if let Some(db) = database {
                    row.fields.push(FieldIr::new(
                        "database",
                        FieldType::String,
                        serde_json::Value::String(db),
                    ));
                }

                if let Some(u) = user {
                    row.fields.push(FieldIr::new(
                        "user",
                        FieldType::String,
                        serde_json::Value::String(u),
                    ));
                }

                if let Some(addr) = address {
                    row.fields.push(FieldIr::new(
                        "address",
                        FieldType::String,
                        serde_json::Value::String(addr),
                    ));
                }

                if let Some(m) = method {
                    let mut method_field = FieldIr::new(
                        "method",
                        FieldType::Enum,
                        serde_json::Value::String(m.clone()),
                    );
                    if let Some(def) = self.manifest.find_field("method") {
                        if validate_field_value(def, &serde_json::Value::String(m)).is_ok() {
                            method_field = method_field.with_validity(true);
                        }
                        method_field.options = def.options.clone();
                        method_field.docs_source = def.docs_source.clone();
                        method_field.help = def.help.clone();
                    }
                    row.fields.push(method_field);
                }

                if let Some(opt) = options {
                    row.fields.push(FieldIr::new(
                        "options",
                        FieldType::String,
                        serde_json::Value::String(opt),
                    ));
                }

                if let Some(comm) = comment_val {
                    row.fields.push(FieldIr::new(
                        "comment",
                        FieldType::String,
                        serde_json::Value::String(comm),
                    ));
                }

                rows.push(row);
            }

            let newlines = count_newlines_in_node(line_node);
            current_line += newlines.max(1);
        }

        Ok(ConfigDocumentIr {
            plugin_name: self.manifest.plugin.name.clone(),
            shape: ShapeIr {
                kind: self.manifest.shape.kind,
                order_sensitive: self.manifest.shape.order_sensitive,
                order_note: self.manifest.shape.order_note.clone(),
            },
            rows,
        })
    }

    fn apply_edit(&self, cst: &mut CstNode, op: &EditOp) -> Result<(), EditError> {
        match op {
            EditOp::UpdateField {
                row_id,
                field_name,
                new_value,
            } => {
                let target_line_no = parse_row_id_line(row_id)?;
                let line_node = find_line_node_mut(cst, target_line_no)
                    .ok_or_else(|| EditError::RowNotFound(row_id.clone()))?;

                if field_name == "comment" {
                    replace_or_set_comment_in_line(line_node, new_value)?;
                } else {
                    let val_str = new_value.as_str().ok_or_else(|| EditError::InvalidValue {
                        field: field_name.clone(),
                        message: "Expected string value".to_string(),
                    })?;

                    let target_kind = SyntaxKind::custom(field_name.as_str());
                    if !line_node.replace_first_token_text(&target_kind, val_str) {
                        return Err(EditError::FieldNotFound(
                            field_name.clone(),
                            row_id.clone(),
                        ));
                    }
                }
                Ok(())
            }
            EditOp::MoveRow {
                row_id,
                after_row_id,
                before_row_id,
            } => {
                let src_line_no = parse_row_id_line(row_id)?;
                let children = cst
                    .children_mut()
                    .ok_or_else(|| EditError::Unsupported("Root is not a rule".to_string()))?;

                let src_idx = find_rule_index_by_line(children, src_line_no)
                    .ok_or_else(|| EditError::RowNotFound(row_id.clone()))?;

                let removed_node = children.remove(src_idx);

                if let Some(before_id) = before_row_id {
                    let before_line_no = parse_row_id_line(before_id)?;
                    let insert_idx = find_rule_index_by_line(children, before_line_no)
                        .ok_or_else(|| EditError::RowNotFound(before_id.clone()))?;
                    children.insert(insert_idx, removed_node);
                } else if let Some(after_id) = after_row_id {
                    let after_line_no = parse_row_id_line(after_id)?;
                    let after_idx = find_rule_index_by_line(children, after_line_no)
                        .ok_or_else(|| EditError::RowNotFound(after_id.clone()))?;
                    children.insert(after_idx + 1, removed_node);
                } else {
                    children.push(removed_node);
                }

                Ok(())
            }
            EditOp::DeleteRow { row_id } => {
                let target_line_no = parse_row_id_line(row_id)?;
                let children = cst
                    .children_mut()
                    .ok_or_else(|| EditError::Unsupported("Root is not a rule".to_string()))?;

                let idx = find_rule_index_by_line(children, target_line_no)
                    .ok_or_else(|| EditError::RowNotFound(row_id.clone()))?;
                children.remove(idx);
                Ok(())
            }
            EditOp::InsertRow {
                after_row_id,
                fields,
            } => {
                let conn_type = fields.get("type").and_then(|v| v.as_str()).unwrap_or("host");
                let database = fields.get("database").and_then(|v| v.as_str()).unwrap_or("all");
                let user = fields.get("user").and_then(|v| v.as_str()).unwrap_or("all");
                let address = fields.get("address").and_then(|v| v.as_str());
                let method = fields.get("method").and_then(|v| v.as_str()).unwrap_or("scram-sha-256");
                let options = fields.get("options").and_then(|v| v.as_str());
                let comment = fields.get("comment").and_then(|v| v.as_str());

                let mut tokens = Vec::new();
                tokens.push(CstNode::token(SyntaxKind::custom("type"), conn_type, Span::default()));
                tokens.push(CstNode::token(SyntaxKind::Whitespace, "\t", Span::default()));

                tokens.push(CstNode::token(SyntaxKind::custom("database"), database, Span::default()));
                tokens.push(CstNode::token(SyntaxKind::Whitespace, "\t", Span::default()));

                tokens.push(CstNode::token(SyntaxKind::custom("user"), user, Span::default()));
                tokens.push(CstNode::token(SyntaxKind::Whitespace, "\t", Span::default()));

                if conn_type != "local" {
                    let addr = address.unwrap_or("127.0.0.1/32");
                    tokens.push(CstNode::token(SyntaxKind::custom("address"), addr, Span::default()));
                    tokens.push(CstNode::token(SyntaxKind::Whitespace, "\t", Span::default()));
                }

                tokens.push(CstNode::token(SyntaxKind::custom("method"), method, Span::default()));

                if let Some(opt) = options {
                    tokens.push(CstNode::token(SyntaxKind::Whitespace, "\t", Span::default()));
                    tokens.push(CstNode::token(SyntaxKind::custom("options"), opt, Span::default()));
                }

                if let Some(comm) = comment {
                    tokens.push(CstNode::token(SyntaxKind::Whitespace, "  ", Span::default()));
                    tokens.push(CstNode::token(SyntaxKind::Comment, format!("# {}", comm), Span::default()));
                }

                tokens.push(CstNode::token(SyntaxKind::Newline, "\n", Span::default()));

                let new_line = CstNode::rule(SyntaxKind::Entry, tokens, Span::default());
                let children = cst.children_mut().ok_or_else(|| EditError::Unsupported("Root is not a rule".to_string()))?;

                if let Some(target_id) = after_row_id {
                    let target_line_no = parse_row_id_line(target_id)?;
                    let idx = find_rule_index_by_line(children, target_line_no)
                        .ok_or_else(|| EditError::RowNotFound(target_id.clone()))?;
                    children.insert(idx + 1, new_line);
                } else {
                    children.push(new_line);
                }

                Ok(())
            }
        }
    }
}

fn parse_row_id_line(row_id: &str) -> Result<usize, EditError> {
    if let Some(num_str) = row_id.strip_prefix("line-") {
        num_str
            .parse::<usize>()
            .map_err(|_| EditError::RowNotFound(row_id.to_string()))
    } else {
        Err(EditError::RowNotFound(row_id.to_string()))
    }
}

fn find_line_node_mut<'a>(cst: &'a mut CstNode, target_line_no: usize) -> Option<&'a mut CstNode> {
    let children = cst.children_mut()?;
    let mut current_line = 1;

    for line in children.iter_mut() {
        let line_no = current_line;
        if line_no == target_line_no {
            return Some(line);
        }
        let newlines = count_newlines_in_node(line);
        current_line += newlines.max(1);
    }
    None
}

fn find_rule_index_by_line(children: &[CstNode], target_line_no: usize) -> Option<usize> {
    let mut current_line = 1;
    for (idx, line) in children.iter().enumerate() {
        let line_no = current_line;
        if line_no == target_line_no {
            return Some(idx);
        }
        let newlines = count_newlines_in_node(line);
        current_line += newlines.max(1);
    }
    None
}

fn replace_or_set_comment_in_line(
    line_node: &mut CstNode,
    new_value: &serde_json::Value,
) -> Result<(), EditError> {
    let children = line_node
        .children_mut()
        .ok_or_else(|| EditError::Unsupported("Line node is not a rule".to_string()))?;

    if new_value.is_null() || new_value.as_str() == Some("") {
        if let Some(idx) = children.iter().position(|c| c.kind() == &SyntaxKind::Comment) {
            if idx > 0 && children[idx - 1].kind() == &SyntaxKind::Whitespace {
                children.drain((idx - 1)..=idx);
            } else {
                children.remove(idx);
            }
        }
    } else {
        let text = new_value.as_str().ok_or_else(|| EditError::InvalidValue {
            field: "comment".to_string(),
            message: "Comment must be a string".to_string(),
        })?;
        let formatted_comment = format!("# {}", text);

        if let Some(comm_node) = children
            .iter_mut()
            .find(|c| c.kind() == &SyntaxKind::Comment)
        {
            if let CstNode::Token { text: c_text, .. } = comm_node {
                *c_text = formatted_comment;
            }
        } else {
            let insert_idx = children
                .iter()
                .position(|c| c.kind() == &SyntaxKind::Newline)
                .unwrap_or(children.len());

            children.insert(
                insert_idx,
                CstNode::token(SyntaxKind::Whitespace, "  ", Span::default()),
            );
            children.insert(
                insert_idx + 1,
                CstNode::token(SyntaxKind::Comment, formatted_comment, Span::default()),
            );
        }
    }

    Ok(())
}

fn count_newlines_in_node(node: &CstNode) -> usize {
    match node {
        CstNode::Token { text, .. } => text.chars().filter(|&c| c == '\n').count(),
        CstNode::Rule { children, .. } => children.iter().map(count_newlines_in_node).sum(),
    }
}

/// Lossless line-oriented parser for `pg_hba.conf`.
pub fn parse_pg_hba_cst(input: &str) -> Vec<CstNode> {
    let mut lines = Vec::new();
    let bytes = input.as_bytes();
    let mut offset = 0;

    while offset < bytes.len() {
        let line_start = offset;
        let mut line_end = line_start;
        while line_end < bytes.len() && bytes[line_end] != b'\n' {
            line_end += 1;
        }
        if line_end < bytes.len() && bytes[line_end] == b'\n' {
            line_end += 1;
        }

        let line_slice = &input[line_start..line_end];
        let parsed_line = parse_single_pg_hba_line(line_slice, line_start);
        lines.push(parsed_line);

        offset = line_end;
    }

    lines
}

fn parse_single_pg_hba_line(line: &str, base_offset: usize) -> CstNode {
    let line_span = Span::new(base_offset, base_offset + line.len());
    let chars: Vec<(usize, char)> = line.char_indices().collect();

    if chars.is_empty() {
        return CstNode::rule(SyntaxKind::BlankLine, Vec::new(), line_span);
    }

    let mut idx = 0;

    // Scan leading whitespace
    while idx < chars.len() && (chars[idx].1 == ' ' || chars[idx].1 == '\t') {
        idx += 1;
    }

    let leading_ws_byte_len = if idx < chars.len() {
        chars[idx].0
    } else {
        line.len()
    };

    let leading_ws_token = if leading_ws_byte_len > 0 {
        Some(CstNode::token(
            SyntaxKind::Whitespace,
            &line[..leading_ws_byte_len],
            Span::new(base_offset, base_offset + leading_ws_byte_len),
        ))
    } else {
        None
    };

    // Find trailing newline
    let (content_end, newline_token) = if line.ends_with("\r\n") {
        let nl_start = line.len() - 2;
        (
            nl_start,
            Some(CstNode::token(
                SyntaxKind::Newline,
                &line[nl_start..],
                Span::new(base_offset + nl_start, base_offset + line.len()),
            )),
        )
    } else if line.ends_with('\n') {
        let nl_start = line.len() - 1;
        (
            nl_start,
            Some(CstNode::token(
                SyntaxKind::Newline,
                &line[nl_start..],
                Span::new(base_offset + nl_start, base_offset + line.len()),
            )),
        )
    } else {
        (line.len(), None)
    };

    // Check blank line
    if leading_ws_byte_len >= content_end {
        let mut tokens = Vec::new();
        if let Some(ws) = leading_ws_token {
            tokens.push(ws);
        }
        if let Some(nl) = newline_token {
            tokens.push(nl);
        }
        return CstNode::rule(SyntaxKind::BlankLine, tokens, line_span);
    }

    // Check comment line
    if chars[idx].1 == '#' {
        let mut tokens = Vec::new();
        if let Some(ws) = leading_ws_token {
            tokens.push(ws);
        }
        let comment_start = chars[idx].0;
        tokens.push(CstNode::token(
            SyntaxKind::Comment,
            &line[comment_start..content_end],
            Span::new(base_offset + comment_start, base_offset + content_end),
        ));
        if let Some(nl) = newline_token {
            tokens.push(nl);
        }
        return CstNode::rule(SyntaxKind::CommentLine, tokens, line_span);
    }

    // Parse tokens and interstitial whitespace
    // A token can be quoted: "..."
    let mut words: Vec<(usize, usize, String)> = Vec::new();
    let mut separators: Vec<(usize, usize)> = Vec::new();

    let mut comment_start_byte = None;

    while idx < chars.len() && chars[idx].0 < content_end {
        if chars[idx].1 == '#' {
            comment_start_byte = Some(chars[idx].0);
            break;
        }

        let w_start = chars[idx].0;
        let mut in_quotes = false;
        while idx < chars.len() && chars[idx].0 < content_end {
            let c = chars[idx].1;
            if c == '"' {
                in_quotes = !in_quotes;
            } else if !in_quotes && (c == ' ' || c == '\t' || c == '#') {
                break;
            }
            idx += 1;
        }
        let w_end = if idx < chars.len() {
            chars[idx].0.min(content_end)
        } else {
            content_end
        };

        let word_text = line[w_start..w_end].to_string();
        words.push((w_start, w_end, word_text));

        // Scan whitespace after word
        let sep_s = w_end;
        while idx < chars.len() && chars[idx].0 < content_end && (chars[idx].1 == ' ' || chars[idx].1 == '\t') {
            idx += 1;
        }
        let sep_e = if idx < chars.len() {
            chars[idx].0.min(content_end)
        } else {
            content_end
        };

        separators.push((sep_s, sep_e));
    }

    if words.is_empty() {
        return make_error_pg_hba_line(line, base_offset, leading_ws_token, leading_ws_byte_len, content_end, newline_token, line_span);
    }

    let conn_type_str = &words[0].2;
    let is_local = conn_type_str == "local";

    // Expected minimum words: local requires at least 4 (type, db, user, method)
    // Non-local requires at least 5 (type, db, user, addr, method)
    let min_words = if is_local { 4 } else { 5 };
    if words.len() < min_words {
        return make_error_pg_hba_line(line, base_offset, leading_ws_token, leading_ws_byte_len, content_end, newline_token, line_span);
    }

    let mut tokens = Vec::new();
    if let Some(ws) = leading_ws_token {
        tokens.push(ws);
    }

    for (w_idx, (w_s, w_e, _text)) in words.iter().enumerate() {
        let kind = if is_local {
            match w_idx {
                0 => SyntaxKind::custom("type"),
                1 => SyntaxKind::custom("database"),
                2 => SyntaxKind::custom("user"),
                3 => SyntaxKind::custom("method"),
                _ => SyntaxKind::custom("options"),
            }
        } else {
            match w_idx {
                0 => SyntaxKind::custom("type"),
                1 => SyntaxKind::custom("database"),
                2 => SyntaxKind::custom("user"),
                3 => SyntaxKind::custom("address"),
                4 => SyntaxKind::custom("method"),
                _ => SyntaxKind::custom("options"),
            }
        };

        tokens.push(CstNode::token(
            kind,
            &line[*w_s..*w_e],
            Span::new(base_offset + w_s, base_offset + w_e),
        ));

        if w_idx < separators.len() {
            let (s_s, s_e) = separators[w_idx];
            if s_s < s_e {
                tokens.push(CstNode::token(
                    SyntaxKind::Whitespace,
                    &line[s_s..s_e],
                    Span::new(base_offset + s_s, base_offset + s_e),
                ));
            }
        }
    }

    if let Some(c_s) = comment_start_byte {
        tokens.push(CstNode::token(
            SyntaxKind::Comment,
            &line[c_s..content_end],
            Span::new(base_offset + c_s, base_offset + content_end),
        ));
    }

    if let Some(nl) = newline_token {
        tokens.push(nl);
    }

    CstNode::rule(SyntaxKind::Entry, tokens, line_span)
}

fn make_error_pg_hba_line(
    line: &str,
    base_offset: usize,
    leading_ws: Option<CstNode>,
    content_start: usize,
    content_end: usize,
    newline: Option<CstNode>,
    line_span: Span,
) -> CstNode {
    let mut tokens = Vec::new();
    if let Some(ws) = leading_ws {
        tokens.push(ws);
    }
    if content_start < content_end {
        tokens.push(CstNode::token(
            SyntaxKind::Error,
            &line[content_start..content_end],
            Span::new(base_offset + content_start, base_offset + content_end),
        ));
    }
    if let Some(nl) = newline {
        tokens.push(nl);
    }
    CstNode::rule(SyntaxKind::Error, tokens, line_span)
}
