use crow_config_core::cst::{CstNode, SourceSpan, Span, SyntaxKind};
use crow_config_core::edit::{BindError, ConfigPlugin, EditError, EditOp, ParseError};
use crow_config_core::ir::{ConfigDocumentIr, FieldIr, RowIr, ShapeIr};
use crow_config_core::schema::{validate_field_value, FieldType, PluginManifest};
use std::sync::LazyLock;

pub const UFW_MANIFEST_TOML: &str = include_str!("../../plugins/ufw.toml");

pub static UFW_MANIFEST: LazyLock<PluginManifest> = LazyLock::new(|| {
    PluginManifest::from_toml_str(UFW_MANIFEST_TOML)
        .expect("Failed to parse embedded ufw.toml manifest")
});

/// Lossless parser and plugin for UFW firewall rules.
#[derive(Debug, Clone)]
pub struct UfwPlugin {
    manifest: &'static PluginManifest,
}

impl UfwPlugin {
    pub fn new() -> Self {
        Self {
            manifest: &UFW_MANIFEST,
        }
    }
}

impl Default for UfwPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigPlugin for UfwPlugin {
    fn manifest(&self) -> &PluginManifest {
        self.manifest
    }

    fn parse(&self, text: &str) -> Result<CstNode, ParseError> {
        let lines = parse_ufw_cst(text);
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

                let mut action: Option<String> = None;
                let mut direction: Option<String> = None;
                let mut proto: Option<String> = None;
                let mut from_val: Option<String> = None;
                let mut to_val: Option<String> = None;
                let mut port_val: Option<String> = None;
                let mut comment_val: Option<String> = None;

                for token in line_node.children() {
                    if let CstNode::Token { kind, text, .. } = token {
                        match kind.as_str() {
                            "action" => action = Some(text.clone()),
                            "direction" => direction = Some(text.clone()),
                            "proto" => proto = Some(text.clone()),
                            "from" => from_val = Some(text.clone()),
                            "to" => to_val = Some(text.clone()),
                            "port" => port_val = Some(text.clone()),
                            "comment" => {
                                let trimmed = text.trim_start_matches('#').trim();
                                comment_val = Some(trimmed.to_string());
                            }
                            _ => {}
                        }
                    }
                }

                if let Some(act) = action {
                    let mut act_field = FieldIr::new(
                        "action",
                        FieldType::Enum,
                        serde_json::Value::String(act.clone()),
                    );
                    if let Some(def) = self.manifest.find_field("action") {
                        if validate_field_value(def, &serde_json::Value::String(act)).is_ok() {
                            act_field = act_field.with_validity(true);
                        }
                        act_field.options = def.options.clone();
                    }
                    row.fields.push(act_field);
                }

                if let Some(dir) = direction {
                    let mut dir_field = FieldIr::new(
                        "direction",
                        FieldType::Enum,
                        serde_json::Value::String(dir.clone()),
                    );
                    if let Some(def) = self.manifest.find_field("direction") {
                        if validate_field_value(def, &serde_json::Value::String(dir)).is_ok() {
                            dir_field = dir_field.with_validity(true);
                        }
                        dir_field.options = def.options.clone();
                    }
                    row.fields.push(dir_field);
                }

                if let Some(pr) = proto {
                    let mut pr_field = FieldIr::new(
                        "proto",
                        FieldType::Enum,
                        serde_json::Value::String(pr.clone()),
                    );
                    if let Some(def) = self.manifest.find_field("proto") {
                        if validate_field_value(def, &serde_json::Value::String(pr)).is_ok() {
                            pr_field = pr_field.with_validity(true);
                        }
                        pr_field.options = def.options.clone();
                    }
                    row.fields.push(pr_field);
                }

                if let Some(f) = from_val {
                    row.fields.push(FieldIr::new("from", FieldType::String, serde_json::Value::String(f)));
                }

                if let Some(t) = to_val {
                    row.fields.push(FieldIr::new("to", FieldType::String, serde_json::Value::String(t)));
                }

                if let Some(p) = port_val {
                    row.fields.push(FieldIr::new("port", FieldType::String, serde_json::Value::String(p)));
                }

                if let Some(c) = comment_val {
                    row.fields.push(FieldIr::new("comment", FieldType::String, serde_json::Value::String(c)));
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
                let action = fields.get("action").and_then(|v| v.as_str()).unwrap_or("ALLOW");
                let direction = fields.get("direction").and_then(|v| v.as_str()).unwrap_or("in");
                let proto = fields.get("proto").and_then(|v| v.as_str()).unwrap_or("tcp");
                let from_val = fields.get("from").and_then(|v| v.as_str()).unwrap_or("any");
                let to_val = fields.get("to").and_then(|v| v.as_str()).unwrap_or("any");
                let port = fields.get("port").and_then(|v| v.as_str()).unwrap_or("any");
                let comment = fields.get("comment").and_then(|v| v.as_str());

                let mut tokens = Vec::new();
                tokens.push(CstNode::token(SyntaxKind::custom("action"), action, Span::default()));
                tokens.push(CstNode::token(SyntaxKind::Whitespace, "\t", Span::default()));

                tokens.push(CstNode::token(SyntaxKind::custom("direction"), direction, Span::default()));
                tokens.push(CstNode::token(SyntaxKind::Whitespace, "\t", Span::default()));

                tokens.push(CstNode::token(SyntaxKind::custom("proto"), proto, Span::default()));
                tokens.push(CstNode::token(SyntaxKind::Whitespace, "\t", Span::default()));

                tokens.push(CstNode::token(SyntaxKind::custom("from"), from_val, Span::default()));
                tokens.push(CstNode::token(SyntaxKind::Whitespace, "\t", Span::default()));

                tokens.push(CstNode::token(SyntaxKind::custom("to"), to_val, Span::default()));
                tokens.push(CstNode::token(SyntaxKind::Whitespace, "\t", Span::default()));

                tokens.push(CstNode::token(SyntaxKind::custom("port"), port, Span::default()));

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

/// Lossless line-oriented parser for UFW rules.
pub fn parse_ufw_cst(input: &str) -> Vec<CstNode> {
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
        let parsed_line = parse_single_ufw_line(line_slice, line_start);
        lines.push(parsed_line);

        offset = line_end;
    }

    lines
}

fn parse_single_ufw_line(line: &str, base_offset: usize) -> CstNode {
    let line_span = Span::new(base_offset, base_offset + line.len());
    let chars: Vec<(usize, char)> = line.char_indices().collect();

    if chars.is_empty() {
        return CstNode::rule(SyntaxKind::BlankLine, Vec::new(), line_span);
    }

    let mut idx = 0;

    // Leading whitespace
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

    // Trailing newline
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

    // Blank line check
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

    // Comment line check
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

    // Parse words
    let mut words: Vec<(usize, usize)> = Vec::new();
    let mut separators: Vec<(usize, usize)> = Vec::new();
    let mut comment_start_byte = None;

    while idx < chars.len() && chars[idx].0 < content_end {
        if chars[idx].1 == '#' {
            comment_start_byte = Some(chars[idx].0);
            break;
        }

        let w_start = chars[idx].0;
        while idx < chars.len() && chars[idx].0 < content_end && chars[idx].1 != ' ' && chars[idx].1 != '\t' && chars[idx].1 != '#' {
            idx += 1;
        }
        let w_end = if idx < chars.len() { chars[idx].0.min(content_end) } else { content_end };
        words.push((w_start, w_end));

        let sep_s = w_end;
        while idx < chars.len() && chars[idx].0 < content_end && (chars[idx].1 == ' ' || chars[idx].1 == '\t') {
            idx += 1;
        }
        let sep_e = if idx < chars.len() { chars[idx].0.min(content_end) } else { content_end };
        separators.push((sep_s, sep_e));
    }

    // Require at least 6 columns: ACTION DIRECTION PROTO FROM TO PORT
    if words.len() < 6 {
        return make_error_ufw_line(line, base_offset, leading_ws_token, leading_ws_byte_len, content_end, newline_token, line_span);
    }

    let mut tokens = Vec::new();
    if let Some(ws) = leading_ws_token {
        tokens.push(ws);
    }

    let col_kinds = [
        SyntaxKind::custom("action"),
        SyntaxKind::custom("direction"),
        SyntaxKind::custom("proto"),
        SyntaxKind::custom("from"),
        SyntaxKind::custom("to"),
        SyntaxKind::custom("port"),
    ];

    for (w_idx, (w_s, w_e)) in words.iter().enumerate() {
        let kind = if w_idx < col_kinds.len() {
            col_kinds[w_idx].clone()
        } else {
            SyntaxKind::custom("extra")
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

fn make_error_ufw_line(
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
