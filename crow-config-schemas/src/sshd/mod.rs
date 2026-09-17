use crow_config_core::cst::{CstNode, SourceSpan, Span, SyntaxKind};
use crow_config_core::edit::{BindError, ConfigPlugin, EditError, EditOp, ParseError};
use crow_config_core::ir::{ConfigDocumentIr, FieldIr, RowIr, ShapeIr};
use crow_config_core::schema::{validate_field_value, FieldType, PluginManifest};
use std::sync::LazyLock;

pub const SSHD_MANIFEST_TOML: &str = include_str!("../../plugins/sshd_config.toml");

pub static SSHD_MANIFEST: LazyLock<PluginManifest> = LazyLock::new(|| {
    PluginManifest::from_toml_str(SSHD_MANIFEST_TOML)
        .expect("Failed to parse embedded sshd_config.toml manifest")
});

/// Lossless parser and plugin for OpenSSH `sshd_config`.
#[derive(Debug, Clone)]
pub struct SshdPlugin {
    manifest: &'static PluginManifest,
}

impl SshdPlugin {
    pub fn new() -> Self {
        Self {
            manifest: &SSHD_MANIFEST,
        }
    }
}

impl Default for SshdPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigPlugin for SshdPlugin {
    fn manifest(&self) -> &PluginManifest {
        self.manifest
    }

    fn parse(&self, text: &str) -> Result<CstNode, ParseError> {
        let lines = parse_sshd_cst(text);
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
                    "key_value_list_row",
                    SourceSpan::single_line(line_no),
                );

                let mut key_str: Option<String> = None;
                let mut val_str: Option<String> = None;
                let mut comment_val: Option<String> = None;

                for token in line_node.children() {
                    match token.kind() {
                        SyntaxKind::Key => {
                            if let CstNode::Token { text, .. } = token {
                                key_str = Some(text.clone());
                            }
                        }
                        SyntaxKind::Value => {
                            if let CstNode::Token { text, .. } = token {
                                val_str = Some(text.clone());
                            }
                        }
                        SyntaxKind::Comment => {
                            if let CstNode::Token { text, .. } = token {
                                let trimmed = text.trim_start_matches('#').trim();
                                comment_val = Some(trimmed.to_string());
                            }
                        }
                        _ => {}
                    }
                }

                if let (Some(key), Some(val)) = (key_str, val_str) {
                    // Match field in manifest case-insensitively
                    let field_def = self
                        .manifest
                        .fields
                        .iter()
                        .find(|f| f.name.eq_ignore_ascii_case(&key));

                    let (field_name, field_type) = match field_def {
                        Some(def) => (def.name.clone(), def.field_type.clone()),
                        None => (key, FieldType::String),
                    };

                    let json_val = if field_type == FieldType::StringList {
                        let parts: Vec<String> =
                            val.split_whitespace().map(|s| s.to_string()).collect();
                        serde_json::to_value(&parts).unwrap_or_default()
                    } else {
                        serde_json::Value::String(val)
                    };

                    let mut field_ir = FieldIr::new(field_name, field_type, json_val.clone());

                    if let Some(def) = field_def {
                        match validate_field_value(def, &json_val) {
                            Ok(()) => field_ir = field_ir.with_validity(true),
                            Err(e) => field_ir = field_ir.with_error(e),
                        }
                        field_ir.options = def.options.clone();
                        field_ir.docs_source = def.docs_source.clone();
                        field_ir.help = def.help.clone();
                    }

                    row.fields.push(field_ir);
                }

                if let Some(comment) = comment_val {
                    row.fields.push(FieldIr::new(
                        "comment",
                        FieldType::String,
                        serde_json::Value::String(comment),
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
                    let val_str = match new_value {
                        serde_json::Value::String(s) => s.clone(),
                        serde_json::Value::Number(n) => n.to_string(),
                        serde_json::Value::Bool(b) => {
                            if *b {
                                "yes".to_string()
                            } else {
                                "no".to_string()
                            }
                        }
                        serde_json::Value::Array(arr) => arr
                            .iter()
                            .filter_map(|v| v.as_str())
                            .collect::<Vec<_>>()
                            .join(" "),
                        _ => {
                            return Err(EditError::InvalidValue {
                                field: field_name.clone(),
                                message: "Unsupported JSON value type for directive".to_string(),
                            });
                        }
                    };

                    let key_token = line_node
                        .children()
                        .iter()
                        .find(|c| c.kind() == &SyntaxKind::Key);

                    let key_matches = match key_token {
                        Some(CstNode::Token { text, .. }) => {
                            text.eq_ignore_ascii_case(field_name)
                        }
                        _ => false,
                    };

                    if !key_matches {
                        return Err(EditError::FieldNotFound(
                            field_name.clone(),
                            row_id.clone(),
                        ));
                    }

                    if !line_node.replace_first_token_text(&SyntaxKind::Value, &val_str) {
                        return Err(EditError::FieldNotFound(
                            field_name.clone(),
                            row_id.clone(),
                        ));
                    }
                }
                Ok(())
            }
            EditOp::DeleteRow { row_id } => {
                let target_line_no = parse_row_id_line(row_id)?;
                let children = cst
                    .children_mut()
                    .ok_or_else(|| EditError::Unsupported("Root is not a rule".to_string()))?;

                let mut current_line = 1;
                let mut found_idx = None;

                for (idx, line) in children.iter().enumerate() {
                    let line_no = current_line;
                    if line_no == target_line_no {
                        found_idx = Some(idx);
                        break;
                    }
                    let newlines = count_newlines_in_node(line);
                    current_line += newlines.max(1);
                }

                if let Some(idx) = found_idx {
                    children.remove(idx);
                    Ok(())
                } else {
                    Err(EditError::RowNotFound(row_id.clone()))
                }
            }
            EditOp::InsertRow {
                after_row_id,
                fields,
            } => {
                let mut key = None;
                let mut value = None;
                let mut comment = None;

                for (k, v) in fields {
                    if k == "comment" {
                        comment = v.as_str();
                    } else {
                        key = Some(k.as_str());
                        value = match v {
                            serde_json::Value::String(s) => Some(s.clone()),
                            serde_json::Value::Number(n) => Some(n.to_string()),
                            serde_json::Value::Bool(b) => {
                                Some(if *b { "yes".to_string() } else { "no".to_string() })
                            }
                            serde_json::Value::Array(arr) => Some(
                                arr.iter()
                                    .filter_map(|x| x.as_str())
                                    .collect::<Vec<_>>()
                                    .join(" "),
                            ),
                            _ => None,
                        };
                    }
                }

                let key_str = key.ok_or_else(|| EditError::InvalidValue {
                    field: "directive".to_string(),
                    message: "Directive key is required for insertion".to_string(),
                })?;

                let val_str = value.ok_or_else(|| EditError::InvalidValue {
                    field: key_str.to_string(),
                    message: "Directive value is required for insertion".to_string(),
                })?;

                let mut tokens = Vec::new();
                tokens.push(CstNode::token(
                    SyntaxKind::Key,
                    key_str,
                    Span::default(),
                ));
                tokens.push(CstNode::token(
                    SyntaxKind::Whitespace,
                    " ",
                    Span::default(),
                ));
                tokens.push(CstNode::token(
                    SyntaxKind::Value,
                    val_str,
                    Span::default(),
                ));

                if let Some(c) = comment {
                    tokens.push(CstNode::token(
                        SyntaxKind::Whitespace,
                        "  ",
                        Span::default(),
                    ));
                    tokens.push(CstNode::token(
                        SyntaxKind::Comment,
                        format!("# {}", c),
                        Span::default(),
                    ));
                }

                tokens.push(CstNode::token(
                    SyntaxKind::Newline,
                    "\n",
                    Span::default(),
                ));

                let new_line = CstNode::rule(SyntaxKind::Entry, tokens, Span::default());

                let children = cst
                    .children_mut()
                    .ok_or_else(|| EditError::Unsupported("Root is not a rule".to_string()))?;

                if let Some(target_id) = after_row_id {
                    let target_line_no = parse_row_id_line(target_id)?;
                    let mut current_line = 1;
                    let mut insert_idx = None;

                    for (idx, line) in children.iter().enumerate() {
                        let line_no = current_line;
                        if line_no == target_line_no {
                            insert_idx = Some(idx + 1);
                            break;
                        }
                        let newlines = count_newlines_in_node(line);
                        current_line += newlines.max(1);
                    }

                    if let Some(idx) = insert_idx {
                        children.insert(idx, new_line);
                    } else {
                        return Err(EditError::RowNotFound(target_id.clone()));
                    }
                } else {
                    children.push(new_line);
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

                let mut current_line = 1;
                let mut src_idx = None;
                for (idx, line) in children.iter().enumerate() {
                    let line_no = current_line;
                    if line_no == src_line_no {
                        src_idx = Some(idx);
                        break;
                    }
                    let newlines = count_newlines_in_node(line);
                    current_line += newlines.max(1);
                }

                let src_idx = src_idx.ok_or_else(|| EditError::RowNotFound(row_id.clone()))?;
                let removed_node = children.remove(src_idx);

                if let Some(before_id) = before_row_id {
                    let before_line_no = parse_row_id_line(before_id)?;
                    let mut current_line = 1;
                    let mut insert_idx = None;
                    for (idx, line) in children.iter().enumerate() {
                        let line_no = current_line;
                        if line_no == before_line_no {
                            insert_idx = Some(idx);
                            break;
                        }
                        let newlines = count_newlines_in_node(line);
                        current_line += newlines.max(1);
                    }
                    let insert_idx = insert_idx.ok_or_else(|| EditError::RowNotFound(before_id.clone()))?;
                    children.insert(insert_idx, removed_node);
                } else if let Some(after_id) = after_row_id {
                    let after_line_no = parse_row_id_line(after_id)?;
                    let mut current_line = 1;
                    let mut insert_idx = None;
                    for (idx, line) in children.iter().enumerate() {
                        let line_no = current_line;
                        if line_no == after_line_no {
                            insert_idx = Some(idx + 1);
                            break;
                        }
                        let newlines = count_newlines_in_node(line);
                        current_line += newlines.max(1);
                    }
                    let insert_idx = insert_idx.ok_or_else(|| EditError::RowNotFound(after_id.clone()))?;
                    children.insert(insert_idx, removed_node);
                } else {
                    children.push(removed_node);
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

/// Lossless line-oriented parser for `sshd_config`.
pub fn parse_sshd_cst(input: &str) -> Vec<CstNode> {
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
        let parsed_line = parse_single_sshd_line(line_slice, line_start);
        lines.push(parsed_line);

        offset = line_end;
    }

    lines
}

fn parse_single_sshd_line(line: &str, base_offset: usize) -> CstNode {
    let line_span = Span::new(base_offset, base_offset + line.len());
    let chars: Vec<(usize, char)> = line.char_indices().collect();

    if chars.is_empty() {
        return CstNode::rule(SyntaxKind::BlankLine, Vec::new(), line_span);
    }

    let mut idx = 0;

    // 1. Scan leading whitespace
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

    // Find trailing newline range
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

    // 2. Parse Directive Keyword
    let key_start = chars[idx].0;
    while idx < chars.len()
        && chars[idx].0 < content_end
        && chars[idx].1 != ' '
        && chars[idx].1 != '\t'
        && chars[idx].1 != '='
        && chars[idx].1 != '#'
    {
        idx += 1;
    }
    let key_end = if idx < chars.len() {
        chars[idx].0.min(content_end)
    } else {
        content_end
    };

    if key_end == key_start {
        // Line starts with '=' or punctuation -> capture entire content as error
        return make_error_line(
            line,
            base_offset,
            leading_ws_token,
            leading_ws_byte_len,
            content_end,
            newline_token,
            line_span,
        );
    }

    // 3. Parse separator: whitespace or '=' (possibly surrounded by whitespace)
    let sep_start = key_end;
    let mut saw_separator = false;

    while idx < chars.len() && chars[idx].0 < content_end && (chars[idx].1 == ' ' || chars[idx].1 == '\t') {
        saw_separator = true;
        idx += 1;
    }

    if idx < chars.len() && chars[idx].0 < content_end && chars[idx].1 == '=' {
        saw_separator = true;
        idx += 1;
        while idx < chars.len() && chars[idx].0 < content_end && (chars[idx].1 == ' ' || chars[idx].1 == '\t') {
            idx += 1;
        }
    }

    let sep_end = if idx < chars.len() {
        chars[idx].0.min(content_end)
    } else {
        content_end
    };

    if !saw_separator || sep_end >= content_end {
        // Missing separator or missing value -> capture as error
        return make_error_line(
            line,
            base_offset,
            leading_ws_token,
            leading_ws_byte_len,
            content_end,
            newline_token,
            line_span,
        );
    }

    // 4. Parse Value (up to unquoted '#' or content_end)
    let val_start = sep_end;
    let mut in_quotes = false;
    let mut comment_start_idx = None;

    while idx < chars.len() && chars[idx].0 < content_end {
        let ch = chars[idx].1;
        if ch == '"' {
            in_quotes = !in_quotes;
        } else if ch == '#' && !in_quotes {
            comment_start_idx = Some(chars[idx].0);
            break;
        }
        idx += 1;
    }

    let val_slice_end = comment_start_idx.unwrap_or(content_end);
    let raw_val = &line[val_start..val_slice_end];
    let trimmed_val = raw_val.trim_end();
    let val_byte_len = trimmed_val.len();

    if val_byte_len == 0 {
        return make_error_line(
            line,
            base_offset,
            leading_ws_token,
            leading_ws_byte_len,
            content_end,
            newline_token,
            line_span,
        );
    }

    let mut tokens = Vec::new();
    if let Some(ws) = leading_ws_token {
        tokens.push(ws);
    }

    tokens.push(CstNode::token(
        SyntaxKind::Key,
        &line[key_start..key_end],
        Span::new(base_offset + key_start, base_offset + key_end),
    ));

    tokens.push(CstNode::token(
        SyntaxKind::Whitespace,
        &line[sep_start..sep_end],
        Span::new(base_offset + sep_start, base_offset + sep_end),
    ));

    tokens.push(CstNode::token(
        SyntaxKind::Value,
        trimmed_val,
        Span::new(base_offset + val_start, base_offset + val_start + val_byte_len),
    ));

    if val_byte_len < raw_val.len() {
        let ws_between = &raw_val[val_byte_len..];
        tokens.push(CstNode::token(
            SyntaxKind::Whitespace,
            ws_between,
            Span::new(
                base_offset + val_start + val_byte_len,
                base_offset + val_slice_end,
            ),
        ));
    }

    if let Some(comm_start) = comment_start_idx {
        tokens.push(CstNode::token(
            SyntaxKind::Comment,
            &line[comm_start..content_end],
            Span::new(base_offset + comm_start, base_offset + content_end),
        ));
    }

    if let Some(nl) = newline_token {
        tokens.push(nl);
    }

    CstNode::rule(SyntaxKind::Entry, tokens, line_span)
}

fn make_error_line(
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
