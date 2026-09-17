use crow_config_core::cst::{CstNode, SourceSpan, Span, SyntaxKind};
use crow_config_core::edit::{BindError, ConfigPlugin, EditError, EditOp, ParseError};
use crow_config_core::ir::{ConfigDocumentIr, FieldIr, RowIr, ShapeIr};
use crow_config_core::schema::{validate_field_value, FieldType, PluginManifest};
use std::sync::LazyLock;

pub const HOSTS_MANIFEST_TOML: &str = include_str!("../../plugins/hosts.toml");

pub static HOSTS_MANIFEST: LazyLock<PluginManifest> = LazyLock::new(|| {
    PluginManifest::from_toml_str(HOSTS_MANIFEST_TOML)
        .expect("Failed to parse embedded hosts.toml manifest")
});

/// Lossless parser and plugin for `/etc/hosts`.
#[derive(Debug, Clone)]
pub struct HostsPlugin {
    manifest: &'static PluginManifest,
}

impl HostsPlugin {
    pub fn new() -> Self {
        Self {
            manifest: &HOSTS_MANIFEST,
        }
    }
}

impl Default for HostsPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigPlugin for HostsPlugin {
    fn manifest(&self) -> &PluginManifest {
        self.manifest
    }

    fn parse(&self, text: &str) -> Result<CstNode, ParseError> {
        let lines = parse_hosts_cst(text);
        let total_span = Span::new(0, text.len());
        Ok(CstNode::rule(SyntaxKind::Document, lines, total_span))
    }

    fn to_ir(&self, cst: &CstNode) -> Result<ConfigDocumentIr, BindError> {
        let mut rows = Vec::new();
        let mut current_line = 1;

        for line_node in cst.children() {
            let line_no = current_line;

            // Check if this line is an entry
            if line_node.kind() == &SyntaxKind::Entry {
                let row_id = format!("line-{}", line_no);
                let mut row = RowIr::new(
                    row_id,
                    "key_value_list_row",
                    SourceSpan::single_line(line_no),
                );

                let mut ip_val: Option<String> = None;
                let mut hostnames = Vec::new();
                let mut comment_val: Option<String> = None;

                for token in line_node.children() {
                    match token.kind() {
                        SyntaxKind::IpAddress => {
                            if let CstNode::Token { text, .. } = token {
                                ip_val = Some(text.clone());
                            }
                        }
                        SyntaxKind::Hostname => {
                            if let CstNode::Token { text, .. } = token {
                                hostnames.push(text.clone());
                            }
                        }
                        SyntaxKind::Comment => {
                            if let CstNode::Token { text, .. } = token {
                                // Strip leading '#' and trim surrounding whitespace
                                let trimmed = text.trim_start_matches('#').trim();
                                comment_val = Some(trimmed.to_string());
                            }
                        }
                        _ => {}
                    }
                }

                if let Some(ip) = ip_val {
                    let mut address_field = FieldIr::new(
                        "address",
                        FieldType::IpAddress,
                        serde_json::Value::String(ip.clone()),
                    );

                    if let Some(def) = self.manifest.find_field("address") {
                        match validate_field_value(def, &serde_json::Value::String(ip)) {
                            Ok(()) => address_field = address_field.with_validity(true),
                            Err(e) => address_field = address_field.with_error(e),
                        }
                    }
                    row.fields.push(address_field);
                }

                let hostnames_json = serde_json::to_value(&hostnames).unwrap_or_default();
                let hostnames_field =
                    FieldIr::new("hostnames", FieldType::StringList, hostnames_json);
                row.fields.push(hostnames_field);

                if let Some(comment) = comment_val {
                    row.fields.push(FieldIr::new(
                        "comment",
                        FieldType::String,
                        serde_json::Value::String(comment),
                    ));
                }

                rows.push(row);
            }

            // Increment line number based on newlines in this line node
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

                match field_name.as_str() {
                    "address" => {
                        let new_ip = new_value.as_str().ok_or_else(|| EditError::InvalidValue {
                            field: "address".to_string(),
                            message: "Expected string IP address".to_string(),
                        })?;
                        if !line_node.replace_first_token_text(&SyntaxKind::IpAddress, new_ip) {
                            return Err(EditError::FieldNotFound("address".to_string(), row_id.clone()));
                        }
                    }
                    "hostnames" => {
                        let new_hostnames = new_value
                            .as_array()
                            .ok_or_else(|| EditError::InvalidValue {
                                field: "hostnames".to_string(),
                                message: "Expected array of hostnames".to_string(),
                            })?
                            .iter()
                            .map(|v| {
                                v.as_str()
                                    .map(|s| s.to_string())
                                    .ok_or_else(|| EditError::InvalidValue {
                                        field: "hostnames".to_string(),
                                        message: "All hostnames must be strings".to_string(),
                                    })
                            })
                            .collect::<Result<Vec<_>, _>>()?;

                        if new_hostnames.is_empty() {
                            return Err(EditError::InvalidValue {
                                field: "hostnames".to_string(),
                                message: "At least one hostname is required".to_string(),
                            });
                        }

                        replace_hostnames_in_line(line_node, &new_hostnames)?;
                    }
                    "comment" => {
                        replace_or_set_comment_in_line(line_node, new_value)?;
                    }
                    _ => {
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
                let address = fields
                    .get("address")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| EditError::InvalidValue {
                        field: "address".to_string(),
                        message: "Field 'address' is required for insertion".to_string(),
                    })?;

                let hostnames = fields
                    .get("hostnames")
                    .and_then(|v| v.as_array())
                    .ok_or_else(|| EditError::InvalidValue {
                        field: "hostnames".to_string(),
                        message: "Field 'hostnames' is required for insertion".to_string(),
                    })?;

                let hostnames_str: Vec<&str> = hostnames
                    .iter()
                    .filter_map(|h| h.as_str())
                    .collect();

                if hostnames_str.is_empty() {
                    return Err(EditError::InvalidValue {
                        field: "hostnames".to_string(),
                        message: "At least one hostname is required".to_string(),
                    });
                }

                let comment = fields.get("comment").and_then(|v| v.as_str());

                let mut line_tokens = Vec::new();
                line_tokens.push(CstNode::token(
                    SyntaxKind::IpAddress,
                    address,
                    Span::default(),
                ));
                line_tokens.push(CstNode::token(
                    SyntaxKind::Whitespace,
                    "\t",
                    Span::default(),
                ));

                for (i, h) in hostnames_str.iter().enumerate() {
                    if i > 0 {
                        line_tokens.push(CstNode::token(
                            SyntaxKind::Whitespace,
                            " ",
                            Span::default(),
                        ));
                    }
                    line_tokens.push(CstNode::token(
                        SyntaxKind::Hostname,
                        *h,
                        Span::default(),
                    ));
                }

                if let Some(comm) = comment {
                    line_tokens.push(CstNode::token(
                        SyntaxKind::Whitespace,
                        "  ",
                        Span::default(),
                    ));
                    line_tokens.push(CstNode::token(
                        SyntaxKind::Comment,
                        format!("# {}", comm),
                        Span::default(),
                    ));
                }

                line_tokens.push(CstNode::token(
                    SyntaxKind::Newline,
                    "\n",
                    Span::default(),
                ));

                let new_line_node =
                    CstNode::rule(SyntaxKind::Entry, line_tokens, Span::default());

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
                        children.insert(idx, new_line_node);
                    } else {
                        return Err(EditError::RowNotFound(target_id.clone()));
                    }
                } else {
                    children.push(new_line_node);
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

fn replace_hostnames_in_line(
    line_node: &mut CstNode,
    new_hostnames: &[String],
) -> Result<(), EditError> {
    let children = line_node
        .children_mut()
        .ok_or_else(|| EditError::Unsupported("Line node is not a rule".to_string()))?;

    // Find the range of tokens containing all hostnames and their interstitial whitespace
    let first_hostname_idx = children
        .iter()
        .position(|c| c.kind() == &SyntaxKind::Hostname)
        .ok_or_else(|| EditError::FieldNotFound("hostnames".to_string(), "unknown".to_string()))?;

    let last_hostname_idx = children
        .iter()
        .rposition(|c| c.kind() == &SyntaxKind::Hostname)
        .unwrap_or(first_hostname_idx);

    // Build replacement tokens for the hostnames
    let mut replacement = Vec::new();
    for (i, h) in new_hostnames.iter().enumerate() {
        if i > 0 {
            replacement.push(CstNode::token(
                SyntaxKind::Whitespace,
                " ",
                Span::default(),
            ));
        }
        replacement.push(CstNode::token(
            SyntaxKind::Hostname,
            h.clone(),
            Span::default(),
        ));
    }

    // Replace the range first_hostname_idx..=last_hostname_idx
    children.splice(first_hostname_idx..=last_hostname_idx, replacement);

    Ok(())
}

fn replace_or_set_comment_in_line(
    line_node: &mut CstNode,
    new_value: &serde_json::Value,
) -> Result<(), EditError> {
    let children = line_node
        .children_mut()
        .ok_or_else(|| EditError::Unsupported("Line node is not a rule".to_string()))?;

    if new_value.is_null() || new_value.as_str() == Some("") {
        // Remove existing comment if present
        if let Some(idx) = children.iter().position(|c| c.kind() == &SyntaxKind::Comment) {
            // Also remove whitespace immediately preceding the comment if present
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
            // Insert before newline if newline exists, else at end
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

/// Lossless line-oriented parser for `/etc/hosts`.
///
/// Ensures:
/// 1. Every character (spaces, tabs, `#`, newlines) is preserved.
/// 2. Malformed lines never cause panics; they are captured as `ERROR` or preserved lines.
/// 3. Round-trip byte identical: `reconstructed == input`.
pub fn parse_hosts_cst(input: &str) -> Vec<CstNode> {
    let mut lines = Vec::new();
    let bytes = input.as_bytes();
    let mut offset = 0;

    while offset < bytes.len() {
        let line_start = offset;

        // Find end of line (\n or EOF)
        let mut line_end = line_start;
        while line_end < bytes.len() && bytes[line_end] != b'\n' {
            line_end += 1;
        }
        if line_end < bytes.len() && bytes[line_end] == b'\n' {
            line_end += 1; // Include newline
        }

        let line_slice = &input[line_start..line_end];
        let parsed_line = parse_single_line(line_slice, line_start);
        lines.push(parsed_line);

        offset = line_end;
    }

    lines
}

fn parse_single_line(line: &str, base_offset: usize) -> CstNode {
    let line_span = Span::new(base_offset, base_offset + line.len());
    let mut idx = 0;
    let chars: Vec<(usize, char)> = line.char_indices().collect();

    if chars.is_empty() {
        return CstNode::rule(SyntaxKind::BlankLine, Vec::new(), line_span);
    }

    // 1. Scan leading whitespace
    let mut leading_ws_end = 0;
    while leading_ws_end < chars.len() && (chars[leading_ws_end].1 == ' ' || chars[leading_ws_end].1 == '\t') {
        leading_ws_end += 1;
    }

    let mut tokens = Vec::new();

    if leading_ws_end > 0 {
        let byte_len = if leading_ws_end < chars.len() {
            chars[leading_ws_end].0
        } else {
            line.len()
        };
        tokens.push(CstNode::token(
            SyntaxKind::Whitespace,
            &line[..byte_len],
            Span::new(base_offset, base_offset + byte_len),
        ));
        idx = leading_ws_end;
    }

    // Check if end of line (blank line)
    if idx >= chars.len() || chars[idx].1 == '\n' || chars[idx].1 == '\r' {
        if idx < chars.len() {
            let nl_start = chars[idx].0;
            tokens.push(CstNode::token(
                SyntaxKind::Newline,
                &line[nl_start..],
                Span::new(base_offset + nl_start, base_offset + line.len()),
            ));
        }
        return CstNode::rule(SyntaxKind::BlankLine, tokens, line_span);
    }

    // Check if comment-only line
    if chars[idx].1 == '#' {
        let comment_start = chars[idx].0;
        let mut comment_end = line.len();

        // Check for trailing newline
        if line.ends_with("\r\n") {
            comment_end = line.len() - 2;
        } else if line.ends_with('\n') {
            comment_end = line.len() - 1;
        }

        tokens.push(CstNode::token(
            SyntaxKind::Comment,
            &line[comment_start..comment_end],
            Span::new(base_offset + comment_start, base_offset + comment_end),
        ));

        if comment_end < line.len() {
            tokens.push(CstNode::token(
                SyntaxKind::Newline,
                &line[comment_end..],
                Span::new(base_offset + comment_end, base_offset + line.len()),
            ));
        }

        return CstNode::rule(SyntaxKind::CommentLine, tokens, line_span);
    }

    // 2. Try parsing an entry: IP address followed by whitespace and hostnames
    let ip_start = chars[idx].0;
    while idx < chars.len()
        && chars[idx].1 != ' '
        && chars[idx].1 != '\t'
        && chars[idx].1 != '#'
        && chars[idx].1 != '\r'
        && chars[idx].1 != '\n'
    {
        idx += 1;
    }
    let ip_end = if idx < chars.len() { chars[idx].0 } else { line.len() };

    let ip_token = CstNode::token(
        SyntaxKind::IpAddress,
        &line[ip_start..ip_end],
        Span::new(base_offset + ip_start, base_offset + ip_end),
    );
    tokens.push(ip_token);

    // 3. Must be followed by whitespace
    let ws_after_ip_start_char = idx;
    while idx < chars.len() && (chars[idx].1 == ' ' || chars[idx].1 == '\t') {
        idx += 1;
    }

    if idx == ws_after_ip_start_char {
        // No whitespace after IP -> malformed line
        return parse_malformed_remainder(line, base_offset, idx, tokens, line_span);
    }

    let ws_after_ip_start = chars[ws_after_ip_start_char].0;
    let ws_after_ip_end = if idx < chars.len() { chars[idx].0 } else { line.len() };

    tokens.push(CstNode::token(
        SyntaxKind::Whitespace,
        &line[ws_after_ip_start..ws_after_ip_end],
        Span::new(base_offset + ws_after_ip_start, base_offset + ws_after_ip_end),
    ));

    // 4. Parse hostnames
    let mut hostname_count = 0;

    while idx < chars.len() && chars[idx].1 != '#' && chars[idx].1 != '\r' && chars[idx].1 != '\n' {
        let h_start = chars[idx].0;
        while idx < chars.len()
            && chars[idx].1 != ' '
            && chars[idx].1 != '\t'
            && chars[idx].1 != '#'
            && chars[idx].1 != '\r'
            && chars[idx].1 != '\n'
        {
            idx += 1;
        }
        let h_end = if idx < chars.len() { chars[idx].0 } else { line.len() };

        tokens.push(CstNode::token(
            SyntaxKind::Hostname,
            &line[h_start..h_end],
            Span::new(base_offset + h_start, base_offset + h_end),
        ));
        hostname_count += 1;

        // Collect whitespace between or after hostnames
        let ws_start_char = idx;
        while idx < chars.len() && (chars[idx].1 == ' ' || chars[idx].1 == '\t') {
            idx += 1;
        }
        if idx > ws_start_char {
            let ws_s = chars[ws_start_char].0;
            let ws_e = if idx < chars.len() { chars[idx].0 } else { line.len() };
            tokens.push(CstNode::token(
                SyntaxKind::Whitespace,
                &line[ws_s..ws_e],
                Span::new(base_offset + ws_s, base_offset + ws_e),
            ));
        }
    }

    if hostname_count == 0 {
        // IP without any hostnames -> malformed entry
        return parse_malformed_remainder(line, base_offset, idx, tokens, line_span);
    }

    // 5. Parse optional trailing comment
    if idx < chars.len() && chars[idx].1 == '#' {
        let comment_start = chars[idx].0;
        let mut comment_end = line.len();

        if line.ends_with("\r\n") {
            comment_end = line.len() - 2;
        } else if line.ends_with('\n') {
            comment_end = line.len() - 1;
        }

        tokens.push(CstNode::token(
            SyntaxKind::Comment,
            &line[comment_start..comment_end],
            Span::new(base_offset + comment_start, base_offset + comment_end),
        ));
        // Finished comment
        idx = chars.len();
    }

    // 6. Trailing newline
    let mut newline_str = "";
    let mut nl_start = line.len();
    if line.ends_with("\r\n") {
        nl_start = line.len() - 2;
        newline_str = &line[nl_start..];
    } else if line.ends_with('\n') {
        nl_start = line.len() - 1;
        newline_str = &line[nl_start..];
    }

    if !newline_str.is_empty() {
        tokens.push(CstNode::token(
            SyntaxKind::Newline,
            newline_str,
            Span::new(base_offset + nl_start, base_offset + line.len()),
        ));
    }

    let _ = idx; // silence unused assignment

    CstNode::rule(SyntaxKind::Entry, tokens, line_span)
}

fn parse_malformed_remainder(
    line: &str,
    base_offset: usize,
    char_idx: usize,
    mut tokens: Vec<CstNode>,
    line_span: Span,
) -> CstNode {
    let chars: Vec<(usize, char)> = line.char_indices().collect();
    let rem_start = if char_idx < chars.len() {
        chars[char_idx].0
    } else {
        line.len()
    };

    let mut rem_end = line.len();
    let mut newline_str = "";
    if line.ends_with("\r\n") {
        rem_end = line.len() - 2;
        newline_str = &line[rem_end..];
    } else if line.ends_with('\n') {
        rem_end = line.len() - 1;
        newline_str = &line[rem_end..];
    }

    if rem_start < rem_end {
        tokens.push(CstNode::token(
            SyntaxKind::Error,
            &line[rem_start..rem_end],
            Span::new(base_offset + rem_start, base_offset + rem_end),
        ));
    }

    if !newline_str.is_empty() {
        tokens.push(CstNode::token(
            SyntaxKind::Newline,
            newline_str,
            Span::new(base_offset + rem_end, base_offset + line.len()),
        ));
    }

    CstNode::rule(SyntaxKind::Error, tokens, line_span)
}
