//! nginx configuration: `directive args;` lines inside nested blocks
//! (`http { server { location /api { ... } } }`).
//!
//! Each line holding one directive is a row named by it; a line opening a
//! block is a scope row (`server`, `location /api`); rows carry the path
//! of blocks they're in (`http › server › location /api`) as their scope.
//! Lines doing more than that (`location / { return 404; }`, a directive
//! spread over lines) are kept as they are, for the text view.

use crow_config_core::cst::{CstNode, SourceSpan, Span, SyntaxKind};
use crow_config_core::edit::{BindError, ConfigPlugin, EditError, EditOp, ParseError};
use crow_config_core::ir::{ConfigDocumentIr, FieldIr, RowIr, ShapeIr};
use crow_config_core::schema::{FieldType, PluginManifest};
use std::sync::LazyLock;

pub const NGINX_MANIFEST_TOML: &str = include_str!("../../plugins/nginx.toml");

pub static NGINX_MANIFEST: LazyLock<PluginManifest> =
    LazyLock::new(|| PluginManifest::from_toml_str(NGINX_MANIFEST_TOML).expect("Failed to parse embedded nginx.toml manifest"));

const OPEN: &str = "block_open";
const CLOSE: &str = "block_close";

/// The separator between block names in a row's scope.
pub const SCOPE_SEP: &str = " › ";

fn help_for(directive: &str) -> Option<&'static str> {
    Some(match directive {
        "server" => "A virtual server: what answers for the names and ports below.",
        "location" => "Rules for requests whose path matches.",
        "upstream" => "A group of backend servers to proxy to.",
        "listen" => "The address and port this server accepts connections on (add ssl for HTTPS).",
        "server_name" => "The host names this server answers for.",
        "root" => "The folder files are served from.",
        "index" => "The files tried when a folder is requested.",
        "proxy_pass" => "Forwards matching requests to this address or upstream.",
        "proxy_set_header" => "A header added to proxied requests.",
        "return" => "Answers right away with this status (and URL or text).",
        "rewrite" => "Rewrites the request path with a regular expression.",
        "try_files" => "Tries these files in order, then the last fallback.",
        "ssl_certificate" => "The TLS certificate (chain) file for this server.",
        "ssl_certificate_key" => "The TLS private key file.",
        "ssl_protocols" => "The TLS versions accepted (TLSv1.2 TLSv1.3 today).",
        "client_max_body_size" => "The biggest request body accepted (uploads), e.g. 10m.",
        "access_log" => "Where requests are logged (off to stop).",
        "error_log" => "Where errors are logged, and from which level.",
        "include" => "Reads more configuration from these files.",
        "worker_processes" => "How many worker processes run (auto: one per CPU).",
        "worker_connections" => "Most connections each worker handles at once.",
        "gzip" => "Compresses responses (on/off).",
        "add_header" => "A header added to responses.",
        "allow" => "Lets these addresses in (checked in order with deny).",
        "deny" => "Turns these addresses away (checked in order with allow).",
        "keepalive_timeout" => "How long an idle client connection stays open.",
        "sendfile" => "Lets the kernel send files directly (on/off).",
        "user" => "The user nginx's workers run as.",
        "events" => "Connection-processing settings.",
        "http" => "Settings for HTTP servers.",
        _ => return None,
    })
}

/// Lossless parser and plugin for nginx configuration.
#[derive(Debug, Clone)]
pub struct NginxPlugin {
    manifest: &'static PluginManifest,
}

impl NginxPlugin {
    pub fn new() -> Self {
        Self { manifest: &NGINX_MANIFEST }
    }
}

impl Default for NginxPlugin {
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

/// Braces opened minus closed in a raw line's code (outside quotes and
/// comments), so the blocks around it stay right.
fn brace_balance(code: &str) -> i32 {
    let (mut depth, mut quote) = (0, None);
    for c in code.chars() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), _) => {}
            (None, '"' | '\'') => quote = Some(c),
            (None, '#') => break,
            (None, '{') => depth += 1,
            (None, '}') => depth -= 1,
            _ => {}
        }
    }
    depth
}

/// Nodes with their line, and the blocks they're in.
fn walk(cst: &CstNode) -> Vec<(usize, &CstNode, Vec<String>)> {
    let mut out = Vec::new();
    let mut line = 1;
    let mut stack: Vec<String> = Vec::new();
    for node in cst.children() {
        let kind = node.kind();
        if kind == &SyntaxKind::custom(OPEN) {
            let name = tok(node, &SyntaxKind::Key).unwrap_or_default();
            let args = tok(node, &SyntaxKind::Value).unwrap_or_default();
            stack.push(if args.is_empty() { name } else { format!("{name} {args}") });
            out.push((line, node, stack.clone()));
        } else if kind == &SyntaxKind::custom(CLOSE) {
            out.push((line, node, stack.clone()));
            stack.pop();
        } else {
            out.push((line, node, stack.clone()));
            if kind == &SyntaxKind::Error {
                let code = tok(node, &SyntaxKind::Error).unwrap_or_default();
                let b = brace_balance(&code);
                for _ in 0..b.max(0) {
                    stack.push("…".into());
                }
                for _ in 0..(-b).max(0) {
                    stack.pop();
                }
            }
        }
        line += newlines(node).max(1);
    }
    out
}

impl ConfigPlugin for NginxPlugin {
    fn manifest(&self) -> &PluginManifest {
        self.manifest
    }

    fn parse(&self, text: &str) -> Result<CstNode, ParseError> {
        Ok(CstNode::rule(SyntaxKind::Document, parse_nginx_cst(text), Span::new(0, text.len())))
    }

    fn to_ir(&self, cst: &CstNode) -> Result<ConfigDocumentIr, BindError> {
        let mut rows = Vec::new();
        for (line, node, stack) in walk(cst) {
            let kind = node.kind();
            let is_open = kind == &SyntaxKind::custom(OPEN);
            if !(is_open || kind == &SyntaxKind::Entry) {
                continue;
            }
            let mut row = RowIr::new(format!("line-{line}"), if is_open { "scope_row" } else { "key_value_row" }, SourceSpan::single_line(line));
            row.scope = (!stack.is_empty()).then(|| stack.join(SCOPE_SEP));
            let name = tok(node, &SyntaxKind::Key).unwrap_or_default();
            let value = tok(node, &SyntaxKind::Value).unwrap_or_default();
            let mut f = FieldIr::new(name.clone(), FieldType::String, serde_json::Value::String(value)).with_validity(true);
            f.help = help_for(&name).map(str::to_string);
            if name == "include" {
                row.include = tok(node, &SyntaxKind::Value).map(|v| v.split_whitespace().map(str::to_string).collect());
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
        let unsupported = |m: &str| EditError::Unsupported(m.to_string());
        match op {
            EditOp::UpdateField { row_id, field_name, new_value } => {
                let text = one_line(field_name, new_value)?;
                let idx = index_of(cst, row_id)?;
                let node = &mut children(cst)?[idx];
                let kind = node.kind().clone();
                if !(kind == SyntaxKind::Entry || kind == SyntaxKind::custom(OPEN)) || tok(node, &SyntaxKind::Key).as_deref() != Some(field_name.as_str()) {
                    return Err(EditError::FieldNotFound(field_name.clone(), row_id.clone()));
                }
                if kind == SyntaxKind::Entry && text.is_empty() {
                    return Err(EditError::InvalidValue { field: field_name.clone(), message: "a directive needs its arguments; delete it instead".into() });
                }
                if !node.replace_first_token_text(&SyntaxKind::Value, &text) {
                    // No arguments yet (`server {`): add them after the name.
                    let tokens = node.children_mut().ok_or_else(|| unsupported("line is not a rule"))?;
                    let at = tokens.iter().position(|t| t.kind() == &SyntaxKind::Key).map_or(0, |i| i + 1);
                    tokens.insert(at, CstNode::token(SyntaxKind::Value, text, Span::default()));
                    tokens.insert(at, CstNode::token(SyntaxKind::Whitespace, " ", Span::default()));
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
                let (name, value) = fields.iter().next().ok_or_else(|| EditError::InvalidValue { field: "directive".into(), message: "a directive is required".into() })?;
                if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    return Err(EditError::InvalidValue { field: name.clone(), message: "a directive is letters, digits and '_'".into() });
                }
                let value = one_line(name, value)?;
                let id = after_row_id.as_ref().ok_or_else(|| unsupported("say which line to add it after"))?;
                let idx = index_of(cst, id)?;
                let after = &cst.children()[idx];
                // Same indentation as the line before; one deeper after a block's opening.
                let mut indent = match after.children().first() {
                    Some(CstNode::Token { kind: SyntaxKind::Whitespace, text, .. }) if !text.contains('\n') => text.clone(),
                    _ => String::new(),
                };
                if after.kind() == &SyntaxKind::custom(OPEN) {
                    indent.push_str("    ");
                }
                let node = parse_nginx_cst(&format!("{indent}{name} {value};\n")).remove(0);
                children(cst)?.insert(idx + 1, node);
                Ok(())
            }
            EditOp::MoveRow { .. } => Err(unsupported("lines are moved in the text view")),
        }
    }
}

fn one_line(field: &str, v: &serde_json::Value) -> Result<String, EditError> {
    let s = v.as_str().ok_or_else(|| EditError::InvalidValue { field: field.into(), message: "Expected a string".into() })?;
    if s.contains(['\n', '\r', ';', '{', '}']) || s.contains('#') {
        return Err(EditError::InvalidValue { field: field.into(), message: "one line, without ; { } or #".into() });
    }
    Ok(s.trim().to_string())
}

fn children(cst: &mut CstNode) -> Result<&mut Vec<CstNode>, EditError> {
    cst.children_mut().ok_or_else(|| EditError::Unsupported("Root is not a rule".into()))
}

fn index_of(cst: &CstNode, row_id: &str) -> Result<usize, EditError> {
    let n: usize = row_id.strip_prefix("line-").and_then(|n| n.parse().ok()).ok_or_else(|| EditError::RowNotFound(row_id.into()))?;
    (n >= 1 && n <= cst.children().len()).then(|| n - 1).ok_or_else(|| EditError::RowNotFound(row_id.into()))
}

/// Where a line's code ends and its comment starts (`#` outside quotes).
fn comment_start(body: &str) -> usize {
    let mut quote = None;
    for (i, c) in body.char_indices() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), _) => {}
            (None, '"' | '\'') => quote = Some(c),
            (None, '#') => return i,
            _ => {}
        }
    }
    body.len()
}

/// One node per line; every byte is kept.
pub fn parse_nginx_cst(input: &str) -> Vec<CstNode> {
    let mut out = Vec::new();
    let mut offset = 0;
    for line in input.split_inclusive('\n') {
        out.push(parse_line(line, offset));
        offset += line.len();
    }
    out
}

fn parse_line(line: &str, base: usize) -> CstNode {
    let body_end = line.strip_suffix("\r\n").or_else(|| line.strip_suffix('\n')).map_or(line.len(), str::len);
    let body = &line[..body_end];
    let c_start = comment_start(body);
    let code = &body[..c_start];
    let lead = code.len() - code.trim_start_matches([' ', '\t']).len();
    let code_end = lead + code[lead..].trim_end().len();
    let t = &code[lead..code_end];
    let mut tokens = Vec::new();
    let mut push = |kind: SyntaxKind, s: usize, e: usize| {
        if s < e {
            tokens.push(CstNode::token(kind, &line[s..e], Span::new(base + s, base + e)));
        }
    };
    let simple = |t: &str| !t[..t.len().saturating_sub(1)].contains(['{', '}', ';']);
    let kind = if t.is_empty() {
        push(SyntaxKind::Whitespace, 0, lead.min(c_start));
        if c_start < body_end {
            push(SyntaxKind::Whitespace, lead, c_start);
            push(SyntaxKind::Comment, c_start, body_end);
            SyntaxKind::CommentLine
        } else {
            push(SyntaxKind::Whitespace, lead, body_end);
            SyntaxKind::BlankLine
        }
    } else if t == "}" {
        push(SyntaxKind::Whitespace, 0, lead);
        push(SyntaxKind::custom("brace"), lead, code_end);
        push(SyntaxKind::Whitespace, code_end, c_start);
        push(SyntaxKind::Comment, c_start, body_end);
        SyntaxKind::custom(CLOSE)
    } else if (t.ends_with('{') || t.ends_with(';')) && simple(t) && t.len() > 1 {
        let opens = t.ends_with('{');
        let end_mark = code_end - 1;
        let name_end = lead + t.find([' ', '\t', '{', ';']).unwrap_or(t.len() - 1);
        let args_start = name_end + (code[name_end..end_mark].len() - code[name_end..end_mark].trim_start().len());
        let args_end = args_start + code[args_start..end_mark].trim_end().len();
        push(SyntaxKind::Whitespace, 0, lead);
        push(SyntaxKind::Key, lead, name_end);
        push(SyntaxKind::Whitespace, name_end, args_start);
        push(SyntaxKind::Value, args_start, args_end);
        push(SyntaxKind::Whitespace, args_end, end_mark);
        push(SyntaxKind::custom(if opens { "brace" } else { "semicolon" }), end_mark, code_end);
        push(SyntaxKind::Whitespace, code_end, c_start);
        push(SyntaxKind::Comment, c_start, body_end);
        if opens { SyntaxKind::custom(OPEN) } else { SyntaxKind::Entry }
    } else {
        // Anything else is kept as it is.
        push(SyntaxKind::Whitespace, 0, lead);
        push(SyntaxKind::Error, lead, body_end);
        SyntaxKind::Error
    };
    push(SyntaxKind::Newline, body_end, line.len());
    CstNode::rule(kind, tokens, Span::new(base, base + line.len()))
}
