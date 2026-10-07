//! systemd's file syntax (systemd.syntax(7)): unit files (`*.service`,
//! `*.timer`, …), their drop-ins (`*.d/*.conf`) and systemd's own settings
//! files (`logind.conf`, `resolved.conf`, …). `[Section]` headers, then
//! `Key=Value` lines; a value ending in `\` continues on the next line;
//! `#` and `;` start comment lines.
//!
//! Each section header is a scope row; its keys carry the section as their
//! scope. Common unit keys say what they do, and offer their values.

use crow_config_core::cst::{CstNode, SourceSpan, Span, SyntaxKind};
use crow_config_core::edit::{BindError, ConfigPlugin, EditError, EditOp, ParseError};
use crow_config_core::ir::{ConfigDocumentIr, FieldIr, RowIr, ShapeIr};
use crow_config_core::schema::{EnumOption, FieldType, PluginManifest, RiskLevel};
use std::sync::LazyLock;

pub const SYSTEMD_MANIFEST_TOML: &str = include_str!("../../plugins/systemd.toml");

pub static SYSTEMD_MANIFEST: LazyLock<PluginManifest> =
    LazyLock::new(|| PluginManifest::from_toml_str(SYSTEMD_MANIFEST_TOML).expect("Failed to parse embedded systemd.toml manifest"));

const SECTION: &str = "section";

type Values = &'static [(&'static str, &'static str, Option<RiskLevel>)];
const YES_NO: Values = &[("no", "no", None), ("yes", "yes", None)];
const HARDEN: Values = &[("no", "no", None), ("yes", "yes", Some(RiskLevel::Recommended))];

/// What a common key does, and its values when it takes a few fixed ones.
fn known(key: &str) -> Option<(&'static str, Values)> {
    use RiskLevel::{Caution, Recommended};
    Some(match key {
        "Description" => ("What the unit is, as status and logs show it.", &[]),
        "Documentation" => ("Where its documentation is (man:, https:, file: URIs).", &[]),
        "After" => ("Start after these units (ordering only; doesn't pull them in).", &[]),
        "Before" => ("Start before these units (ordering only).", &[]),
        "Requires" => ("Pull these units in; if they fail to start, so does this one.", &[]),
        "Wants" => ("Pull these units in, without depending on them succeeding.", &[]),
        "BindsTo" => ("Like Requires, and also stop when they stop.", &[]),
        "PartOf" => ("Stop and restart with these units.", &[]),
        "Conflicts" => ("Starting this unit stops these, and the other way round.", &[]),
        "Type" => (
            "How systemd knows the service has started.",
            &[("simple", "the process runs in the foreground (default)", None), ("exec", "started once the binary has been executed", None), ("forking", "the program forks into the background", None), ("oneshot", "runs to completion, then the unit is done", None), ("notify", "the program tells systemd when it's ready", None), ("dbus", "ready once it takes its D-Bus name", None), ("idle", "like simple, but waits for other jobs first", None)],
        ),
        "ExecStart" => ("The command that runs the service (an absolute path, or a name found in PATH).", &[]),
        "ExecStartPre" => ("A command run before ExecStart.", &[]),
        "ExecStartPost" => ("A command run after ExecStart.", &[]),
        "ExecStop" => ("A command that stops the service (without it, systemd sends a signal).", &[]),
        "ExecReload" => ("A command that reloads the service's configuration.", &[]),
        "Restart" => (
            "When systemd restarts the service after it exits.",
            &[("no", "never (default)", None), ("on-failure", "on a non-zero exit, a signal, a timeout or a watchdog", Some(Recommended)), ("on-abnormal", "on a signal, a timeout or a watchdog", None), ("on-abort", "on an uncaught signal", None), ("on-success", "only on a clean exit", None), ("on-watchdog", "on a watchdog timeout", None), ("always", "whenever it stops, even when stopped cleanly", None)],
        ),
        "RestartSec" => ("How long to wait before restarting (e.g. 5s, 1min).", &[]),
        "TimeoutStartSec" => ("How long starting may take before it's treated as failed.", &[]),
        "TimeoutStopSec" => ("How long stopping may take before the service is killed.", &[]),
        "User" => ("The user the service runs as (root if unset).", &[]),
        "Group" => ("The group the service runs as.", &[]),
        "WorkingDirectory" => ("The directory the service starts in.", &[]),
        "Environment" => ("Environment variables, as NAME=value (quote values with spaces).", &[]),
        "EnvironmentFile" => ("A file of NAME=value lines to read the environment from (a leading - means optional).", &[]),
        "PIDFile" => ("Where a forking service writes its process id.", &[]),
        "KillMode" => (
            "Which processes are killed when the service stops.",
            &[("control-group", "every process of the service (default)", Some(Recommended)), ("mixed", "the main process gets SIGTERM, the rest SIGKILL", None), ("process", "only the main process", Some(Caution)), ("none", "none: they're left running", Some(Caution))],
        ),
        "LimitNOFILE" => ("Most files the service can have open.", &[]),
        "MemoryMax" => ("A hard memory cap (e.g. 512M, 2G, or a percentage).", &[]),
        "CPUQuota" => ("A CPU time cap, as a percentage of one CPU (200% = two).", &[]),
        "Nice" => ("Scheduling priority, -20 (highest) to 19 (lowest).", &[]),
        "StandardOutput" => ("Where the service's output goes (journal by default).", &[]),
        "StandardError" => ("Where the service's errors go (journal by default).", &[]),
        "NoNewPrivileges" => ("Stops the service and its children gaining privileges (setuid, file capabilities).", HARDEN),
        "PrivateTmp" => ("Gives the service its own /tmp and /var/tmp.", HARDEN),
        "ProtectSystem" => (
            "Makes the system's files read-only for the service.",
            &[("no", "no", None), ("yes", "/usr and the boot loader read-only", None), ("full", "also /etc", None), ("strict", "the whole file system, except what's allowed", Some(Recommended))],
        ),
        "ProtectHome" => ("Hides or protects /home, /root and /run/user from the service.", &[("no", "no", None), ("read-only", "read-only", None), ("tmpfs", "replaced by empty folders", None), ("yes", "inaccessible", Some(Recommended))]),
        "DynamicUser" => ("Runs the service as a temporary user made when it starts.", YES_NO),
        "WantedBy" => ("When enabled, this unit is started with these targets (multi-user.target for most services).", &[]),
        "RequiredBy" => ("When enabled, these units require this one.", &[]),
        "Alias" => ("Other names the unit has when enabled.", &[]),
        "OnCalendar" => ("When the timer fires, as a calendar expression (daily, Mon *-*-* 03:00:00).", &[]),
        "OnBootSec" => ("Fire this long after boot.", &[]),
        "OnUnitActiveSec" => ("Fire this long after the unit last ran.", &[]),
        "Persistent" => ("Run a missed calendar run as soon as the machine is back up.", YES_NO),
        "Unit" => ("The unit the timer or path starts (by default, the one with the same name).", &[]),
        "ListenStream" => ("The address or port the socket listens on (TCP or a Unix socket path).", &[]),
        _ => return None,
    })
}

/// Lossless parser and plugin for systemd-style files.
#[derive(Debug, Clone)]
pub struct SystemdPlugin {
    manifest: &'static PluginManifest,
}

impl SystemdPlugin {
    pub fn new() -> Self {
        Self { manifest: &SYSTEMD_MANIFEST }
    }
}

impl Default for SystemdPlugin {
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

/// Nodes with their first line and the section they're in.
fn walk(cst: &CstNode) -> Vec<(usize, &CstNode, Option<String>)> {
    let mut out = Vec::new();
    let mut line = 1;
    let mut section = None;
    for node in cst.children() {
        if node.kind() == &SyntaxKind::custom(SECTION) {
            section = tok(node, &SyntaxKind::Key);
        }
        out.push((line, node, section.clone()));
        line += newlines(node).max(1);
    }
    out
}

/// A value with its continuations joined into one line.
fn flatten(value: &str) -> String {
    value.split("\\\n").map(str::trim).collect::<Vec<_>>().join(" ").trim().to_string()
}

impl ConfigPlugin for SystemdPlugin {
    fn manifest(&self) -> &PluginManifest {
        self.manifest
    }

    fn parse(&self, text: &str) -> Result<CstNode, ParseError> {
        Ok(CstNode::rule(SyntaxKind::Document, parse_systemd_cst(text), Span::new(0, text.len())))
    }

    fn to_ir(&self, cst: &CstNode) -> Result<ConfigDocumentIr, BindError> {
        let mut rows = Vec::new();
        for (line, node, section) in walk(cst) {
            let span = SourceSpan::new(line, line + newlines(node).saturating_sub(1));
            let mut row = RowIr::new(format!("line-{line}"), "key_value_row", span);
            row.scope = section.clone();
            if node.kind() == &SyntaxKind::custom(SECTION) {
                row.widget = "scope_row".into();
                row.fields.push(FieldIr::new("section", FieldType::String, serde_json::Value::String(section.clone().unwrap_or_default())).with_validity(true));
            } else if node.kind() == &SyntaxKind::Entry {
                let key = tok(node, &SyntaxKind::Key).unwrap_or_default();
                let value = flatten(&tok(node, &SyntaxKind::Value).unwrap_or_default());
                let mut f = FieldIr::new(key.clone(), FieldType::String, serde_json::Value::String(value)).with_validity(true);
                if let Some((help, values)) = known(&key) {
                    f.help = Some(help.to_string());
                    if !values.is_empty() {
                        f.options = Some(values.iter().map(|(v, l, r)| EnumOption { value: v.to_string(), label: l.to_string(), risk: r.clone() }).collect());
                    }
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
                if node.kind() != &SyntaxKind::Entry || tok(node, &SyntaxKind::Key).as_deref() != Some(field_name.as_str()) {
                    return Err(if node.kind() == &SyntaxKind::custom(SECTION) { unsupported("sections are renamed in the text view") } else { EditError::FieldNotFound(field_name.clone(), row_id.clone()) });
                }
                // A value continued over several lines becomes one line.
                if !node.replace_first_token_text(&SyntaxKind::Value, &text) {
                    let tokens = node.children_mut().ok_or_else(|| unsupported("line is not a rule"))?;
                    let at = tokens.iter().position(|t| t.kind() == &SyntaxKind::custom("equals")).map_or(tokens.len(), |i| i + 1);
                    tokens.insert(at, CstNode::token(SyntaxKind::Value, text, Span::default()));
                }
                Ok(())
            }
            EditOp::DeleteRow { row_id } => {
                let idx = index_of(cst, row_id)?;
                if children(cst)?[idx].kind() == &SyntaxKind::custom(SECTION) {
                    return Err(unsupported("a section is removed in the text view, with its keys"));
                }
                children(cst)?.remove(idx);
                Ok(())
            }
            EditOp::InsertRow { after_row_id, fields } => {
                let (key, value) = fields.iter().next().ok_or_else(|| EditError::InvalidValue { field: "key".into(), message: "a key is required".into() })?;
                if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.') {
                    return Err(EditError::InvalidValue { field: key.clone(), message: "a key is letters, digits, '_', '-' and '.'".into() });
                }
                let value = one_line(key, value)?;
                let node = parse_systemd_cst(&format!("{key}={value}\n")).remove(0);
                let at = match after_row_id {
                    Some(id) => index_of(cst, id)? + 1,
                    None => children(cst)?.len(),
                };
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
            EditOp::MoveRow { .. } => Err(unsupported("keys are moved in the text view")),
        }
    }
}

fn one_line(field: &str, v: &serde_json::Value) -> Result<String, EditError> {
    let s = v.as_str().ok_or_else(|| EditError::InvalidValue { field: field.into(), message: "Expected a string".into() })?;
    if s.contains(['\n', '\r']) {
        return Err(EditError::InvalidValue { field: field.into(), message: "must be one line".into() });
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

/// One node per logical line (a value ending in `\` takes the next line
/// too); every byte is kept.
pub fn parse_systemd_cst(input: &str) -> Vec<CstNode> {
    let lines: Vec<&str> = input.split_inclusive('\n').collect();
    let mut out = Vec::new();
    let mut offset = 0;
    let mut i = 0;
    while i < lines.len() {
        let t = body_of(lines[i]).trim_start();
        let mut end = i + 1;
        let is_entry = !t.is_empty() && !t.starts_with(['#', ';', '[']) && t.contains('=');
        if is_entry {
            while end <= lines.len() && body_of(lines[end - 1]).trim_end().ends_with('\\') && end < lines.len() {
                end += 1;
            }
        }
        let text: String = lines[i..end].concat();
        out.push(parse_node(&text, offset));
        offset += text.len();
        i = end;
    }
    out
}

fn parse_node(text: &str, base: usize) -> CstNode {
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
    } else if t.starts_with(['#', ';']) {
        push(SyntaxKind::Whitespace, 0, lead);
        push(SyntaxKind::Comment, lead, body_end);
        SyntaxKind::CommentLine
    } else if t.starts_with('[') && t.ends_with(']') {
        let close = lead + body[lead..].rfind(']').unwrap_or(0);
        push(SyntaxKind::Whitespace, 0, lead);
        push(SyntaxKind::custom("bracket"), lead, lead + 1);
        push(SyntaxKind::Key, lead + 1, close);
        push(SyntaxKind::custom("bracket"), close, close + 1);
        push(SyntaxKind::Whitespace, close + 1, body_end);
        SyntaxKind::custom(SECTION)
    } else if let Some(eq) = body[lead..].find('=').map(|i| lead + i) {
        let key_end = lead + body[lead..eq].trim_end().len();
        let v_start = eq + 1 + (body[eq + 1..].len() - body[eq + 1..].trim_start_matches([' ', '\t']).len());
        let v_end = v_start + body[v_start..].trim_end_matches([' ', '\t']).len();
        push(SyntaxKind::Whitespace, 0, lead);
        push(SyntaxKind::Key, lead, key_end);
        push(SyntaxKind::Whitespace, key_end, eq);
        push(SyntaxKind::custom("equals"), eq, eq + 1);
        push(SyntaxKind::Whitespace, eq + 1, v_start);
        push(SyntaxKind::Value, v_start, v_end);
        push(SyntaxKind::Whitespace, v_end, body_end);
        SyntaxKind::Entry
    } else {
        push(SyntaxKind::Whitespace, 0, lead);
        push(SyntaxKind::Error, lead, body_end);
        SyntaxKind::Error
    };
    push(SyntaxKind::Newline, body_end, text.len());
    CstNode::rule(kind, tokens, Span::new(base, base + text.len()))
}
