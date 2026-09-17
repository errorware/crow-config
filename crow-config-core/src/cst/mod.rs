use serde::{Deserialize, Serialize};

/// A byte span (start..end) in the original source buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    pub fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    pub fn is_empty(&self) -> bool {
        self.start >= self.end
    }

    pub fn merge(&self, other: &Span) -> Span {
        Span {
            start: self.start.min(other.start),
            end: self.end.max(other.end),
        }
    }
}

/// A 1-indexed line range representing the visual/source position of a row or rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SourceSpan {
    pub start_line: usize,
    pub end_line: usize,
}

impl SourceSpan {
    pub const fn new(start_line: usize, end_line: usize) -> Self {
        Self {
            start_line,
            end_line,
        }
    }

    pub const fn single_line(line: usize) -> Self {
        Self {
            start_line: line,
            end_line: line,
        }
    }
}

/// Identifies the kind of syntax node or token.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyntaxKind {
    Document,
    Line,
    BlankLine,
    CommentLine,
    Entry,
    Whitespace,
    Comment,
    Newline,
    Key,
    Value,
    IpAddress,
    Hostname,
    Error,
    Custom(String),
}

impl SyntaxKind {
    pub fn custom(name: impl Into<String>) -> Self {
        Self::Custom(name.into())
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Document => "document",
            Self::Line => "line",
            Self::BlankLine => "blank_line",
            Self::CommentLine => "comment_line",
            Self::Entry => "entry",
            Self::Whitespace => "whitespace",
            Self::Comment => "comment",
            Self::Newline => "newline",
            Self::Key => "key",
            Self::Value => "value",
            Self::IpAddress => "ip_address",
            Self::Hostname => "hostname",
            Self::Error => "error",
            Self::Custom(s) => s.as_str(),
        }
    }
}

impl std::fmt::Display for SyntaxKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A node in the Concrete Syntax Tree (CST).
///
/// CST nodes are either leaf `Token`s (carrying exact text slices) or `Rule`s
/// (containers of child nodes). Every whitespace character, comment, and newline
/// is preserved in the tree, guaranteeing 100% lossless serialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum CstNode {
    Token {
        kind: SyntaxKind,
        text: String,
        span: Span,
    },
    Rule {
        kind: SyntaxKind,
        children: Vec<CstNode>,
        span: Span,
    },
}

impl CstNode {
    pub fn token(kind: SyntaxKind, text: impl Into<String>, span: Span) -> Self {
        Self::Token {
            kind,
            text: text.into(),
            span,
        }
    }

    pub fn rule(kind: SyntaxKind, children: Vec<CstNode>, span: Span) -> Self {
        Self::Rule {
            kind,
            children,
            span,
        }
    }

    pub fn kind(&self) -> &SyntaxKind {
        match self {
            Self::Token { kind, .. } => kind,
            Self::Rule { kind, .. } => kind,
        }
    }

    pub fn span(&self) -> Span {
        match self {
            Self::Token { span, .. } => *span,
            Self::Rule { span, .. } => *span,
        }
    }

    pub fn children(&self) -> &[CstNode] {
        match self {
            Self::Token { .. } => &[],
            Self::Rule { children, .. } => children,
        }
    }

    pub fn children_mut(&mut self) -> Option<&mut Vec<CstNode>> {
        match self {
            Self::Token { .. } => None,
            Self::Rule { children, .. } => Some(children),
        }
    }

    /// Serializes this CST node back into text.
    pub fn to_text(&self, out: &mut String) {
        match self {
            Self::Token { text, .. } => out.push_str(text),
            Self::Rule { children, .. } => {
                for child in children {
                    child.to_text(out);
                }
            }
        }
    }

    /// Reconstructs the entire text represented by this CST node.
    pub fn to_string_lossless(&self) -> String {
        let mut s = String::new();
        self.to_text(&mut s);
        s
    }

    /// Recursively finds the first token of `kind` and replaces its text.
    /// Returns true if replaced.
    pub fn replace_first_token_text(&mut self, target_kind: &SyntaxKind, new_text: &str) -> bool {
        match self {
            Self::Token { kind, text, span } => {
                if kind == target_kind {
                    let old_len = text.len();
                    *text = new_text.to_string();
                    let diff = new_text.len() as isize - old_len as isize;
                    span.end = (span.end as isize + diff) as usize;
                    true
                } else {
                    false
                }
            }
            Self::Rule { children, .. } => {
                for child in children.iter_mut() {
                    if child.replace_first_token_text(target_kind, new_text) {
                        return true;
                    }
                }
                false
            }
        }
    }

    /// Collects all token texts with the matching kind.
    pub fn collect_token_texts(&self, target_kind: &SyntaxKind) -> Vec<String> {
        let mut out = Vec::new();
        self.collect_token_texts_internal(target_kind, &mut out);
        out
    }

    fn collect_token_texts_internal(&self, target_kind: &SyntaxKind, out: &mut Vec<String>) {
        match self {
            Self::Token { kind, text, .. } => {
                if kind == target_kind {
                    out.push(text.clone());
                }
            }
            Self::Rule { children, .. } => {
                for child in children {
                    child.collect_token_texts_internal(target_kind, out);
                }
            }
        }
    }
}
