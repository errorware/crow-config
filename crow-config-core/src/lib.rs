pub mod cst;
pub mod edit;
pub mod ir;
pub mod schema;

pub use cst::{CstNode, SourceSpan, Span, SyntaxKind};
pub use edit::{BindError, ConfigDocument, ConfigPlugin, EditError, EditOp, ParseError};
pub use ir::{ConfigDocumentIr, FieldIr, RowIr, ShapeIr};
pub use schema::{
    validate_field_value, EnumOption, FieldDef, FieldType, PluginManifest, PluginMeta, RiskLevel,
    ShapeMeta, ValidatorDef, WidgetKind,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manifest_deserialization() {
        let manifest_toml = r#"
[plugin]
name = "hosts"
grammar = "hosts-line-grammar"

[shape]
kind = "key_value_list"
order_sensitive = true
order_note = "On most systems, the first matching entry for a hostname wins — duplicate entries below the first are effectively dead."

[[fields]]
name = "address"
type = "ip_address"
required = true

[[fields]]
name = "hostnames"
type = "string_list"
required = true
help = "First entry is the canonical hostname; the rest are aliases."

[[fields]]
name = "comment"
type = "string"
required = false

[[validators]]
command = "getent hosts {address}"
description = "Confirms the address resolves as entered."
"#;

        let manifest = PluginManifest::from_toml_str(manifest_toml).unwrap();
        assert_eq!(manifest.plugin.name, "hosts");
        assert_eq!(manifest.shape.kind, WidgetKind::KeyValueList);
        assert!(manifest.shape.order_sensitive);
        assert_eq!(manifest.fields.len(), 3);
        assert_eq!(manifest.validators.len(), 1);

        let mut params = std::collections::HashMap::new();
        params.insert("address".to_string(), "10.0.4.12".to_string());
        assert_eq!(
            manifest.validators[0].render_command(&params),
            "getent hosts 10.0.4.12"
        );
    }

    #[test]
    fn test_manifest_with_enum_risk_and_docs() {
        let manifest_toml = r#"
[plugin]
name = "pg_hba"
grammar = "tree-sitter-pg-hba"

[shape]
kind = "rule_table"
order_sensitive = true
order_note = "First match wins — rule order is evaluated top to bottom."

[[fields]]
name = "method"
type = "enum"
docs_source = "man:pg_hba.conf(5)#auth-method"
options = [
  { value = "scram-sha-256", label = "Salted challenge-response, password never in cleartext", risk = "recommended" },
  { value = "md5", label = "Deprecated hash, replayable on the wire", risk = "weak" },
  { value = "trust", label = "Any connection accepted with no password whatsoever", risk = "never_on_prod" },
]

[[validators]]
command = "postgres --check-config"
"#;

        let manifest = PluginManifest::from_toml_str(manifest_toml).unwrap();
        assert_eq!(manifest.plugin.name, "pg_hba");
        assert_eq!(manifest.shape.kind, WidgetKind::RuleTable);
        let method_field = manifest.find_field("method").unwrap();
        assert_eq!(method_field.docs_source.as_deref(), Some("man:pg_hba.conf(5)#auth-method"));
        let opts = method_field.options.as_ref().unwrap();
        assert_eq!(opts.len(), 3);
        assert_eq!(opts[0].risk, Some(RiskLevel::Recommended));
        assert_eq!(opts[1].risk, Some(RiskLevel::Weak));
        assert_eq!(opts[2].risk, Some(RiskLevel::NeverOnProd));
    }

    #[test]
    fn test_ir_row_json_serialization_matches_spec() {
        let mut row = RowIr::new("line-4", "key_value_list_row", SourceSpan::new(4, 4));
        row.fields.push(
            FieldIr::new(
                "address",
                FieldType::IpAddress,
                serde_json::Value::String("10.0.4.12".to_string()),
            )
            .with_validity(true),
        );
        row.fields.push(FieldIr::new(
            "hostnames",
            FieldType::StringList,
            serde_json::json!(["db-primary-01.internal", "db-primary-01"]),
        ));
        row.fields.push(FieldIr::new(
            "comment",
            FieldType::String,
            serde_json::Value::String("primary postgres".to_string()),
        ));

        let json_val = serde_json::to_value(&row).unwrap();
        let expected: serde_json::Value = serde_json::json!({
            "row_id": "line-4",
            "widget": "key_value_list_row",
            "fields": [
                { "name": "address", "value": "10.0.4.12", "type": "ip_address", "valid": true },
                { "name": "hostnames", "value": ["db-primary-01.internal", "db-primary-01"], "type": "string_list" },
                { "name": "comment", "value": "primary postgres", "type": "string" }
            ],
            "source_span": { "start_line": 4, "end_line": 4 }
        });

        assert_eq!(json_val, expected);
    }

    #[test]
    fn test_validation_logic() {
        let ip_field = FieldDef {
            name: "address".to_string(),
            field_type: FieldType::IpAddress,
            required: Some(true),
            help: None,
            docs_source: None,
            options: None,
        };

        assert!(validate_field_value(&ip_field, &serde_json::json!("10.0.4.12")).is_ok());
        assert!(validate_field_value(&ip_field, &serde_json::json!("::1")).is_ok());
        assert!(validate_field_value(&ip_field, &serde_json::json!("invalid-ip")).is_err());
        assert!(validate_field_value(&ip_field, &serde_json::Value::Null).is_err());
    }

    #[test]
    fn test_cst_lossless_roundtrip_simple() {
        let text = "  127.0.0.1\tlocalhost # local  \n";
        let cst = CstNode::rule(
            SyntaxKind::Line,
            vec![
                CstNode::token(SyntaxKind::Whitespace, "  ", Span::new(0, 2)),
                CstNode::token(SyntaxKind::IpAddress, "127.0.0.1", Span::new(2, 11)),
                CstNode::token(SyntaxKind::Whitespace, "\t", Span::new(11, 12)),
                CstNode::token(SyntaxKind::Hostname, "localhost", Span::new(12, 21)),
                CstNode::token(SyntaxKind::Whitespace, " ", Span::new(21, 22)),
                CstNode::token(SyntaxKind::Comment, "# local  ", Span::new(22, 31)),
                CstNode::token(SyntaxKind::Newline, "\n", Span::new(31, 32)),
            ],
            Span::new(0, 32),
        );

        assert_eq!(cst.to_string_lossless(), text);
    }
}
