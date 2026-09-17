pub mod hosts;
pub mod sshd;

pub use hosts::{HostsPlugin, HOSTS_MANIFEST, HOSTS_MANIFEST_TOML};
pub use sshd::{SshdPlugin, SSHD_MANIFEST, SSHD_MANIFEST_TOML};

#[cfg(test)]
mod tests {
    use super::*;
    use crow_config_core::edit::{ConfigDocument, EditOp};
    use crow_config_core::schema::RiskLevel;
    use proptest::prelude::*;

    const SAMPLE_HOSTS: &str = include_str!("../test_data/hosts_sample.txt");
    const SAMPLE_SSHD: &str = include_str!("../test_data/sshd_config_sample.txt");

    // ==========================================
    // /etc/hosts Tests
    // ==========================================

    #[test]
    fn test_acceptance_ir_target_step_1() {
        let plugin = HostsPlugin::new();
        let doc = ConfigDocument::parse(&plugin, SAMPLE_HOSTS).expect("Failed to parse hosts file");
        let ir = doc.to_ir().expect("Failed to bind to IR");

        let row_4 = ir
            .rows
            .iter()
            .find(|r| r.row_id == "line-4")
            .expect("Row line-4 must exist");

        let row_json = serde_json::to_value(row_4).expect("Failed to serialize row to JSON");

        let expected_json = serde_json::json!({
            "row_id": "line-4",
            "widget": "key_value_list_row",
            "fields": [
                { "name": "address", "value": "10.0.4.12", "type": "ip_address", "valid": true },
                { "name": "hostnames", "value": ["db-primary-01.internal", "db-primary-01"], "type": "string_list" },
                { "name": "comment", "value": "primary postgres", "type": "string" }
            ],
            "source_span": { "start_line": 4, "end_line": 4 }
        });

        assert_eq!(row_json, expected_json);
    }

    #[test]
    fn test_lossless_roundtrip_unedited() {
        let plugin = HostsPlugin::new();
        let doc = ConfigDocument::parse(&plugin, SAMPLE_HOSTS).expect("Failed to parse hosts");

        let serialized = doc.serialize();
        assert_eq!(serialized, SAMPLE_HOSTS);

        let doc2 = ConfigDocument::parse(&plugin, &serialized).expect("Failed to re-parse");
        assert_eq!(doc.cst(), doc2.cst());
        assert_eq!(doc.to_ir().unwrap(), doc2.to_ir().unwrap());
    }

    #[test]
    fn test_single_semantic_edit_only_intended_line_changes() {
        let plugin = HostsPlugin::new();
        let mut doc = ConfigDocument::parse(&plugin, SAMPLE_HOSTS).expect("Failed to parse hosts");

        let edit = EditOp::UpdateField {
            row_id: "line-4".to_string(),
            field_name: "address".to_string(),
            new_value: serde_json::json!("10.0.4.13"),
        };
        doc.apply_edit(&edit).expect("Failed to apply edit");

        let serialized = doc.serialize();

        let orig_lines: Vec<&str> = SAMPLE_HOSTS.lines().collect();
        let new_lines: Vec<&str> = serialized.lines().collect();

        assert_eq!(orig_lines.len(), new_lines.len());

        for (i, (orig, new)) in orig_lines.iter().zip(new_lines.iter()).enumerate() {
            let line_no = i + 1;
            if line_no == 4 {
                assert_eq!(
                    *new,
                    "10.0.4.13  db-primary-01.internal db-primary-01  # primary postgres"
                );
            } else {
                assert_eq!(orig, new, "Line {} changed unexpectedly", line_no);
            }
        }
    }

    #[test]
    fn test_edit_hostnames_and_comment() {
        let plugin = HostsPlugin::new();
        let mut doc = ConfigDocument::parse(&plugin, SAMPLE_HOSTS).expect("Failed to parse hosts");

        doc.apply_edit(&EditOp::UpdateField {
            row_id: "line-4".to_string(),
            field_name: "hostnames".to_string(),
            new_value: serde_json::json!(["db-primary-01.internal", "db-primary-01", "db-01"]),
        })
        .unwrap();

        doc.apply_edit(&EditOp::UpdateField {
            row_id: "line-4".to_string(),
            field_name: "comment".to_string(),
            new_value: serde_json::json!("updated postgres comment"),
        })
        .unwrap();

        let serialized = doc.serialize();
        assert!(serialized.contains("10.0.4.12  db-primary-01.internal db-primary-01 db-01  # updated postgres comment"));

        let orig_lines: Vec<&str> = SAMPLE_HOSTS.lines().collect();
        let new_lines: Vec<&str> = serialized.lines().collect();
        assert_eq!(orig_lines[0], new_lines[0]);
        assert_eq!(orig_lines[1], new_lines[1]);
        assert_eq!(orig_lines[2], new_lines[2]);
        assert_eq!(orig_lines[4], new_lines[4]);
    }

    #[test]
    fn test_delete_and_insert_row() {
        let plugin = HostsPlugin::new();
        let mut doc = ConfigDocument::parse(&plugin, SAMPLE_HOSTS).unwrap();

        doc.apply_edit(&EditOp::DeleteRow {
            row_id: "line-4".to_string(),
        })
        .unwrap();

        let serialized = doc.serialize();
        assert!(!serialized.contains("10.0.4.12"));

        let mut fields = std::collections::HashMap::new();
        fields.insert("address".to_string(), serde_json::json!("10.0.4.99"));
        fields.insert("hostnames".to_string(), serde_json::json!(["new-host.internal"]));
        fields.insert("comment".to_string(), serde_json::json!("brand new host"));

        doc.apply_edit(&EditOp::InsertRow {
            after_row_id: Some("line-3".to_string()),
            fields,
        })
        .unwrap();

        let updated_serialized = doc.serialize();
        assert!(updated_serialized.contains("10.0.4.99\tnew-host.internal  # brand new host\n"));
    }

    #[test]
    fn test_malformed_input_never_panics_and_is_lossless() {
        let malformed = "### Header\nnot-an-ip-or-anything\n127.0.0.1\n999.999.999.999 validname\n\n";
        let plugin = HostsPlugin::new();
        let doc = ConfigDocument::parse(&plugin, malformed).expect("Should parse without panic");

        assert_eq!(doc.serialize(), malformed);

        let ir = doc.to_ir().unwrap();
        let invalid_ip_row = ir.rows.iter().find(|r| {
            r.fields
                .iter()
                .any(|f| f.name == "address" && f.value == "999.999.999.999")
        });
        assert!(invalid_ip_row.is_some());
        let addr_field = invalid_ip_row.unwrap().get_field("address").unwrap();
        assert_eq!(addr_field.valid, Some(false));
    }

    proptest! {
        #[test]
        fn proptest_arbitrary_input_never_panics_and_roundtrips(input in "\\PC*") {
            let plugin = HostsPlugin::new();
            let doc = ConfigDocument::parse(&plugin, &input).unwrap();
            let roundtripped = doc.serialize();
            prop_assert_eq!(roundtripped, input);
        }
    }

    // ==========================================
    // sshd_config Tests
    // ==========================================

    #[test]
    fn test_sshd_config_lossless_roundtrip() {
        let plugin = SshdPlugin::new();
        let doc = ConfigDocument::parse(&plugin, SAMPLE_SSHD).expect("Failed to parse sshd_config");

        let serialized = doc.serialize();
        assert_eq!(serialized, SAMPLE_SSHD);

        let doc2 = ConfigDocument::parse(&plugin, &serialized).expect("Failed to re-parse");
        assert_eq!(doc.cst(), doc2.cst());
        assert_eq!(doc.to_ir().unwrap(), doc2.to_ir().unwrap());
    }

    #[test]
    fn test_sshd_config_risk_metadata_and_docs() {
        let plugin = SshdPlugin::new();
        let doc = ConfigDocument::parse(&plugin, SAMPLE_SSHD).unwrap();
        let ir = doc.to_ir().unwrap();

        // Check PermitRootLogin row
        let root_login_row = ir
            .rows
            .iter()
            .find(|r| r.get_field("PermitRootLogin").is_some())
            .expect("PermitRootLogin row must exist");

        let field = root_login_row.get_field("PermitRootLogin").unwrap();
        assert_eq!(field.value, "prohibit-password");
        assert_eq!(field.valid, Some(true));
        assert_eq!(
            field.docs_source.as_deref(),
            Some("man:sshd_config(5)#PermitRootLogin")
        );

        // Verify risk metadata on options
        let opts = field.options.as_ref().expect("Options must be populated");
        let rec = opts.iter().find(|o| o.value == "prohibit-password").unwrap();
        assert_eq!(rec.risk, Some(RiskLevel::Recommended));
        let bad = opts.iter().find(|o| o.value == "yes").unwrap();
        assert_eq!(bad.risk, Some(RiskLevel::NeverOnProd));

        // Check PasswordAuthentication row
        let pass_row = ir
            .rows
            .iter()
            .find(|r| r.get_field("PasswordAuthentication").is_some())
            .expect("PasswordAuthentication row must exist");

        let pass_field = pass_row.get_field("PasswordAuthentication").unwrap();
        assert_eq!(pass_field.value, "no");
        assert_eq!(pass_field.valid, Some(true));
        let pass_opts = pass_field.options.as_ref().unwrap();
        assert_eq!(
            pass_opts.iter().find(|o| o.value == "no").unwrap().risk,
            Some(RiskLevel::Recommended)
        );
        assert_eq!(
            pass_opts.iter().find(|o| o.value == "yes").unwrap().risk,
            Some(RiskLevel::Caution)
        );
    }

    #[test]
    fn test_sshd_config_semantic_edit() {
        let plugin = SshdPlugin::new();
        let mut doc = ConfigDocument::parse(&plugin, SAMPLE_SSHD).unwrap();

        // Line 4 is: "Port 2222"
        doc.apply_edit(&EditOp::UpdateField {
            row_id: "line-4".to_string(),
            field_name: "Port".to_string(),
            new_value: serde_json::json!("22"),
        })
        .unwrap();

        let serialized = doc.serialize();

        let orig_lines: Vec<&str> = SAMPLE_SSHD.lines().collect();
        let new_lines: Vec<&str> = serialized.lines().collect();
        assert_eq!(orig_lines.len(), new_lines.len());

        for (i, (orig, new)) in orig_lines.iter().zip(new_lines.iter()).enumerate() {
            let line_no = i + 1;
            if line_no == 4 {
                assert_eq!(*new, "Port 22");
            } else {
                assert_eq!(orig, new, "Line {} changed unexpectedly", line_no);
            }
        }
    }

    #[test]
    fn test_sshd_config_edit_preserves_equals_separator_and_comment() {
        let plugin = SshdPlugin::new();
        let mut doc = ConfigDocument::parse(&plugin, SAMPLE_SSHD).unwrap();

        // Line 16 is: "PasswordAuthentication = no"
        // Find row_id for PasswordAuthentication
        let ir = doc.to_ir().unwrap();
        let pass_row = ir
            .rows
            .iter()
            .find(|r| r.get_field("PasswordAuthentication").is_some())
            .unwrap();

        doc.apply_edit(&EditOp::UpdateField {
            row_id: pass_row.row_id.clone(),
            field_name: "PasswordAuthentication".to_string(),
            new_value: serde_json::json!("yes"),
        })
        .unwrap();

        let serialized = doc.serialize();
        // The '=' separator must remain intact!
        assert!(serialized.contains("PasswordAuthentication = yes\n"));

        // Line 19 is: "X11Forwarding no # disable GUI tunneling"
        let x11_row = ir
            .rows
            .iter()
            .find(|r| r.get_field("X11Forwarding").is_some())
            .unwrap();

        doc.apply_edit(&EditOp::UpdateField {
            row_id: x11_row.row_id.clone(),
            field_name: "X11Forwarding".to_string(),
            new_value: serde_json::json!("yes"),
        })
        .unwrap();

        let serialized_2 = doc.serialize();
        assert!(serialized_2.contains("X11Forwarding yes # disable GUI tunneling\n"));
    }

    #[test]
    fn test_sshd_delete_and_insert() {
        let plugin = SshdPlugin::new();
        let mut doc = ConfigDocument::parse(&plugin, SAMPLE_SSHD).unwrap();

        // Delete line 4 (Port)
        doc.apply_edit(&EditOp::DeleteRow {
            row_id: "line-4".to_string(),
        })
        .unwrap();
        assert!(!doc.serialize().contains("Port 2222"));

        // Insert new Banner directive
        let mut fields = std::collections::HashMap::new();
        fields.insert("Banner".to_string(), serde_json::json!("/etc/issue.net"));
        fields.insert("comment".to_string(), serde_json::json!("legal warning banner"));

        doc.apply_edit(&EditOp::InsertRow {
            after_row_id: Some("line-15".to_string()),
            fields,
        })
        .unwrap();

        let res = doc.serialize();
        assert!(res.contains("Banner /etc/issue.net  # legal warning banner\n"));
    }

    proptest! {
        #[test]
        fn proptest_sshd_arbitrary_input_never_panics_and_roundtrips(input in "\\PC*") {
            let plugin = SshdPlugin::new();
            let doc = ConfigDocument::parse(&plugin, &input).unwrap();
            let roundtripped = doc.serialize();
            prop_assert_eq!(roundtripped, input);
        }
    }
}
