pub mod fstab;
pub mod hosts;
pub mod logrotate;
pub mod pg_hba;
pub mod sshd;
pub mod sudoers;
pub mod sysctl;
pub mod systemd;
pub mod ufw;

pub use fstab::{boot_risk as fstab_boot_risk, mounts as fstab_mounts, FstabPlugin, Mount as FstabMount, FSTAB_MANIFEST, FSTAB_MANIFEST_TOML};
pub use logrotate::{LogrotatePlugin, LOGROTATE_MANIFEST, LOGROTATE_MANIFEST_TOML};
pub use hosts::{HostsPlugin, HOSTS_MANIFEST, HOSTS_MANIFEST_TOML};
pub use pg_hba::{PgHbaPlugin, PG_HBA_MANIFEST, PG_HBA_MANIFEST_TOML};
pub use sshd::{SshdPlugin, SSHD_MANIFEST, SSHD_MANIFEST_TOML};
pub use sudoers::{rule_risk as sudoers_rule_risk, SudoersPlugin, SUDOERS_MANIFEST, SUDOERS_MANIFEST_TOML};
pub use systemd::{SystemdPlugin, SYSTEMD_MANIFEST, SYSTEMD_MANIFEST_TOML};
pub use sysctl::{SysctlPlugin, SYSCTL_MANIFEST, SYSCTL_MANIFEST_TOML};
pub use ufw::{UfwPlugin, UFW_MANIFEST, UFW_MANIFEST_TOML};

#[cfg(test)]
mod tests {
    use super::*;
    use crow_config_core::edit::{ConfigDocument, ConfigPlugin, EditOp};
    use crow_config_core::schema::RiskLevel;
    use proptest::prelude::*;

    const SAMPLE_HOSTS: &str = include_str!("../test_data/hosts_sample.txt");
    const SAMPLE_SSHD: &str = include_str!("../test_data/sshd_config_sample.txt");
    const SAMPLE_PG_HBA: &str = include_str!("../test_data/pg_hba_sample.conf");
    const SAMPLE_UFW: &str = include_str!("../test_data/ufw_sample.rules");
    const SAMPLE_SYSCTL: &str = include_str!("../test_data/sysctl_sample.conf");
    const SAMPLE_SUDOERS: &str = include_str!("../test_data/sudoers_sample");
    const SAMPLE_FSTAB: &str = include_str!("../test_data/fstab_sample");
    const SAMPLE_LOGROTATE: &str = include_str!("../test_data/logrotate_sample");
    const SAMPLE_SYSTEMD: &str = include_str!("../test_data/systemd_sample.service");
    const SAMPLE_LOGROTATE_MARIADB: &str = include_str!("../test_data/logrotate_mariadb");

    /// Every shipped manifest is a valid config-format plugin.
    #[test]
    fn shipped_manifests_declare_the_config_format_category() {
        use crow_config_core::{categories, PluginKind};
        for m in [&*HOSTS_MANIFEST, &*PG_HBA_MANIFEST, &*SSHD_MANIFEST, &*UFW_MANIFEST, &*SYSCTL_MANIFEST, &*SUDOERS_MANIFEST, &*FSTAB_MANIFEST, &*LOGROTATE_MANIFEST, &*SYSTEMD_MANIFEST] {
            assert_eq!(m.validate(), Ok(()), "{}", m.plugin.name);
            assert_eq!(m.plugin.kind, PluginKind::Config);
            assert_eq!(m.plugin.category.as_deref(), Some(categories::CONFIG_FORMAT), "{}", m.plugin.name);
        }
    }

    /// Every sshd directive has a UI group, and the security-relevant ones
    /// carry OpenSSH's built-in default so a UI can show effective values.
    #[test]
    fn sshd_fields_have_groups_and_defaults() {
        let plugin = SshdPlugin::new();
        let fields = &plugin.manifest().fields;
        assert!(fields.iter().all(|f| f.group.is_some()), "every sshd field has a group");
        let default = |name: &str| fields.iter().find(|f| f.name == name).and_then(|f| f.default.clone());
        assert_eq!(default("PermitRootLogin").as_deref(), Some("prohibit-password"));
        assert_eq!(default("PasswordAuthentication").as_deref(), Some("yes"));
        assert_eq!(default("Port").as_deref(), Some("22"));
        assert_eq!(default("AllowUsers"), None, "no default: unset means everyone");
        // An enum's default is one of its options.
        for f in fields.iter().filter(|f| f.options.is_some()) {
            if let Some(d) = &f.default {
                assert!(f.options.as_ref().unwrap().iter().any(|o| &o.value == d), "{}: default {d} is an option", f.name);
            }
        }
    }

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
    fn test_hosts_lossless_roundtrip_unedited() {
        let plugin = HostsPlugin::new();
        let doc = ConfigDocument::parse(&plugin, SAMPLE_HOSTS).expect("Failed to parse hosts");

        let serialized = doc.serialize();
        assert_eq!(serialized, SAMPLE_HOSTS);

        let doc2 = ConfigDocument::parse(&plugin, &serialized).expect("Failed to re-parse");
        assert_eq!(doc.cst(), doc2.cst());
        assert_eq!(doc.to_ir().unwrap(), doc2.to_ir().unwrap());
    }

    #[test]
    fn test_hosts_single_semantic_edit_only_intended_line_changes() {
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
    fn test_hosts_edit_hostnames_and_comment() {
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
    }

    #[test]
    fn test_hosts_delete_and_insert_row() {
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

    proptest! {
        #[test]
        fn proptest_hosts_arbitrary_input_never_panics_and_roundtrips(input in "\\PC*") {
            let plugin = HostsPlugin::new();
            let doc = ConfigDocument::parse(&plugin, &input).unwrap();
            let roundtripped = doc.serialize();
            prop_assert_eq!(roundtripped, input);
        }
    }

    // ==========================================
    // sshd_config Tests
    // ==========================================

    /// A stock Ubuntu sshd_config's shape: an Include at the top, globals,
    /// then Match blocks (ERR-12).
    const SSHD_WITH_SCOPES: &str = "Include /etc/ssh/sshd_config.d/*.conf\n\nPort 22\nPermitRootLogin no\n\n# deploy may use a password\nMatch User deploy\n\tPasswordAuthentication yes\n\tPermitRootLogin yes\nMatch Address 10.0.0.0/8,192.168.0.0/16\n    X11Forwarding yes\n";

    #[test]
    fn sshd_rows_carry_their_match_scope() {
        let plugin = SshdPlugin::new();
        let ir = ConfigDocument::parse(&plugin, SSHD_WITH_SCOPES).unwrap().to_ir().unwrap();
        let by_key = |k: &str| ir.rows.iter().filter(|r| r.fields.first().is_some_and(|f| f.name.eq_ignore_ascii_case(k))).collect::<Vec<_>>();
        let root = by_key("PermitRootLogin");
        assert_eq!(root[0].scope, None, "the global one");
        assert_eq!(root[1].scope.as_deref(), Some("User deploy"), "not a global never-on-prod value");
        assert_eq!(by_key("PasswordAuthentication")[0].scope.as_deref(), Some("User deploy"));
        assert_eq!(by_key("X11Forwarding")[0].scope.as_deref(), Some("Address 10.0.0.0/8,192.168.0.0/16"));
        let matches = by_key("Match");
        assert_eq!(matches.len(), 2);
        assert!(matches.iter().all(|m| m.widget == "scope_row"));
        assert_eq!(matches[0].scope.as_deref(), Some("User deploy"), "a block's opening line carries its scope");
        assert_eq!(by_key("Port")[0].scope, None);
    }

    #[test]
    fn sshd_include_rows_expose_their_globs() {
        let plugin = SshdPlugin::new();
        let ir = ConfigDocument::parse(&plugin, "Include /etc/ssh/sshd_config.d/*.conf /etc/ssh/extra.conf\nPort 22\n").unwrap().to_ir().unwrap();
        assert_eq!(ir.rows[0].widget, "include_row");
        assert_eq!(ir.rows[0].include.as_deref(), Some(&["/etc/ssh/sshd_config.d/*.conf".to_string(), "/etc/ssh/extra.conf".to_string()][..]));
        assert_eq!(ir.rows[1].include, None);
    }

    #[test]
    fn sshd_scoped_configs_round_trip_and_edit_in_place() {
        let plugin = SshdPlugin::new();
        let mut doc = ConfigDocument::parse(&plugin, SSHD_WITH_SCOPES).unwrap();
        assert_eq!(doc.serialize(), SSHD_WITH_SCOPES, "lossless");
        let ir = doc.to_ir().unwrap();
        let scoped = ir.rows.iter().find(|r| r.scope.as_deref() == Some("User deploy") && r.fields.first().is_some_and(|f| f.name == "PermitRootLogin")).unwrap();
        doc.apply_edit(&EditOp::UpdateField { row_id: scoped.row_id.clone(), field_name: "PermitRootLogin".into(), new_value: serde_json::json!("no") }).unwrap();
        assert_eq!(doc.serialize(), SSHD_WITH_SCOPES.replace("\tPermitRootLogin yes", "\tPermitRootLogin no"), "only that line changed");
    }

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

        let opts = field.options.as_ref().expect("Options must be populated");
        let rec = opts.iter().find(|o| o.value == "prohibit-password").unwrap();
        assert_eq!(rec.risk, Some(RiskLevel::Recommended));
        let bad = opts.iter().find(|o| o.value == "yes").unwrap();
        assert_eq!(bad.risk, Some(RiskLevel::NeverOnProd));
    }

    #[test]
    fn test_sshd_config_semantic_edit() {
        let plugin = SshdPlugin::new();
        let mut doc = ConfigDocument::parse(&plugin, SAMPLE_SSHD).unwrap();

        doc.apply_edit(&EditOp::UpdateField {
            row_id: "line-4".to_string(),
            field_name: "Port".to_string(),
            new_value: serde_json::json!("22"),
        })
        .unwrap();

        let serialized = doc.serialize();
        assert!(serialized.contains("Port 22\n"));
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

    // ==========================================
    // pg_hba.conf Tests (Order-Sensitive Rule Table)
    // ==========================================

    #[test]
    fn test_pg_hba_lossless_roundtrip() {
        let plugin = PgHbaPlugin::new();
        let doc = ConfigDocument::parse(&plugin, SAMPLE_PG_HBA).expect("Failed to parse pg_hba.conf");

        let serialized = doc.serialize();
        assert_eq!(serialized, SAMPLE_PG_HBA);

        let doc2 = ConfigDocument::parse(&plugin, &serialized).expect("Failed to re-parse");
        assert_eq!(doc.cst(), doc2.cst());
        assert_eq!(doc.to_ir().unwrap(), doc2.to_ir().unwrap());
    }

    #[test]
    fn test_pg_hba_risk_metadata_and_shape() {
        let plugin = PgHbaPlugin::new();
        let doc = ConfigDocument::parse(&plugin, SAMPLE_PG_HBA).unwrap();
        let ir = doc.to_ir().unwrap();

        assert_eq!(ir.shape.kind, crow_config_core::schema::WidgetKind::RuleTable);
        assert!(ir.shape.order_sensitive);

        // Find rule with method "trust" (line 18)
        let trust_row = ir
            .rows
            .iter()
            .find(|r| {
                r.get_field("method")
                    .map(|f| f.value == "trust")
                    .unwrap_or(false)
            })
            .expect("Trust row must exist");

        let method_field = trust_row.get_field("method").unwrap();
        let opts = method_field.options.as_ref().unwrap();

        let trust_opt = opts.iter().find(|o| o.value == "trust").unwrap();
        assert_eq!(trust_opt.risk, Some(RiskLevel::NeverOnProd));

        let md5_opt = opts.iter().find(|o| o.value == "md5").unwrap();
        assert_eq!(md5_opt.risk, Some(RiskLevel::Weak));

        let scram_opt = opts.iter().find(|o| o.value == "scram-sha-256").unwrap();
        assert_eq!(scram_opt.risk, Some(RiskLevel::Recommended));
    }

    #[test]
    fn test_pg_hba_move_row_order_sensitivity() {
        let plugin = PgHbaPlugin::new();
        let mut doc = ConfigDocument::parse(&plugin, SAMPLE_PG_HBA).unwrap();

        // Move the trust rule (line 19) before the local peer rule (line 6)
        doc.apply_edit(&EditOp::MoveRow {
            row_id: "line-19".to_string(),
            before_row_id: Some("line-6".to_string()),
            after_row_id: None,
        })
        .unwrap();

        let serialized = doc.serialize();
        let trust_idx = serialized.find("trust").unwrap();
        let local_idx = serialized.find("local   all             postgres").unwrap();

        // After moving, the trust rule must appear BEFORE the local peer rule!
        assert!(trust_idx < local_idx);

        // Unaffected comments and blank lines are preserved
        assert!(serialized.contains("# PostgreSQL Client Authentication Configuration File"));
    }

    #[test]
    fn test_pg_hba_semantic_edit() {
        let plugin = PgHbaPlugin::new();
        let mut doc = ConfigDocument::parse(&plugin, SAMPLE_PG_HBA).unwrap();

        // Change the dangerous trust rule's method to scram-sha-256 on line 19
        doc.apply_edit(&EditOp::UpdateField {
            row_id: "line-19".to_string(),
            field_name: "method".to_string(),
            new_value: serde_json::json!("scram-sha-256"),
        })
        .unwrap();

        let serialized = doc.serialize();
        assert!(serialized.contains("host    test_db         test_user       192.168.1.100/32        scram-sha-256  # dangerous on prod\n"));
    }

    proptest! {
        #[test]
        fn proptest_pg_hba_arbitrary_input_never_panics_and_roundtrips(input in "\\PC*") {
            let plugin = PgHbaPlugin::new();
            let doc = ConfigDocument::parse(&plugin, &input).unwrap();
            let roundtripped = doc.serialize();
            prop_assert_eq!(roundtripped, input);
        }
    }

    // ==========================================
    // UFW Rules Tests
    // ==========================================

    #[test]
    fn test_ufw_lossless_roundtrip() {
        let plugin = UfwPlugin::new();
        let doc = ConfigDocument::parse(&plugin, SAMPLE_UFW).expect("Failed to parse UFW rules");

        let serialized = doc.serialize();
        assert_eq!(serialized, SAMPLE_UFW);

        let doc2 = ConfigDocument::parse(&plugin, &serialized).expect("Failed to re-parse");
        assert_eq!(doc.cst(), doc2.cst());
        assert_eq!(doc.to_ir().unwrap(), doc2.to_ir().unwrap());
    }

    #[test]
    fn test_ufw_move_row_and_edit() {
        let plugin = UfwPlugin::new();
        let mut doc = ConfigDocument::parse(&plugin, SAMPLE_UFW).unwrap();

        // 1. Edit DENY action to REJECT on line 7
        doc.apply_edit(&EditOp::UpdateField {
            row_id: "line-7".to_string(),
            field_name: "action".to_string(),
            new_value: serde_json::json!("REJECT"),
        })
        .unwrap();

        let serialized_edit = doc.serialize();
        assert!(serialized_edit.contains("REJECT") && !serialized_edit.contains("DENY"));

        // 2. Move REJECT rule (line 7) to top (before line 4)
        doc.apply_edit(&EditOp::MoveRow {
            row_id: "line-7".to_string(),
            before_row_id: Some("line-4".to_string()),
            after_row_id: None,
        })
        .unwrap();

        let serialized_move = doc.serialize();
        let reject_pos = serialized_move.find("REJECT").unwrap();
        let limit_pos = serialized_move.find("LIMIT").unwrap();
        assert!(reject_pos < limit_pos);
    }

    proptest! {
        #[test]
        fn proptest_ufw_arbitrary_input_never_panics_and_roundtrips(input in "\\PC*") {
            let plugin = UfwPlugin::new();
            let doc = ConfigDocument::parse(&plugin, &input).unwrap();
            let roundtripped = doc.serialize();
            prop_assert_eq!(roundtripped, input);
        }
    }

    // ==========================================
    // sysctl Tests
    // ==========================================

    fn sysctl_rows(text: &str) -> Vec<(String, String, String, Option<bool>)> {
        let ir = ConfigDocument::parse(&SysctlPlugin::new(), text).unwrap().to_ir().unwrap();
        ir.rows
            .iter()
            .map(|r| {
                let f = |n: &str| r.get_field(n).unwrap();
                (r.row_id.clone(), f("key").value.as_str().unwrap().to_string(), f("value").value.as_str().unwrap().to_string(), f("key").valid)
            })
            .collect()
    }

    #[test]
    fn sysctl_reads_keys_values_and_keeps_every_byte() {
        let plugin = SysctlPlugin::new();
        let doc = ConfigDocument::parse(&plugin, SAMPLE_SYSCTL).unwrap();
        assert_eq!(doc.serialize(), SAMPLE_SYSCTL);
        let rows = sysctl_rows(SAMPLE_SYSCTL);
        let kv: Vec<(&str, &str)> = rows.iter().map(|(_, k, v, _)| (k.as_str(), v.as_str())).collect();
        assert_eq!(
            kv,
            vec![
                ("net.ipv4.ip_forward", "0"),
                ("net.ipv4.conf.all.rp_filter", "1"),
                ("kernel.kptr_restrict", "2"),
                ("net.ipv6.conf.all.disable_ipv6", "1"),
                ("net.ipv4.ip_local_port_range", "32768\t60999"),
                ("kernel.core_pattern", "|/usr/lib/systemd/systemd-coredump %P # not a comment"),
                ("net.ipv4.ip_forward", "1"),
            ],
            "comments, blanks and the line without '=' aren't rows; '#' after a value is part of it"
        );
        assert_eq!(rows[0].0, "line-4");
        assert!(rows.iter().all(|r| r.3 == Some(true)));
    }

    #[test]
    fn sysctl_edits_touch_only_their_token() {
        let plugin = SysctlPlugin::new();
        let mut doc = ConfigDocument::parse(&plugin, SAMPLE_SYSCTL).unwrap();
        doc.apply_edit(&EditOp::UpdateField { row_id: "line-6".into(), field_name: "value".into(), new_value: serde_json::json!("1") }).unwrap();
        doc.apply_edit(&EditOp::UpdateField { row_id: "line-7".into(), field_name: "key".into(), new_value: serde_json::json!("net.ipv6.conf.default.disable_ipv6") }).unwrap();
        let expected = SAMPLE_SYSCTL
            .replace("  kernel.kptr_restrict =\t2", "  kernel.kptr_restrict =\t1")
            .replace("-net.ipv6.conf.all.disable_ipv6", "-net.ipv6.conf.default.disable_ipv6");
        assert_eq!(doc.serialize(), expected, "spacing and the '-' marker survive");
        let bad = doc.apply_edit(&EditOp::UpdateField { row_id: "line-4".into(), field_name: "key".into(), new_value: serde_json::json!("net ipv4") });
        assert!(bad.is_err(), "spaces aren't allowed in a key");
        let bad = doc.apply_edit(&EditOp::UpdateField { row_id: "line-4".into(), field_name: "value".into(), new_value: serde_json::json!("1\nkernel.x = 2") });
        assert!(bad.is_err(), "a value can't smuggle in another line");
    }

    #[test]
    fn sysctl_known_keys_explain_themselves_and_offer_values() {
        let ir = ConfigDocument::parse(&SysctlPlugin::new(), "kernel.randomize_va_space = 0\nnet/ipv4/conf/all/rp_filter = 1\nvm.swappiness = 10\nmade.up = 1\n").unwrap().to_ir().unwrap();
        let value = |i: usize| ir.rows[i].get_field("value").unwrap();
        let aslr = value(0).options.as_ref().unwrap();
        assert_eq!(aslr.iter().find(|o| o.value == "0").unwrap().risk, Some(RiskLevel::NeverOnProd));
        assert!(value(0).help.as_deref().unwrap().contains("ASLR"));
        assert!(value(1).options.is_some(), "slash form is recognised");
        assert!(value(2).options.is_none() && value(2).help.is_some(), "a number: explained, typed freely");
        assert!(value(3).options.is_none() && value(3).help.is_none());
    }

    #[test]
    fn sysctl_insert_delete_and_move() {
        let plugin = SysctlPlugin::new();
        // No newline at the end: an appended line must still start on its own.
        let mut doc = ConfigDocument::parse(&plugin, "a.b = 1\nc.d = 2").unwrap();
        let mut fields = std::collections::HashMap::new();
        fields.insert("key".to_string(), serde_json::json!("vm.swappiness"));
        fields.insert("value".to_string(), serde_json::json!("10"));
        doc.apply_edit(&EditOp::InsertRow { after_row_id: Some("line-2".into()), fields }).unwrap();
        assert_eq!(doc.serialize(), "a.b = 1\nc.d = 2\nvm.swappiness = 10\n");
        doc.apply_edit(&EditOp::MoveRow { row_id: "line-3".into(), before_row_id: Some("line-1".into()), after_row_id: None }).unwrap();
        assert_eq!(doc.serialize(), "vm.swappiness = 10\na.b = 1\nc.d = 2\n");
        doc.apply_edit(&EditOp::DeleteRow { row_id: "line-2".into() }).unwrap();
        assert_eq!(doc.serialize(), "vm.swappiness = 10\nc.d = 2\n");
    }

    #[test]
    fn sysctl_flags_malformed_keys_and_empty_values() {
        let rows = sysctl_rows("bad key! = 1\nnet.x =\n");
        assert_eq!(rows[0].3, Some(false));
        let ir = ConfigDocument::parse(&SysctlPlugin::new(), "net.x =\n").unwrap().to_ir().unwrap();
        assert_eq!(ir.rows[0].get_field("value").unwrap().valid, Some(false));
    }

    proptest! {
        #[test]
        fn proptest_sysctl_arbitrary_input_never_panics_and_roundtrips(input in "\\PC*") {
            let plugin = SysctlPlugin::new();
            let doc = ConfigDocument::parse(&plugin, &input).unwrap();
            prop_assert_eq!(doc.serialize(), input.clone());
            let _ = doc.to_ir().unwrap();
        }
    }

    // ==========================================
    // sudoers Tests
    // ==========================================

    fn sudoers_rows(text: &str) -> Vec<(String, String, String, String)> {
        let ir = ConfigDocument::parse(&SudoersPlugin::new(), text).unwrap().to_ir().unwrap();
        ir.rows
            .iter()
            .map(|r| {
                let f = |n: &str| r.get_field(n).and_then(|f| f.value.as_str()).unwrap_or("-").to_string();
                (r.row_id.clone(), f("kind"), f("who"), f("rule"))
            })
            .collect()
    }

    #[test]
    fn sudoers_reads_every_kind_of_entry_and_keeps_every_byte() {
        let plugin = SudoersPlugin::new();
        let doc = ConfigDocument::parse(&plugin, SAMPLE_SUDOERS).unwrap();
        assert_eq!(doc.serialize(), SAMPLE_SUDOERS);
        let rows = sudoers_rows(SAMPLE_SUDOERS);
        let view: Vec<(&str, &str, &str)> = rows.iter().map(|(_, k, w, r)| (k.as_str(), w.as_str(), r.as_str())).collect();
        assert_eq!(
            view,
            vec![
                ("Defaults", "", "env_reset"),
                ("Defaults", "", "mail_badpass"),
                ("Defaults", "", "secure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin\""),
                ("Defaults", "deploy", "!requiretty"),
                ("Cmnd_Alias", "SERVICES", "/usr/bin/systemctl restart nginx, /usr/bin/systemctl reload nginx"),
                ("rule", "root", "ALL=(ALL:ALL) ALL"),
                ("rule", "%admin", "ALL=(ALL) ALL"),
                ("rule", "%sudo", "ALL=(ALL:ALL) ALL"),
                ("rule", "deploy, ci", "ALL=(root) NOPASSWD: SERVICES"),
                ("rule", "#1001", "ALL=(ALL) NOPASSWD: ALL"),
                ("@includedir", "-", "/etc/sudoers.d"),
            ]
        );
        // The alias spans two lines; the next row's id is the line after it.
        assert_eq!(rows[4].0, "line-10");
        assert_eq!(rows[5].0, "line-14");
    }

    #[test]
    fn sudoers_edits_rules_defaults_and_aliases_in_place() {
        let plugin = SudoersPlugin::new();
        let mut doc = ConfigDocument::parse(&plugin, SAMPLE_SUDOERS).unwrap();
        doc.apply_edit(&EditOp::UpdateField { row_id: "line-17".into(), field_name: "rule".into(), new_value: serde_json::json!("ALL=(ALL:ALL) ALL") }).unwrap();
        doc.apply_edit(&EditOp::UpdateField { row_id: "line-7".into(), field_name: "who".into(), new_value: serde_json::json!("ci") }).unwrap();
        doc.apply_edit(&EditOp::UpdateField { row_id: "line-10".into(), field_name: "rule".into(), new_value: serde_json::json!("/usr/bin/systemctl restart nginx") }).unwrap();
        let out = doc.serialize();
        assert!(out.contains("%admin ALL=(ALL:ALL) ALL\n"));
        assert!(out.contains("Defaults:ci\t!requiretty\n"));
        assert!(out.contains("Cmnd_Alias\tSERVICES = /usr/bin/systemctl restart nginx\n\n# User"), "the continuation is folded into one line");
        assert!(doc.apply_edit(&EditOp::UpdateField { row_id: "line-14".into(), field_name: "kind".into(), new_value: serde_json::json!("Defaults") }).is_err());
        assert!(doc.apply_edit(&EditOp::UpdateField { row_id: "line-14".into(), field_name: "rule".into(), new_value: serde_json::json!("ALL\nevil ALL=(ALL) ALL") }).is_err());
    }

    #[test]
    fn sudoers_insert_move_delete() {
        let plugin = SudoersPlugin::new();
        let mut doc = ConfigDocument::parse(&plugin, "root ALL=(ALL) ALL\n%sudo ALL=(ALL) ALL").unwrap();
        let mut fields = std::collections::HashMap::new();
        fields.insert("who".to_string(), serde_json::json!("deploy"));
        fields.insert("rule".to_string(), serde_json::json!("ALL=(root) /usr/bin/systemctl"));
        doc.apply_edit(&EditOp::InsertRow { after_row_id: Some("line-2".into()), fields }).unwrap();
        assert_eq!(doc.serialize(), "root ALL=(ALL) ALL\n%sudo ALL=(ALL) ALL\ndeploy ALL=(root) /usr/bin/systemctl\n");
        doc.apply_edit(&EditOp::MoveRow { row_id: "line-3".into(), before_row_id: Some("line-1".into()), after_row_id: None }).unwrap();
        assert!(doc.serialize().starts_with("deploy "));
        doc.apply_edit(&EditOp::DeleteRow { row_id: "line-1".into() }).unwrap();
        assert_eq!(doc.serialize(), "root ALL=(ALL) ALL\n%sudo ALL=(ALL) ALL\n");
    }

    /// Found by the property test: a ',' right before a line continuation
    /// used to hang the parser.
    #[test]
    fn sudoers_comma_before_continuation_doesnt_hang() {
        let plugin = SudoersPlugin::new();
        for input in ["a,\\", "deploy,\\\n ci ALL=(ALL) ALL\n", "a, ,\\x", ",\\"] {
            let doc = ConfigDocument::parse(&plugin, input).unwrap();
            assert_eq!(doc.serialize(), input);
            let _ = doc.to_ir().unwrap();
        }
    }

    #[test]
    fn sudoers_names_risky_rules() {
        assert_eq!(sudoers_rule_risk("ALL=(ALL) NOPASSWD: ALL"), Some("any command as root, without a password"));
        assert_eq!(sudoers_rule_risk("ALL=(ALL:ALL) ALL"), None, "asks for the password: sudo's normal shape");
        assert!(sudoers_rule_risk("ALL=(root) NOPASSWD: /usr/bin/vim /etc/hosts").is_some(), "vim can spawn a shell");
        assert_eq!(sudoers_rule_risk("ALL=(root) NOPASSWD: /usr/bin/systemctl restart nginx"), None);
        assert_eq!(sudoers_rule_risk("ALL=(root) SERVICES"), None);
    }

    proptest! {
        #[test]
        fn proptest_sudoers_arbitrary_input_never_panics_and_roundtrips(input in "\\PC*") {
            let plugin = SudoersPlugin::new();
            let doc = ConfigDocument::parse(&plugin, &input).unwrap();
            prop_assert_eq!(doc.serialize(), input.clone());
            let _ = doc.to_ir().unwrap();
        }
    }

    // ==========================================
    // fstab Tests
    // ==========================================

    #[test]
    fn fstab_reads_mounts_and_keeps_every_byte() {
        let plugin = FstabPlugin::new();
        let doc = ConfigDocument::parse(&plugin, SAMPLE_FSTAB).unwrap();
        assert_eq!(doc.serialize(), SAMPLE_FSTAB);
        let ir = doc.to_ir().unwrap();
        let rows: Vec<Vec<String>> = ir.rows.iter().map(|r| r.fields.iter().map(|f| f.value.as_str().unwrap().to_string()).collect()).collect();
        assert_eq!(rows.len(), 8, "the broken line isn't a mount");
        assert_eq!(rows[0], ["UUID=1b2c3d4e-0000-4000-8000-000000000001", "/", "ext4", "errors=remount-ro", "0", "1"]);
        assert_eq!(rows[3], ["tmpfs", "/tmp", "tmpfs", "defaults,size=2G", "0", "0"], "dump and pass default to 0");
        assert_eq!(ir.rows[0].row_id, "line-4");
    }

    #[test]
    fn fstab_edits_in_place_and_fills_left_out_fields() {
        let plugin = FstabPlugin::new();
        let mut doc = ConfigDocument::parse(&plugin, SAMPLE_FSTAB).unwrap();
        doc.apply_edit(&EditOp::UpdateField { row_id: "line-8".into(), field_name: "options".into(), new_value: serde_json::json!("defaults,_netdev,nofail") }).unwrap();
        doc.apply_edit(&EditOp::UpdateField { row_id: "line-7".into(), field_name: "pass".into(), new_value: serde_json::json!("0") }).unwrap();
        let out = doc.serialize();
        assert!(out.contains("nas:/export/backups /mnt/backups nfs defaults,_netdev,nofail 0 0\n"));
        assert!(out.contains("tmpfs /tmp tmpfs defaults,size=2G 0 0\n"), "dump was written too");
        assert!(doc.apply_edit(&EditOp::UpdateField { row_id: "line-8".into(), field_name: "mountpoint".into(), new_value: serde_json::json!("mnt") }).is_err());
        assert!(doc.apply_edit(&EditOp::UpdateField { row_id: "line-8".into(), field_name: "pass".into(), new_value: serde_json::json!("two") }).is_err());
        doc.apply_edit(&EditOp::UpdateField { row_id: "line-11".into(), field_name: "mountpoint".into(), new_value: serde_json::json!("/mnt/our disk") }).unwrap();
        assert!(doc.serialize().contains("LABEL=My\\040Disk /mnt/our\\040disk ext4"), "spaces are written \\040");
    }

    #[test]
    fn fstab_insert_move_delete() {
        let plugin = FstabPlugin::new();
        let mut doc = ConfigDocument::parse(&plugin, "/dev/sda1 / ext4 defaults 0 1").unwrap();
        let mut fields = std::collections::HashMap::new();
        fields.insert("device".to_string(), serde_json::json!("/dev/sdb1"));
        fields.insert("mountpoint".to_string(), serde_json::json!("/data"));
        fields.insert("type".to_string(), serde_json::json!("xfs"));
        doc.apply_edit(&EditOp::InsertRow { after_row_id: Some("line-1".into()), fields }).unwrap();
        assert_eq!(doc.serialize(), "/dev/sda1 / ext4 defaults 0 1\n/dev/sdb1\t/data\txfs\tdefaults\t0\t0\n");
        doc.apply_edit(&EditOp::MoveRow { row_id: "line-2".into(), before_row_id: Some("line-1".into()), after_row_id: None }).unwrap();
        assert!(doc.serialize().starts_with("/dev/sdb1"));
        doc.apply_edit(&EditOp::DeleteRow { row_id: "line-1".into() }).unwrap();
        assert_eq!(doc.serialize(), "/dev/sda1 / ext4 defaults 0 1\n");
    }

    #[test]
    fn fstab_names_mounts_that_can_stop_a_boot() {
        let all = fstab_mounts(SAMPLE_FSTAB);
        let risks: Vec<(String, Option<&str>)> = all.iter().map(|m| (m.mountpoint.clone(), fstab_boot_risk(m, &all))).collect();
        let risk = |mp: &str| risks.iter().find(|(m, _)| m == mp).unwrap().1;
        assert_eq!(risk("/"), None, "essential");
        assert_eq!(risk("none"), None, "swap");
        assert_eq!(risk("/tmp"), None, "tmpfs");
        assert!(risk("/mnt/backups").unwrap().contains("_netdev"));
        assert_eq!(risk("/data"), None, "nofail");
        assert_eq!(risk("/mnt/share"), None, "_netdev and nofail");
        assert_eq!(risk("/mnt/my\\040disk"), None, "noauto");
        let usb = FstabMount { device: "/dev/sdc1".into(), mountpoint: "/media/usb".into(), fstype: "ext4".into(), options: vec!["defaults".into()] };
        assert!(fstab_boot_risk(&usb, &all).unwrap().contains("nofail"));
        // A btrfs subvolume of the root disk (Fedora/Bazzite /home) can't go missing alone.
        let root = FstabMount { device: "UUID=aa".into(), mountpoint: "/".into(), fstype: "btrfs".into(), options: vec!["subvol=root".into()] };
        let home = FstabMount { device: "UUID=aa".into(), mountpoint: "/home".into(), fstype: "btrfs".into(), options: vec!["subvol=home".into()] };
        assert_eq!(fstab_boot_risk(&home, &[root, home.clone()]), None);
    }

    proptest! {
        #[test]
        fn proptest_fstab_arbitrary_input_never_panics_and_roundtrips(input in "\\PC*") {
            let plugin = FstabPlugin::new();
            let doc = ConfigDocument::parse(&plugin, &input).unwrap();
            prop_assert_eq!(doc.serialize(), input.clone());
            let _ = doc.to_ir().unwrap();
        }
    }

    // ==========================================
    // logrotate Tests
    // ==========================================

    fn logrotate_rows(text: &str) -> Vec<(String, String, String, Option<String>)> {
        let ir = ConfigDocument::parse(&LogrotatePlugin::new(), text).unwrap().to_ir().unwrap();
        ir.rows.iter().map(|r| (r.row_id.clone(), r.fields[0].name.clone(), r.fields[0].value.as_str().unwrap().to_string(), r.scope.clone())).collect()
    }

    #[test]
    fn logrotate_reads_globals_blocks_and_scripts_and_keeps_every_byte() {
        let plugin = LogrotatePlugin::new();
        for sample in [SAMPLE_LOGROTATE, SAMPLE_LOGROTATE_MARIADB] {
            assert_eq!(ConfigDocument::parse(&plugin, sample).unwrap().serialize(), sample);
        }
        let rows = logrotate_rows(SAMPLE_LOGROTATE);
        let view: Vec<(&str, &str, Option<&str>)> = rows.iter().map(|(_, k, v, s)| (k.as_str(), v.as_str(), s.as_deref())).collect();
        let nginx = Some("/var/log/nginx/*.log /var/log/nginx/extra/*.log");
        assert_eq!(
            view,
            vec![
                ("weekly", "on", None),
                ("rotate", "4", None),
                ("create", "on", None),
                ("include", "/etc/logrotate.d", None),
                ("logs", "/var/log/nginx/*.log /var/log/nginx/extra/*.log", nginx),
                ("daily", "on", nginx),
                ("rotate", "14", nginx),
                ("compress", "on", nginx),
                ("missingok", "on", nginx),
                ("postrotate", "invoke-rc.d nginx rotate >/dev/null 2>&1", nginx),
                ("logs", "/var/log/app.log", Some("/var/log/app.log")),
                ("size", "100M", Some("/var/log/app.log")),
            ]
        );
        let maria = logrotate_rows(SAMPLE_LOGROTATE_MARIADB);
        let script = maria.iter().find(|r| r.1 == "postrotate").unwrap();
        assert!(script.2.starts_with("if test -x /usr/bin/mariadb-admin (+"), "{}", script.2);
        assert!(maria.iter().all(|r| r.3.as_deref() == Some("/var/log/mariadb/mariadb.log")), "comments inside the block don't end it");
    }

    #[test]
    fn logrotate_edits_values_and_paths_and_adds_inside_blocks() {
        let plugin = LogrotatePlugin::new();
        let mut doc = ConfigDocument::parse(&plugin, SAMPLE_LOGROTATE).unwrap();
        let rows = logrotate_rows(SAMPLE_LOGROTATE);
        let id = |k: &str, v: &str| rows.iter().find(|r| r.1 == k && r.2 == v).unwrap().0.clone();
        doc.apply_edit(&EditOp::UpdateField { row_id: id("rotate", "14"), field_name: "rotate".into(), new_value: serde_json::json!("30") }).unwrap();
        doc.apply_edit(&EditOp::UpdateField { row_id: id("logs", "/var/log/app.log"), field_name: "logs".into(), new_value: serde_json::json!("/var/log/app.log /var/log/app-error.log") }).unwrap();
        let mut fields = std::collections::HashMap::new();
        fields.insert("notifempty".to_string(), serde_json::json!("on"));
        doc.apply_edit(&EditOp::InsertRow { after_row_id: Some(id("size", "100M")), fields }).unwrap();
        let out = doc.serialize();
        assert!(out.contains("    rotate 30\n"));
        assert!(out.contains("/var/log/app.log /var/log/app-error.log {\n  size 100M\n    notifempty\n}\n"), "{out}");
        assert!(doc.apply_edit(&EditOp::UpdateField { row_id: id("compress", "on"), field_name: "compress".into(), new_value: serde_json::json!("yes") }).is_err(), "a flag has no value");
        assert!(doc.apply_edit(&EditOp::UpdateField { row_id: id("postrotate", "invoke-rc.d nginx rotate >/dev/null 2>&1"), field_name: "postrotate".into(), new_value: serde_json::json!("x") }).is_err(), "scripts: text view");
        assert!(doc.apply_edit(&EditOp::DeleteRow { row_id: id("logs", "/var/log/nginx/*.log /var/log/nginx/extra/*.log") }).is_err(), "blocks: text view");
        doc.apply_edit(&EditOp::DeleteRow { row_id: id("compress", "on") }).unwrap();
        assert!(!doc.serialize().contains("compress"));
    }

    proptest! {
        #[test]
        fn proptest_logrotate_arbitrary_input_never_panics_and_roundtrips(input in "\\PC*") {
            let plugin = LogrotatePlugin::new();
            let doc = ConfigDocument::parse(&plugin, &input).unwrap();
            prop_assert_eq!(doc.serialize(), input.clone());
            let _ = doc.to_ir().unwrap();
        }
    }

    // ==========================================
    // systemd Tests
    // ==========================================

    #[test]
    fn systemd_reads_sections_keys_and_continuations() {
        let plugin = SystemdPlugin::new();
        let doc = ConfigDocument::parse(&plugin, SAMPLE_SYSTEMD).unwrap();
        assert_eq!(doc.serialize(), SAMPLE_SYSTEMD);
        let ir = doc.to_ir().unwrap();
        let view: Vec<(&str, &str, Option<&str>)> = ir.rows.iter().map(|r| (r.fields[0].name.as_str(), r.fields[0].value.as_str().unwrap(), r.scope.as_deref())).collect();
        assert_eq!(view[0], ("section", "Unit", Some("Unit")));
        assert!(view.contains(&("ExecStart", "/usr/bin/app --port 8080 --workers 4", Some("Service"))), "continuations joined");
        assert!(view.contains(&("Restart", "on-failure", Some("Service"))), "spaces around = are allowed");
        assert!(view.contains(&("Environment", "", Some("Service"))), "an empty assignment resets the key");
        assert!(view.contains(&("WantedBy", "multi-user.target", Some("Install"))));
        let restart = ir.rows.iter().find(|r| r.fields[0].name == "Restart").unwrap();
        assert!(restart.fields[0].options.as_ref().unwrap().iter().any(|o| o.value == "on-failure" && o.risk == Some(RiskLevel::Recommended)));
        assert!(restart.fields[0].help.is_some());
    }

    #[test]
    fn systemd_edits_in_place_and_adds_keys() {
        let plugin = SystemdPlugin::new();
        let mut doc = ConfigDocument::parse(&plugin, SAMPLE_SYSTEMD).unwrap();
        // Row ids are line numbers: read them again after each edit, as Crow does.
        let id = |doc: &ConfigDocument, k: &str| doc.to_ir().unwrap().rows.iter().find(|r| r.fields[0].name == k).unwrap().row_id.clone();
        let rid = id(&doc, "Restart");
        doc.apply_edit(&EditOp::UpdateField { row_id: rid, field_name: "Restart".into(), new_value: serde_json::json!("always") }).unwrap();
        let rid = id(&doc, "ExecStart");
        doc.apply_edit(&EditOp::UpdateField { row_id: rid, field_name: "ExecStart".into(), new_value: serde_json::json!("/usr/bin/app --port 9090") }).unwrap();
        let rid = id(&doc, "Environment");
        doc.apply_edit(&EditOp::UpdateField { row_id: rid, field_name: "Environment".into(), new_value: serde_json::json!("MODE=prod") }).unwrap();
        let mut fields = std::collections::HashMap::new();
        fields.insert("PrivateTmp".to_string(), serde_json::json!("yes"));
        let rid = id(&doc, "NoNewPrivileges");
        doc.apply_edit(&EditOp::InsertRow { after_row_id: Some(rid), fields }).unwrap();
        let out = doc.serialize();
        assert!(out.contains("Restart = always\n"), "spacing kept");
        assert!(out.contains("ExecStart=/usr/bin/app --port 9090\nRestart"), "continuation folded");
        assert!(out.contains("Environment=MODE=prod\n"), "an empty value can be filled");
        assert!(out.contains("NoNewPrivileges=yes\nPrivateTmp=yes\n"));
        let rid = id(&doc, "section");
        assert!(doc.apply_edit(&EditOp::DeleteRow { row_id: rid }).is_err(), "sections: text view");
    }

    proptest! {
        #[test]
        fn proptest_systemd_arbitrary_input_never_panics_and_roundtrips(input in "\\PC*") {
            let plugin = SystemdPlugin::new();
            let doc = ConfigDocument::parse(&plugin, &input).unwrap();
            prop_assert_eq!(doc.serialize(), input.clone());
            let _ = doc.to_ir().unwrap();
        }
    }
}

