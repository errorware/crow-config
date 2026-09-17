# crow-config-core

A standalone Rust engine that transforms arbitrary line/block-oriented Linux configuration file formats (`/etc/hosts`, `sshd_config`, `pg_hba.conf`, UFW, etc.) into structured, typed, round-trippable intermediate representations (IR) that user interfaces or CLI tools can render and edit generically — without needing format-specific UI code.

Zero UI dependencies. Zero filesystem side effects. Pure in-memory transformation.

---

## Key Features

- **100% Lossless Concrete Syntax Tree (CST)**: Every comment, trailing whitespace, blank line, and formatting quirk is preserved. Serializing an unedited parsed tree outputs the exact input byte-for-byte.
- **Surgical In-Place Edits**: Updating a field (e.g. changing an IP address or toggling a directive) modifies only the targeted tokens in the CST. Surrounding whitespace, inline comments, and adjacent lines remain byte-identical.
- **Resilient & Panic-Free**: Designed for production servers. Malformed syntax, unexpected tokens, or truncated inputs never panic; errors are captured into structured nodes and round-tripped losslessly.
- **Semantic Schemas & Risk Metadata**: TOML plugin manifests define field types, validation rules, man-page documentation anchors, and risk ratings (`recommended`, `caution`, `weak`, `never_on_prod`) for dangerous security settings.
- **View-Binding Intermediate Representation (IR)**: Emits a generic intermediate representation with widget kinds (`key_value_list`, `rule_table`, `block_tree`, `toggle_panel`), source spans, and validation states.

---

## Workspace Layout

```
crow-config-core/
├── Cargo.toml                         # Workspace definition
├── LICENSE                            # AEUPL-1.2 License
├── README.md
├── crow-config-core/                  # Core engine (grammar abstractions, schema types, IR, edit primitives)
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── cst/mod.rs                 # Lossless Concrete Syntax Tree
│       ├── schema/mod.rs              # Plugin manifests, field types, risk levels, validators
│       ├── ir/mod.rs                  # View-Binding IR model
│       └── edit/mod.rs                # Mutation engine (ConfigDocument, EditOp)
└── crow-config-schemas/               # Authored plugins, format grammars & tests
    ├── Cargo.toml
    ├── plugins/
    │   ├── hosts.toml                 # /etc/hosts manifest
    │   └── sshd_config.toml           # OpenSSH daemon manifest with risk ratings
    ├── test_data/                     # Real-world test configurations
    ├── examples/                      # Diagnostic IR inspection tools
    └── src/
        ├── lib.rs
        ├── hosts/mod.rs               # /etc/hosts line grammar, binder & tests
        └── sshd/mod.rs                # sshd_config grammar, binder & tests
```

---

## Three-Layer Architecture

1. **Grammar Layer (`cst`)**:
   Parses raw text into a lossless concrete syntax tree (`CstNode`). All trivia (whitespace, comments, separators, newlines) are retained as tokens in document order.

2. **Semantic Schema Layer (`schema`)**:
   Maps CST nodes to typed fields declared in declarative TOML manifests (`PluginManifest`). Validates values and enriches fields with risk classifications and docs links.

3. **View-Binding IR Layer (`ir`)**:
   Emits a generic intermediate representation for UI consumption:
   ```json
   {
     "row_id": "line-4",
     "widget": "key_value_list_row",
     "fields": [
       { "name": "address", "value": "10.0.4.12", "type": "ip_address", "valid": true },
       { "name": "hostnames", "value": ["db-primary-01.internal", "db-primary-01"], "type": "string_list" },
       { "name": "comment", "value": "primary postgres", "type": "string" }
     ],
     "source_span": { "start_line": 4, "end_line": 4 }
   }
   ```

---

## Supported Formats

| Format | Shape Kind | Order Sensitive | Risk Ratings | External Validator |
| :--- | :--- | :---: | :---: | :--- |
| `/etc/hosts` | `key_value_list` | Yes | N/A | `getent hosts {address}` |
| `sshd_config` | `key_value_list` | No | Yes (`PermitRootLogin`, `PasswordAuthentication`, etc.) | `sshd -t -f {file}` |
| `pg_hba.conf` | `rule_table` | Yes (First match wins) | Yes (`scram-sha-256`, `md5`, `trust`, `peer`, etc.) | `postgres --check-config` |
| UFW rules | `rule_table` | Yes (First match wins) | Yes (`ALLOW`, `DENY`, `REJECT`, `LIMIT`) | `ufw --dry-run reload` |

---

## Quick Example

```rust
use crow_config_core::edit::{ConfigDocument, EditOp};
use crow_config_schemas::HostsPlugin;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let hosts_content = "127.0.0.1  localhost\n10.0.4.12  db-01  # primary\n";
    let plugin = HostsPlugin::new();

    // 1. Parse into a ConfigDocument
    let mut doc = ConfigDocument::parse(&plugin, hosts_content)?;

    // 2. Generate View-Binding IR
    let ir = doc.to_ir()?;
    println!("{}", serde_json::to_string_pretty(&ir)?);

    // 3. Apply in-place semantic edit
    doc.apply_edit(&EditOp::UpdateField {
        row_id: "line-2".to_string(),
        field_name: "address".to_string(),
        new_value: serde_json::json!("10.0.4.13"),
    })?;

    // 4. Serialize back (byte-identical except for the modified token)
    let updated_text = doc.serialize();
    assert_eq!(updated_text, "127.0.0.1  localhost\n10.0.4.13  db-01  # primary\n");

    Ok(())
}
```

---

## Running Tests & Diagnostics

Run the full workspace test suite (unit tests, golden file round-trip tests, and property-based tests):

```bash
cargo test --workspace
```

Run diagnostic examples to inspect generated IR and mutation previews:

```bash
# Dump /etc/hosts IR
cargo run --example dump_hosts_ir -p crow-config-schemas

# Dump sshd_config IR with security risk ratings
cargo run --example dump_sshd_ir -p crow-config-schemas

# Dump pg_hba.conf rule table IR and test rule reordering
cargo run --example dump_pg_hba_ir -p crow-config-schemas

# Dump UFW rule table IR and test first-match priority reordering
cargo run --example dump_ufw_ir -p crow-config-schemas
```

---

## License

This project is licensed under the [AEUPL-1.2](LICENSE) (Ancient European Union Public License · v1.2). See `LICENSE` for details.
