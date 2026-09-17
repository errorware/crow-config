use crow_config_core::edit::{ConfigDocument, EditOp};
use crow_config_schemas::HostsPlugin;

fn main() {
    let sample = include_str!("../test_data/hosts_sample.txt");
    println!("=== 1. Original /etc/hosts ===");
    println!("{}", sample);

    let plugin = HostsPlugin::new();
    let mut doc = ConfigDocument::parse(&plugin, sample).expect("Failed to parse");
    let ir = doc.to_ir().expect("Failed to generate IR");

    println!("=== 2. Generated View-Binding IR (JSON) ===");
    println!("{}", serde_json::to_string_pretty(&ir).unwrap());

    println!("=== 3. Applying Semantic Edit: Update line-4 address to 10.0.4.99 ===");
    doc.apply_edit(&EditOp::UpdateField {
        row_id: "line-4".to_string(),
        field_name: "address".to_string(),
        new_value: serde_json::json!("10.0.4.99"),
    })
    .expect("Failed to apply edit");

    println!("=== 4. Serialized Text after Edit (Only line 4 changed, lossless elsewhere) ===");
    let serialized = doc.serialize();
    println!("{}", serialized);
}
