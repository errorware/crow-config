use crow_config_core::edit::{ConfigDocument, EditOp};
use crow_config_schemas::SshdPlugin;

fn main() {
    let sample = include_str!("../test_data/sshd_config_sample.txt");
    println!("=== 1. Original sshd_config ===");
    println!("{}", sample);

    let plugin = SshdPlugin::new();
    let mut doc = ConfigDocument::parse(&plugin, sample).expect("Failed to parse sshd_config");
    let ir = doc.to_ir().expect("Failed to generate IR");

    println!("=== 2. Generated View-Binding IR (JSON) ===");
    println!("{}", serde_json::to_string_pretty(&ir).unwrap());

    println!("=== 3. Applying Semantic Edit: Set PermitRootLogin to 'no' ===");
    // Find PermitRootLogin row
    let root_row = ir
        .rows
        .iter()
        .find(|r| r.get_field("PermitRootLogin").is_some())
        .expect("PermitRootLogin row");

    doc.apply_edit(&EditOp::UpdateField {
        row_id: root_row.row_id.clone(),
        field_name: "PermitRootLogin".to_string(),
        new_value: serde_json::json!("no"),
    })
    .expect("Failed to apply edit");

    println!("=== 4. Serialized Text after Edit (Only PermitRootLogin line changed) ===");
    let serialized = doc.serialize();
    println!("{}", serialized);
}
