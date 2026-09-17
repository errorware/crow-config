use crow_config_core::edit::{ConfigDocument, EditOp};
use crow_config_schemas::UfwPlugin;

fn main() {
    let sample = include_str!("../test_data/ufw_sample.rules");
    println!("=== 1. Original UFW Rules ===");
    println!("{}", sample);

    let plugin = UfwPlugin::new();
    let mut doc = ConfigDocument::parse(&plugin, sample).expect("Failed to parse UFW rules");
    let ir = doc.to_ir().expect("Failed to generate IR");

    println!("=== 2. Generated View-Binding IR (Rule Table JSON) ===");
    println!("{}", serde_json::to_string_pretty(&ir).unwrap());

    println!("=== 3. Applying Semantic Edit: Move DENY rule (line 7) to top of table (before line 4) ===");
    doc.apply_edit(&EditOp::MoveRow {
        row_id: "line-7".to_string(),
        before_row_id: Some("line-4".to_string()),
        after_row_id: None,
    })
    .expect("Failed to move row");

    println!("=== 4. Serialized Text after Rule Reorder (Top-To-Bottom First Match Priority) ===");
    let serialized = doc.serialize();
    println!("{}", serialized);
}
