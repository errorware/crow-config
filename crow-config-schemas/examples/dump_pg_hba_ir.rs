use crow_config_core::edit::{ConfigDocument, EditOp};
use crow_config_schemas::PgHbaPlugin;

fn main() {
    let sample = include_str!("../test_data/pg_hba_sample.conf");
    println!("=== 1. Original pg_hba.conf ===");
    println!("{}", sample);

    let plugin = PgHbaPlugin::new();
    let mut doc = ConfigDocument::parse(&plugin, sample).expect("Failed to parse pg_hba.conf");
    let ir = doc.to_ir().expect("Failed to generate IR");

    println!("=== 2. Generated View-Binding IR (Rule Table JSON) ===");
    println!("{}", serde_json::to_string_pretty(&ir).unwrap());

    // Locate the line with method "trust" (line 18) and move it before line 9
    println!("=== 3. Applying Semantic Edit: Move dangerous trust rule to the top of host rules ===");
    doc.apply_edit(&EditOp::MoveRow {
        row_id: "line-18".to_string(),
        before_row_id: Some("line-9".to_string()),
        after_row_id: None,
    })
    .expect("Failed to move row");

    println!("=== 4. Serialized Text after Rule Reorder (Order Sensitivity In Action) ===");
    let serialized = doc.serialize();
    println!("{}", serialized);
}
