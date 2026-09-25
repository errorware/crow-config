//! Lossless, schema-driven editing of Linux configuration files.
//!
//! This crate bundles the engine ([`core`], `crow-config-core`) with its
//! format plugins ([`schemas`], `crow-config-schemas`): parse a file into a
//! lossless syntax tree, bind it to a generic view model a UI can render,
//! and apply edits that change only the targeted tokens.
//!
//! ```
//! use crow_config::{ConfigDocument, HostsPlugin};
//!
//! let text = "# local names\n127.0.0.1  localhost\n";
//! let plugin = HostsPlugin::new();
//! let doc = ConfigDocument::parse(&plugin, text).unwrap();
//! assert_eq!(doc.to_ir().unwrap().rows.iter().filter(|r| !r.fields.is_empty()).count(), 1);
//! ```

pub use crow_config_core as core;
pub use crow_config_schemas as schemas;

pub use crow_config_core::{ConfigDocument, ConfigDocumentIr, ConfigPlugin, EditError, EditOp, FieldIr, RowIr};
pub use crow_config_schemas::{HostsPlugin, PgHbaPlugin, SshdPlugin, UfwPlugin};
