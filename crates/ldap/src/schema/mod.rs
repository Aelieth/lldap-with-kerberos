pub mod definitions;
pub mod manager;

pub use definitions::{AttributeDefinition, ExpandedAttributes, LogicalAttr};
pub use manager::SchemaManager;

/// Returns a default SchemaManager instance.
/// In the future this can be made more sophisticated (e.g. cached singleton).
pub fn get_schema_manager() -> SchemaManager {
    SchemaManager::new()
}
