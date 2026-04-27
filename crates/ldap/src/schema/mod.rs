pub mod definitions;
pub mod manager;

pub use definitions::{ExpandedAttributes, LogicalAttr, UserFieldType, GroupFieldType};
pub use manager::SchemaManager;

/// Returns a default SchemaManager instance built from PublicSchema.
pub fn get_schema_manager() -> SchemaManager {
    SchemaManager::new(&lldap_domain::public_schema::PublicSchema::get())
}
