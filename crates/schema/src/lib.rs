pub mod schema;
pub mod public_schema;

pub use schema::{AttributeList, AttributeSchema, AttributeType, Schema};
pub use public_schema::PublicSchema;

// Re-export for convenience in domain-model and SQL layers
pub use crate::schema::AttributeList as UserAttributeList;
pub use crate::schema::AttributeList as GroupAttributeList;
