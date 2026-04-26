//! Schema-related type definitions.

use lldap_domain::types::{AttributeName, AttributeType};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogicalAttr {
    ObjectClass,
    MemberOf,
    Dn,
    EntryDn,
    Primary(lldap_domain_model::model::UserColumn),
    Custom(&'static str, AttributeType, bool),
    Operational,
}

#[derive(Clone, Debug)]
pub struct AttributeDefinition {
    pub canonical_name: String,
    pub aliases: Vec<String>,
    pub attribute_type: AttributeType,
    pub is_list: bool,
    pub is_operational: bool,
    pub is_readonly: bool,
    pub oid: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ExpandedAttributes {
    pub attribute_keys: BTreeMap<AttributeName, String>,
    pub include_custom_attributes: bool,
}

pub use crate::core::utils::{UserFieldType, GroupFieldType};

// LogicalAttr is defined above
