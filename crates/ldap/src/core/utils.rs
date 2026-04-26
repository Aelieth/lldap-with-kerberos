//! Core LDAP utilities that are still needed after the modular split.
//!
//! Most attribute resolution and DN handling has moved to:
//! - `crate::dn`          → DN/OU/RDN parsing and helpers
//! - `crate::schema`      → SchemaManager (resolve_attribute, expand, map_*_field)
//! - `crate::attributes`  → Bridge layer for user/group attribute access

use crate::core::error::LdapResult;
use chrono::{NaiveDateTime, TimeZone};
use itertools::join;
use ldap3_proto::LdapPartialAttribute;
use lldap_domain::{
    public_schema::PublicSchema,
    types::{Attribute, AttributeName, AttributeValue, Cardinality},
};

// Re-export the constants that are still widely used
pub use crate::dn::{
    DEFAULT_PRIMARY_GROUP_OU,
    DEFAULT_PRIMARY_USER_OU,
    internal_ou_to_ldap_rdn_chain,
    // Re-export DN types for backward compatibility during final transition
    UserOrGroupName,
    get_user_or_group_id_from_distinguished_name,
    get_user_id_from_distinguished_name,
};

// Re-export FieldType enums from schema (single source of truth)
pub use crate::schema::definitions::{UserFieldType, GroupFieldType};

// get_default_*_object_classes_bytes are defined in this file (see below)

// Bridge functions are now in attributes.rs (re-exported from lib.rs)

/// Convert a NaiveDateTime to LDAP GeneralizedTime format (e.g. 20260101120000.000000Z)
pub fn to_generalized_time(dt: &NaiveDateTime) -> Vec<u8> {
    chrono::Utc
        .from_utc_datetime(dt)
        .format("%Y%m%d%H%M%S.%fZ")
        .to_string()
        .into_bytes()
}

/// Extracts a custom attribute value from a list of attributes.
pub fn get_custom_attribute(
    attributes: &[Attribute],
    attribute_name: &AttributeName,
) -> Option<Vec<Vec<u8>>> {
    attributes
        .iter()
        .find(|a| &a.name == attribute_name)
        .map(|attribute| match &attribute.value {
            AttributeValue::String(Cardinality::Singleton(s)) => {
                if attribute_name.as_str().eq_ignore_ascii_case("ou") {
                    let leaf = s.split('\\').last().unwrap_or(s).to_string();
                    vec![leaf.into_bytes()]
                } else {
                    vec![s.clone().into_bytes()]
                }
            }
            AttributeValue::String(Cardinality::Unbounded(l)) => {
                if attribute_name.as_str().eq_ignore_ascii_case("ou") {
                    l.iter()
                        .map(|s| s.split('\\').last().unwrap_or(s).to_string().into_bytes())
                        .collect()
                } else {
                    l.iter().map(|s| s.clone().into_bytes()).collect()
                }
            }
            AttributeValue::Integer(Cardinality::Singleton(i)) => vec![i.to_string().into_bytes()],
            AttributeValue::Integer(Cardinality::Unbounded(l)) => {
                l.iter().map(|i| i.to_string().into_bytes()).collect()
            }
            AttributeValue::Avatar(Cardinality::Singleton(p)) => vec![p.0.clone()],
            AttributeValue::Avatar(Cardinality::Unbounded(l)) => l.iter().map(|p| p.0.clone()).collect(),
            AttributeValue::DateTime(Cardinality::Singleton(dt)) => vec![to_generalized_time(dt)],
            AttributeValue::DateTime(Cardinality::Unbounded(l)) => l.iter().map(to_generalized_time).collect(),
        })
}

/// Common OU extractor from entity attributes (used by users and groups).
/// Falls back to the provided default (e.g. "people" or "groups").
pub fn get_ou_from_attributes(attributes: &[Attribute], default: &str) -> String {
    attributes
        .iter()
        .find(|a| a.name.as_str().eq_ignore_ascii_case("ou"))
        .and_then(|a| match &a.value {
            AttributeValue::String(Cardinality::Singleton(s)) => Some(s.clone()),
            AttributeValue::String(Cardinality::Unbounded(list)) if !list.is_empty() => Some(list[0].clone()),
            _ => None,
        })
        .unwrap_or_else(|| default.to_string())
}

/// Injects the standard operational attributes we always add to every LDAP search result.
pub(crate) fn inject_operational_attributes(attrs: &mut Vec<LdapPartialAttribute>, structural_class: &str, base_dn_str: &str) {
    attrs.push(LdapPartialAttribute {
        atype: "hasSubordinates".to_string(),
        vals: vec![b"FALSE".to_vec()],
    });
    attrs.push(LdapPartialAttribute {
        atype: "structuralObjectClass".to_string(),
        vals: vec![structural_class.as_bytes().to_vec()],
    });
    attrs.push(LdapPartialAttribute {
        atype: "subschemaSubentry".to_string(),
        vals: vec![format!("cn=Subschema,{}", base_dn_str).into_bytes()],
    });
}

/// 0-argument versions for GraphQL + public API (returns LdapObjectClass).
pub fn get_default_user_object_classes() -> Vec<lldap_domain::types::LdapObjectClass> {
    let schema = PublicSchema::get();
    get_default_user_object_classes_bytes(&schema)
        .into_iter()
        .map(|b| lldap_domain::types::LdapObjectClass::from(String::from_utf8_lossy(&b).to_string()))
        .collect()
}

pub fn get_default_group_object_classes() -> Vec<lldap_domain::types::LdapObjectClass> {
    let schema = PublicSchema::get();
    get_default_group_object_classes_bytes(&schema)
        .into_iter()
        .map(|b| lldap_domain::types::LdapObjectClass::from(String::from_utf8_lossy(&b).to_string()))
        .collect()
}

/// Returns the default object classes for a user as raw bytes (for LDAP internal use).
pub fn get_default_user_object_classes_bytes(schema: &PublicSchema) -> Vec<Vec<u8>> {
    let mut classes: Vec<Vec<u8>> = vec![
        b"top".to_vec(),
        b"mailAccount".to_vec(),
        b"person".to_vec(),
    ];
    classes.extend(
        schema
            .get_schema()
            .extra_user_object_classes
            .iter()
            .map(|c| c.as_str().as_bytes().to_vec()),
    );
    classes
}

/// Returns the default object classes for a group as raw bytes (for LDAP internal use).
pub fn get_default_group_object_classes_bytes(schema: &PublicSchema) -> Vec<Vec<u8>> {
    let mut classes: Vec<Vec<u8>> = vec![
        b"groupOfUniqueNames".to_vec(),
        b"groupOfNames".to_vec(),
    ];
    classes.extend(
        schema
            .get_schema()
            .extra_group_object_classes
            .iter()
            .map(|c| c.as_str().as_bytes().to_vec()),
    );
    classes
}

/// Returns the preferred LDAP attribute name for a schema attribute.
pub fn get_preferred_ldap_name(attr: &lldap_schema::AttributeSchema) -> String {
    const STANDARD_LDAP_NAMES: &[&str] = &[
        "cn", "sn", "givenname", "uid", "mail", "ou", "dc", "o", "c", "l", "st",
        "title", "description", "member", "uniquemember", "memberof",
        "createtimestamp", "modifytimestamp", "pwdchangedtime", "entryuuid",
        "hassubordinates", "structuralobjectclass", "subschemasubentry",
        "uidnumber", "gidnumber", "homedirectory", "loginshell", "sshpublickey",
        "krbprincipalname", "jpegphoto", "avatar",
    ];

    for alias in &attr.aliases {
        let lower = alias.to_ascii_lowercase();
        if STANDARD_LDAP_NAMES.contains(&lower.as_str()) {
            return alias.clone();
        }
    }
    attr.name.clone()
}

// ============================================================================
// LdapInfo (still needed by search handler and many places)
// ============================================================================

// Temporary type aliases so user.rs and group.rs continue to compile during transition
pub use crate::schema::definitions::ExpandedAttributes;

pub struct LdapInfo {
    pub base_dn: Vec<(String, String)>,
    pub base_dn_str: String,
    pub ignored_user_attributes: Vec<AttributeName>,
    pub ignored_group_attributes: Vec<AttributeName>,
}

impl LdapInfo {
    pub fn new(
        base_dn: &str,
        ignored_user_attributes: Vec<AttributeName>,
        ignored_group_attributes: Vec<AttributeName>,
    ) -> LdapResult<Self> {
        let base_dn = crate::dn::parse_distinguished_name(&base_dn.to_ascii_lowercase())?;
        let base_dn_str = join(base_dn.iter().map(|(k, v)| format!("{k}={v}")), ",");
        Ok(Self {
            base_dn,
            base_dn_str,
            ignored_user_attributes,
            ignored_group_attributes,
        })
    }
}
