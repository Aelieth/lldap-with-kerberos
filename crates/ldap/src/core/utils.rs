use crate::core::error::LdapResult;
use itertools::join;
use lldap_domain::types::AttributeName;

// Re-export the constants and DN helpers that are still widely used
pub use crate::dn::{
    DEFAULT_PRIMARY_GROUP_OU,
    DEFAULT_PRIMARY_USER_OU,
    internal_ou_to_ldap_rdn_chain,
    get_user_id_from_distinguished_name,
};

// Re-export FieldType enums from schema (single source of truth)
pub use crate::schema::definitions::{UserFieldType, GroupFieldType, ExpandedAttributes};

/// LdapInfo — shared configuration for the LDAP layer (base DN + ignored attributes).
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
