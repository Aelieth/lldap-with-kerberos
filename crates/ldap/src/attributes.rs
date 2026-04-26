//! Attribute handling bridge layer.
//!
//! This module centralizes functions that are used by both user and group
//! paths. It acts as a bridge between the core logic and SchemaManager.

use crate::core::utils::{
    get_custom_attribute, get_ou_from_attributes, inject_operational_attributes,
    internal_ou_to_ldap_rdn_chain, is_operational_attribute, to_generalized_time,
    DEFAULT_PRIMARY_GROUP_OU, DEFAULT_PRIMARY_USER_OU,
};
use lldap_domain::{
    public_schema::PublicSchema,
        types::{AttributeName, Group, GroupDetails, User, UserAndGroups},
};
use ldap3_proto::{LdapPartialAttribute, LdapSearchResultEntry};

pub use crate::core::utils::{
    get_default_group_object_classes_bytes, get_default_user_object_classes_bytes,
};

pub fn get_user_ou(user: &User) -> String {
    get_ou_from_attributes(&user.attributes, DEFAULT_PRIMARY_USER_OU)
}

pub fn get_group_ou(group: &Group) -> String {
    get_ou_from_attributes(&group.attributes, DEFAULT_PRIMARY_GROUP_OU)
}

/// Core function to retrieve a single attribute value for a user.
pub fn get_user_attribute(
    user: &User,
    attribute: &AttributeName,
    base_dn_str: &str,
    groups: Option<&[GroupDetails]>,
    ignored_user_attributes: &[AttributeName],
    schema: &PublicSchema,
) -> Option<Vec<Vec<u8>>> {
    // For now we delegate to the existing implementation in user.rs
    // In a future step we will move the full logic here.
    crate::core::user::get_user_attribute(
        user,
        attribute,
        base_dn_str,
        groups,
        ignored_user_attributes,
        schema,
    )
}

/// Core function to retrieve a single attribute value for a group.
pub fn get_group_attribute(
    group: &Group,
    base_dn_str: &str,
    attribute: &AttributeName,
    user_filter: &Option<lldap_domain::types::UserId>,
    ignored_group_attributes: &[AttributeName],
    schema: &PublicSchema,
) -> Option<Vec<Vec<u8>>> {
    // For now we delegate to the existing implementation in group.rs
    // In a future step we will move the full logic here.
    crate::core::group::get_group_attribute(
        group,
        base_dn_str,
        attribute,
        user_filter,
        ignored_group_attributes,
        schema,
    )
}

/// Creates a full LDAP search result entry for a user.
pub fn make_ldap_search_user_result_entry(
    user: User,
    base_dn_str: &str,
    expanded_attributes: crate::core::utils::ExpandedAttributes,
    groups: Option<&[GroupDetails]>,
    ignored_user_attributes: &[AttributeName],
    schema: &PublicSchema,
) -> LdapSearchResultEntry {
    // Delegate for now
    crate::core::user::make_ldap_search_user_result_entry(
        user,
        base_dn_str,
        expanded_attributes,
        groups,
        ignored_user_attributes,
        schema,
    )
}

/// Creates a full LDAP search result entry for a group.
pub fn make_ldap_search_group_result_entry(
    group: Group,
    base_dn_str: &str,
    expanded_attributes: crate::core::utils::ExpandedAttributes,
    user_filter: &Option<lldap_domain::types::UserId>,
    ignored_group_attributes: &[AttributeName],
    schema: &PublicSchema,
) -> LdapSearchResultEntry {
    // Delegate for now
    crate::core::group::make_ldap_search_group_result_entry(
        group,
        base_dn_str,
        expanded_attributes,
        user_filter,
        ignored_group_attributes,
        schema,
    )
}
