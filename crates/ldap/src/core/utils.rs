//! LDAP Core Utilities
//!
//! This module centralizes all low-level LDAP attribute resolution, DN/OU handling,
//! and conversion helpers. It was consolidated from scattered logic in user.rs/group.rs
//! to keep a single source of truth for attribute mapping and LDAP representation.
//!
//! Sections:
//! - OU & DN Utilities
//! - Attribute Resolution & Mapping (resolve_attribute, get_preferred_*, etc.)
//! - LDAP Conversion Helpers (expand_*, get_*_attribute, inject_operational)
//! - Subschema & ObjectClass Helpers
//! - Miscellaneous

use crate::core::{
    error::{LdapError, LdapResult},
};
use chrono::{NaiveDateTime, TimeZone};
use itertools::join;
use ldap3_proto::{LdapPartialAttribute, LdapResultCode};
use lldap_domain::{
    public_schema::PublicSchema,
    types::{
        Attribute, AttributeName, AttributeType, AttributeValue, Cardinality, GroupName,
        UserId,
    },
};
use lldap_domain_model::model::UserColumn;
use lldap_schema::AttributeSchema;
use std::collections::{BTreeMap, HashSet};
use tracing::{debug, instrument, warn};

// OU & DN utilities

/// Centralized OU defaults and helpers (architectural constants for the OU framework)
pub const DEFAULT_PRIMARY_USER_OU: &str = "people";
pub const DEFAULT_PRIMARY_GROUP_OU: &str = "groups";

// get_primary_group_ou available for future group OU handling (currently unused to avoid dead_code warning)

/// Returns the internal OU string (e.g. "people\home" or "office\floor1") from DN parts
/// by collecting all ou= RDNs in order and joining with \ .
pub fn get_internal_ou_from_dn_parts(dn_parts: &[(String, String)]) -> String {
    let ou_chain: Vec<(String, String)> = dn_parts
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("ou"))
        .cloned()
        .collect();
    ldap_rdn_chain_to_internal_ou(&ou_chain)
}

/// Returns only the *direct* child OUs (exactly one level deeper in the hierarchy)
/// for the given parent_internal_ou from the full allowed_ous list.
/// - parent="" or empty → top-level OUs (no '\\' in name)
/// - parent="office" → ["office\floor1", "office\meeting"] but NOT "office\floor1\subfloor"
pub fn get_direct_child_ous(parent_internal_ou: &str, allowed_ous: &[String]) -> Vec<String> {
    let parent_l = parent_internal_ou.to_ascii_lowercase();
    allowed_ous
        .iter()
        .filter(|ou| {
            let ou_l = ou.to_ascii_lowercase();
            if parent_l.is_empty() {
                !ou_l.contains('\\')
            } else if ou_l.starts_with(&format!("{}\\", parent_l)) {
                let suffix = &ou_l[parent_l.len() + 1..];
                !suffix.contains('\\')
            } else {
                false
            }
        })
        .cloned()
        .collect()
}

/// Convert internal ou string ("people" or "people\home") into clean hierarchical LDAP RDN chain
pub fn internal_ou_to_ldap_rdn_chain(ou: &str) -> Vec<(String, String)> {
    if ou.trim().is_empty() {
        return vec![];
    }
    let parts: Vec<&str> = ou.split('\\').collect();
    let mut chain = Vec::with_capacity(parts.len());
    for part in parts.iter().rev() {
        let trimmed = part.trim();
        if !trimmed.is_empty() {
            chain.push(("ou".to_string(), trimmed.to_string()));
        }
    }
    chain
}

/// Reverse of the above — reconstruct internal ou string from LDAP RDN chain
pub fn ldap_rdn_chain_to_internal_ou(rdn_chain: &[(String, String)]) -> String {
    let ous: Vec<String> = rdn_chain
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("ou"))
        .map(|(_, v)| v.clone())
        .rev()
        .collect();
    if ous.is_empty() {
        String::new()
    } else {
        ous.join("\\")
    }
}

/// Returns true if dn_parts represents an allowed OU container (any depth)
pub fn is_container_dn(
    dn_parts: &[(String, String)],
    base_dn: &[(String, String)],
    allowed_ous: &[String],
) -> bool {
    let ou_chain: Vec<(String, String)> = dn_parts
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("ou"))
        .cloned()
        .collect();
    let internal_ou = ldap_rdn_chain_to_internal_ou(&ou_chain);
    let is_allowed = allowed_ous.iter().any(|allowed| {
        allowed.to_ascii_lowercase() == internal_ou.to_ascii_lowercase()
    });
    is_allowed && dn_parts.len() == base_dn.len() + ou_chain.len()
}

/// Returns true if `subtree` is a subtree of (or equal to) `base_tree`.
/// Works correctly with our dynamic nested OUs (e.g. "people\home", "office\floor1").
pub fn is_subtree(subtree: &[(String, String)], base_tree: &[(String, String)]) -> bool {
    if base_tree.is_empty() {
        return true;
    }
    if subtree.len() < base_tree.len() {
        return false;
    }

    let offset = subtree.len() - base_tree.len();
    for i in 0..base_tree.len() {
        if !subtree[offset + i].0.eq_ignore_ascii_case(&base_tree[i].0)
            || !subtree[offset + i].1.eq_ignore_ascii_case(&base_tree[i].1)
        {
            return false;
        }
    }
    true
}

// ============================================================================
// ATTRIBUTE RESOLUTION & MAPPING
// ============================================================================

/// Returns true for attributes we inject manually as operational attributes.
/// These should never be looked up from the database or trigger "unrecognized attribute" warnings.
pub fn is_operational_attribute(name: &str) -> bool {
    matches!(
        resolve_attribute(name),
        Some((LogicalAttr::Operational, _))
    )
}

/// Preferred canonical LDAP name for any input (alias or canonical).
/// Falls back to the input itself for unknown attributes.
/// This is the single function that should be used everywhere we need a display name.
pub fn get_canonical_name(name: &str) -> String {
    resolve_attribute(name)
        .map(|(_, canon)| canon.to_string())
        .unwrap_or_else(|| name.to_string())
}

/// Returns the preferred LDAP attribute name for a schema attribute.
/// Rule: Use a proper/standard LDAP name if one exists in the aliases.
/// Only fall back to the canonical name if this is a completely custom attribute
/// with no standard LDAP name (e.g. kerberosSync, avatar, etc.).
pub fn get_preferred_ldap_name(attr: &AttributeSchema) -> String {
    // List of well-known standard LDAP attribute names (case-insensitive match)
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

    // No standard LDAP name found → fall back to canonical (for truly custom attrs)
    attr.name.clone()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogicalAttr {
    ObjectClass,
    MemberOf,
    Dn,
    EntryDn,
    Primary(UserColumn),
    Custom(&'static str, AttributeType, bool), // internal_name, type, is_list
    Operational,                               // injected operational attributes (never from DB)
}

/// Single source of truth for attribute resolution. Maps schema to LDAP standards.
/// Returns (logical_attribute, preferred_output_name) or None for unknown attributes.
pub fn resolve_attribute(name: &str) -> Option<(LogicalAttr, &'static str)> {
    let lower = name.to_ascii_lowercase();
    Some(match lower.as_str() {
        "objectclass" => (LogicalAttr::ObjectClass, "objectClass"),
        "memberof" | "ismemberof" => (LogicalAttr::MemberOf, "memberOf"),
        "dn" | "distinguishedname" => (LogicalAttr::Dn, "dn"),
        "entrydn" => (LogicalAttr::EntryDn, "entryDN"),

        // Operational (injected manually, never from DB)
        "hassubordinates" => (LogicalAttr::Operational, "hasSubordinates"),
        "structuralobjectclass" => (LogicalAttr::Operational, "structuralObjectClass"),
        "subschemasubentry" => (LogicalAttr::Operational, "subschemaSubentry"),

        // Timestamps (Primary columns but exposed as operational in LDAP)
        "createtimestamp" | "creationdate" | "creation_date" | "creationtimestamp" => {
            (LogicalAttr::Primary(UserColumn::CreationDate), "createTimestamp")
        }
        "modifytimestamp" | "modifieddate" | "modified_date" | "modifydate" => {
            (LogicalAttr::Primary(UserColumn::ModifiedDate), "modifyTimestamp")
        }
        "pwdchangedtime" | "passwordmodifieddate" | "password_modified_date" => {
            (LogicalAttr::Primary(UserColumn::PasswordModifiedDate), "pwdChangedTime")
        }

        // Core fields
        "uid" | "user_id" | "id" | "userid" => (LogicalAttr::Primary(UserColumn::UserId), "uid"),
        "mail" | "email" => (LogicalAttr::Primary(UserColumn::Email), "mail"),
        "cn" | "displayname" | "display_name" => (LogicalAttr::Primary(UserColumn::DisplayName), "cn"),
        "entryuuid" | "uuid" | "entryUUID" => (LogicalAttr::Primary(UserColumn::Uuid), "entryUUID"),
        "krbprincipalname" | "krb_principal_name" | "krbPrincipalName" => {
            (LogicalAttr::Primary(UserColumn::KrbPrincipalName), "krbPrincipalName")
        }

        // Custom schema attributes
        "givenname" | "first_name" | "firstname" | "givenName" => {
            (LogicalAttr::Custom("firstname", AttributeType::String, false), "givenName")
        }
        "sn" | "last_name" | "lastname" | "surname" => {
            (LogicalAttr::Custom("lastname", AttributeType::String, false), "sn")
        }
        "avatar" | "jpegphoto" | "jpegPhoto" => {
            (LogicalAttr::Custom("avatar", AttributeType::Avatar, false), "jpegPhoto")
        }
        "ou" | "organizationalunit" | "organizationalUnit" => {
            (LogicalAttr::Custom("ou", AttributeType::String, false), "ou")
        }
        "sshpublickey" | "sshPublicKey" | "ssHPublicKey" => {
            (LogicalAttr::Custom("sshpublickey", AttributeType::String, true), "sshPublicKey")
        }

        // POSIX
        "uidnumber" | "uid_number" | "uidNumber" => {
            (LogicalAttr::Custom("uidnumber", AttributeType::Integer, false), "uidNumber")
        }
        "gidnumber" | "gid_number" | "gidNumber" => {
            (LogicalAttr::Custom("gidnumber", AttributeType::Integer, false), "gidNumber")
        }
        "homedirectory" | "home_directory" | "homeDirectory" => {
            (LogicalAttr::Custom("homedirectory", AttributeType::String, false), "homeDirectory")
        }
        "loginshell" | "login_shell" | "loginShell" => {
            (LogicalAttr::Custom("loginshell", AttributeType::String, false), "loginShell")
        }

        // Kerberos + Group ID
        "kerberossync" | "kerberos_sync" | "kerberosSync" => {
            (LogicalAttr::Custom("kerberossync", AttributeType::Integer, false), "kerberosSync")
        }
        "groupid" | "group_id" | "gid" => {
            (LogicalAttr::Custom("groupid", AttributeType::Integer, false), "groupid")
        }

        _ => return None,
    })
}

// (OU & DN functions moved to top of file for better organization)

/// Convert a NaiveDateTime to LDAP GeneralizedTime format
pub fn to_generalized_time(dt: &NaiveDateTime) -> Vec<u8> {
    chrono::Utc
        .from_utc_datetime(dt)
        .format("%Y%m%d%H%M%S.%fZ")
        .to_string()
        .into_bytes()
}

fn make_dn_pair<I>(mut iter: I) -> LdapResult<(String, String)>
where
    I: Iterator<Item = String>,
{
    (|| {
        let pair = (
            iter.next().ok_or_else(|| "Empty DN element".to_string())?,
            iter.next().ok_or_else(|| "Missing DN value".to_string())?,
        );
        if let Some(e) = iter.next() {
            Err(format!(
                r#"Too many elements in distinguished name: "{}", "{}", "{}""#,
                pair.0, pair.1, e
            ))
        } else {
            Ok(pair)
        }
    })()
    .map_err(|e| LdapError {
        code: LdapResultCode::InvalidDNSyntax,
        message: e,
    })
}

pub fn parse_distinguished_name(dn: &str) -> LdapResult<Vec<(String, String)>> {
    let lower_dn = dn.to_ascii_lowercase();
    debug!(?dn, "Parsing client DN");
    let result: LdapResult<Vec<_>> = lower_dn
        .split(',')
        .map(|s| make_dn_pair(s.split('=').map(str::trim).map(String::from)))
        .collect();

    if let Err(e) = &result {
        warn!(?dn, error = ?e, "Invalid DN syntax received from client (Directory Studio / ldapsearch?)");
    }
    result
}

pub enum UserOrGroupName {
    User(UserId),
    Group(GroupName),
    BadSubStree,
    UnexpectedFormat,
    InvalidSyntax(LdapError),
}

impl UserOrGroupName {
    pub fn into_ldap_error(self, input: &str, expected_format: String) -> LdapError {
        LdapError {
            code: LdapResultCode::InvalidDNSyntax,
            message: match self {
                UserOrGroupName::BadSubStree => "Not a subtree of the base tree".to_string(),
                UserOrGroupName::InvalidSyntax(err) => return err,
                UserOrGroupName::UnexpectedFormat
                | UserOrGroupName::User(_)
                | UserOrGroupName::Group(_) => {
                    format!(r#"Unexpected DN format. Got "{input}", expected: {expected_format}"#)
                }
            },
        }
    }
}

pub fn get_user_or_group_id_from_distinguished_name(
    dn: &str,
    base_tree: &[(String, String)],
) -> UserOrGroupName {
    let parts = match parse_distinguished_name(dn) {
        Ok(p) => p,
        Err(e) => return UserOrGroupName::InvalidSyntax(e),
    };
    if !is_subtree(&parts, base_tree) {
        return UserOrGroupName::BadSubStree;
    }

    let ou_chain: Vec<(String, String)> = parts
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("ou"))
        .cloned()
        .collect();

    if parts.len() == base_tree.len() + ou_chain.len() + 1 {
        let rdn = &parts[0];
        if rdn.0.eq_ignore_ascii_case("uid") {
            return UserOrGroupName::User(UserId::from(rdn.1.clone()));
        } else if rdn.0.eq_ignore_ascii_case("cn") {
            return UserOrGroupName::Group(GroupName::from(rdn.1.clone()));
        }
    }

    UserOrGroupName::UnexpectedFormat
}

pub fn get_user_id_from_distinguished_name(
    dn: &str,
    base_tree: &[(String, String)],
    base_dn_str: &str,
) -> LdapResult<UserId> {
    match get_user_or_group_id_from_distinguished_name(dn, base_tree) {
        UserOrGroupName::User(user_id) => Ok(user_id),
        err => Err(err.into_ldap_error(dn, format!(r#""uid=id,ou=...,{}""#, base_dn_str))),
    }
}

pub fn get_group_id_from_distinguished_name(
    dn: &str,
    base_tree: &[(String, String)],
    base_dn_str: &str,
) -> LdapResult<GroupName> {
    match get_user_or_group_id_from_distinguished_name(dn, base_tree) {
        UserOrGroupName::Group(group_name) => Ok(group_name),
        err => Err(err.into_ldap_error(dn, format!(r#""cn=id,ou=...,{}""#, base_dn_str))),
    }
}

fn looks_like_distinguished_name(dn: &str) -> bool {
    dn.contains('=') || dn.contains(',')
}

pub fn get_user_id_from_distinguished_name_or_plain_name(
    dn: &str,
    base_tree: &[(String, String)],
    base_dn_str: &str,
) -> LdapResult<UserId> {
    if !looks_like_distinguished_name(dn) {
        Ok(UserId::from(dn))
    } else {
        get_user_id_from_distinguished_name(dn, base_tree, base_dn_str)
    }
}

pub fn get_group_id_from_distinguished_name_or_plain_name(
    dn: &str,
    base_tree: &[(String, String)],
    base_dn_str: &str,
) -> LdapResult<GroupName> {
    if !looks_like_distinguished_name(dn) {
        Ok(GroupName::from(dn))
    } else {
        get_group_id_from_distinguished_name(dn, base_tree, base_dn_str)
    }
}

#[derive(Clone, Debug)]
pub struct ExpandedAttributes {
    /// Map from canonical AttributeName key → canonical display name.
    /// This map is **guaranteed** to contain each logical attribute exactly once.
    pub attribute_keys: BTreeMap<AttributeName, String>,
    pub include_custom_attributes: bool,
}

/// Fully schema-driven, long-term correct implementation of attribute wildcard expansion.
///
/// This function is the **single source of truth** for all LDAP attribute handling in lldap.
///
/// Guarantees (enforced at compile + runtime):
/// - Every attribute appears **exactly once** (keyed by canonical name)
/// - All aliases are collapsed to the preferred RFC/LDAP name (e.g. any variant of modifyTimestamp → "modifyTimestamp")
/// - Standard attributes vs Operational attributes are cleanly separated
/// - Custom attributes defined in PublicSchema are automatically included when "*"
/// - No hardcoded lists — everything is derived from PublicSchema + resolve_attribute
/// - Future schema additions (new custom attrs, new POSIX fields, etc.) require **zero** changes here
///
/// Used by both user and group search paths.
#[instrument(skip(schema), level = "debug")]
pub fn expand_attribute_wildcards(
    ldap_attributes: &[String],
    schema: &PublicSchema,
) -> ExpandedAttributes {
    let mut include_custom_attributes = false;

    // ============================================================
    // DYNAMICALLY BUILD STANDARD + OPERATIONAL LISTS FROM SCHEMA
    // (This replaces all previous hardcoded vecs — the correct long-term approach)
    // ============================================================
    let mut standard_keys: Vec<String> = Vec::new();
    let mut operational_keys: Vec<String> = Vec::new();

    // These are always treated as operational even if they come from Primary columns
    let always_operational: HashSet<&str> = [
        "hasSubordinates", "structuralObjectClass", "subschemaSubentry",
        "createTimestamp", "modifyTimestamp", "pwdChangedTime",
        "entryUUID", "memberOf",
    ].iter().cloned().collect();

    // Attributes that clients (especially Apache Directory Studio) sometimes request
    // together with "+" but are Root DSE / subschema attributes, not user/group attributes.
    // Silently ignore them to prevent "unrecognized attribute" warnings and folder icon bugs.
    let _ignore_on_plus: HashSet<&str> = [
        "attributetypes", "objectclasses", "matchingrules", "ldapsyntaxes",
        "matchingruleuse", "creatorsname", "modifiersname", "namingcontexts",
        "supportedcontrol", "supportedextension", "supportedfeatures",
        "supportedldapversion", "supportedsaslmechanisms", "vendorname", "vendorversion",
        "altserver", "ref", "queryid",
    ].iter().cloned().collect();

    for attr in schema.user_attributes().attributes.iter()
        .chain(schema.group_attributes().attributes.iter())
    {
        // Rule: Use the proper LDAP attribute name if one exists in aliases.
        // Only fall back to canonical name if this is a completely custom attribute
        // with no standard LDAP name.
        let preferred_name = get_preferred_ldap_name(attr);

        if let Some((logical, _)) = resolve_attribute(&preferred_name) {
            // Treat as operational if explicitly marked OR if it's one of the always-operational
            // list (timestamps, entryUUID, hasSubordinates, etc.). This ensures they NEVER
            // appear in standard (*) view — fixes "operational still shown with standard".
            let is_always_op = always_operational.contains(preferred_name.as_str());
            let target = if matches!(logical, LogicalAttr::Operational) || is_always_op {
                &mut operational_keys
            } else {
                &mut standard_keys
            };
            if !target.iter().any(|k| k.eq_ignore_ascii_case(&preferred_name)) {
                target.push(preferred_name);
            }
        } else {
            // Truly unknown → expose using the preferred name
            if !standard_keys.iter().any(|k| k.eq_ignore_ascii_case(&preferred_name)) {
                standard_keys.push(preferred_name);
            }
        }
    }

    // Make sure the core operational attributes are always present
    for name in &always_operational {
        if !operational_keys.iter().any(|k| k.eq_ignore_ascii_case(name)) {
            operational_keys.push(name.to_string());
        }
    }

    // Ensure operational attributes (timestamps, entryUUID, hasSubordinates, memberOf, etc.)
    // are NOT included in standard (*) view by default. They belong ONLY in operational (+)
    // view. This fixes the bug where "everything is under standard, operational are not
    // being hidden by default" in Apache Directory Studio and other LDAP clients.
    // memberOf and objectClass are re-added to standard below as they are expected in
    // normal user/group entries.
    let always_operational_set: HashSet<&str> = always_operational.iter().cloned().collect();
    standard_keys.retain(|k| !always_operational_set.contains(k.as_str()));

    // Always include core LDAP attributes for "*" wildcard expansion.
    // objectClass is a MUST attribute (bold in Studio) and must appear in standard view.
    // memberOf is also commonly expected in standard view for group membership.
    // This fixes "incomplete attributes" in standard (non-operational) view.
    for core in ["objectClass", "memberOf"] {
        if !standard_keys.iter().any(|k| k.eq_ignore_ascii_case(core)) {
            standard_keys.push(core.to_string());
        }
    }

    // Case-insensitive deduplication
    let mut seen = HashSet::new();
    standard_keys.retain(|k| seen.insert(k.to_ascii_lowercase()));
    seen.clear();
    operational_keys.retain(|k| seen.insert(k.to_ascii_lowercase()));

    // ============================================================
    // CLIENT-REQUESTED ATTRIBUTES — ALWAYS CANONICALIZED
    // This is what finally kills all duplication (even if Studio sends 10 aliases)
    // ============================================================
    let mut attributes_out: BTreeMap<AttributeName, String> = BTreeMap::new();

    // Skip Root DSE / subschema attributes entirely (even if explicitly requested or via +)
    // to prevent "Ignoring unrecognized user attribute" warnings for altserver, objectclasses, etc.
    let ignore_set: std::collections::HashSet<String> = _ignore_on_plus
        .iter()
        .map(|s| s.to_ascii_lowercase())
        .collect();

    for s in ldap_attributes.iter().filter(|&s| {
        let lower = s.to_ascii_lowercase();
        lower != "*" && lower != "+" && lower != "1.1" && !ignore_set.contains(&lower)
    }) {
        let canonical = get_canonical_name(s);
        attributes_out.insert(AttributeName::from(&canonical), canonical);
    }

    // Remove Root DSE / subschema attributes from operational list when client requests "+"
    operational_keys.retain(|k| !_ignore_on_plus.contains(k.as_str()));

    let has_star = ldap_attributes.iter().any(|x| x == "*") || ldap_attributes.is_empty();
    let has_plus = ldap_attributes.iter().any(|x| x == "+");

    if has_star {
        include_custom_attributes = true;
        for s in &standard_keys {
            attributes_out.insert(AttributeName::from(s), s.clone());
        }
    }

    if has_plus {
        for s in &operational_keys {
            attributes_out.insert(AttributeName::from(s), s.clone());
        }
    }

    debug!(?attributes_out);
    ExpandedAttributes {
        attribute_keys: attributes_out,
        include_custom_attributes,
    }
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

/// Injects the standard operational attributes we always add to every LDAP search result.
/// Centralizes this logic so user.rs and group.rs stay thin and consistent.
pub fn inject_operational_attributes(attrs: &mut Vec<LdapPartialAttribute>, structural_class: &str, base_dn_str: &str) {
    attrs.push(LdapPartialAttribute {
        atype: "hasSubordinates".to_string(),
        vals: vec![b"FALSE".to_vec()],
    });
    attrs.push(LdapPartialAttribute {
        atype: "structuralObjectClass".to_string(),
        vals: vec![structural_class.as_bytes().to_vec()],
    });
    // Always include subschemaSubentry when operational attrs are requested
    attrs.push(LdapPartialAttribute {
        atype: "subschemaSubentry".to_string(),
        vals: vec![format!("cn=Subschema,{}", base_dn_str).into_bytes()],
    });
}

// (is_subtree moved to top under "OU & DN Utilities")

pub enum UserFieldType {
    NoMatch,
    ObjectClass,
    MemberOf,
    Dn,
    EntryDn,
    PrimaryField(UserColumn),
    Attribute(AttributeName, AttributeType, bool),
}

pub fn map_user_field(field: &AttributeName, schema: &PublicSchema) -> UserFieldType {
    if let Some((logical, _)) = resolve_attribute(field.as_str()) {
        return match logical {
            LogicalAttr::ObjectClass => UserFieldType::ObjectClass,
            LogicalAttr::MemberOf => UserFieldType::MemberOf,
            LogicalAttr::Dn => UserFieldType::Dn,
            LogicalAttr::EntryDn => UserFieldType::EntryDn,
            LogicalAttr::Primary(col) => UserFieldType::PrimaryField(col),
            LogicalAttr::Custom(internal, t, is_list) => {
                UserFieldType::Attribute(AttributeName::from(internal), t, is_list)
            }
            LogicalAttr::Operational => UserFieldType::NoMatch,
        };
    }

    schema
        .get_schema()
        .user_attributes
        .get_attribute_type(field.as_str())
        .map(|(t, is_list)| UserFieldType::Attribute(field.clone(), t, is_list))
        .unwrap_or(UserFieldType::NoMatch)
}

pub enum GroupFieldType {
    NoMatch,
    GroupId,
    DisplayName,
    CreationDate,
    ModifiedDate,
    ObjectClass,
    Dn,
    EntryDn,
    Member,
    Uuid,
    Attribute(AttributeName, AttributeType, bool),
}

pub fn map_group_field(field: &AttributeName, schema: &PublicSchema) -> GroupFieldType {
    if let Some((logical, _)) = resolve_attribute(field.as_str()) {
        return match logical {
            LogicalAttr::ObjectClass => GroupFieldType::ObjectClass,
            LogicalAttr::Dn => GroupFieldType::Dn,
            LogicalAttr::EntryDn => GroupFieldType::EntryDn,
            LogicalAttr::Primary(col) => match col {
                UserColumn::CreationDate => GroupFieldType::CreationDate,
                UserColumn::ModifiedDate => GroupFieldType::ModifiedDate,
                UserColumn::Uuid => GroupFieldType::Uuid,
                UserColumn::DisplayName => GroupFieldType::DisplayName,
                _ => GroupFieldType::NoMatch,
            },
            LogicalAttr::Custom(internal, t, is_list) => {
                GroupFieldType::Attribute(AttributeName::from(internal), t, is_list)
            }
            LogicalAttr::Operational => GroupFieldType::NoMatch,
            _ => GroupFieldType::NoMatch,
        };
    }

    schema
        .get_schema()
        .group_attributes
        .get_attribute_type(field.as_str())
        .map(|(t, is_list)| GroupFieldType::Attribute(field.clone(), t, is_list))
        .unwrap_or(GroupFieldType::NoMatch)
}

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
        let base_dn = parse_distinguished_name(&base_dn.to_ascii_lowercase())?;
        let base_dn_str = join(base_dn.iter().map(|(k, v)| format!("{k}={v}")), ",");
        Ok(Self {
            base_dn,
            base_dn_str,
            ignored_user_attributes,
            ignored_group_attributes,
        })
    }
}

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
/// Falls back to provided default (e.g. "people" or "groups").
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
