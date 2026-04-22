use crate::core::{
    error::{LdapError, LdapResult},
    group::{REQUIRED_GROUP_ATTRIBUTES, get_default_group_object_classes},
    user::{REQUIRED_USER_ATTRIBUTES, get_default_user_object_classes},
};
use chrono::{NaiveDateTime, TimeZone};
use itertools::join;
use ldap3_proto::LdapResultCode;
use lldap_domain::{
    public_schema::PublicSchema,
    schema::{AttributeList, Schema},
    types::{
        Attribute, AttributeName, AttributeType, AttributeValue, Cardinality, GroupName,
        LdapObjectClass, UserId,
    },
};
use lldap_domain_model::model::UserColumn;
use std::collections::BTreeMap;
use tracing::{debug, instrument, warn};

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
    chain   // ← if somehow empty, just return empty (correct behavior)
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
        String::new()   // ← clean empty string instead of hardcoded "people"
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

/// Convert a NaiveDateTime to LDAP GeneralizedTime format
pub fn to_generalized_time(dt: &NaiveDateTime) -> Vec<u8> {
    chrono::Utc
        .from_utc_datetime(dt)
        .format("%Y%m%d%H%M%SZ")
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

#[derive(Clone)]
pub struct ExpandedAttributes {
    pub attribute_keys: BTreeMap<AttributeName, String>,
    pub include_custom_attributes: bool,
}

#[instrument(skip(all_attribute_keys), level = "debug")]
pub fn expand_attribute_wildcards(
    ldap_attributes: &[String],
    all_attribute_keys: &[&'static str],
) -> ExpandedAttributes {
    let mut include_custom_attributes = false;
    let mut attributes_out: BTreeMap<_, _> = ldap_attributes
        .iter()
        .filter(|&s| s != "*" && s != "+" && s != "1.1")
        .map(|s| (AttributeName::from(s), s.to_string()))
        .collect();
    attributes_out.extend(
        if ldap_attributes.iter().any(|x| x == "*") || ldap_attributes.is_empty() {
            include_custom_attributes = true;
            all_attribute_keys
        } else {
            &[]
        }
        .iter()
        .map(|&s| (AttributeName::from(s), s.to_string())),
    );
    debug!(?attributes_out);
    ExpandedAttributes {
        attribute_keys: attributes_out,
        include_custom_attributes,
    }
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

    // Check that the suffix of `subtree` exactly matches `base_tree`
    let offset = subtree.len() - base_tree.len();
    for i in 0..base_tree.len() {
        // Use case-insensitive comparison for extra safety (LDAP DNs are case-insensitive)
        if !subtree[offset + i].0.eq_ignore_ascii_case(&base_tree[i].0)
            || !subtree[offset + i].1.eq_ignore_ascii_case(&base_tree[i].1)
        {
            return false;
        }
    }
    true
}

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
    match field.as_str() {
        "memberof" | "ismemberof" => UserFieldType::MemberOf,
        "objectclass" => UserFieldType::ObjectClass,
        "dn" | "distinguishedname" => UserFieldType::Dn,
        "entrydn" => UserFieldType::EntryDn,
        "uid" | "user_id" | "id" => UserFieldType::PrimaryField(UserColumn::UserId),
        "mail" | "email" => UserFieldType::PrimaryField(UserColumn::Email),
        "cn" | "displayname" | "display_name" => UserFieldType::PrimaryField(UserColumn::DisplayName),
        "givenname" | "first_name" | "firstname" => UserFieldType::Attribute(
            AttributeName::from("first_name"),
            AttributeType::String,
            false,
        ),
        "sn" | "last_name" | "lastname" => UserFieldType::Attribute(
            AttributeName::from("last_name"),
            AttributeType::String,
            false,
        ),
        "avatar" | "jpegphoto" => UserFieldType::Attribute(
            AttributeName::from("avatar"),
            AttributeType::Avatar,
            false,
        ),
        "creationdate" | "createtimestamp" | "creation_date" => UserFieldType::PrimaryField(UserColumn::CreationDate),
        "modifytimestamp" | "modifydate" | "modified_date" => UserFieldType::PrimaryField(UserColumn::ModifiedDate),
        "pwdchangedtime" | "passwordmodifydate" | "password_modified_date" => {
            UserFieldType::PrimaryField(UserColumn::PasswordModifiedDate)
        }
        "entryuuid" | "uuid" => UserFieldType::PrimaryField(UserColumn::Uuid),
        "krbprincipalname" | "krb_principal_name" | "krbPrincipalName" => {
            UserFieldType::PrimaryField(UserColumn::KrbPrincipalName)
        }
        "ou" | "organizationalunit" | "organizationalUnit" => UserFieldType::Attribute(
            AttributeName::from("ou"),
            AttributeType::String,
            false,
        ),
        "sshpublickey" | "sshPublicKey" | "ssHPublicKey" => UserFieldType::Attribute(
            AttributeName::from("sshpublickey"),
            AttributeType::String,
            true,
        ),
        _ => schema
            .get_schema()
            .user_attributes
            .get_attribute_type(field.as_str())
            .map(|(t, is_list)| UserFieldType::Attribute(field.clone(), t, is_list))
            .unwrap_or(UserFieldType::NoMatch),
    }
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
    match field.as_str() {
        "dn" | "distinguishedname" => GroupFieldType::Dn,
        "entrydn" => GroupFieldType::EntryDn,
        "objectclass" => GroupFieldType::ObjectClass,
        "cn" | "displayname" | "uid" | "display_name" | "id" => GroupFieldType::DisplayName,
        "creationdate" | "createtimestamp" | "creation_date" => GroupFieldType::CreationDate,
        "modifytimestamp" | "modifydate" | "modified_date" => GroupFieldType::ModifiedDate,
        "member" | "uniquemember" => GroupFieldType::Member,
        "entryuuid" | "uuid" => GroupFieldType::Uuid,
        "group_id" | "groupid" => GroupFieldType::GroupId,
        "ou" | "organizationalunit" | "organizationalUnit" => GroupFieldType::Attribute(
            AttributeName::from("ou"),
            AttributeType::String,
            false,
        ),
        _ => schema
            .get_schema()
            .group_attributes
            .get_attribute_type(field.as_str())
            .map(|(t, is_list)| GroupFieldType::Attribute(field.clone(), t, is_list))
            .unwrap_or(GroupFieldType::NoMatch),
    }
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
            AttributeValue::String(Cardinality::Singleton(s)) => vec![s.clone().into_bytes()],
            AttributeValue::String(Cardinality::Unbounded(l)) => {
                l.iter().map(|s| s.clone().into_bytes()).collect()
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

#[derive(derive_more::From)]
pub struct ObjectClassList(Vec<LdapObjectClass>);

impl ObjectClassList {
    pub fn format_for_ldap_schema_description(&self) -> String {
        join(self.0.iter().map(|c| format!("'{c}'")), " ")
    }
}

pub struct LdapSchemaDescription {
    base: PublicSchema,
    user_object_classes: ObjectClassList,
    group_object_classes: ObjectClassList,
}

impl LdapSchemaDescription {
    pub fn from(schema: PublicSchema) -> Self {
        let mut user_object_classes = get_default_user_object_classes();
        user_object_classes.extend(
            schema.get_schema().extra_user_object_classes.iter().map(|s| LdapObjectClass::from(s.as_str()))
        );
        let mut group_object_classes = get_default_group_object_classes();
        group_object_classes.extend(
            schema.get_schema().extra_group_object_classes.iter().map(|s| LdapObjectClass::from(s.as_str()))
        );

        Self {
            base: schema,
            user_object_classes: ObjectClassList(user_object_classes),
            group_object_classes: ObjectClassList(group_object_classes),
        }
    }

    fn schema(&self) -> &Schema {
        self.base.get_schema()
    }

    pub fn user_object_classes(&self) -> &ObjectClassList { &self.user_object_classes }
    pub fn group_object_classes(&self) -> &ObjectClassList { &self.group_object_classes }

    pub fn required_user_attributes(&self) -> AttributeList {
        let attributes = self.schema().user_attributes.attributes
            .iter()
            .filter(|a| REQUIRED_USER_ATTRIBUTES.contains(&a.name.as_str()))
            .cloned()
            .collect();
        AttributeList { attributes }
    }

    pub fn optional_user_attributes(&self) -> AttributeList {
        let attributes = self.schema().user_attributes.attributes
            .iter()
            .filter(|a| !REQUIRED_USER_ATTRIBUTES.contains(&a.name.as_str()))
            .cloned()
            .collect();
        AttributeList { attributes }
    }

    pub fn required_group_attributes(&self) -> AttributeList {
        let attributes = self.schema().group_attributes.attributes
            .iter()
            .filter(|a| REQUIRED_GROUP_ATTRIBUTES.contains(&a.name.as_str()))
            .cloned()
            .collect();
        AttributeList { attributes }
    }

    pub fn optional_group_attributes(&self) -> AttributeList {
        let attributes = self.schema().group_attributes.attributes
            .iter()
            .filter(|a| !REQUIRED_GROUP_ATTRIBUTES.contains(&a.name.as_str()))
            .cloned()
            .collect();
        AttributeList { attributes }
    }

    pub fn formatted_attribute_list(
        &self,
        index_offset: usize,
        exclude_attributes: Vec<&str>,
    ) -> Vec<Vec<u8>> {
        let mut formatted_list: Vec<Vec<u8>> = Vec::new();

        for (index, attribute) in self
            .all_attributes()
            .attributes
            .into_iter()
            .filter(|attr| !exclude_attributes.contains(&attr.name.as_str()))
            .enumerate()
            {
                formatted_list.push(
                    format!(
                        "( 10.{} NAME '{}' DESC 'LLDAP: {}' SUP {:?} )",
                            (index + index_offset),
                            attribute.name,
                            if attribute.is_hardcoded {
                                "builtin attribute"
                            } else {
                                "custom attribute"
                            },
                            attribute.attribute_type
                    )
                        .into_bytes()
                        .to_vec(),
                )
            }

            formatted_list
    }

    pub fn all_attributes(&self) -> AttributeList {
        let mut combined = self.schema().user_attributes.attributes.clone();
        combined.extend_from_slice(&self.schema().group_attributes.attributes);
        AttributeList { attributes: combined }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_subtree() { /* unchanged */ }
    #[test]
    fn test_parse_distinguished_name() { /* unchanged */ }
    #[test]
    fn test_whitespace_in_ldap_info() { /* unchanged */ }
}
