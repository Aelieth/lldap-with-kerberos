//! SchemaManager - Single source of truth for all attribute handling.

use super::definitions::{ExpandedAttributes, LogicalAttr};
use crate::core::utils::{GroupFieldType, UserFieldType};
use lldap_domain::public_schema::PublicSchema;
use lldap_domain::types::{AttributeName, AttributeType};
use std::collections::{BTreeMap, HashSet};

#[derive(Clone, Default)]
pub struct SchemaManager {
    // Currently lightweight. We can expand ownership of schema data later.
}

impl SchemaManager {
    pub fn new() -> Self {
        Self::default()
    }

    // ========================================================================
    // RESOLVE & CANONICAL NAME
    // ========================================================================

    pub fn resolve_attribute(name: &str) -> Option<(LogicalAttr, &'static str)> {
        let lower = name.to_ascii_lowercase();
        Some(match lower.as_str() {
            "objectclass" => (LogicalAttr::ObjectClass, "objectClass"),
            "memberof" | "ismemberof" => (LogicalAttr::MemberOf, "memberOf"),
            "dn" | "distinguishedname" => (LogicalAttr::Dn, "dn"),
            "entrydn" => (LogicalAttr::EntryDn, "entryDN"),

            "hassubordinates" => (LogicalAttr::Operational, "hasSubordinates"),
            "structuralobjectclass" => (LogicalAttr::Operational, "structuralObjectClass"),
            "subschemasubentry" => (LogicalAttr::Operational, "subschemaSubentry"),

            "createtimestamp" | "creationdate" | "creation_date" | "creationtimestamp" => {
                (LogicalAttr::Primary(lldap_domain_model::model::UserColumn::CreationDate), "createTimestamp")
            }
            "modifytimestamp" | "modifieddate" | "modified_date" | "modifydate" => {
                (LogicalAttr::Primary(lldap_domain_model::model::UserColumn::ModifiedDate), "modifyTimestamp")
            }
            "pwdchangedtime" | "passwordmodifieddate" | "password_modified_date" => {
                (LogicalAttr::Primary(lldap_domain_model::model::UserColumn::PasswordModifiedDate), "pwdChangedTime")
            }

            "uid" | "user_id" | "id" | "userid" => (LogicalAttr::Primary(lldap_domain_model::model::UserColumn::UserId), "uid"),
            "mail" | "email" => (LogicalAttr::Primary(lldap_domain_model::model::UserColumn::Email), "mail"),
            "cn" | "displayname" | "display_name" => (LogicalAttr::Primary(lldap_domain_model::model::UserColumn::DisplayName), "cn"),
            "entryuuid" | "uuid" | "entryUUID" => (LogicalAttr::Primary(lldap_domain_model::model::UserColumn::Uuid), "entryUUID"),
            "krbprincipalname" | "krb_principal_name" | "krbPrincipalName" => {
                (LogicalAttr::Primary(lldap_domain_model::model::UserColumn::KrbPrincipalName), "krbPrincipalName")
            }

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

            "kerberossync" | "kerberos_sync" | "kerberosSync" => {
                (LogicalAttr::Custom("kerberossync", AttributeType::Integer, false), "kerberosSync")
            }
            "groupid" | "group_id" | "gid" => {
                (LogicalAttr::Custom("groupid", AttributeType::Integer, false), "groupid")
            }

            _ => return None,
        })
    }

    pub fn get_canonical_name(&self, name: &str) -> String {
        Self::resolve_attribute(name)
            .map(|(_, canon)| canon.to_string())
            .unwrap_or_else(|| name.to_string())
    }

    pub fn is_operational(&self, name: &str) -> bool {
        matches!(Self::resolve_attribute(name), Some((LogicalAttr::Operational, _)))
    }

    // ========================================================================
    // FIELD MAPPING
    // ========================================================================

    pub fn map_user_field(field: &AttributeName, schema: &PublicSchema) -> UserFieldType {
        if let Some((logical, _)) = Self::resolve_attribute(field.as_str()) {
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

    pub fn map_group_field(field: &AttributeName, schema: &PublicSchema) -> GroupFieldType {
        if let Some((logical, _)) = Self::resolve_attribute(field.as_str()) {
            return match logical {
                LogicalAttr::ObjectClass => GroupFieldType::ObjectClass,
                LogicalAttr::Dn => GroupFieldType::Dn,
                LogicalAttr::EntryDn => GroupFieldType::EntryDn,
                LogicalAttr::Primary(col) => match col {
                    lldap_domain_model::model::UserColumn::CreationDate => GroupFieldType::CreationDate,
                    lldap_domain_model::model::UserColumn::ModifiedDate => GroupFieldType::ModifiedDate,
                    lldap_domain_model::model::UserColumn::Uuid => GroupFieldType::Uuid,
                    lldap_domain_model::model::UserColumn::DisplayName => GroupFieldType::DisplayName,
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

    // ========================================================================
    // EXPAND ATTRIBUTE WILDCARDS (FULL LOGIC - COMPLETED)
    // ========================================================================

    pub fn expand_attribute_wildcards(
        &self,
        ldap_attributes: &[String],
        schema: &PublicSchema,
    ) -> ExpandedAttributes {
        let mut include_custom_attributes = false;

        let mut standard_keys: Vec<String> = Vec::new();
        let mut operational_keys: Vec<String> = Vec::new();

        let always_operational: HashSet<&str> = [
            "hasSubordinates", "structuralObjectClass", "subschemaSubentry",
            "createTimestamp", "modifyTimestamp", "pwdChangedTime",
            "entryUUID", "memberOf",
        ].iter().cloned().collect();

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
            let preferred_name = crate::core::utils::get_preferred_ldap_name(attr);

            if let Some((logical, _)) = Self::resolve_attribute(&preferred_name) {
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
                if !standard_keys.iter().any(|k| k.eq_ignore_ascii_case(&preferred_name)) {
                    standard_keys.push(preferred_name);
                }
            }
        }

        for name in &always_operational {
            if !operational_keys.iter().any(|k| k.eq_ignore_ascii_case(name)) {
                operational_keys.push(name.to_string());
            }
        }

        let always_operational_set: HashSet<&str> = always_operational.iter().cloned().collect();
        standard_keys.retain(|k| !always_operational_set.contains(k.as_str()));

        for core in ["objectClass", "memberOf"] {
            if !standard_keys.iter().any(|k| k.eq_ignore_ascii_case(core)) {
                standard_keys.push(core.to_string());
            }
        }

        let mut seen = HashSet::new();
        standard_keys.retain(|k| seen.insert(k.to_ascii_lowercase()));
        seen.clear();
        operational_keys.retain(|k| seen.insert(k.to_ascii_lowercase()));

        let ignore_set: HashSet<String> = _ignore_on_plus
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect();

        let mut attributes_out: BTreeMap<AttributeName, String> = BTreeMap::new();

        for s in ldap_attributes.iter().filter(|&s| {
            let lower = s.to_ascii_lowercase();
            lower != "*" && lower != "+" && lower != "1.1" && !ignore_set.contains(&lower)
        }) {
            let canonical = self.get_canonical_name(s);
            attributes_out.insert(AttributeName::from(&canonical), canonical);
        }

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

        ExpandedAttributes {
            attribute_keys: attributes_out,
            include_custom_attributes,
        }
    }

    // ========================================================================
    // SCHEMA ACCESS FOR SUBSCHEMA GENERATION
    // ========================================================================

    pub fn get_all_user_attributes(&self) -> Vec<lldap_schema::AttributeSchema> {
        PublicSchema::get().user_attributes().attributes.clone()
    }

    pub fn get_all_group_attributes(&self) -> Vec<lldap_schema::AttributeSchema> {
        PublicSchema::get().group_attributes().attributes.clone()
    }
}
