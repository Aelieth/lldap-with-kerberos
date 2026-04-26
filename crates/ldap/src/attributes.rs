//! Attribute handling — Single canonical source of truth (ApacheDS style).
//!
//! All user/group attribute resolution, EntryDn construction, memberOf,
//! operational attributes, and search result entry building lives here.

use crate::core::utils::{
    get_custom_attribute, get_ou_from_attributes, inject_operational_attributes,
    to_generalized_time, DEFAULT_PRIMARY_GROUP_OU, DEFAULT_PRIMARY_USER_OU,
};
use crate::dn::internal_ou_to_ldap_rdn_chain;
use lldap_domain::{
    public_schema::PublicSchema,
    types::{AttributeName, Group, GroupDetails, User},
};
use ldap3_proto::LdapSearchResultEntry;

pub use crate::core::utils::{
    get_default_group_object_classes_bytes, get_default_user_object_classes_bytes,
};

pub fn get_user_ou(user: &User) -> String {
    get_ou_from_attributes(&user.attributes, DEFAULT_PRIMARY_USER_OU)
}

pub fn get_group_ou(group: &Group) -> String {
    get_ou_from_attributes(&group.attributes, DEFAULT_PRIMARY_GROUP_OU)
}

// ============================================================================
// USER ATTRIBUTE RESOLUTION (canonical implementation)
// ============================================================================

pub fn get_user_attribute(
    user: &User,
    attribute: &AttributeName,
    base_dn_str: &str,
    groups: Option<&[GroupDetails]>,
    ignored_user_attributes: &[AttributeName],
    schema: &PublicSchema,
) -> Option<Vec<Vec<u8>>> {
    let attribute = AttributeName::from(attribute.as_str());
    let attribute_values = match crate::schema::SchemaManager::map_user_field(&attribute, schema) {
        crate::core::utils::UserFieldType::ObjectClass => get_default_user_object_classes_bytes(schema),
        crate::core::utils::UserFieldType::Dn => return None,
        crate::core::utils::UserFieldType::EntryDn => {
            let internal_ou = get_user_ou(user);
            let rdn_chain = internal_ou_to_ldap_rdn_chain(&internal_ou);
            let ou_part = rdn_chain.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join(",");
            vec![format!("uid={},{}", &user.user_id, ou_part + "," + base_dn_str).into_bytes()]
        }
        crate::core::utils::UserFieldType::MemberOf => groups
            .into_iter()
            .flatten()
            .map(|group| {
                let group_ou = group.attributes.iter()
                    .find(|a| a.name.as_str() == "ou")
                    .and_then(|a| {
                        if let lldap_domain::types::AttributeValue::String(
                            lldap_domain::types::Cardinality::Singleton(s),
                        ) = &a.value { Some(s.clone()) } else { None }
                    })
                    .unwrap_or_else(|| "groups".to_string());
                format!("cn={},ou={},{}", &group.display_name, group_ou, base_dn_str).into_bytes()
            })
            .collect(),
        crate::core::utils::UserFieldType::PrimaryField(lldap_domain_model::model::UserColumn::UserId) => {
            vec![user.user_id.to_string().into_bytes()]
        }
        crate::core::utils::UserFieldType::PrimaryField(lldap_domain_model::model::UserColumn::Email) => {
            vec![user.email.to_string().into_bytes()]
        }
        crate::core::utils::UserFieldType::PrimaryField(
            lldap_domain_model::model::UserColumn::LowercaseEmail
            | lldap_domain_model::model::UserColumn::PasswordHash
            | lldap_domain_model::model::UserColumn::TotpSecret
            | lldap_domain_model::model::UserColumn::MfaType,
        ) => panic!("Should not get here"),
        crate::core::utils::UserFieldType::PrimaryField(lldap_domain_model::model::UserColumn::Uuid) => {
            vec![user.uuid.to_string().into_bytes()]
        }
        crate::core::utils::UserFieldType::PrimaryField(lldap_domain_model::model::UserColumn::DisplayName) => {
            vec![user.display_name.clone()?.into_bytes()]
        }
        crate::core::utils::UserFieldType::PrimaryField(lldap_domain_model::model::UserColumn::CreationDate) => {
            vec![to_generalized_time(&user.creation_date)]
        }
        crate::core::utils::UserFieldType::PrimaryField(lldap_domain_model::model::UserColumn::ModifiedDate) => {
            vec![to_generalized_time(&user.modified_date)]
        }
        crate::core::utils::UserFieldType::PrimaryField(lldap_domain_model::model::UserColumn::PasswordModifiedDate) => {
            vec![to_generalized_time(&user.password_modified_date)]
        }
        crate::core::utils::UserFieldType::PrimaryField(lldap_domain_model::model::UserColumn::KrbPrincipalName) => {
            vec![user.krb_principal_name.clone()?.into_bytes()]
        }
        crate::core::utils::UserFieldType::Attribute(attr, _, _) => {
            let values = get_custom_attribute(&user.attributes, &attr)?;
            if attr.as_str().eq_ignore_ascii_case("ou") {
                if let Some(first) = values.first() {
                    let s = String::from_utf8_lossy(first);
                    let leaf = s.split('\\').last().unwrap_or(&s).to_string();
                    vec![leaf.into_bytes()]
                } else { vec![] }
            } else { values }
        }
        crate::core::utils::UserFieldType::NoMatch => match attribute.as_str() {
            "1.1" => return None,
            "+" => return None,
            "*" => panic!("Matched {attribute}, * should have been expanded"),
            _ => {
                if ignored_user_attributes.contains(&attribute) { return None; }
                let is_unknown = crate::schema::SchemaManager::resolve_attribute(attribute.as_str()).is_none();
                get_custom_attribute(&user.attributes, &attribute).or_else(|| {
                    if is_unknown {
                        tracing::warn!(r#"Ignoring unrecognized user attribute: {}. Add to "ignored_user_attributes"."#, attribute);
                    }
                    None
                })?
            }
        },
    };
    if attribute_values.len() == 1 && attribute_values[0].is_empty() { None } else { Some(attribute_values) }
}

// ============================================================================
// GROUP ATTRIBUTE RESOLUTION (canonical implementation)
// ============================================================================

pub fn get_group_attribute(
    group: &Group,
    base_dn_str: &str,
    attribute: &AttributeName,
    user_filter: &Option<lldap_domain::types::UserId>,
    ignored_group_attributes: &[AttributeName],
    schema: &PublicSchema,
) -> Option<Vec<Vec<u8>>> {
    let attribute_values = match crate::schema::SchemaManager::map_group_field(attribute, schema) {
        crate::core::utils::GroupFieldType::ObjectClass => get_default_group_object_classes_bytes(schema),
        crate::core::utils::GroupFieldType::Dn => return None,
        crate::core::utils::GroupFieldType::EntryDn => {
            let internal_ou = get_group_ou(group);
            let rdn_chain = internal_ou_to_ldap_rdn_chain(&internal_ou);
            let ou_part = rdn_chain.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join(",");
            vec![format!("cn={},{}", group.display_name, ou_part + "," + base_dn_str).into_bytes()]
        }
        crate::core::utils::GroupFieldType::GroupId => vec![group.id.0.to_string().into_bytes()],
        crate::core::utils::GroupFieldType::DisplayName => vec![group.display_name.to_string().into_bytes()],
        crate::core::utils::GroupFieldType::CreationDate => vec![to_generalized_time(&group.creation_date)],
        crate::core::utils::GroupFieldType::ModifiedDate => vec![to_generalized_time(&group.modified_date)],
        crate::core::utils::GroupFieldType::Member => {
            let members: std::collections::BTreeSet<_> = group.users.iter()
                .filter(|u| user_filter.as_ref().map(|f| u.user_id == *f).unwrap_or(true))
                .map(|u| {
                    let rdn_chain = internal_ou_to_ldap_rdn_chain(&u.ou);
                    let ou_part = rdn_chain.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join(",");
                    format!("uid={},{}", u.user_id, ou_part + "," + base_dn_str)
                })
                .collect();
            members.into_iter().map(|s| s.into_bytes()).collect()
        }
        crate::core::utils::GroupFieldType::Uuid => vec![group.uuid.to_string().into_bytes()],
        crate::core::utils::GroupFieldType::Attribute(attr, _, _) => {
            let values = get_custom_attribute(&group.attributes, &attr)?;
            if attr.as_str().eq_ignore_ascii_case("ou") {
                if let Some(first) = values.first() {
                    let s = String::from_utf8_lossy(first);
                    let leaf = s.split('\\').last().unwrap_or(&s).to_string();
                    vec![leaf.into_bytes()]
                } else { vec![] }
            } else { values }
        }
        crate::core::utils::GroupFieldType::NoMatch => match attribute.as_str() {
            "1.1" => return None,
            "+" => return None,
            "*" => panic!("Matched {attribute}, * should have been expanded"),
            _ => {
                if ignored_group_attributes.contains(attribute) { return None; }
                let is_unknown = crate::schema::SchemaManager::resolve_attribute(attribute.as_str()).is_none();
                get_custom_attribute(&group.attributes, attribute).or_else(|| {
                    if is_unknown {
                        tracing::warn!(r#"Ignoring unrecognized group attribute: {}. Add to "ignored_group_attributes"."#, attribute);
                    }
                    None
                })?
            }
        },
    };
    if attribute_values.len() == 1 && attribute_values[0].is_empty() { None } else { Some(attribute_values) }
}

// ============================================================================
// SEARCH RESULT ENTRY BUILDERS (canonical implementation)
// ============================================================================

pub fn make_ldap_search_user_result_entry(
    user: User,
    base_dn_str: &str,
    mut expanded_attributes: crate::core::utils::ExpandedAttributes,
    groups: Option<&[GroupDetails]>,
    ignored_user_attributes: &[AttributeName],
    schema: &PublicSchema,
) -> LdapSearchResultEntry {
    if expanded_attributes.include_custom_attributes {
        let standardized: std::collections::HashSet<String> = schema.user_attributes().attributes.iter()
            .flat_map(|a| { let mut names = vec![a.name.to_string()]; names.extend(a.aliases.iter().map(|al| al.to_string())); names })
            .collect();
        let custom_to_add: Vec<_> = user.attributes.iter()
            .filter(|a| !standardized.contains(a.name.as_str()))
            .map(|a| (a.name.clone(), a.name.to_string()))
            .collect();
        expanded_attributes.attribute_keys.extend(custom_to_add);
    }

    LdapSearchResultEntry {
        dn: {
            let internal_ou = get_user_ou(&user);
            let rdn_chain = internal_ou_to_ldap_rdn_chain(&internal_ou);
            let ou_part = rdn_chain.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join(",");
            format!("uid={},{}", user.user_id.as_str(), ou_part + "," + base_dn_str)
        },
        attributes: {
            let mut attrs: Vec<ldap3_proto::LdapPartialAttribute> = expanded_attributes.attribute_keys.into_iter()
                .filter(|(attribute, _)| !crate::schema::get_schema_manager().is_operational(attribute.as_str()))
                .filter_map(|(attribute, name)| {
                    let values = get_user_attribute(&user, &attribute, base_dn_str, groups, ignored_user_attributes, schema)?;
                    Some(ldap3_proto::LdapPartialAttribute { atype: name, vals: values })
                })
                .collect();
            inject_operational_attributes(&mut attrs, "inetOrgPerson", base_dn_str);
            let mut seen = std::collections::HashSet::new();
            attrs.retain(|attr| seen.insert(attr.atype.clone()));
            attrs
        },
    }
}

pub fn make_ldap_search_group_result_entry(
    group: Group,
    base_dn_str: &str,
    mut expanded_attributes: crate::core::utils::ExpandedAttributes,
    user_filter: &Option<lldap_domain::types::UserId>,
    ignored_group_attributes: &[AttributeName],
    schema: &PublicSchema,
) -> LdapSearchResultEntry {
    if expanded_attributes.include_custom_attributes {
        let standardized: std::collections::HashSet<String> = schema.group_attributes().attributes.iter()
            .flat_map(|a| { let mut names = vec![a.name.to_string()]; names.extend(a.aliases.iter().map(|al| al.to_string())); names })
            .collect();
        let custom_to_add: Vec<_> = group.attributes.iter()
            .filter(|a| !standardized.contains(a.name.as_str()))
            .map(|a| (a.name.clone(), a.name.to_string()))
            .collect();
        expanded_attributes.attribute_keys.extend(custom_to_add);
    }

    LdapSearchResultEntry {
        dn: {
            let internal_ou = get_group_ou(&group);
            let rdn_chain = internal_ou_to_ldap_rdn_chain(&internal_ou);
            let ou_part = rdn_chain.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join(",");
            format!("cn={},{}", group.display_name, ou_part + "," + base_dn_str)
        },
        attributes: {
            let mut attrs: Vec<ldap3_proto::LdapPartialAttribute> = expanded_attributes.attribute_keys.into_iter()
                .filter(|(attribute, _)| !crate::schema::get_schema_manager().is_operational(attribute.as_str()))
                .filter_map(|(attribute, name)| {
                    let values = get_group_attribute(&group, base_dn_str, &attribute, user_filter, ignored_group_attributes, schema)?;
                    Some(ldap3_proto::LdapPartialAttribute { atype: name, vals: values })
                })
                .collect();
            inject_operational_attributes(&mut attrs, "groupOfUniqueNames", base_dn_str);
            let mut seen = std::collections::HashSet::new();
            attrs.retain(|attr| seen.insert(attr.atype.clone()));
            attrs
        },
    }
}
