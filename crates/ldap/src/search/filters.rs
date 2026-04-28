//! Filter conversion logic
//!
//! This module handles conversion of LDAP filters to domain-specific request filters.
//! Kept here so search/handler.rs can orchestrate cleanly while core/ stays slim.

use crate::core::error::{LdapError, LdapResult};
use crate::dn::{get_group_id_from_distinguished_name_or_plain_name, get_user_id_from_distinguished_name_or_plain_name};
use lldap_domain::deserialize::deserialize_attribute_value;
use lldap_domain::public_schema::PublicSchema;
use lldap_domain::types::{AttributeName, AttributeType, UserId};
use lldap_domain_handlers::handler::{GroupRequestFilter, UserRequestFilter};
use ldap3_proto::LdapFilter;
use tracing::warn;

use crate::core::utils::LdapInfo;

// USER FILTER CONVERSION

fn get_user_attribute_equality_filter(
    field: &AttributeName,
    typ: AttributeType,
    is_list: bool,
    value: &str,
) -> UserRequestFilter {
    let value_lc = value.to_ascii_lowercase();
    let attribute_value = deserialize_attribute_value(&[value.to_owned()], typ, is_list);
    let attribute_value_lc = deserialize_attribute_value(&[value_lc.to_owned()], typ, is_list);
    match (attribute_value, attribute_value_lc) {
        (Ok(v), Ok(v_lc)) => UserRequestFilter::Or(vec![
            UserRequestFilter::AttributeEquality(field.clone(), v),
            UserRequestFilter::AttributeEquality(field.clone(), v_lc),
        ]),
        (Ok(_), Err(e)) => {
            warn!("Invalid value for attribute {} (lowercased): {}", field, e);
            UserRequestFilter::False
        }
        (Err(e), _) => {
            warn!("Invalid value for attribute {}: {}", field, e);
            UserRequestFilter::False
        }
    }
}

pub fn convert_user_filter(
    ldap_info: &LdapInfo,
    filter: &LdapFilter,
    schema: &PublicSchema,
) -> LdapResult<UserRequestFilter> {
    let rec = |f| convert_user_filter(ldap_info, f, schema);
    match filter {
        LdapFilter::And(filters) => {
            let res = filters
                .iter()
                .map(rec)
                .filter(|c| !matches!(c, Ok(UserRequestFilter::True)))
                .flat_map(|f| match f {
                    Ok(UserRequestFilter::And(v)) => v.into_iter().map(Ok).collect(),
                    f => vec![f],
                })
                .collect::<LdapResult<Vec<_>>>()?;
            if res.is_empty() {
                Ok(UserRequestFilter::True)
            } else if res.len() == 1 {
                Ok(res.into_iter().next().unwrap())
            } else {
                Ok(UserRequestFilter::And(res))
            }
        }
        LdapFilter::Or(filters) => {
            let res = filters
                .iter()
                .map(rec)
                .filter(|c| !matches!(c, Ok(UserRequestFilter::False)))
                .flat_map(|f| match f {
                    Ok(UserRequestFilter::Or(v)) => v.into_iter().map(Ok).collect(),
                    f => vec![f],
                })
                .collect::<LdapResult<Vec<_>>>()?;
            if res.is_empty() {
                Ok(UserRequestFilter::False)
            } else if res.len() == 1 {
                Ok(res.into_iter().next().unwrap())
            } else {
                Ok(UserRequestFilter::Or(res))
            }
        }
        LdapFilter::Not(filter) => Ok(match rec(filter)? {
            UserRequestFilter::True => UserRequestFilter::False,
            UserRequestFilter::False => UserRequestFilter::True,
            f => UserRequestFilter::Not(Box::new(f)),
        }),
        LdapFilter::Equality(field, value) => {
            let field = AttributeName::from(field.as_str());
            let value_lc = value.to_ascii_lowercase();
            match crate::schema::get_schema_manager().map_user_field(&field, schema) {
                crate::core::utils::UserFieldType::PrimaryField(lldap_domain_model::model::UserColumn::UserId) => {
                    Ok(UserRequestFilter::UserId(UserId::new(&value_lc)))
                }
                crate::core::utils::UserFieldType::PrimaryField(lldap_domain_model::model::UserColumn::Email) => Ok(UserRequestFilter::Equality(
                    lldap_domain_model::model::UserColumn::LowercaseEmail,
                    value_lc,
                )),
                crate::core::utils::UserFieldType::PrimaryField(field) => {
                    Ok(UserRequestFilter::Equality(field, value_lc))
                }
                crate::core::utils::UserFieldType::Attribute(field, typ, is_list) => Ok(
                    get_user_attribute_equality_filter(&field, typ, is_list, value),
                ),
                crate::core::utils::UserFieldType::NoMatch => {
                    if !ldap_info.ignored_user_attributes.contains(&field) {
                        warn!(
                            r#"Ignoring unknown user attribute "{}" in filter.\n\
                                      To disable this warning, add it to "ignored_user_attributes" in the config"#,
                            field
                        );
                    }
                    Ok(UserRequestFilter::False)
                }
                crate::core::utils::UserFieldType::ObjectClass => Ok(UserRequestFilter::And(vec![])),
                crate::core::utils::UserFieldType::MemberOf => Ok(get_group_id_from_distinguished_name_or_plain_name(
                    &value_lc,
                    &ldap_info.base_dn,
                    &ldap_info.base_dn_str,
                )
                .map(UserRequestFilter::MemberOf)
                .unwrap_or_else(|e| {
                    warn!("Invalid memberOf filter: {}", e);
                    UserRequestFilter::False
                })),
                crate::core::utils::UserFieldType::EntryDn | crate::core::utils::UserFieldType::Dn => {
                    Ok(get_user_id_from_distinguished_name_or_plain_name(
                        value_lc.as_str(),
                        &ldap_info.base_dn,
                        &ldap_info.base_dn_str,
                    )
                    .map(UserRequestFilter::UserId)
                    .unwrap_or_else(|_| {
                        warn!("Invalid dn filter on user: {}", value_lc);
                        UserRequestFilter::False
                    }))
                }
                crate::core::utils::UserFieldType::EntryUuid => Ok(UserRequestFilter::False),
            }
        }
        LdapFilter::GreaterOrEqual(field, value) => {
            let field = AttributeName::from(field.as_str());
            match crate::schema::get_schema_manager().map_user_field(&field, schema) {
                crate::core::utils::UserFieldType::PrimaryField(f)
                    if matches!(f, lldap_domain_model::model::UserColumn::CreationDate | lldap_domain_model::model::UserColumn::ModifiedDate | lldap_domain_model::model::UserColumn::PasswordModifiedDate) =>
                {
                    Ok(UserRequestFilter::GreaterOrEqual(f, value.to_string()))
                }
                crate::core::utils::UserFieldType::Attribute(name, typ, _)
                    if typ == AttributeType::DateTime =>
                {
                    Ok(UserRequestFilter::AttributeGreaterOrEqual(name, value.to_string()))
                }
                _ => Err(LdapError {
                    code: ldap3_proto::LdapResultCode::UnwillingToPerform,
                    message: format!("GreaterOrEqual not supported on this attribute: {}", field),
                }),
            }
        }
        LdapFilter::LessOrEqual(field, value) => {
            let field = AttributeName::from(field.as_str());
            match crate::schema::get_schema_manager().map_user_field(&field, schema) {
                crate::core::utils::UserFieldType::PrimaryField(f)
                    if matches!(f, lldap_domain_model::model::UserColumn::CreationDate | lldap_domain_model::model::UserColumn::ModifiedDate | lldap_domain_model::model::UserColumn::PasswordModifiedDate) =>
                {
                    Ok(UserRequestFilter::LessOrEqual(f, value.to_string()))
                }
                crate::core::utils::UserFieldType::Attribute(name, typ, _)
                    if typ == AttributeType::DateTime =>
                {
                    Ok(UserRequestFilter::AttributeLessOrEqual(name, value.to_string()))
                }
                _ => Err(LdapError {
                    code: ldap3_proto::LdapResultCode::UnwillingToPerform,
                    message: format!("LessOrEqual not supported on this attribute: {}", field),
                }),
            }
        }
        LdapFilter::Present(field) => {
            let field = AttributeName::from(field.as_str());
            Ok(match crate::schema::get_schema_manager().map_user_field(&field, schema) {
                crate::core::utils::UserFieldType::Attribute(name, _, _) => {
                    UserRequestFilter::CustomAttributePresent(name)
                }
                crate::core::utils::UserFieldType::NoMatch => UserRequestFilter::False,
                _ => UserRequestFilter::True,
            })
        }
        LdapFilter::Substring(field, substring_filter) => {
            let field = AttributeName::from(field.as_str());
            match crate::schema::get_schema_manager().map_user_field(&field, schema) {
                crate::core::utils::UserFieldType::PrimaryField(lldap_domain_model::model::UserColumn::UserId) => Ok(
                    UserRequestFilter::UserIdSubString(substring_filter.clone().into()),
                ),
                crate::core::utils::UserFieldType::Attribute(_, _, _)
                | crate::core::utils::UserFieldType::ObjectClass
                | crate::core::utils::UserFieldType::MemberOf
                | crate::core::utils::UserFieldType::Dn
                | crate::core::utils::UserFieldType::EntryDn
                | crate::core::utils::UserFieldType::EntryUuid
                | crate::core::utils::UserFieldType::PrimaryField(lldap_domain_model::model::UserColumn::CreationDate)
                | crate::core::utils::UserFieldType::PrimaryField(lldap_domain_model::model::UserColumn::Uuid) => Err(LdapError {
                    code: ldap3_proto::LdapResultCode::UnwillingToPerform,
                    message: format!("Unsupported user attribute for substring filter: {field:?}"),
                }),
                crate::core::utils::UserFieldType::NoMatch => Ok(UserRequestFilter::False),
                crate::core::utils::UserFieldType::PrimaryField(lldap_domain_model::model::UserColumn::Email) => Ok(UserRequestFilter::SubString(
                    lldap_domain_model::model::UserColumn::LowercaseEmail,
                    substring_filter.clone().into(),
                )),
                crate::core::utils::UserFieldType::PrimaryField(field) => Ok(UserRequestFilter::SubString(
                    field,
                    substring_filter.clone().into(),
                )),
            }
        }
        _ => Err(LdapError {
            code: ldap3_proto::LdapResultCode::UnwillingToPerform,
            message: format!("Unsupported user filter: {filter:?}"),
        }),
    }
}

// GROUP FILTER CONVERSION

fn get_group_attribute_equality_filter(
    field: &AttributeName,
    typ: AttributeType,
    is_list: bool,
    value: &str,
) -> GroupRequestFilter {
    let value_lc = value.to_ascii_lowercase();
    let serialized_value = deserialize_attribute_value(&[value.to_owned()], typ, is_list);
    let serialized_value_lc = deserialize_attribute_value(&[value_lc.to_owned()], typ, is_list);
    match (serialized_value, serialized_value_lc) {
        (Ok(v), Ok(v_lc)) => GroupRequestFilter::Or(vec![
            GroupRequestFilter::AttributeEquality(field.clone(), v),
            GroupRequestFilter::AttributeEquality(field.clone(), v_lc),
        ]),
        (Ok(_), Err(e)) => {
            warn!("Invalid value for attribute {} (lowercased): {}", field, e);
            GroupRequestFilter::False
        }
        (Err(e), _) => {
            warn!("Invalid value for attribute {}: {}", field, e);
            GroupRequestFilter::False
        }
    }
}

pub fn convert_group_filter(
    ldap_info: &LdapInfo,
    filter: &LdapFilter,
    schema: &PublicSchema,
) -> LdapResult<GroupRequestFilter> {
    let rec = |f| convert_group_filter(ldap_info, f, schema);
    match filter {
        LdapFilter::Equality(field, value) if field.eq_ignore_ascii_case("objectclass") => {
            let v = value.to_ascii_lowercase();
            if v == "groupofuniquenames" || v == "groupofnames" || v == "posixgroup" {
                Ok(GroupRequestFilter::True)
            } else {
                Ok(GroupRequestFilter::False)
            }
        }

        LdapFilter::Equality(field, value) => {
            let field = AttributeName::from(field.as_str());
            let value_lc = value.to_ascii_lowercase();
            match crate::schema::get_schema_manager().map_group_field(&field, schema) {
                crate::core::utils::GroupFieldType::GroupId => Ok(value_lc
                    .parse::<i32>()
                    .map(|id| GroupRequestFilter::GroupId(lldap_domain::types::GroupId(id)))
                    .unwrap_or_else(|_| {
                        warn!("Given group id is not a valid integer: {}", value_lc);
                        GroupRequestFilter::False
                    })),
                crate::core::utils::GroupFieldType::DisplayName => Ok(GroupRequestFilter::DisplayName(value_lc.into())),
                crate::core::utils::GroupFieldType::Uuid => lldap_domain::types::Uuid::try_from(value_lc.as_str())
                    .map(GroupRequestFilter::Uuid)
                    .map_err(|e| LdapError {
                        code: ldap3_proto::LdapResultCode::Other,
                        message: format!("Invalid UUID: {e:#}"),
                    }),
                crate::core::utils::GroupFieldType::Member => Ok(get_user_id_from_distinguished_name_or_plain_name(
                    &value_lc,
                    &ldap_info.base_dn,
                    &ldap_info.base_dn_str,
                )
                .map(GroupRequestFilter::Member)
                .unwrap_or_else(|e| {
                    warn!("Invalid member filter on group: {}", e);
                    GroupRequestFilter::False
                })),
                crate::core::utils::GroupFieldType::ObjectClass => Ok(GroupRequestFilter::And(vec![])),
                crate::core::utils::GroupFieldType::Dn | crate::core::utils::GroupFieldType::EntryDn => {
                    Ok(get_group_id_from_distinguished_name_or_plain_name(
                        value_lc.as_str(),
                        &ldap_info.base_dn,
                        &ldap_info.base_dn_str,
                    )
                    .map(GroupRequestFilter::DisplayName)
                    .unwrap_or_else(|_| {
                        warn!("Invalid dn filter on group: {}", value_lc);
                        GroupRequestFilter::False
                    }))
                }
                crate::core::utils::GroupFieldType::EntryUuid => Ok(GroupRequestFilter::False),
                crate::core::utils::GroupFieldType::NoMatch => {
                    if !ldap_info.ignored_group_attributes.contains(&field) {
                        warn!(
                            r#"Ignoring unknown group attribute "{}" in filter.\n\
                                To disable this warning, add it to "ignored_group_attributes" in the config."#,
                            field
                        );
                    }
                    Ok(GroupRequestFilter::False)
                }
                crate::core::utils::GroupFieldType::Attribute(field, typ, is_list) => Ok(
                    get_group_attribute_equality_filter(&field, typ, is_list, value),
                ),
                crate::core::utils::GroupFieldType::CreationDate => Err(LdapError {
                    code: ldap3_proto::LdapResultCode::UnwillingToPerform,
                    message: "Creation date filter for groups not supported".to_owned(),
                }),
                crate::core::utils::GroupFieldType::ModifiedDate => Err(LdapError {
                    code: ldap3_proto::LdapResultCode::UnwillingToPerform,
                    message: "Modified date filter for groups not supported".to_owned(),
                }),
            }
        }
        LdapFilter::GreaterOrEqual(field, value) => {
            let field = AttributeName::from(field.as_str());
            match crate::schema::get_schema_manager().map_group_field(&field, schema) {
                crate::core::utils::GroupFieldType::CreationDate | crate::core::utils::GroupFieldType::ModifiedDate => {
                    Ok(GroupRequestFilter::GreaterOrEqual(
                        field.as_str().to_string(),
                        value.to_string(),
                    ))
                }
                crate::core::utils::GroupFieldType::Attribute(name, typ, _)
                    if typ == AttributeType::DateTime =>
                {
                    Ok(GroupRequestFilter::AttributeGreaterOrEqual(
                        name,
                        value.to_string(),
                    ))
                }
                _ => Err(LdapError {
                    code: ldap3_proto::LdapResultCode::UnwillingToPerform,
                    message: format!("GreaterOrEqual not supported on this attribute: {}", field),
                }),
            }
        }
        LdapFilter::LessOrEqual(field, value) => {
            let field = AttributeName::from(field.as_str());
            match crate::schema::get_schema_manager().map_group_field(&field, schema) {
                crate::core::utils::GroupFieldType::CreationDate | crate::core::utils::GroupFieldType::ModifiedDate => {
                    Ok(GroupRequestFilter::LessOrEqual(
                        field.as_str().to_string(),
                        value.to_string(),
                    ))
                }
                crate::core::utils::GroupFieldType::Attribute(name, typ, _)
                    if typ == AttributeType::DateTime =>
                {
                    Ok(GroupRequestFilter::AttributeLessOrEqual(
                        name,
                        value.to_string(),
                    ))
                }
                _ => Err(LdapError {
                    code: ldap3_proto::LdapResultCode::UnwillingToPerform,
                    message: format!("LessOrEqual not supported on this attribute: {}", field),
                }),
            }
        }
        LdapFilter::And(filters) => {
            let res = filters
                .iter()
                .map(rec)
                .filter(|f| !matches!(f, Ok(GroupRequestFilter::True)))
                .flat_map(|f| match f {
                    Ok(GroupRequestFilter::And(v)) => v.into_iter().map(Ok).collect(),
                    f => vec![f],
                })
                .collect::<LdapResult<Vec<_>>>()?;
            if res.is_empty() {
                Ok(GroupRequestFilter::True)
            } else if res.len() == 1 {
                Ok(res.into_iter().next().unwrap())
            } else {
                Ok(GroupRequestFilter::And(res))
            }
        }
        LdapFilter::Or(filters) => {
            let res = filters
                .iter()
                .map(rec)
                .filter(|c| !matches!(c, Ok(GroupRequestFilter::False)))
                .flat_map(|f| match f {
                    Ok(GroupRequestFilter::Or(v)) => v.into_iter().map(Ok).collect(),
                    f => vec![f],
                })
                .collect::<LdapResult<Vec<_>>>()?;
            if res.is_empty() {
                Ok(GroupRequestFilter::False)
            } else if res.len() == 1 {
                Ok(res.into_iter().next().unwrap())
            } else {
                Ok(GroupRequestFilter::Or(res))
            }
        }
        LdapFilter::Not(filter) => Ok(match rec(filter)? {
            GroupRequestFilter::True => GroupRequestFilter::False,
            GroupRequestFilter::False => GroupRequestFilter::True,
            f => GroupRequestFilter::Not(Box::new(f)),
        }),
        LdapFilter::Present(field) => {
            let field = AttributeName::from(field.as_str());
            Ok(match crate::schema::get_schema_manager().map_group_field(&field, schema) {
                crate::core::utils::GroupFieldType::Attribute(name, _, _) => {
                    GroupRequestFilter::CustomAttributePresent(name)
                }
                crate::core::utils::GroupFieldType::NoMatch => GroupRequestFilter::False,
                _ => GroupRequestFilter::True,
            })
        }
        LdapFilter::Substring(field, substring_filter) => {
            let field = AttributeName::from(field.as_str());
            match crate::schema::get_schema_manager().map_group_field(&field, schema) {
                crate::core::utils::GroupFieldType::DisplayName => Ok(GroupRequestFilter::DisplayNameSubString(
                    substring_filter.clone().into(),
                )),
                crate::core::utils::GroupFieldType::NoMatch => Ok(GroupRequestFilter::False),
                _ => Err(LdapError {
                    code: ldap3_proto::LdapResultCode::UnwillingToPerform,
                    message: format!(
                        "Unsupported group attribute for substring filter: \"{field}\""
                    ),
                }),
            }
        }
        _ => Err(LdapError {
            code: ldap3_proto::LdapResultCode::UnwillingToPerform,
            message: format!("Unsupported group filter: {filter:?}"),
        }),
    }
}
