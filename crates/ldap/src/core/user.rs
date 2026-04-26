use crate::{
    attributes::get_default_user_object_classes_bytes,
    core::{
        error::{LdapError, LdapResult},
        utils::{get_custom_attribute, get_ou_from_attributes, inject_operational_attributes, internal_ou_to_ldap_rdn_chain, is_operational_attribute, to_generalized_time, DEFAULT_PRIMARY_USER_OU, LdapInfo, UserFieldType, ExpandedAttributes},
    },
    dn::{get_group_id_from_distinguished_name_or_plain_name, get_user_id_from_distinguished_name_or_plain_name},
    schema::SchemaManager,
};
use ldap3_proto::{
    LdapFilter, LdapPartialAttribute, LdapResultCode, LdapSearchResultEntry,
};
use lldap_domain::{
    deserialize::deserialize_attribute_value,
    public_schema::PublicSchema,
    types::{AttributeName, AttributeType, GroupDetails, User, UserAndGroups, UserId},
};
use lldap_domain_handlers::handler::{UserListerBackendHandler, UserRequestFilter};
use lldap_domain_model::model::UserColumn;
use tracing::{debug, instrument, warn};

pub fn get_default_user_object_classes() -> Vec<lldap_domain::types::LdapObjectClass> {
    crate::core::utils::get_default_user_object_classes()
}

pub fn get_user_attribute(
    user: &User,
    attribute: &AttributeName,
    base_dn_str: &str,
    groups: Option<&[GroupDetails]>,
    ignored_user_attributes: &[AttributeName],
    schema: &PublicSchema,
) -> Option<Vec<Vec<u8>>> {
    let attribute = AttributeName::from(attribute.as_str());
    let attribute_values = match SchemaManager::map_user_field(&attribute, schema) {
        UserFieldType::ObjectClass => get_default_user_object_classes_bytes(schema),
        UserFieldType::Dn => return None,
        UserFieldType::EntryDn => {
            let internal_ou = get_user_ou(user);
            let rdn_chain = internal_ou_to_ldap_rdn_chain(&internal_ou);
            let ou_part = rdn_chain
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join(",");
            vec![format!("uid={},{}", &user.user_id, ou_part + "," + base_dn_str).into_bytes()]
        }
        UserFieldType::MemberOf => groups
            .into_iter()
            .flatten()
            .map(|group| {
                let group_ou = group.attributes
                    .iter()
                    .find(|a| a.name.as_str() == "ou")
                    .and_then(|a| {
                        if let lldap_domain::types::AttributeValue::String(
                            lldap_domain::types::Cardinality::Singleton(s),
                        ) = &a.value
                        {
                            Some(s.clone())
                        } else {
                            None
                        }
                    })
                    .unwrap_or_else(|| "groups".to_string());

                format!("cn={},ou={},{}", &group.display_name, group_ou, base_dn_str).into_bytes()
            })
            .collect(),
        UserFieldType::PrimaryField(UserColumn::UserId) => {
            vec![user.user_id.to_string().into_bytes()]
        }
        UserFieldType::PrimaryField(UserColumn::Email) => vec![user.email.to_string().into_bytes()],
        UserFieldType::PrimaryField(
            UserColumn::LowercaseEmail
            | UserColumn::PasswordHash
            | UserColumn::TotpSecret
            | UserColumn::MfaType,
        ) => panic!("Should not get here"),
        UserFieldType::PrimaryField(UserColumn::Uuid) => vec![user.uuid.to_string().into_bytes()],
        UserFieldType::PrimaryField(UserColumn::DisplayName) => {
            vec![user.display_name.clone()?.into_bytes()]
        }
        UserFieldType::PrimaryField(UserColumn::CreationDate) => {
            vec![to_generalized_time(&user.creation_date)]
        }
        UserFieldType::PrimaryField(UserColumn::ModifiedDate) => {
            vec![to_generalized_time(&user.modified_date)]
        }
        UserFieldType::PrimaryField(UserColumn::PasswordModifiedDate) => {
            vec![to_generalized_time(&user.password_modified_date)]
        }
        UserFieldType::PrimaryField(UserColumn::KrbPrincipalName) => {
            vec![user.krb_principal_name.clone()?.into_bytes()]
        }
        UserFieldType::Attribute(attr, _, _) => {
            let values = get_custom_attribute(&user.attributes, &attr)?;
            if attr.as_str().eq_ignore_ascii_case("ou") {
                if let Some(first) = values.first() {
                    let s = String::from_utf8_lossy(first);
                    let leaf = s.split('\\').last().unwrap_or(&s).to_string();
                    vec![leaf.into_bytes()]
                } else {
                    vec![]
                }
            } else {
                values
            }
        }
        UserFieldType::NoMatch => match attribute.as_str() {
            "1.1" => return None,
            "+" => return None,
            "*" => {
                panic!(
                    "Matched {attribute}, * should have been expanded into attribute list and * removed"
                )
            }
            _ => {
                if ignored_user_attributes.contains(&attribute) {
                    return None;
                }
                let is_unknown = SchemaManager::resolve_attribute(attribute.as_str()).is_none();
                get_custom_attribute(&user.attributes, &attribute).or_else(|| {
                    if is_unknown {
                        warn!(
                            r#"Ignoring unrecognized user attribute: {}. To disable this warning, add it to "ignored_user_attributes" in the config."#,
                            attribute
                        );
                    }
                    None
                })?
            }
        },
    };
    if attribute_values.len() == 1 && attribute_values[0].is_empty() {
        None
    } else {
        Some(attribute_values)
    }
}

pub fn make_ldap_search_user_result_entry(
    user: User,
    base_dn_str: &str,
    mut expanded_attributes: ExpandedAttributes,
    groups: Option<&[GroupDetails]>,
    ignored_user_attributes: &[AttributeName],
    schema: &PublicSchema,
) -> LdapSearchResultEntry {
    if expanded_attributes.include_custom_attributes {
        let standardized: std::collections::HashSet<String> = schema
            .user_attributes()
            .attributes
            .iter()
            .flat_map(|a| {
                let mut names = vec![a.name.to_string()];
                names.extend(a.aliases.iter().map(|al| al.to_string()));
                names
            })
            .collect();

        let custom_to_add: Vec<_> = user.attributes
            .iter()
            .filter(|a| !standardized.contains(a.name.as_str()))
            .map(|a| (a.name.clone(), a.name.to_string()))
            .collect();

        expanded_attributes.attribute_keys.extend(custom_to_add);
    }

    LdapSearchResultEntry {
        dn: {
            let internal_ou = get_user_ou(&user);
            let rdn_chain = internal_ou_to_ldap_rdn_chain(&internal_ou);
            let ou_part = rdn_chain
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join(",");
            format!("uid={},{}", user.user_id.as_str(), ou_part + "," + base_dn_str)
        },
        attributes: {
            let mut attrs: Vec<LdapPartialAttribute> = expanded_attributes
                .attribute_keys
                .into_iter()
                .filter(|(attribute, _)| !is_operational_attribute(attribute.as_str()))
                .filter_map(|(attribute, name)| {
                    let values = get_user_attribute(
                        &user,
                        &attribute,
                        base_dn_str,
                        groups,
                        ignored_user_attributes,
                        schema,
                    )?;
                    Some(LdapPartialAttribute {
                        atype: name,
                        vals: values,
                    })
                })
                .collect();

            inject_operational_attributes(&mut attrs, "inetOrgPerson", base_dn_str);

            let mut seen = std::collections::HashSet::new();
            attrs.retain(|attr| seen.insert(attr.atype.clone()));

            attrs
        },
    }
}

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

fn convert_user_filter(
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
            match SchemaManager::map_user_field(&field, schema) {
                UserFieldType::PrimaryField(UserColumn::UserId) => {
                    Ok(UserRequestFilter::UserId(UserId::new(&value_lc)))
                }
                UserFieldType::PrimaryField(UserColumn::Email) => Ok(UserRequestFilter::Equality(
                    UserColumn::LowercaseEmail,
                    value_lc,
                )),
                UserFieldType::PrimaryField(field) => {
                    Ok(UserRequestFilter::Equality(field, value_lc))
                }
                UserFieldType::Attribute(field, typ, is_list) => Ok(
                    get_user_attribute_equality_filter(&field, typ, is_list, value),
                ),
                UserFieldType::NoMatch => {
                    if !ldap_info.ignored_user_attributes.contains(&field) {
                        warn!(
                            r#"Ignoring unknown user attribute "{}" in filter.\n\
                                      To disable this warning, add it to "ignored_user_attributes" in the config"#,
                            field
                        );
                    }
                    Ok(UserRequestFilter::False)
                }
                UserFieldType::ObjectClass => Ok(UserRequestFilter::And(vec![])),
                UserFieldType::MemberOf => Ok(get_group_id_from_distinguished_name_or_plain_name(
                    &value_lc,
                    &ldap_info.base_dn,
                    &ldap_info.base_dn_str,
                )
                .map(UserRequestFilter::MemberOf)
                .unwrap_or_else(|e| {
                    warn!("Invalid memberOf filter: {}", e);
                    UserRequestFilter::False
                })),
                UserFieldType::EntryDn | UserFieldType::Dn => {
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
            }
        }
        LdapFilter::GreaterOrEqual(field, value) => {
            let field = AttributeName::from(field.as_str());
            match SchemaManager::map_user_field(&field, schema) {
                UserFieldType::PrimaryField(f)
                    if matches!(f, UserColumn::CreationDate | UserColumn::ModifiedDate | UserColumn::PasswordModifiedDate) =>
                {
                    Ok(UserRequestFilter::GreaterOrEqual(f, value.to_string()))
                }
                UserFieldType::Attribute(name, typ, _)
                    if typ == AttributeType::DateTime =>
                {
                    Ok(UserRequestFilter::AttributeGreaterOrEqual(name, value.to_string()))
                }
                _ => Err(LdapError {
                    code: LdapResultCode::UnwillingToPerform,
                    message: format!("GreaterOrEqual not supported on this attribute: {}", field),
                }),
            }
        }
        LdapFilter::LessOrEqual(field, value) => {
            let field = AttributeName::from(field.as_str());
            match SchemaManager::map_user_field(&field, schema) {
                UserFieldType::PrimaryField(f)
                    if matches!(f, UserColumn::CreationDate | UserColumn::ModifiedDate | UserColumn::PasswordModifiedDate) =>
                {
                    Ok(UserRequestFilter::LessOrEqual(f, value.to_string()))
                }
                UserFieldType::Attribute(name, typ, _)
                    if typ == AttributeType::DateTime =>
                {
                    Ok(UserRequestFilter::AttributeLessOrEqual(name, value.to_string()))
                }
                _ => Err(LdapError {
                    code: LdapResultCode::UnwillingToPerform,
                    message: format!("LessOrEqual not supported on this attribute: {}", field),
                }),
            }
        }
        LdapFilter::Present(field) => {
            let field = AttributeName::from(field.as_str());
            Ok(match SchemaManager::map_user_field(&field, schema) {
                UserFieldType::Attribute(name, _, _) => {
                    UserRequestFilter::CustomAttributePresent(name)
                }
                UserFieldType::NoMatch => UserRequestFilter::False,
                _ => UserRequestFilter::True,
            })
        }
        LdapFilter::Substring(field, substring_filter) => {
            let field = AttributeName::from(field.as_str());
            match SchemaManager::map_user_field(&field, schema) {
                UserFieldType::PrimaryField(UserColumn::UserId) => Ok(
                    UserRequestFilter::UserIdSubString(substring_filter.clone().into()),
                ),
                UserFieldType::Attribute(_, _, _)
                | UserFieldType::ObjectClass
                | UserFieldType::MemberOf
                | UserFieldType::Dn
                | UserFieldType::EntryDn
                | UserFieldType::PrimaryField(UserColumn::CreationDate)
                | UserFieldType::PrimaryField(UserColumn::Uuid) => Err(LdapError {
                    code: LdapResultCode::UnwillingToPerform,
                    message: format!("Unsupported user attribute for substring filter: {field:?}"),
                }),
                UserFieldType::NoMatch => Ok(UserRequestFilter::False),
                UserFieldType::PrimaryField(UserColumn::Email) => Ok(UserRequestFilter::SubString(
                    UserColumn::LowercaseEmail,
                    substring_filter.clone().into(),
                )),
                UserFieldType::PrimaryField(field) => Ok(UserRequestFilter::SubString(
                    field,
                    substring_filter.clone().into(),
                )),
            }
        }
        _ => Err(LdapError {
            code: LdapResultCode::UnwillingToPerform,
            message: format!("Unsupported user filter: {filter:?}"),
        }),
    }
}

#[instrument(skip_all, level = "debug", fields(ldap_filter, request_groups))]
pub(crate) async fn get_user_list<Backend: UserListerBackendHandler>(
    ldap_info: &LdapInfo,
    ldap_filter: &LdapFilter,
    request_groups: bool,
    base: &str,
    backend: &Backend,
    schema: &PublicSchema,
) -> LdapResult<Vec<UserAndGroups>> {
    let filters = convert_user_filter(ldap_info, ldap_filter, schema)?;
    debug!(?filters);
    backend
        .list_users(Some(filters), request_groups)
        .await
        .map_err(|e| LdapError {
            code: LdapResultCode::Other,
            message: format!(r#"Error while searching user "{base}": {e:#}"#),
        })
}

// convert_users_to_ldap_op moved to search/results.rs (single source of truth)

pub(crate) fn get_user_ou(user: &User) -> String {
    get_ou_from_attributes(&user.attributes, DEFAULT_PRIMARY_USER_OU)
}
