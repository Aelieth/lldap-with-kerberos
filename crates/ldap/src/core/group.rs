use crate::{
    attributes::get_default_group_object_classes_bytes,
    core::{
        error::{LdapError, LdapResult},
        utils::{get_custom_attribute, get_ou_from_attributes, inject_operational_attributes, internal_ou_to_ldap_rdn_chain, is_operational_attribute, to_generalized_time, DEFAULT_PRIMARY_GROUP_OU, LdapInfo, GroupFieldType, ExpandedAttributes},
    },
    dn::{get_group_id_from_distinguished_name_or_plain_name, get_user_id_from_distinguished_name_or_plain_name},
    schema::{get_schema_manager, SchemaManager},
};
use ldap3_proto::{
    LdapFilter, LdapPartialAttribute, LdapResultCode, LdapSearchResultEntry, proto::LdapOp,
};
use lldap_domain::{
    deserialize::deserialize_attribute_value,
    public_schema::PublicSchema,
    types::{AttributeName, AttributeType, Group, GroupId, UserId, Uuid},
};
use lldap_domain_handlers::handler::{GroupListerBackendHandler, GroupRequestFilter};
use tracing::{debug, instrument, warn};

pub fn get_default_group_object_classes() -> Vec<lldap_domain::types::LdapObjectClass> {
    crate::core::utils::get_default_group_object_classes()
}

pub fn get_group_attribute(
    group: &Group,
    base_dn_str: &str,
    attribute: &AttributeName,
    user_filter: &Option<UserId>,
    ignored_group_attributes: &[AttributeName],
    schema: &PublicSchema,
) -> Option<Vec<Vec<u8>>> {
    let attribute_values = match SchemaManager::map_group_field(attribute, schema) {
        GroupFieldType::ObjectClass => get_default_group_object_classes_bytes(schema),
        GroupFieldType::Dn => return None,
        GroupFieldType::EntryDn => {
            let internal_ou = get_group_ou(group);
            let rdn_chain = internal_ou_to_ldap_rdn_chain(&internal_ou);
            let ou_part = rdn_chain
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join(",");
            vec![format!("cn={},{}", group.display_name, ou_part + "," + base_dn_str).into_bytes()]
        }
        GroupFieldType::GroupId => {
            vec![group.id.0.to_string().into_bytes()]
        }
        GroupFieldType::DisplayName => vec![group.display_name.to_string().into_bytes()],
        GroupFieldType::CreationDate => vec![to_generalized_time(&group.creation_date)],
        GroupFieldType::ModifiedDate => vec![to_generalized_time(&group.modified_date)],
        GroupFieldType::Member => {
            let members: std::collections::BTreeSet<_> = group
                .users
                .iter()
                .filter(|u| user_filter.as_ref().map(|f| u.user_id == *f).unwrap_or(true))
                .map(|u| {
                    let rdn_chain = internal_ou_to_ldap_rdn_chain(&u.ou);
                    let ou_part = rdn_chain
                        .iter()
                        .map(|(k, v)| format!("{}={}", k, v))
                        .collect::<Vec<_>>()
                        .join(",");
                    format!("uid={},{}", u.user_id, ou_part + "," + base_dn_str)
                })
                .collect();

            members.into_iter().map(|s| s.into_bytes()).collect()
        }
        GroupFieldType::Uuid => vec![group.uuid.to_string().into_bytes()],
        GroupFieldType::Attribute(attr, _, _) => {
            let values = get_custom_attribute(&group.attributes, &attr)?;
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
        GroupFieldType::NoMatch => match attribute.as_str() {
            "1.1" => return None,
            "+" => return None,
            "*" => {
                panic!(
                    "Matched {attribute}, * should have been expanded into attribute list and * removed"
                )
            }
            _ => {
                if ignored_group_attributes.contains(attribute) {
                    return None;
                }
                let is_unknown = SchemaManager::resolve_attribute(attribute.as_str()).is_none();
                get_custom_attribute(
                    &group.attributes,
                    attribute,
                ).or_else(|| {
                    if is_unknown {
                        warn!(
                            r#"Ignoring unrecognized group attribute: {}. To disable this warning, add it to "ignored_group_attributes" in the config."#,
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

pub fn make_ldap_search_group_result_entry(
    group: Group,
    base_dn_str: &str,
    mut expanded_attributes: ExpandedAttributes,
    user_filter: &Option<UserId>,
    ignored_group_attributes: &[AttributeName],
    schema: &PublicSchema,
) -> LdapSearchResultEntry {
    if expanded_attributes.include_custom_attributes {
        let standardized: std::collections::HashSet<String> = schema
            .group_attributes()
            .attributes
            .iter()
            .flat_map(|a| {
                let mut names = vec![a.name.to_string()];
                names.extend(a.aliases.iter().map(|al| al.to_string()));
                names
            })
            .collect();

        let custom_to_add: Vec<_> = group
        .attributes
        .iter()
        .filter(|a| !standardized.contains(a.name.as_str()))
        .map(|a| (a.name.clone(), a.name.to_string()))
        .collect();

        expanded_attributes.attribute_keys.extend(custom_to_add);
    }

    LdapSearchResultEntry {
        dn: {
            let internal_ou = get_group_ou(&group);
            let rdn_chain = internal_ou_to_ldap_rdn_chain(&internal_ou);
            let ou_part = rdn_chain
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join(",");
            format!("cn={},{}", group.display_name, ou_part + "," + base_dn_str)
        },
        attributes: {
            let mut attrs: Vec<LdapPartialAttribute> = expanded_attributes
                .attribute_keys
                .into_iter()
                .filter(|(attribute, _)| !is_operational_attribute(attribute.as_str()))
                .filter_map(|(attribute, name)| {
                    let values = get_group_attribute(
                        &group,
                        base_dn_str,
                        &attribute,
                        user_filter,
                        ignored_group_attributes,
                        schema,
                    )?;
                    Some(LdapPartialAttribute {
                        atype: name,
                        vals: values,
                    })
                })
                .collect();

            inject_operational_attributes(&mut attrs, "groupOfUniqueNames", base_dn_str);

            let mut seen = std::collections::HashSet::new();
            attrs.retain(|attr| seen.insert(attr.atype.clone()));

            attrs
        },
    }
}

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

fn convert_group_filter(
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
            match SchemaManager::map_group_field(&field, schema) {
                GroupFieldType::GroupId => Ok(value_lc
                    .parse::<i32>()
                    .map(|id| GroupRequestFilter::GroupId(GroupId(id)))
                    .unwrap_or_else(|_| {
                        warn!("Given group id is not a valid integer: {}", value_lc);
                        GroupRequestFilter::False
                    })),
                GroupFieldType::DisplayName => Ok(GroupRequestFilter::DisplayName(value_lc.into())),
                GroupFieldType::Uuid => Uuid::try_from(value_lc.as_str())
                    .map(GroupRequestFilter::Uuid)
                    .map_err(|e| LdapError {
                        code: LdapResultCode::Other,
                        message: format!("Invalid UUID: {e:#}"),
                    }),
                GroupFieldType::Member => Ok(get_user_id_from_distinguished_name_or_plain_name(
                    &value_lc,
                    &ldap_info.base_dn,
                    &ldap_info.base_dn_str,
                )
                .map(GroupRequestFilter::Member)
                .unwrap_or_else(|e| {
                    warn!("Invalid member filter on group: {}", e);
                    GroupRequestFilter::False
                })),
                GroupFieldType::ObjectClass => Ok(GroupRequestFilter::And(vec![])),
                GroupFieldType::Dn | GroupFieldType::EntryDn => {
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
                GroupFieldType::NoMatch => {
                    if !ldap_info.ignored_group_attributes.contains(&field) {
                        warn!(
                            r#"Ignoring unknown group attribute "{}" in filter.\n\
                                To disable this warning, add it to "ignored_group_attributes" in the config."#,
                            field
                        );
                    }
                    Ok(GroupRequestFilter::False)
                }
                GroupFieldType::Attribute(field, typ, is_list) => Ok(
                    get_group_attribute_equality_filter(&field, typ, is_list, value),
                ),
                GroupFieldType::CreationDate => Err(LdapError {
                    code: LdapResultCode::UnwillingToPerform,
                    message: "Creation date filter for groups not supported".to_owned(),
                }),
                GroupFieldType::ModifiedDate => Err(LdapError {
                    code: LdapResultCode::UnwillingToPerform,
                    message: "Modified date filter for groups not supported".to_owned(),
                }),
            }
        }
        LdapFilter::GreaterOrEqual(field, value) => {
            let field = AttributeName::from(field.as_str());
            match SchemaManager::map_group_field(&field, schema) {
                GroupFieldType::CreationDate | GroupFieldType::ModifiedDate => {
                    Ok(GroupRequestFilter::GreaterOrEqual(
                        field.as_str().to_string(),
                        value.to_string(),
                    ))
                }
                GroupFieldType::Attribute(name, typ, _)
                    if typ == AttributeType::DateTime =>
                {
                    Ok(GroupRequestFilter::AttributeGreaterOrEqual(
                        name,
                        value.to_string(),
                    ))
                }
                _ => Err(LdapError {
                    code: LdapResultCode::UnwillingToPerform,
                    message: format!("GreaterOrEqual not supported on this attribute: {}", field),
                }),
            }
        }
        LdapFilter::LessOrEqual(field, value) => {
            let field = AttributeName::from(field.as_str());
            match SchemaManager::map_group_field(&field, schema) {
                GroupFieldType::CreationDate | GroupFieldType::ModifiedDate => {
                    Ok(GroupRequestFilter::LessOrEqual(
                        field.as_str().to_string(),
                        value.to_string(),
                    ))
                }
                GroupFieldType::Attribute(name, typ, _)
                    if typ == AttributeType::DateTime =>
                {
                    Ok(GroupRequestFilter::AttributeLessOrEqual(
                        name,
                        value.to_string(),
                    ))
                }
                _ => Err(LdapError {
                    code: LdapResultCode::UnwillingToPerform,
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
            Ok(match SchemaManager::map_group_field(&field, schema) {
                GroupFieldType::Attribute(name, _, _) => {
                    GroupRequestFilter::CustomAttributePresent(name)
                }
                GroupFieldType::NoMatch => GroupRequestFilter::False,
                _ => GroupRequestFilter::True,
            })
        }
        LdapFilter::Substring(field, substring_filter) => {
            let field = AttributeName::from(field.as_str());
            match SchemaManager::map_group_field(&field, schema) {
                GroupFieldType::DisplayName => Ok(GroupRequestFilter::DisplayNameSubString(
                    substring_filter.clone().into(),
                )),
                GroupFieldType::NoMatch => Ok(GroupRequestFilter::False),
                _ => Err(LdapError {
                    code: LdapResultCode::UnwillingToPerform,
                    message: format!(
                        "Unsupported group attribute for substring filter: \"{field}\""
                    ),
                }),
            }
        }
        _ => Err(LdapError {
            code: LdapResultCode::UnwillingToPerform,
            message: format!("Unsupported group filter: {filter:?}"),
        }),
    }
}

#[instrument(skip_all, level = "debug", fields(ldap_filter))]
pub(crate) async fn get_groups_list<Backend: GroupListerBackendHandler>(
    ldap_info: &LdapInfo,
    ldap_filter: &LdapFilter,
    base: &str,
    backend: &Backend,
    schema: &PublicSchema,
) -> LdapResult<Vec<Group>> {
    let filters = convert_group_filter(ldap_info, ldap_filter, schema)?;
    debug!(?filters);
    backend
        .list_groups(Some(filters))
        .await
        .map_err(|e| LdapError {
            code: LdapResultCode::Other,
            message: format!(r#"Error while listing groups "{base}": {e:#}"#),
        })
}

pub(crate) fn convert_groups_to_ldap_op<'a>(
    groups: Vec<Group>,
    attributes: &'a [String],
    ldap_info: &'a LdapInfo,
    user_filter: &'a Option<UserId>,
    schema: &'a PublicSchema,
) -> impl Iterator<Item = LdapOp> + 'a {
    let expanded_attributes = if groups.is_empty() {
        None
    } else {
        Some(get_schema_manager().expand_attribute_wildcards(attributes, schema))
    };

    groups.into_iter().map(move |g| {
        LdapOp::SearchResultEntry(make_ldap_search_group_result_entry(
            g,
            &ldap_info.base_dn_str,
            expanded_attributes.clone().unwrap(),
            user_filter,
            &ldap_info.ignored_group_attributes,
            schema,
        ))
    })
}

fn get_group_ou(group: &Group) -> String {
    get_ou_from_attributes(&group.attributes, DEFAULT_PRIMARY_GROUP_OU)
}
