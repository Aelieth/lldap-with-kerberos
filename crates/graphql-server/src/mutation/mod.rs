pub mod helpers;
pub mod inputs;

// Re-export public types
pub use inputs::{
    AttributeValue, CreateGroupInput, CreateUserInput, Success, UpdateGroupInput, UpdateUserInput,
};

use tracing::{Instrument, info, debug, debug_span, warn};
use crate::api::{Context, field_error_callback, FullHandler};
use anyhow::anyhow;
use juniper::{FieldError, FieldResult, graphql_object, graphql_value};
use lldap_access_control::{
    AdminBackendHandler, UserReadableBackendHandler, UserWriteableBackendHandler,
};
use lldap_domain::{
    requests::{CreateAttributeRequest, CreateUserRequest, UpdateGroupRequest, UpdateUserRequest},
    types::{AttributeName, Email, GroupId, LdapObjectClass, UserId},
    schema::AttributeType,
};
use lldap_domain_handlers::handler::{BackendHandler, ReadSchemaBackendHandler};
use lldap_validation::attributes::{ALLOWED_CHARACTERS_DESCRIPTION, validate_attribute_name};
use std::sync::Arc;
use lldap_opaque_handler::OpaqueHandler;
use lldap_kerberos::{decrypt_password, delete_kerberos_principal, sync_kerberos_principal,
};
use helpers::{
    UnpackedAttributes, consolidate_attributes, create_group_with_details, deserialize_attribute,
    unpack_attributes,
};
use lldap_schema::PublicSchema;

#[derive(juniper::GraphQLObject)]
struct ExportKeytabForKeycloakResponse {
    ok: bool,
    path: String,
    error_msg: String,
}

#[derive(juniper::GraphQLInputObject)]
struct TestKeycloakConnectionInput {
    url: String,
    realm: String,
    admin_user: String,
    admin_pass: String,
}

#[derive(juniper::GraphQLObject)]
struct TestKeycloakConnectionResponse {
    ok: bool,
    message: String,
}

#[derive(juniper::GraphQLInputObject)]
struct SaveKeycloakConfigInput {
    url: String,
    realm: String,
    admin_user: String,
}

#[derive(juniper::GraphQLObject)]
struct SaveKeycloakConfigResponse {
    ok: bool,
    message: String,
}

#[derive(juniper::GraphQLObject)]
struct PushRealmResponse {
    ok: bool,
    message: String,
}

#[derive(juniper::GraphQLInputObject, Debug)]
struct PosixSettingsInput {
    // === Users ===
    pub user_uidnumber_assign: bool,
    pub user_uidnumber_start: i32,
    pub user_uidnumber_max: i32,

    pub user_gidnumber_assign: bool,
    pub user_gidnumber_start: i32,

    pub user_loginshell_assign: bool,
    pub user_loginshell_default: String,

    pub user_homedirectory_assign: bool,
    pub user_homedirectory_prefix: String,

    // === Groups ===
    pub group_gidnumber_assign: bool,
    pub group_gidnumber_start: i32,
    pub group_gidnumber_max: i32,
}

#[derive(juniper::GraphQLObject)]
struct PosixSettingsResponse {
    success: bool,
    message: String,
}

#[derive(PartialEq, Eq, Debug)]
/// The top-level GraphQL mutation type.
pub struct Mutation<Handler: BackendHandler + OpaqueHandler> {
    _phantom: std::marker::PhantomData<Box<Handler>>,
}

impl<Handler: BackendHandler + OpaqueHandler> Default for Mutation<Handler> {
    fn default() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

fn extract_kerberos_sync(schema: &PublicSchema, attrs: &[lldap_domain::types::Attribute]) -> bool {
    let kerb_name = schema
    .user_attributes()
    .get_by_name_or_alias("kerberossync")
    .map(|a| a.name.as_str())
    .unwrap_or("kerberossync");

    attrs.iter()
    .find(|a| a.name.as_str() == kerb_name)
    .and_then(|a| match &a.value {
        lldap_domain::types::AttributeValue::Integer(
            lldap_domain::types::Cardinality::Singleton(i),
        ) if *i == 1 => Some(true),
              lldap_domain::types::AttributeValue::String(
                  lldap_domain::types::Cardinality::Singleton(s),
              ) if s == "1" || s.to_lowercase() == "true" => Some(true),
              _ => None,
    })
    .unwrap_or(false)
}

#[graphql_object(context = Context<Handler>)]
impl<Handler: FullHandler + OpaqueHandler> Mutation<Handler> {
    async fn create_user(
        context: &Context<Handler>,
        user: CreateUserInput,
    ) -> FieldResult<super::query::User<Handler>> {
        let span = debug_span!("[GraphQL mutation] create_user");
        span.in_scope(|| debug!("{:?}", &user.id));

        let user_id = UserId::new(&user.id);
        let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(&span, "Unauthorized user creation"))?;

        let schema = handler.get_schema().await?;

        let consolidated_attributes = consolidate_attributes(
            user.attributes.unwrap_or_default(),
                                                             user.first_name,
                                                             user.last_name,
                                                             user.avatar,
        );

        let ou_value = consolidated_attributes
        .iter()
        .find(|a| a.name == "ou")
        .and_then(|a| a.value.first().cloned())
        .unwrap_or_else(|| "people".to_string());

        let attributes_for_unpack: Vec<_> = consolidated_attributes
        .into_iter()
        .filter(|a| a.name != "ou")
        .collect();

        let UnpackedAttributes {
            email,
            display_name,
            attributes: unpacked_attributes,
        } = unpack_attributes(attributes_for_unpack, &schema, true)?;

        // Add the OU back as a proper typed attribute (backend is allowed to set readonly fields on create)
        let mut attributes = unpacked_attributes;
        attributes.push(lldap_domain::types::Attribute {
            name: lldap_domain::types::AttributeName::from("ou"),
                        value: lldap_domain::types::AttributeValue::String(
                            lldap_domain::types::Cardinality::Singleton(ou_value),
                        ),
        });

        handler
        .create_user(CreateUserRequest {
            user_id: user_id.clone(),
                     email: user.email.map(Email::from).or(email).ok_or_else(|| anyhow!("Email is required when creating a new user"))?,
                     display_name: user.display_name.or(display_name),
                     attributes,
        })
        .instrument(span.clone())
        .await?;

        let user_details = handler.get_user_details(&user_id).instrument(span).await?;
        super::query::User::<Handler>::from_user(user_details, Arc::new(schema))
    }

    async fn set_user_password(
        context: &Context<Handler>,
        user_id: String,
        password: String,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] set_user_password");
        span.in_scope(|| debug!("Setting password for user: {}", &user_id));

        let target_user_id = UserId::new(&user_id);

        let handler = context.get_writeable_handler(target_user_id.clone())
        .ok_or_else(field_error_callback(&span, "Unauthorized password set"))?;

        // OPAQUE registration
        use lldap_auth::{opaque, registration};
        use anyhow::Context as AnyhowContext;
        use rand::rngs::OsRng;
        let mut rng = OsRng;
        let registration_start_request = opaque::client::registration::start_registration(password.as_bytes(), &mut rng)
        .context("Could not initiate password registration")?;
        let req = registration::ClientRegistrationStartRequest {
            username: target_user_id.clone(),
            registration_start_request: registration_start_request.message,
        };
        let start_response = handler.registration_start(req).await
        .context("Registration start failed")?;
        let registration_finish = opaque::client::registration::finish_registration(
            registration_start_request.state,
            start_response.registration_response,
            &mut rng,
        )
        .context("Error during password registration finish")?;
        let req = registration::ClientRegistrationFinishRequest {
            server_data: start_response.server_data,
            registration_upload: registration_finish.message,
        };
        handler.registration_finish(req).await
        .context("Registration finish failed")?;

        // Fetch for sync check
        let user = handler.get_user_details(&target_user_id).await
        .context("Failed to fetch user for Kerberos sync check")?;
        let schema = handler.get_schema().await?;
        let sync_enabled = extract_kerberos_sync(&schema, &user.attributes);

        // Real Kerberos sync
        if let Err(e) = lldap_kerberos::sync_kerberos_if_enabled(sync_enabled, &user_id, &password) {
            warn!("Kerberos sync failed after password set: {}", e);
        } else if sync_enabled {
            info!("Kerberos principal synced for user {} (password change)", user_id);
        }

        let inner = UserWriteableBackendHandler::unsafe_get_handler(handler);
        let _ = inner.ensure_kerberos_principal_consistency(&target_user_id, sync_enabled).await;

        Ok(Success::new())
    }

    async fn create_group(
        context: &Context<Handler>,
        group: CreateGroupInput,
    ) -> FieldResult<super::query::Group<Handler>> {
        let span = debug_span!("[GraphQL mutation] create_group");
        span.in_scope(|| {
            debug!(?group);
        });
        create_group_with_details(context, group, span).await
    }

    async fn create_group_with_details(
        context: &Context<Handler>,
        request: CreateGroupInput,
    ) -> FieldResult<super::query::Group<Handler>> {
        let span = debug_span!("[GraphQL mutation] create_group_with_details");
        span.in_scope(|| {
            debug!(?request);
        });
        create_group_with_details(context, request, span).await
    }

    async fn update_user(
        context: &Context<Handler>,
        user: UpdateUserInput,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] update_user");
        span.in_scope(|| debug!(?user.id));

        let user_id = UserId::new(&user.id);
        let handler = context
            .get_writeable_handler(user_id.clone())
            .ok_or_else(field_error_callback(&span, "Unauthorized user update"))?;

        let is_admin = context.validation_result.is_admin();
        let schema = handler.get_schema().await?;

        let consolidated_attributes = consolidate_attributes(
            user.insert_attributes.unwrap_or_default(),
            user.first_name,
            user.last_name,
            user.avatar,
        );

        let mut delete_attributes: Vec<String> = user.remove_attributes.unwrap_or_default();

        // === PROTECT ou from direct editing (controlled by global list) ===
        delete_attributes.retain(|attr| attr != "ou");

        let UnpackedAttributes {
            email,
            display_name,
            attributes: insert_attributes,
        } = unpack_attributes(
            consolidated_attributes
                .into_iter()
                .filter(|a| !delete_attributes.contains(&a.name))
                .collect(),
            &schema,
            is_admin,
        )?;

        handler
            .update_user(UpdateUserRequest {
                user_id: user_id.clone(),
                email: user.email.map(Into::into).or(email),
                display_name: user.display_name.or(display_name),
                delete_attributes: delete_attributes
                    .clone()
                    .into_iter()
                    .filter(|attr| attr != "mail" && attr.to_lowercase() != "displayname")
                    .map(|s| AttributeName::from(s))
                    .collect(),
                insert_attributes: insert_attributes.clone(),
            })
            .instrument(span.clone())
            .await?;

        Ok(Success::new())
    }

    async fn update_group(
        context: &Context<Handler>,
        group: UpdateGroupInput,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] update_group");
        span.in_scope(|| {
            debug!(?group.id);
        });
        let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(&span, "Unauthorized group update"))?;
        let new_display_name = group.display_name.clone().or_else(|| {
            group.insert_attributes.as_ref().and_then(|a| {
                a.iter()
                .find(|attr| attr.name == "displayname")
                .map(|attr| attr.value[0].clone())
            })
        });
        if group.id == 1 && new_display_name.is_some() {
            span.in_scope(|| debug!("Cannot change lldap_admin group name"));
            return Err("Cannot change lldap_admin group name".into());
        }

        let schema = handler.get_schema().await?;
        let insert_attributes = group
        .insert_attributes
        .unwrap_or_default()
        .into_iter()
        .filter(|attr| attr.name != "displayname")
        .map(|attr| deserialize_attribute(schema.group_attributes(), attr, true))
        .collect::<Result<Vec<_>, _>>()?;

        handler
        .update_group(UpdateGroupRequest {
            group_id: GroupId(group.id),
                      display_name: new_display_name.map(|s| s.as_str().into()),
                      delete_attributes: group
                      .remove_attributes
                      .unwrap_or_default()
                      .into_iter()
                      .filter(|attr| attr != "displayname")
                      .map(|s| AttributeName::from(s))
                      .collect(),
                      insert_attributes,
        })
        .instrument(span)
        .await?;
        Ok(Success::new())
    }

    async fn add_user_to_group(
        context: &Context<Handler>,
        user_id: String,
        group_id: i32,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] add_user_to_group");
        span.in_scope(|| {
            debug!(?user_id, ?group_id);
        });
        let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(
            &span,
            "Unauthorized group membership modification",
        ))?;
        handler
        .add_user_to_group(&UserId::new(&user_id), GroupId(group_id))
        .instrument(span)
        .await?;
        Ok(Success::new())
    }

    async fn remove_user_from_group(
        context: &Context<Handler>,
        user_id: String,
        group_id: i32,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] remove_user_from_group");
        span.in_scope(|| {
            debug!(?user_id, ?group_id);
        });
        let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(
            &span,
            "Unauthorized group membership modification",
        ))?;
        let user_id = UserId::new(&user_id);
        if context.validation_result.user == user_id && group_id == 1 {
            span.in_scope(|| debug!("Cannot remove admin rights for current user"));
            return Err("Cannot remove admin rights for current user".into());
        }
        handler
        .remove_user_from_group(&user_id, GroupId(group_id))
        .instrument(span)
        .await?;
        Ok(Success::new())
    }

    async fn delete_user(
        context: &Context<Handler>,
        user_id: String,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] delete_user");
        span.in_scope(|| {
            debug!(?user_id);
        });
        let user_id_typed = UserId::new(&user_id);
        let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(&span, "Unauthorized user deletion"))?;

        if context.validation_result.user == user_id_typed {
            span.in_scope(|| debug!("Cannot delete current user"));
            return Err("Cannot delete current user".into());
        }

        // Delete from LLDAP
        handler
        .delete_user(&user_id_typed)
        .instrument(span.clone())
        .await
        .map_err(|e| FieldError::new(
            "User deletion failed",
            graphql_value!({ "details": (e.to_string()) })
        ))?;

        if let Err(e) = delete_kerberos_principal(&user_id) {
            warn!("Failed to delete Kerberos principal for user {}: {}", user_id, e);
        } else {
            info!("Deleted Kerberos principal for user {}", user_id);
        }

        // Kerberos consistency cleanup is allowed to do nothing if the user row is already gone
        // (this is normal during bulk delete where the same user may already be removed by a previous call)
        let inner = AdminBackendHandler::unsafe_get_handler(handler);
        if let Err(e) = inner.ensure_kerberos_principal_consistency(&user_id_typed, false).await {
            if e.to_string().contains("None of the records are updated") {
                debug!("User already deleted — Kerberos consistency cleanup skipped for {}", user_id);
            } else {
                warn!("Kerberos principal consistency cleanup failed for {}: {}", user_id, e);
            }
        }

        Ok(Success::new())
    }

    async fn delete_group(context: &Context<Handler>, group_id: i32) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] delete_group");
        span.in_scope(|| {
            debug!(?group_id);
        });
        let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(&span, "Unauthorized group deletion"))?;
        if group_id == 1 {
            span.in_scope(|| debug!("Cannot delete admin group"));
            return Err("Cannot delete admin group".into());
        }
        handler
        .delete_group(GroupId(group_id))
        .instrument(span)
        .await?;
        Ok(Success::new())
    }

    async fn create_ou(
        context: &Context<Handler>,
        name: String,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] create_ou");
        span.in_scope(|| debug!(?name));

        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(&span, "Unauthorized OU creation"))?;

        let name_lower = name.trim().to_lowercase();
        if name_lower.is_empty() || name_lower == "all" || name_lower == "people" || name_lower == "groups" {
            return Err("Invalid OU name (cannot be empty or built-in)".into());
        }

        let parts: Vec<&str> = name.splitn(2, '\\').collect();
        let (primary, secondary) = match parts.len() {
            1 => (name.as_str(), None),
            2 => (parts[0], Some(parts[1])),
            _ => return Err(FieldError::new(
                "Invalid OU format: only one level of secondary OU allowed (primary\\secondary)",
                juniper::Value::null(),
            )),
        };

        if primary.len() < 2 || primary.len() > 64 ||
           !primary.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') ||
           primary.starts_with('-') || primary.starts_with('_') ||
           primary.ends_with('-') || primary.ends_with('_') {
            return Err(FieldError::new(
                "Invalid primary OU name: 2-64 characters, only a-z A-Z 0-9 - _ allowed. No spaces or special characters.",
                juniper::Value::null(),
            ));
        }
        if let Some(sec) = secondary {
            if sec.trim().is_empty() ||
               sec.len() < 2 || sec.len() > 64 ||
               !sec.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') ||
               sec.starts_with('-') || sec.starts_with('_') ||
               sec.ends_with('-') || sec.ends_with('_') {
                return Err(FieldError::new(
                    "Invalid secondary OU name: 2-64 characters, only a-z A-Z 0-9 - _ allowed. No spaces or special characters.",
                    juniper::Value::null(),
                ));
            }
        }

        let inner = AdminBackendHandler::unsafe_get_handler(handler);
        let mut current_ous = inner.get_allowed_ous().await
            .map_err(|_e| FieldError::new("Failed to load allowedous", juniper::Value::null()))?;

        let name_lower = name.to_lowercase();
        if current_ous.iter().any(|existing| existing.to_lowercase() == name_lower) {
            return Err(FieldError::new(
                format!("Organizational Unit '{}' already exists", name),
                juniper::Value::null(),
            ));
        }

        if secondary.is_some() && !current_ous.iter().any(|p| p.to_lowercase() == primary.to_lowercase()) {
            return Err(FieldError::new(
                format!("Primary OU '{}' does not exist. Create it first before adding a secondary.", primary),
                juniper::Value::null(),
            ));
        }

        current_ous.push(name.clone());
        current_ous.sort();

        inner.set_system_config("allowedous", serde_json::to_string(&current_ous).unwrap())
            .await
            .map_err(|_e| FieldError::new("Failed to save updated OU list", juniper::Value::null()))?;

        Ok(Success::new())
    }

    async fn delete_ou(
        context: &Context<Handler>,
        name: String,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] delete_ou");
        span.in_scope(|| debug!(?name));

        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(&span, "Unauthorized OU deletion"))?;

        let name_lower = name.trim().to_lowercase();
        if name_lower == "people" || name_lower == "groups" || name_lower == "all" {
            return Err("Cannot delete built-in OU 'people', 'groups', or 'All'".into());
        }

        let inner = AdminBackendHandler::unsafe_get_handler(handler);
        let mut current_ous = inner.get_allowed_ous().await
            .map_err(|_e| FieldError::new("Failed to load allowedous", juniper::Value::null()))?;

        let has_children = current_ous.iter().any(|ou| {
            let parts: Vec<&str> = ou.splitn(2, '\\').collect();
            parts.len() == 2 && parts[0].to_lowercase() == name_lower
        });

        if has_children {
            return Err(FieldError::new(
                format!("Cannot delete primary OU '{}' because it still contains secondary OUs. Delete the secondary OUs first.", name),
                juniper::Value::null(),
            ));
        }

        current_ous.retain(|o| o.to_lowercase() != name_lower);

        inner.set_system_config("allowedous", serde_json::to_string(&current_ous).unwrap())
            .await
            .map_err(|_e| FieldError::new("Failed to save updated OU list", juniper::Value::null()))?;

        info!("Organizational Unit '{}' deleted from system_config.", name);
        Ok(Success::new())
    }

    async fn change_user_ou(
        context: &Context<Handler>,
        user_ids: Vec<String>,
        new_ou: String,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] change_user_ou");
        span.in_scope(|| debug!(?user_ids, ?new_ou));

        let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(&span, "Unauthorized OU change"))?;

        let name_lower = new_ou.trim().to_lowercase();
        if name_lower == "all" {
            return Err("Cannot move users to built-in OU 'All'".into());
        }

        for user_id_str in user_ids {
            let user_id = lldap_domain::types::UserId::new(&user_id_str);

            let insert_attributes = vec![lldap_domain::types::Attribute {
                name: lldap_domain::types::AttributeName::from("ou"),
                value: lldap_domain::types::AttributeValue::String(
                    lldap_domain::types::Cardinality::Singleton(new_ou.clone()),
                ),
            }];

            let update_req = lldap_domain::requests::UpdateUserRequest {
                user_id: user_id.clone(),
                email: None,
                display_name: None,
                delete_attributes: vec![],
                insert_attributes,
            };

            handler.update_user(update_req).await.map_err(|e| {
                FieldError::new(
                    format!("Failed to change OU for user {}", user_id_str),
                        graphql_value!({ "details": (e.to_string()) }),
                )
            })?;
            info!("Changed OU for user {} to '{}'", user_id_str, new_ou);
        }

        Ok(Success::new())
    }

    async fn change_group_ou(
        context: &Context<Handler>,
        group_ids: Vec<i32>,
        new_ou: String,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] change_group_ou");
        span.in_scope(|| debug!(?group_ids, ?new_ou));

        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(&span, "Unauthorized OU change"))?;

        let name_lower = new_ou.trim().to_lowercase();
        if name_lower == "all" {
            return Err("Cannot move groups to built-in OU 'All'".into());
        }

        for group_id in group_ids {
            let group_id_typed = GroupId(group_id);

            let insert_attributes = vec![lldap_domain::types::Attribute {
                name: lldap_domain::types::AttributeName::from("ou"),
                value: lldap_domain::types::AttributeValue::String(
                    lldap_domain::types::Cardinality::Singleton(new_ou.clone()),
                ),
            }];

            let update_req = lldap_domain::requests::UpdateGroupRequest {
                group_id: group_id_typed,
                display_name: None,
                delete_attributes: vec![],
                insert_attributes,
            };

            handler.update_group(update_req).await.map_err(|e| {
                FieldError::new(
                    format!("Failed to change OU for group {}", group_id),
                    graphql_value!({ "details": (e.to_string()) }),
                )
            })?;
            info!("Changed OU for group {} to '{}'", group_id, new_ou);
        }

        Ok(Success::new())
    }

    async fn add_user_attribute(
        context: &Context<Handler>,
        name: String,
        attribute_type: AttributeType,
        is_list: bool,
        is_visible: bool,
        is_editable: bool,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] add_user_attribute");
        span.in_scope(|| debug!(?name, ?attribute_type, is_list));

        let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(&span, "Unauthorized attribute creation"))?;

        let schema = handler.get_schema().await?;

        // === STRICTER #1202 FIX: No duplicate names at all across user/group ===
        if schema.group_attributes().get_by_name_or_alias(&name).is_some() {
            return Err(anyhow!(
                "Attribute '{}' already exists in the group schema. Duplicate names are not allowed across user and group attributes.",
                name
            ).into());
        }

        validate_attribute_name(&name).map_err(|invalid_chars: Vec<char>| -> FieldError {
            let chars = String::from_iter(invalid_chars);
            anyhow!(
                "Cannot create attribute with invalid name. Valid characters: {}. Invalid chars found: {}",
                ALLOWED_CHARACTERS_DESCRIPTION,
                chars
            )
            .into()
        })?;

        handler
        .add_user_attribute(CreateAttributeRequest {
            name: name.into(),
                            attribute_type,
                            is_list,
                            is_visible,
                            is_editable,
        })
        .instrument(span)
        .await?;
        Ok(Success::new())
    }

    async fn add_group_attribute(
        context: &Context<Handler>,
        name: String,
        attribute_type: AttributeType,
        is_list: bool,
        is_visible: bool,
        is_editable: bool,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] add_group_attribute");
        span.in_scope(|| debug!(?name, ?attribute_type, is_list));

        let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(&span, "Unauthorized attribute creation"))?;

        let schema = handler.get_schema().await?;

        // === STRICTER #1202 FIX: No duplicate names at all across user/group ===
        if schema.user_attributes().get_by_name_or_alias(&name).is_some() {
            return Err(anyhow!(
                "Attribute '{}' already exists in the user schema. Duplicate names are not allowed across user and group attributes.",
                name
            ).into());
        }

        validate_attribute_name(&name).map_err(|invalid_chars: Vec<char>| -> FieldError {
            let chars = String::from_iter(invalid_chars);
            anyhow!(
                "Cannot create attribute with invalid name. Valid characters: {}. Invalid chars found: {}",
                ALLOWED_CHARACTERS_DESCRIPTION,
                chars
            )
            .into()
        })?;

        handler
        .add_group_attribute(CreateAttributeRequest {
            name: name.into(),
                             attribute_type,
                             is_list,
                             is_visible,
                             is_editable,
        })
        .instrument(span)
        .await?;
        Ok(Success::new())
    }

    async fn delete_user_attribute(
        context: &Context<Handler>,
        name: String,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] delete_user_attribute");
        let name = AttributeName::from(name.as_str());
        span.in_scope(|| debug!(?name));

        let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(&span, "Unauthorized attribute deletion"))?;

        let schema = handler.get_schema().await?;   // live PublicSchema — 17+ attributes (custom + POSIX + Kerberos)

        let attribute_schema = schema
        .user_attributes()
        .get_attribute_schema(name.as_str())
        .ok_or_else(|| anyhow!("Attribute {} is not defined in the schema", &name))?;

        if attribute_schema.is_hardcoded {
            return Err(anyhow!("Permission denied: Attribute {} cannot be deleted", &name).into());
        }
        handler
        .delete_user_attribute(&name)
        .instrument(span)
        .await?;
        Ok(Success::new())
    }

    async fn delete_group_attribute(
        context: &Context<Handler>,
        name: String,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] delete_group_attribute");
        let name = AttributeName::from(name.as_str());
        span.in_scope(|| debug!(?name));

        let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(&span, "Unauthorized attribute deletion"))?;

        let schema = handler.get_schema().await?;   // live PublicSchema — 17+ attributes (custom + POSIX + Kerberos)

        let attribute_schema = schema
        .group_attributes()
        .get_attribute_schema(name.as_str())
        .ok_or_else(|| anyhow!("Attribute {} is not defined in the schema", &name))?;

        if attribute_schema.is_hardcoded {
            return Err(anyhow!("Permission denied: Attribute {} cannot be deleted", &name).into());
        }
        handler
        .delete_group_attribute(&name)
        .instrument(span)
        .await?;
        Ok(Success::new())
    }

    async fn add_user_object_class(
        context: &Context<Handler>,
        name: String,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] add_user_object_class");
        span.in_scope(|| {
            debug!(?name);
        });
        let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(
            &span,
            "Unauthorized object class addition",
        ))?;
        handler
        .add_user_object_class(&LdapObjectClass::from(name))
        .instrument(span)
        .await?;
        Ok(Success::new())
    }

    async fn add_group_object_class(
        context: &Context<Handler>,
        name: String,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] add_group_object_class");
        span.in_scope(|| {
            debug!(?name);
        });
        let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(
            &span,
            "Unauthorized object class addition",
        ))?;
        handler
        .add_group_object_class(&LdapObjectClass::from(name))
        .instrument(span)
        .await?;
        Ok(Success::new())
    }

    async fn delete_user_object_class(
        context: &Context<Handler>,
        name: String,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] delete_user_object_class");
        span.in_scope(|| {
            debug!(?name);
        });
        let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(
            &span,
            "Unauthorized object class deletion",
        ))?;
        handler
        .delete_user_object_class(&LdapObjectClass::from(name))
        .instrument(span)
        .await?;
        Ok(Success::new())
    }

    async fn delete_group_object_class(
        context: &Context<Handler>,
        name: String,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] delete_group_object_class");
        span.in_scope(|| {
            debug!(?name);
        });
        let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(
            &span,
            "Unauthorized object class deletion",
        ))?;
        handler
        .delete_group_object_class(&LdapObjectClass::from(name))
        .instrument(span)
        .await?;
        Ok(Success::new())
    }

    async fn sync_kerberos_password(
        context: &Context<Handler>,
        user_id: String,
        encrypted_password: String,
    ) -> FieldResult<bool> {
        let span = debug_span!("[GraphQL mutation] sync_kerberos_password");
        let _guard = span.enter();

        let target_user_id = UserId::new(&user_id);

        // Allow regular users to sync their OWN Kerberos principal after password change
        // (exactly like set_user_password). Admins can do any user.
        let handler = context
        .get_writeable_handler(target_user_id.clone())
        .ok_or_else(field_error_callback(&span, "Unauthorized Kerberos sync"))?;

        let plain_password = decrypt_password(&encrypted_password)
        .map_err(|e| FieldError::new(
            "Kerberos password decryption failed",
            graphql_value!({ "details": (e.to_string()) })
        ))?;

        let user = handler.get_user_details(&target_user_id).await
        .map_err(|e| FieldError::new(
            "Failed to fetch user for Kerberos sync check",
            graphql_value!({ "details": (e.to_string()) })
        ))?;

        let schema = handler.get_schema().await?;
        let sync_enabled = extract_kerberos_sync(&schema, &user.attributes);

        if sync_enabled {
            sync_kerberos_principal(&user_id, &plain_password)
            .map_err(|e| FieldError::new(
                "Kerberos sync failed",
                graphql_value!({ "details": (e.to_string()) })
            ))?;
            info!("Kerberos principal synced for user {} (password change by self or admin)", user_id);
        } else {
            info!("Kerberos sync disabled for user {} (kerberossync != '1'), skipping", user_id);
        }

        let inner = UserWriteableBackendHandler::unsafe_get_handler(handler);
        let _ = inner.ensure_kerberos_principal_consistency(&target_user_id, sync_enabled).await;

        Ok(true)
    }

    async fn export_keytab_for_keycloak(
        _context: &Context<Handler>,
        hostname: String,
    ) -> FieldResult<ExportKeytabForKeycloakResponse> {
        let span = debug_span!("[GraphQL mutation] export_keytab_for_keycloak");
        span.in_scope(|| debug!("Hostname input: {}", &hostname));

        match lldap_kerberos::export_keytab_for_keycloak(&hostname) {
            Ok(path) => Ok(ExportKeytabForKeycloakResponse {
                ok: true,
                path,
                error_msg: "".to_string(),
            }),
            Err(e) => {
                warn!("Keytab export failed: {}", e);
                Ok(ExportKeytabForKeycloakResponse {
                    ok: false,
                    path: "".to_string(),
                   error_msg: e.to_string(),
                })
            }
        }
    }

    async fn test_keycloak_connection(
        _context: &Context<Handler>,
        input: TestKeycloakConnectionInput,
    ) -> FieldResult<TestKeycloakConnectionResponse> {
        let client = lldap_kerberos::KeycloakClient::from_test_input(
            input.url,
            input.realm,
            input.admin_user,
            input.admin_pass,
        );

        match client.test_connection().await {
            Ok(message) => Ok(TestKeycloakConnectionResponse {
                ok: true,
                message,
            }),
            Err(e) => Ok(TestKeycloakConnectionResponse {
                ok: false,
                message: format!("❌ {}", e),
            }),
        }
    }

    async fn save_keycloak_config(
        _context: &Context<Handler>,
        input: SaveKeycloakConfigInput,
    ) -> FieldResult<SaveKeycloakConfigResponse> {
        let config = lldap_kerberos::KeycloakConfig {
            url: input.url,
            realm: input.realm,
            admin_user: input.admin_user,
        };

        match lldap_kerberos::save_keycloak_config(&config) {
            Ok(_) => Ok(SaveKeycloakConfigResponse {
                ok: true,
                message: "✅ Keycloak settings saved to /data/keycloak_config.toml (password remains in-memory/env only)".to_string(),
            }),
            Err(e) => Ok(SaveKeycloakConfigResponse {
                ok: false,
                message: format!("❌ Failed to save config: {}", e),
            }),
        }
    }

    async fn push_realm_to_keycloak(
        _context: &Context<Handler>,
        url: String,
        realm: String,
        admin_user: String,
        admin_pass: String,
        lldap_url: String,
        sync_username: String,
        sync_password: String,
    ) -> FieldResult<PushRealmResponse> {
        let client = lldap_kerberos::KeycloakClient::from_test_input(url, realm, admin_user, admin_pass);

        let message = client.setup_realm(lldap_url, sync_username, sync_password)
        .await
        .map_err(|e| juniper::FieldError::new(e.to_string(), juniper::Value::null()))?;

        Ok(PushRealmResponse { ok: true, message })
    }

    async fn set_posix_settings(
        context: &Context<Handler>,
        input: PosixSettingsInput,
    ) -> FieldResult<PosixSettingsResponse> {
        let span = debug_span!("[GraphQL mutation] set_posix_settings");
        span.in_scope(|| debug!(?input));

        // === CONDITIONAL range enforcement — only check fields that are actually enabled ===
        if input.user_uidnumber_assign {
            if input.user_uidnumber_start < 3000 || input.user_uidnumber_start > 60000 ||
               input.user_uidnumber_max < 3000 || input.user_uidnumber_max > 60000 {
                return Err(FieldError::new(
                    "user_uidnumber must be between 3000 and 60000",
                    juniper::Value::null(),
                ));
            }
        }
        if input.user_gidnumber_assign && (input.user_gidnumber_start < 3000 || input.user_gidnumber_start > 60000) {
            return Err(FieldError::new(
                "user_gidnumber_start must be between 3000 and 60000",
                juniper::Value::null(),
            ));
        }
        if input.group_gidnumber_assign {
            if input.group_gidnumber_start < 3000 || input.group_gidnumber_start > 60000 ||
               input.group_gidnumber_max < 3000 || input.group_gidnumber_max > 60000 {
                return Err(FieldError::new(
                    "group_gidnumber must be between 3000 and 60000",
                    juniper::Value::null(),
                ));
            }
        }

        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(&span, "Unauthorized POSIX settings change"))?;

        let inner = AdminBackendHandler::unsafe_get_handler(handler);

        let settings = lldap_domain_handlers::handler::PosixSettings {
            user_uidnumber_assign: input.user_uidnumber_assign,
            user_uidnumber_start: input.user_uidnumber_start as i64,
            user_uidnumber_max: input.user_uidnumber_max as i64,
            user_gidnumber_assign: input.user_gidnumber_assign,
            user_gidnumber_start: input.user_gidnumber_start as i64,
            user_loginshell_assign: input.user_loginshell_assign,
            user_loginshell_default: input.user_loginshell_default,
            user_homedirectory_assign: input.user_homedirectory_assign,
            user_homedirectory_prefix: input.user_homedirectory_prefix,
            group_gidnumber_assign: input.group_gidnumber_assign,
            group_gidnumber_start: input.group_gidnumber_start as i64,
            group_gidnumber_max: input.group_gidnumber_max as i64,
        };

        inner.set_posix_settings(settings).await
            .map_err(|e| FieldError::new(
                "Failed to save POSIX settings",
                graphql_value!({ "details": (e.to_string()) }),
            ))?;

        Ok(PosixSettingsResponse {
            success: true,
            message: "✅ POSIX settings saved (toggles and ranges updated)".to_string(),
        })
    }

    async fn reassign_user_uid_numbers(
        context: &Context<Handler>,
    ) -> FieldResult<PosixSettingsResponse> {
        let span = debug_span!("[GraphQL mutation] reassign_user_uid_numbers");
        span.in_scope(|| debug!("Reassigning all user uidNumbers"));

        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(&span, "Unauthorized uidNumber reassign"))?;

        let inner = AdminBackendHandler::unsafe_get_handler(handler);

        inner.reassign_user_uid_numbers().await
            .map_err(|e| FieldError::new(
                "Failed to reassign user uidNumbers",
                graphql_value!({ "details": (e.to_string()) }),
            ))?;

        Ok(PosixSettingsResponse {
            success: true,
            message: "✅ All user uidNumbers have been reassigned".to_string(),
        })
    }

    async fn reassign_user_gid_numbers(
        context: &Context<Handler>,
    ) -> FieldResult<PosixSettingsResponse> {
        let span = debug_span!("[GraphQL mutation] reassign_user_gid_numbers");
        span.in_scope(|| debug!("Reassigning all user gidNumbers"));

        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(&span, "Unauthorized gidNumber reassign"))?;

        let inner = AdminBackendHandler::unsafe_get_handler(handler);

        inner.reassign_user_gid_numbers().await
            .map_err(|e| FieldError::new(
                "Failed to reassign user gidNumbers",
                graphql_value!({ "details": (e.to_string()) }),
            ))?;

        Ok(PosixSettingsResponse {
            success: true,
            message: "✅ All user gidNumbers have been reassigned".to_string(),
        })
    }

    async fn reassign_user_homedirectories(
        context: &Context<Handler>,
    ) -> FieldResult<PosixSettingsResponse> {
        let span = debug_span!("[GraphQL mutation] reassign_user_homedirectories");
        span.in_scope(|| debug!("Reassigning all user homeDirectories"));

        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(&span, "Unauthorized homeDirectory reassign"))?;

        let inner = AdminBackendHandler::unsafe_get_handler(handler);

        inner.reassign_user_homedirectories().await
            .map_err(|e| FieldError::new(
                "Failed to reassign user homeDirectories",
                graphql_value!({ "details": (e.to_string()) }),
            ))?;

        Ok(PosixSettingsResponse {
            success: true,
            message: "✅ All user homeDirectories have been reassigned".to_string(),
        })
    }

    async fn reassign_user_loginshells(
        context: &Context<Handler>,
    ) -> FieldResult<PosixSettingsResponse> {
        let span = debug_span!("[GraphQL mutation] reassign_user_loginshells");
        span.in_scope(|| debug!("Reassigning all user loginShells"));

        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(&span, "Unauthorized loginShell reassign"))?;

        let inner = AdminBackendHandler::unsafe_get_handler(handler);

        inner.reassign_user_loginshells().await
            .map_err(|e| FieldError::new(
                "Failed to reassign user loginShells",
                graphql_value!({ "details": (e.to_string()) }),
            ))?;

        Ok(PosixSettingsResponse {
            success: true,
            message: "✅ All user loginShells have been reassigned".to_string(),
        })
    }

    async fn reassign_gid_numbers(
        context: &Context<Handler>,
    ) -> FieldResult<PosixSettingsResponse> {
        let span = debug_span!("[GraphQL mutation] reassign_gid_numbers");
        span.in_scope(|| debug!("Reassigning all group gidNumbers"));

        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(&span, "Unauthorized gidNumber reassign"))?;

        let inner = AdminBackendHandler::unsafe_get_handler(handler);

        inner.reassign_gid_numbers().await
            .map_err(|e| FieldError::new(
                "Failed to reassign gidNumbers",
                graphql_value!({ "details": (e.to_string()) }),
            ))?;

        Ok(PosixSettingsResponse {
            success: true,
            message: "✅ All group gidNumbers have been reassigned".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::Query;
    use juniper::{
        DefaultScalarValue, EmptySubscription, GraphQLType, InputValue, RootNode, Variables,
        execute, graphql_value,
    };
    use lldap_auth::access_control::{Permission, ValidationResults};
    use lldap_domain::types::{AttributeName, AttributeType};
    use lldap_test_utils::MockTestBackendHandler;
    use mockall::predicate::eq;
    use pretty_assertions::assert_eq;

    fn mutation_schema<'q, C, Q, M>(
        query_root: Q,
        mutation_root: M,
    ) -> RootNode<'q, Q, M, EmptySubscription<C>>
    where
        Q: GraphQLType<DefaultScalarValue, Context = C, TypeInfo = ()> + 'q,
        M: GraphQLType<DefaultScalarValue, Context = C, TypeInfo = ()> + 'q,
    {
        RootNode::new(query_root, mutation_root, EmptySubscription::<C>::new())
    }

    #[tokio::test]
    async fn test_create_user_attribute_valid() {
        const QUERY: &str = r#"
            mutation CreateUserAttribute($name: String!, $attributeType: AttributeType!, $isList: Boolean!, $isVisible: Boolean!, $isEditable: Boolean!) {
                addUserAttribute(name: $name, attributeType: $attributeType, isList: $isList, isVisible: $isVisible, isEditable: $isEditable) {
                    ok
                }
            }
        "#;
        let mut mock = MockTestBackendHandler::new();
        mock.expect_add_user_attribute()
            .with(eq(CreateAttributeRequest {
                name: AttributeName::new("AttrName0"),
                attribute_type: AttributeType::String,
                is_list: false,
                is_visible: false,
                is_editable: false,
            }))
            .return_once(|_| Ok(()));
        let context = Context::<MockTestBackendHandler>::new_for_tests(
            mock,
            ValidationResults {
                user: UserId::new("bob"),
                permission: Permission::Admin,
            },
        );
        let vars = Variables::from([
            ("name".to_string(), InputValue::scalar("AttrName0")),
            (
                "attributeType".to_string(),
                InputValue::enum_value("STRING"),
            ),
            ("isList".to_string(), InputValue::scalar(false)),
            ("isVisible".to_string(), InputValue::scalar(false)),
            ("isEditable".to_string(), InputValue::scalar(false)),
        ]);
        let schema = mutation_schema(
            Query::<MockTestBackendHandler>::new(),
            Mutation::<MockTestBackendHandler>::new(),
        );
        assert_eq!(
            execute(QUERY, None, &schema, &vars, &context).await,
            Ok((
                graphql_value!(
                {
                    "addUserAttribute": {
                        "ok": true
                    }
                } ),
                vec![]
            ))
        );
    }

    #[tokio::test]
    async fn test_create_user_attribute_invalid() {
        const QUERY: &str = r#"
            mutation CreateUserAttribute($name: String!, $attributeType: AttributeType!, $isList: Boolean!, $isVisible: Boolean!, $isEditable: Boolean!) {
                addUserAttribute(name: $name, attributeType: $attributeType, isList: $isList, isVisible: $isVisible, isEditable: $isEditable) {
                    ok
                }
            }
        "#;
        let mock = MockTestBackendHandler::new();
        let context = Context::<MockTestBackendHandler>::new_for_tests(
            mock,
            ValidationResults {
                user: UserId::new("bob"),
                permission: Permission::Admin,
            },
        );
        let vars = Variables::from([
            ("name".to_string(), InputValue::scalar("AttrName_0")),
            (
                "attributeType".to_string(),
                InputValue::enum_value("STRING"),
            ),
            ("isList".to_string(), InputValue::scalar(false)),
            ("isVisible".to_string(), InputValue::scalar(false)),
            ("isEditable".to_string(), InputValue::scalar(false)),
        ]);
        let schema = mutation_schema(
            Query::<MockTestBackendHandler>::new(),
            Mutation::<MockTestBackendHandler>::new(),
        );
        let result = execute(QUERY, None, &schema, &vars, &context).await;
        match result {
            Ok(res) => {
                let (response, errors) = res;
                assert!(response.is_null());
                let expected_error_msg =
                    "Cannot create attribute with invalid name. Valid characters: a-z, A-Z, 0-9, and dash (-). Invalid chars found: _"
                        .to_string();
                assert!(
                    errors
                        .iter()
                        .all(|e| e.error().message() == expected_error_msg)
                );
            }
            Err(_) => {
                panic!();
            }
        }
    }

    #[tokio::test]
    async fn test_create_group_attribute_valid() {
        const QUERY: &str = r#"
            mutation CreateGroupAttribute($name: String!, $attributeType: AttributeType!, $isList: Boolean!, $isVisible: Boolean!) {
                addGroupAttribute(name: $name, attributeType: $attributeType, isList: $isList, isVisible: $isVisible, isEditable: false) {
                    ok
                }
            }
        "#;
        let mut mock = MockTestBackendHandler::new();
        mock.expect_add_group_attribute()
            .with(eq(CreateAttributeRequest {
                name: AttributeName::new("AttrName0"),
                attribute_type: AttributeType::String,
                is_list: false,
                is_visible: false,
                is_editable: false,
            }))
            .return_once(|_| Ok(()));
        let context = Context::<MockTestBackendHandler>::new_for_tests(
            mock,
            ValidationResults {
                user: UserId::new("bob"),
                permission: Permission::Admin,
            },
        );
        let vars = Variables::from([
            ("name".to_string(), InputValue::scalar("AttrName0")),
            (
                "attributeType".to_string(),
                InputValue::enum_value("STRING"),
            ),
            ("isList".to_string(), InputValue::scalar(false)),
            ("isVisible".to_string(), InputValue::scalar(false)),
            ("isEditable".to_string(), InputValue::scalar(false)),
        ]);
        let schema = mutation_schema(
            Query::<MockTestBackendHandler>::new(),
            Mutation::<MockTestBackendHandler>::new(),
        );
        assert_eq!(
            execute(QUERY, None, &schema, &vars, &context).await,
            Ok((
                graphql_value!(
                {
                    "addGroupAttribute": {
                        "ok": true
                    }
                } ),
                vec![]
            ))
        );
    }

    #[tokio::test]
    async fn test_create_group_attribute_invalid() {
        const QUERY: &str = r#"
            mutation CreateUserAttribute($name: String!, $attributeType: AttributeType!, $isList: Boolean!, $isVisible: Boolean!, $isEditable: Boolean!) {
                addUserAttribute(name: $name, attributeType: $attributeType, isList: $isList, isVisible: $isVisible, isEditable: $isEditable) {
                    ok
                }
            }
        "#;
        let mock = MockTestBackendHandler::new();
        let context = Context::<MockTestBackendHandler>::new_for_tests(
            mock,
            ValidationResults {
                user: UserId::new("bob"),
                permission: Permission::Admin,
            },
        );
        let vars = Variables::from([
            ("name".to_string(), InputValue::scalar("AttrName_0")),
            (
                "attributeType".to_string(),
                InputValue::enum_value("STRING"),
            ),
            ("isList".to_string(), InputValue::scalar(false)),
            ("isVisible".to_string(), InputValue::scalar(false)),
            ("isEditable".to_string(), InputValue::scalar(false)),
        ]);
        let schema = mutation_schema(
            Query::<MockTestBackendHandler>::new(),
            Mutation::<MockTestBackendHandler>::new(),
        );
        let result = execute(QUERY, None, &schema, &vars, &context).await;
        match result {
            Ok(res) => {
                let (response, errors) = res;
                assert!(response.is_null());
                let expected_error_msg =
                    "Cannot create attribute with invalid name. Valid characters: a-z, A-Z, 0-9, and dash (-). Invalid chars found: _"
                        .to_string();
                assert!(
                    errors
                        .iter()
                        .all(|e| e.error().message() == expected_error_msg)
                );
            }
            Err(_) => {
                panic!();
            }
        }
    }

    #[tokio::test]
    async fn test_attribute_consolidation_attr_precedence() {
        let attributes = vec![
            AttributeValue {
                name: "first_name".to_string(),
                value: vec!["expected-first".to_string()],
            },
            AttributeValue {
                name: "last_name".to_string(),
                value: vec!["expected-last".to_string()],
            },
            AttributeValue {
                name: "avatar".to_string(),
                value: vec!["expected-avatar".to_string()],
            },
        ];
        let res = consolidate_attributes(
            attributes.clone(),
            Some("overridden-first".to_string()),
            Some("overridden-last".to_string()),
            Some("overriden-avatar".to_string()),
        );
        assert_eq!(
            res,
            vec![
                AttributeValue {
                    name: "avatar".to_string(),
                    value: vec!["expected-avatar".to_string()],
                },
                AttributeValue {
                    name: "first_name".to_string(),
                    value: vec!["expected-first".to_string()],
                },
                AttributeValue {
                    name: "last_name".to_string(),
                    value: vec!["expected-last".to_string()],
                },
            ]
        );
    }

    #[tokio::test]
    async fn test_attribute_consolidation_field_fallback() {
        let attributes = Vec::new();
        let res = consolidate_attributes(
            attributes.clone(),
            Some("expected-first".to_string()),
            Some("expected-last".to_string()),
            Some("expected-avatar".to_string()),
        );
        assert_eq!(
            res,
            vec![
                AttributeValue {
                    name: "avatar".to_string(),
                    value: vec!["expected-avatar".to_string()],
                },
                AttributeValue {
                    name: "first_name".to_string(),
                    value: vec!["expected-first".to_string()],
                },
                AttributeValue {
                    name: "last_name".to_string(),
                    value: vec!["expected-last".to_string()],
                },
            ]
        );
    }

    #[tokio::test]
    async fn test_attribute_consolidation_field_fallback_2() {
        let attributes = vec![AttributeValue {
            name: "First_Name".to_string(),
            value: vec!["expected-first".to_string()],
        }];
        let res = consolidate_attributes(
            attributes.clone(),
            Some("overriden-first".to_string()),
            Some("expected-last".to_string()),
            Some("expected-avatar".to_string()),
        );
        assert_eq!(
            res,
            vec![
                AttributeValue {
                    name: "avatar".to_string(),
                    value: vec!["expected-avatar".to_string()],
                },
                AttributeValue {
                    name: "first_name".to_string(),
                    value: vec!["expected-first".to_string()],
                },
                AttributeValue {
                    name: "last_name".to_string(),
                    value: vec!["expected-last".to_string()],
                },
            ]
        );
    }

    #[tokio::test]
    async fn test_create_service_principal() {
        use mockito::{mock, Server};
        let mut server = Server::new_async().await;
        let url = server.url();

        let mock_auth = mock("POST", "/auth/realms/master/protocol/openid-connect/token")
        .with_status(200)
        .with_body("{\"access_token\": \"test_token\"}")
        .create();

        let mock_create = mock("POST", "/admin/realms/master/users")
        .with_status(201)
        .create();

        mock_auth.assert();
        mock_create.assert();
    }
}
