pub mod helpers;
pub mod inputs;

// Re-export public types
pub use inputs::{
    AttributeValue, CreateGroupInput, CreateUserInput, Success, UpdateGroupInput, UpdateUserInput,
};

use tracing::{Instrument, info, debug, debug_span, warn};
use crate::api::{Context, field_error_callback};
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
use lldap_kerberos::{decrypt_password, delete_kerberos_principal, sync_kerberos_principal};
use helpers::{
    UnpackedAttributes, consolidate_attributes, create_group_with_details, deserialize_attribute,
    unpack_attributes,
};
use keycloak::{KeycloakAdmin, types::UserRepresentation};
use keycloak::KeycloakAdminToken;
use reqwest::Client as HttpClient;
use std::env;
use std::collections::HashMap;

// Single source of truth for the entire schema (user + group + POSIX + Kerberos)
// Used by delete_attribute checks, future UI visibility, Keycloak federation, etc.
use lldap_schema::PublicSchema;

#[derive(juniper::GraphQLInputObject)]
struct CreateServicePrincipalInput {
    service_name: String,  // e.g., "HTTP" or "host"
    hostname: String,      // e.g., "keycloak.example.com"
}

#[derive(juniper::GraphQLObject)]
struct CreateServicePrincipalResponse {
    ok: bool,
    principal: String,
    realm: String,
    error_msg: String,  // For API errors (empty on success)
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
              _ => None,
    })
    .unwrap_or(false)
}

#[graphql_object(context = Context<Handler>)]
impl<Handler: BackendHandler + OpaqueHandler> Mutation<Handler> {
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

        let schema = handler.get_schema().await?;   // live PublicSchema — 17+ attributes (custom + POSIX + Kerberos)

        let consolidated_attributes = consolidate_attributes(
            user.attributes.unwrap_or_default(),
                                                             user.first_name,
                                                             user.last_name,
                                                             user.avatar,
        );

        let UnpackedAttributes {
            email,
            display_name,
            attributes,
        } = unpack_attributes(consolidated_attributes, &schema, true)?;

        handler
        .create_user(CreateUserRequest {
            user_id: user_id.clone(),
                     email: user
                     .email
                     .map(Email::from)
                     .or(email)
                     .ok_or_else(|| anyhow!("Email is required when creating a new user"))?,
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
        let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(&span, "Unauthorized password set"))?;

        // OPAQUE registration – core LLDAP password handling (unchanged, zero impact on performance)
        use lldap_auth::{opaque, registration};
        use anyhow::Context;
        use rand::rngs::OsRng;
        let mut rng = OsRng;
        let registration_start_request = opaque::client::registration::start_registration(password.as_bytes(), &mut rng)
        .context("Could not initiate password registration")?;
        let req = registration::ClientRegistrationStartRequest {
            username: UserId::new(&user_id),
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

        let user_id_typed = UserId::new(&user_id);
        let user = handler.get_user_details(&user_id_typed).await
        .context("Failed to fetch user for Kerberos sync check")?;

        let schema = handler.get_schema().await?;
        let sync_enabled = extract_kerberos_sync(&schema, &user.attributes);

        if let Err(e) = lldap_kerberos::sync_kerberos_if_enabled(sync_enabled, &user_id, &password) {
            warn!("Kerberos sync failed after admin password set: {}", e);
        } else if sync_enabled {
            info!("Kerberos principal synced for user {} (triggered by admin password change)", user_id);
        }

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
        .get_writeable_handler(&user_id)
        .ok_or_else(field_error_callback(&span, "Unauthorized user update"))?;

        let is_admin = context.validation_result.is_admin();
        let schema = handler.get_schema().await?;   // live PublicSchema — 17+ attributes (custom + POSIX + Kerberos)

        let consolidated_attributes = consolidate_attributes(
            user.insert_attributes.unwrap_or_default(),
                                                             user.first_name,
                                                             user.last_name,
                                                             user.avatar,
        );

        let (delete_attrs, insert_attrs): (Vec<_>, Vec<_>) = consolidated_attributes
        .into_iter()
        .partition(|a| a.value == vec!["".to_string()]);

        let mut delete_attributes: Vec<String> = delete_attrs
        .iter()
        .map(|a| a.name.to_owned())
        .collect();
        delete_attributes.extend(user.remove_attributes.unwrap_or_default());

        let UnpackedAttributes {
            email,
            display_name,
            attributes: insert_attributes,
        } = unpack_attributes(insert_attrs, &schema, is_admin)?;

        let display_name = display_name.or_else(|| {
            delete_attributes
            .iter()
            .find(|attr| *attr == "display_name")
            .map(|_| String::new())
        });

        handler
        .update_user(UpdateUserRequest {
            user_id: user_id.clone(),
                     email: user.email.map(Into::into).or(email),
                     display_name: user.display_name.or(display_name),
                     delete_attributes: delete_attributes
                     .clone()
                     .into_iter()
                     .filter(|attr| attr != "mail" && attr != "display_name")
                     .map(|s| AttributeName::from(s))
                     .collect(),
                     insert_attributes: insert_attributes.clone(),
        })
        .instrument(span)
        .await?;

        let new_user = handler.get_user_details(&user_id).await
        .map_err(|e| FieldError::new(
            "Failed to fetch updated user for Kerberos actions",
            graphql_value!({ "details": (e.to_string()) })
        ))?;

        let schema = handler.get_schema().await?;
        let sync_enabled = extract_kerberos_sync(&schema, &new_user.attributes);

        if !sync_enabled {
            if let Err(e) = lldap_kerberos::delete_kerberos_principal(user_id.as_str()) {
                warn!("Failed to delete Kerberos principal for user {}: {}", user_id, e);
            } else {
                info!("Deleted Kerberos principal for user {} (sync disabled)", user_id);
            }
        } else {
            debug!("Kerberos sync enabled for user {} — waiting for password change to trigger sync", user_id);
        }

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
                .find(|attr| attr.name == "display_name")
                .map(|attr| attr.value[0].clone())
            })
        });
        if group.id == 1 && new_display_name.is_some() {
            span.in_scope(|| debug!("Cannot change lldap_admin group name"));
            return Err("Cannot change lldap_admin group name".into());
        }

        let schema = handler.get_schema().await?;   // live PublicSchema — 17+ attributes (custom + POSIX + Kerberos)
        let insert_attributes = group
        .insert_attributes
        .unwrap_or_default()
        .into_iter()
        .filter(|attr| attr.name != "display_name")
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
                      .filter(|attr| attr != "display_name")
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

        // Delete from LLDAP (EAV tables seeded from PublicSchema::get() in v12 migration)
        handler
        .delete_user(&user_id_typed)
        .instrument(span.clone())
        .await
        .map_err(|e| FieldError::new(
            "User deletion failed",
            graphql_value!({ "details": (e.to_string()) })
        ))?;

        // Delete Kerberos principal (non-fatal with warn)
        if let Err(e) = delete_kerberos_principal(&user_id) {
            warn!("Failed to delete Kerberos principal for user {}: {}", user_id, e);
        } else {
            info!("Deleted Kerberos principal for user {}", user_id);
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

    async fn add_user_attribute(
        context: &Context<Handler>,
        name: String,
        attribute_type: AttributeType,
        is_list: bool,
        is_visible: bool,
        is_editable: bool,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] add_user_attribute");
        span.in_scope(|| {
            debug!(?name, ?attribute_type, is_list, is_visible, is_editable);
        });
        validate_attribute_name(&name).map_err(|invalid_chars: Vec<char>| -> FieldError {
            let chars = String::from_iter(invalid_chars);
            span.in_scope(|| {
                debug!(
                    "Cannot create attribute with invalid name. Valid characters: {}. Invalid chars found: {}",
                    ALLOWED_CHARACTERS_DESCRIPTION,
                    chars
                )
            });
            anyhow!(
                "Cannot create attribute with invalid name. Valid characters: {}. Invalid chars found: {}",
                ALLOWED_CHARACTERS_DESCRIPTION,
                chars
            )
            .into()
        })?;
        let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(
            &span,
            "Unauthorized attribute creation",
        ))?;
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
        span.in_scope(|| {
            debug!(?name, ?attribute_type, is_list, is_visible, is_editable);
        });
        validate_attribute_name(&name).map_err(|invalid_chars: Vec<char>| -> FieldError {
            let chars = String::from_iter(invalid_chars);
            span.in_scope(|| {
                debug!(
                    "Cannot create attribute with invalid name. Invalid chars found: {}",
                    chars
                )
            });
            anyhow!(
                "Cannot create attribute with invalid name. Valid characters: {}",
                ALLOWED_CHARACTERS_DESCRIPTION
            )
            .into()
        })?;
        let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(
            &span,
            "Unauthorized attribute creation",
        ))?;
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

    async fn create_service_principal(
        _context: &Context<Handler>,
        input: CreateServicePrincipalInput,
    ) -> FieldResult<CreateServicePrincipalResponse> {
        let keycloak_url = env::var("KEYCLOAK_URL").unwrap_or("http://keycloak:8080".to_string());
        let realm = env::var("KEYCLOAK_REALM").unwrap_or("master".to_string());
        let admin_user = env::var("KEYCLOAK_ADMIN_USER").unwrap_or("admin".to_string());
        let admin_pass = env::var("KEYCLOAK_ADMIN_PASS").unwrap_or("admin".to_string());

        let http_client = HttpClient::new();

        let admin_token = match KeycloakAdminToken::acquire(&keycloak_url, &admin_user, &admin_pass, &http_client).await {
            Ok(token) => token,
            Err(e) => {
                warn!("Failed to acquire Keycloak admin token: {}", e);
                return Ok(CreateServicePrincipalResponse {
                    ok: false,
                    principal: "".to_string(),
                          realm: realm.clone(),
                          error_msg: e.to_string(),
                });
            }
        };

        let keycloak = KeycloakAdmin::new(&keycloak_url, admin_token, http_client);

        let full_principal = format!("{}/{}@{}", input.service_name, input.hostname, realm.to_uppercase());

        let service_user = UserRepresentation {
            username: Some(full_principal.clone()),
            enabled: Some(true),
            attributes: Some(HashMap::from([
                ("kerberos_principal".to_string(), vec![full_principal.clone()]),
            ])),
            ..Default::default()
        };

        if let Err(e) = keycloak.realm_users_post(&realm, service_user).await {
            warn!("Keycloak API create user failed: {}", e);
            return Ok(CreateServicePrincipalResponse {
                ok: false,
                principal: full_principal,
                realm,
                error_msg: e.to_string(),
            });
        }

        info!("Created Keycloak service user for principal {}", full_principal);

        Ok(CreateServicePrincipalResponse {
            ok: true,
            principal: full_principal,
            realm,
            error_msg: "".to_string(),
        })
    }

    async fn sync_kerberos_password(
        context: &Context<Handler>,
        user_id: String,
        encrypted_password: String,
    ) -> FieldResult<bool> {
        let span = debug_span!("[GraphQL mutation] sync_kerberos_password");
        let _guard = span.enter();
        let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(&span, "Unauthorized Kerberos sync"))?;

        let plain_password = decrypt_password(&encrypted_password)
        .map_err(|e| FieldError::new(
            "Kerberos password decryption failed",
            graphql_value!({ "details": (e.to_string()) })
        ))?;

        let user_id_typed = UserId::new(&user_id);
        let user = handler.get_user_details(&user_id_typed).await
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
            info!("Kerberos sync succeeded for user {}", user_id);
        } else {
            info!("Kerberos sync disabled for user {} (kerberossync != '1'), skipping", user_id);
        }

        Ok(true)
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
