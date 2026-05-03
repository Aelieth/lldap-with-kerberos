use anyhow::anyhow;
use base64::{engine::general_purpose, Engine as _};
use juniper::FieldResult;
use lldap_access_control::{AdminBackendHandler, ReadonlyBackendHandler};
use lldap_domain::{
    requests::CreateGroupRequest,
    types::{Attribute as DomainAttribute, AttributeName, Email, Serialized},
    images::process_avatar_input,
};
use lldap_domain_handlers::handler::{BackendHandler, ReadSchemaBackendHandler};
use lldap_domain_model::model::deserialize::deserialize_attribute_value;
use std::{collections::BTreeMap, sync::Arc};
use tracing::{Instrument, Span};
use lldap_opaque_handler::OpaqueHandler;
use super::inputs::AttributeValue;
use crate::api::{Context, field_error_callback};
use lldap_schema::{PublicSchema, schema::AttributeList};

pub struct UnpackedAttributes {
    pub email: Option<Email>,
    pub display_name: Option<String>,
    pub attributes: Vec<DomainAttribute>,
}

fn validate_ssh_public_key(key: &str) -> Result<(), String> {
    let trimmed = key.trim();
    if trimmed.is_empty() {
        return Err("SSH public key cannot be empty".to_string());
    }
    // Must start with a recognized OpenSSH key type prefix
    if !(trimmed.starts_with("ssh-")
        || trimmed.starts_with("ecdsa-")
        || trimmed.starts_with("sk-")
        || trimmed.starts_with("ssh-ed25519")) {
        return Err(format!(
            "Invalid SSH public key format. Expected to start with ssh-, ecdsa-, sk-, or ssh-ed25519. Got: '{}'",
            trimmed.split_whitespace().next().unwrap_or(trimmed)
        ));
        }
        // Must contain at least one space (key type + base64)
        if !trimmed.contains(' ') {
            return Err("Invalid SSH public key: missing space after key type".to_string());
        }
        // Reasonable length guard (prevents accidental huge pastes)
        if trimmed.len() > 4096 {
            return Err("SSH public key is too long (max 4096 characters)".to_string());
        }
        Ok(())
}

pub fn unpack_attributes(
    attributes: Vec<AttributeValue>,
    schema: &PublicSchema,
    is_admin: bool,
) -> FieldResult<UnpackedAttributes> {
    let user_schema = schema.user_attributes();

    let email = attributes
        .iter()
        .find(|attr| attr.name == "mail")
        .cloned()
        .map(|attr| deserialize_attribute(user_schema, attr, is_admin))
        .transpose()?
        .map(|attr| attr.value.into_string().unwrap())
        .map(Email::from);

    let display_name = attributes
        .iter()
        .find(|attr| attr.name == "display_name")
        .cloned()
        .map(|attr| deserialize_attribute(user_schema, attr, is_admin))
        .transpose()?
        .map(|attr| attr.value.into_string().unwrap());

    let attributes = attributes
        .into_iter()
        .filter(|attr| attr.name != "mail" && attr.name != "display_name")
        .map(|attr| deserialize_attribute(user_schema, attr, is_admin))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(UnpackedAttributes {
        email,
        display_name,
        attributes,
    })
}

pub fn consolidate_attributes(
    attributes: Vec<AttributeValue>,
    first_name: Option<String>,
    last_name: Option<String>,
    avatar: Option<String>,
) -> Vec<AttributeValue> {
    let mut provided_attributes: BTreeMap<AttributeName, AttributeValue> = attributes
        .into_iter()
        .map(|x| {
            (
                x.name.clone().into(),
                AttributeValue {
                    name: x.name.to_ascii_lowercase(),
                    value: x.value,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();

    let field_attrs = [
        ("first_name", first_name),
        ("last_name", last_name),
        ("avatar", avatar),
    ];
    for (name, value) in field_attrs.into_iter() {
        if let Some(val) = value {
            if name == "avatar" && val.trim().is_empty() {
                continue; // let removeAttributes handle deletion
            }
            let attr_name: AttributeName = name.into();
            provided_attributes
                .entry(attr_name)
                .or_insert_with(|| AttributeValue {
                    name: name.to_string(),
                    value: vec![val],
                });
        }
    }
    provided_attributes.into_values().collect()
}

pub async fn create_group_with_details<Handler: BackendHandler + OpaqueHandler>(
    context: &Context<Handler>,
    request: super::inputs::CreateGroupInput,
    span: Span,
) -> FieldResult<crate::query::Group<Handler>> {
    let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(&span, "Unauthorized group creation"))?;

    let schema = handler.get_schema().await?;

    let raw_attributes = request.attributes.unwrap_or_default();

    // === EXACT SAME OU BYPASS PATTERN AS create_user ===
    let ou_value = raw_attributes
        .iter()
        .find(|a| a.name == "ou")
        .and_then(|a| a.value.first().cloned())
        .unwrap_or_else(|| "groups".to_string());

    let attributes_for_unpack: Vec<_> = raw_attributes
        .into_iter()
        .filter(|a| a.name != "ou")
        .collect();

    let attributes = attributes_for_unpack
        .into_iter()
        .map(|attr| deserialize_attribute(schema.group_attributes(), attr, true))
        .collect::<Result<Vec<_>, _>>()?;

    // Add the OU back as a proper typed attribute (backend is allowed to set readonly fields on create)
    let mut final_attributes = attributes;
    final_attributes.push(DomainAttribute {
        name: AttributeName::from("ou"),
        value: lldap_domain::types::AttributeValue::String(
            lldap_domain::types::Cardinality::Singleton(ou_value),
        ),
    });

    let request = CreateGroupRequest {
        display_name: request.display_name.into(),
        attributes: final_attributes,
    };

    let group_id = handler.create_group(request).await?;
    let group_details = handler.get_group_details(group_id).instrument(span).await?;
    crate::query::Group::<Handler>::from_group_details(group_details, Arc::new(schema))
}

pub fn deserialize_attribute(
    attribute_schema: &AttributeList,
    attribute: AttributeValue,
    is_admin: bool,
) -> FieldResult<DomainAttribute> {
    // === TEMP DEBUG ===
    if attribute.name.to_ascii_lowercase() == "avatar" || attribute.name.to_ascii_lowercase() == "jpegphoto" {
    }
    let attribute_name = AttributeName::from(attribute.name.as_str());

    let attr_schema = attribute_schema
        .get_attribute_schema(attribute_name.as_str())
        .ok_or_else(|| anyhow!("Attribute {} is not defined in the schema", attribute.name))?;

    if attr_schema.is_readonly {
        return Err(anyhow!(
            "Permission denied: Attribute {} is read-only",
            attribute.name
        ).into());
    }
    if !is_admin && !attr_schema.is_editable {
        return Err(anyhow!(
            "Permission denied: Attribute {} is not editable by regular users",
            attribute.name
        ).into());
    }

    if attribute.name.to_ascii_lowercase() == "sshpublickey" && attr_schema.is_list {
        for key in &attribute.value {
            if let Err(err_msg) = validate_ssh_public_key(key) {
                return Err(anyhow!(
                    "Invalid SSH public key: {}", err_msg
                ).into());
            }
        }
    }

    // === SPECIAL CASE FOR AVATAR: decode base64 BEFORE creating Serialized ===
    let is_avatar = attribute.name.to_ascii_lowercase() == "avatar"
    || attribute.name.to_ascii_lowercase() == "jpegphoto";

    let serialized = if is_avatar && !attr_schema.is_list {
        let val = attribute.value.first().cloned().unwrap_or_default().trim().to_string();

        if val.is_empty() {
            Serialized(vec![])
        } else {
            match general_purpose::STANDARD.decode(&val) {
                Ok(raw_bytes) => {
                    match process_avatar_input(&raw_bytes) {
                        Ok(jpeg) => {
                            Serialized(jpeg)
                        }
                        Err(e) => {
                            return Err(anyhow!("Invalid avatar upload: {}", e).into());
                        }
                    }
                }
                Err(e) => {
                    tracing::error!(
                        target: "avatar_debug",
                        "Avatar base64 decode FAILED: {}",
                        e
                    );
                    return Err(anyhow!("Invalid base64 avatar data: {}", e).into());
                }
            }
        }
    } else if attr_schema.is_list {
        Serialized(serde_json::to_vec(&attribute.value).unwrap_or_else(|_| b"[]".to_vec()))
    } else {
        let val = attribute.value.first().cloned().unwrap_or_default();
        Serialized(val.into_bytes())
    };

    let value = deserialize_attribute_value(
        &serialized,
        attr_schema.attribute_type,
        attr_schema.is_list,
    );

    Ok(DomainAttribute {
        name: attribute_name,
        value,
    })
}
