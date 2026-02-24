use anyhow::{Context as AnyhowContext, anyhow};
use juniper::FieldResult;
use lldap_access_control::{AdminBackendHandler, ReadonlyBackendHandler};
use lldap_domain::{
    deserialize::deserialize_attribute_value,
    requests::CreateGroupRequest,
    types::{Attribute as DomainAttribute, AttributeName, Email},
};
use lldap_domain_handlers::handler::{BackendHandler, ReadSchemaBackendHandler};
use std::{collections::BTreeMap, sync::Arc};
use tracing::{Instrument, Span};
use lldap_opaque_handler::OpaqueHandler;
use super::inputs::AttributeValue;
use crate::api::{Context, field_error_callback};

// Single source of truth — now always the live PublicSchema from DB
use lldap_schema::{PublicSchema, schema::AttributeList};

pub struct UnpackedAttributes {
    pub email: Option<Email>,
    pub display_name: Option<String>,
    pub attributes: Vec<DomainAttribute>,
}

pub fn unpack_attributes(
    attributes: Vec<AttributeValue>,
    schema: &PublicSchema,
    is_admin: bool,
) -> FieldResult<UnpackedAttributes> {
    // Single-source-of-truth size check (now 16 user attrs: core + POSIX + Kerberos)
    let expected = PublicSchema::get().user_attributes().attributes.len();
    let actual = schema.user_attributes().attributes.len();
    if actual != expected {
        tracing::warn!(
            "Schema size mismatch in unpack_attributes: got {} attributes, expected {} from PublicSchema",
            actual, expected
        );
    }

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

    // handler.get_schema() now returns PublicSchema directly (live from DB)
    let schema = handler.get_schema().await?;

    let attributes = request
    .attributes
    .unwrap_or_default()
    .into_iter()
    .map(|attr| deserialize_attribute(schema.group_attributes(), attr, true))
    .collect::<Result<Vec<_>, _>>()?;

    let request = CreateGroupRequest {
        display_name: request.display_name.into(),
        attributes,
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
    let attribute_name = AttributeName::from(attribute.name.as_str());

    let attribute_schema = attribute_schema
    .get_attribute_schema(attribute_name.as_str())
    .ok_or_else(|| anyhow!("Attribute {} is not defined in the schema", attribute.name))?;
    if attribute_schema.is_readonly {
        return Err(anyhow!(
            "Permission denied: Attribute {} is read-only",
            attribute.name
        ).into());
    }
    if !is_admin && !attribute_schema.is_editable {
        return Err(anyhow!(
            "Permission denied: Attribute {} is not editable by regular users",
            attribute.name
        ).into());
    }
    let deserialized_values = deserialize_attribute_value(
        &attribute.value,
        attribute_schema.attribute_type,
        attribute_schema.is_list,
    ).context(format!("While deserializing attribute {}", attribute.name))?;

    Ok(DomainAttribute {
        name: attribute_name,
       value: deserialized_values,
    })
}
