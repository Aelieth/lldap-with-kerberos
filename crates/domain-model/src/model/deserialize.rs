// crates/domain-model/src/model/deserialize.rs — FULL FUNCTION (with missing import + explicit Avatar construction)
use crate::error::DomainError;
use lldap_domain::{
    schema::AttributeList,
    types::{Attribute, AttributeName, AttributeType, AttributeValue, Avatar, Cardinality, Serialized},
};

// Value must be a serialized attribute value of the type denoted by typ,
// and either a singleton or unbounded list, depending on is_list.
pub fn deserialize_attribute_value(
    value: &Serialized,
    typ: AttributeType,
    is_list: bool,
) -> AttributeValue {
    match (typ, is_list) {
        (AttributeType::String, false) => {
            let s = std::str::from_utf8(&value.0).unwrap_or("");
            AttributeValue::String(Cardinality::Singleton(s.to_string()))
        }
        (AttributeType::String, true) => {
            let s = std::str::from_utf8(&value.0).unwrap_or("");
            AttributeValue::String(Cardinality::Unbounded(vec![s.to_string()]))
        }
        (AttributeType::Integer, false) => {
            let s = std::str::from_utf8(&value.0).unwrap_or("0");
            let i: i64 = s.parse().unwrap_or(0);
            AttributeValue::Integer(Cardinality::Singleton(i))
        }
        (AttributeType::Integer, true) => {
            let s = std::str::from_utf8(&value.0).unwrap_or("0");
            let i: i64 = s.parse().unwrap_or(0);
            AttributeValue::Integer(Cardinality::Unbounded(vec![i]))
        }
        (AttributeType::DateTime, false) => {
            AttributeValue::DateTime(Cardinality::Singleton(value.unwrap()))
        }
        (AttributeType::DateTime, true) => {
            AttributeValue::DateTime(Cardinality::Unbounded(value.unwrap()))
        }
        (AttributeType::Avatar, false) => {
            tracing::info!("DOMAIN_MODEL_DESERIALIZE_AVATAR: ENTERED (singleton) - Serialized raw bytes length = {}", value.0.len());
            if !value.0.is_empty() {
                tracing::info!("DOMAIN_MODEL_DESERIALIZE_AVATAR: first 16 bytes hex = {:02x?}", &value.0[0..16.min(value.0.len())]);
            }
            // ← EXPLICIT CONSTRUCTION (this was the missing piece)
            AttributeValue::Avatar(Cardinality::Singleton(Avatar(value.0.clone())))
        }
        (AttributeType::Avatar, true) => {
            tracing::info!("DOMAIN_MODEL_DESERIALIZE_AVATAR: ENTERED (list) - Serialized raw bytes length = {}", value.0.len());
            if !value.0.is_empty() {
                tracing::info!("DOMAIN_MODEL_DESERIALIZE_AVATAR: first 16 bytes hex = {:02x?}", &value.0[0..16.min(value.0.len())]);
            }
            AttributeValue::Avatar(Cardinality::Unbounded(vec![Avatar(value.0.clone())]))
        }
    }
}

pub fn deserialize_attribute(
    name: AttributeName,
    value: &Serialized,
    schema: &AttributeList,
) -> Result<Attribute, DomainError> {
    match schema.get_attribute_type(name.as_str()) {
        Some((typ, is_list)) => Ok(Attribute {
            name,
            value: deserialize_attribute_value(value, typ, is_list),
        }),
        None => Err(DomainError::InternalError(format!(
            "Unable to find schema for attribute named '{}'",
            name.into_string()
        ))),
    }
}
