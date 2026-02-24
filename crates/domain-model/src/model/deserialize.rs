use crate::error::DomainError;
use lldap_domain::{
    schema::AttributeList,
    types::{Attribute, AttributeName, AttributeType, AttributeValue, Cardinality, Serialized},
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
            AttributeValue::String(Cardinality::Singleton(value.unwrap()))
        }
        (AttributeType::String, true) => {
            AttributeValue::String(Cardinality::Unbounded(value.unwrap()))
        }
        (AttributeType::Integer, false) => {
            // NEW: parse string bytes ("1" or "0") back to i64
            let s = std::str::from_utf8(&value.0).unwrap_or("0");
            let i: i64 = s.parse().unwrap_or(0);
            AttributeValue::Integer(Cardinality::Singleton(i))
        }
        (AttributeType::Integer, true) => {
            // list of integers (future-proof)
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
        (AttributeType::JpegPhoto, false) => {
            AttributeValue::JpegPhoto(Cardinality::Singleton(value.unwrap()))
        }
        (AttributeType::JpegPhoto, true) => {
            AttributeValue::JpegPhoto(Cardinality::Unbounded(value.unwrap()))
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
