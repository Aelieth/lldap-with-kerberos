use derive_more::Display;
use serde::{Deserialize, Serialize};
use strum::EnumString;
use validator::ValidationError;

#[derive(Serialize, Deserialize, Debug, Copy, Clone, PartialEq, Eq, Hash, EnumString, Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[strum(ascii_case_insensitive)]
pub(crate) enum AttributeType {
    String,
    Integer,
    #[strum(serialize = "DATE_TIME", serialize = "DATETIME")]
    DateTime,
    #[strum(serialize = "AVATAR", serialize = "AVATAR")]
    Avatar,
}

pub fn validate_attribute_type(attribute_type: &str) -> Result<(), ValidationError> {
    AttributeType::try_from(attribute_type)
    .map_err(|_| ValidationError::new("Invalid attribute type"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_attribute_type() {
        let attr_type: AttributeType = "STRING".try_into().unwrap();
        assert_eq!(attr_type, AttributeType::String);

        let attr_type: AttributeType = "Integer".try_into().unwrap();
        assert_eq!(attr_type, AttributeType::Integer);

        let attr_type: AttributeType = "DATE_TIME".try_into().unwrap();
        assert_eq!(attr_type, AttributeType::DateTime);

        let attr_type: AttributeType = "AVATAR".try_into().unwrap();
        assert_eq!(attr_type, AttributeType::Avatar);

        // Also accept the old aliases for backward compatibility during migration
        let attr_type: AttributeType = "JPEGPHOTO".try_into().unwrap();
        assert_eq!(attr_type, AttributeType::Avatar);
    }
}
