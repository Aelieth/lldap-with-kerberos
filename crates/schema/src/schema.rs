use serde::{Deserialize, Serialize};
use strum::{EnumIter, EnumString, IntoStaticStr};
use juniper::GraphQLEnum;
use derive_more::Display;

// ==================== ATTRIBUTE TYPE (SINGLE SOURCE OF TRUTH) ====================
#[derive(
Clone, Copy, Debug, PartialEq, Eq,
Serialize, Deserialize,
sea_orm::DeriveActiveEnum,   // ← SeaORM can now read/write this enum from DB columns
EnumIter,                    // ← required by DeriveActiveEnum
EnumString, IntoStaticStr, GraphQLEnum, Display,
)]
#[sea_orm(rs_type = "String", db_type = "Text")]   // Text = simple VARCHAR/TEXT, avoids StringLen constructor conflict
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
#[display("{_0}")]
pub enum AttributeType {
    #[sea_orm(string_value = "String")]
    String,
    #[sea_orm(string_value = "Integer")]
    Integer,
    #[sea_orm(string_value = "JpegPhoto")]
    JpegPhoto,
    #[sea_orm(string_value = "DateTime")]
    DateTime,
}

// ==================== SCHEMA STRUCTS ====================
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct Schema {
    pub user_attributes: AttributeList,
    pub group_attributes: AttributeList,
    pub extra_user_object_classes: Vec<String>,
    pub extra_group_object_classes: Vec<String>,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct AttributeSchema {
    pub name: String,
    pub aliases: Vec<String>,
    pub attribute_type: AttributeType,
    pub is_list: bool,
    pub is_visible: bool,
    pub is_editable: bool,
    pub is_hardcoded: bool,
    pub is_readonly: bool,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct AttributeList {
    pub attributes: Vec<AttributeSchema>,
}

impl AttributeList {
    /// Find by exact name OR any alias (used by LDAP, GraphQL, frontend, etc.)
    pub fn get_by_name_or_alias(&self, name: &str) -> Option<&AttributeSchema> {
        self.attributes.iter().find(|a| {
            a.name == name || a.aliases.iter().any(|alias| alias == name)
        })
    }

    /// Compatibility for old domain code
    pub fn get_attribute_schema(&self, name: &str) -> Option<&AttributeSchema> {
        self.get_by_name_or_alias(name)
    }

    pub fn get_attribute_type(&self, name: &str) -> Option<(AttributeType, bool)> {
        self.get_by_name_or_alias(name)
        .map(|a| (a.attribute_type, a.is_list))
    }

    pub fn format_for_ldap_schema_description(&self) -> String {
        self.attributes
        .iter()
        .map(|a| a.name.as_str())
        .collect::<Vec<_>>()
        .join(" $ ")
    }
}
