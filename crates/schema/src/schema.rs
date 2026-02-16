use serde::{Deserialize, Serialize};

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttributeType {
    String,
    Integer,
    JpegPhoto,
    DateTime,
}

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
    /// Find attribute by exact name OR any alias (case-sensitive, as stored)
    pub fn get_by_name_or_alias(&self, name: &str) -> Option<&AttributeSchema> {
        self.attributes.iter().find(|a| {
            a.name == name || a.aliases.iter().any(|alias| alias == name)
        })
    }
}
