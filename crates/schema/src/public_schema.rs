use crate::schema::{AttributeSchema, AttributeType, Schema};
use serde::{Deserialize, Serialize};

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct PublicSchema(pub Schema);

impl PublicSchema {
    pub fn get_schema(&self) -> &Schema {
        &self.0
    }
}

impl From<Schema> for PublicSchema {
    fn from(mut schema: Schema) -> Self {
        // === Upstream hard-coded attributes (matching LLDAP style) ===
        schema.user_attributes.attributes.extend_from_slice(&[
            AttributeSchema {
                name: "userid".into(),
                aliases: vec!["user_id".into(), "id".into()],
                attribute_type: AttributeType::String,
                is_list: false,
                is_visible: true,
                is_editable: false,
                is_hardcoded: true,
                is_readonly: true,
            },
            AttributeSchema {
                name: "creationdate".into(),
                aliases: vec!["creation_date".into(), "createtimestamp".into()],
                attribute_type: AttributeType::DateTime,
                is_list: false,
                is_visible: true,
                is_editable: false,
                is_hardcoded: true,
                is_readonly: true,
            },
            AttributeSchema {
                name: "modifieddate".into(),
                aliases: vec!["modified_date".into(), "modifytimestamp".into()],
                attribute_type: AttributeType::DateTime,
                is_list: false,
                is_visible: true,
                is_editable: false,
                is_hardcoded: true,
                is_readonly: true,
            },
            AttributeSchema {
                name: "passwordmodifieddate".into(),
                aliases: vec!["password_modified_date".into(), "pwdchangedtime".into()],
                attribute_type: AttributeType::DateTime,
                is_list: false,
                is_visible: true,
                is_editable: false,
                is_hardcoded: true,
                is_readonly: true,
            },
            AttributeSchema {
                name: "mail".into(),
                aliases: vec!["email".into()],
                attribute_type: AttributeType::String,
                is_list: false,
                is_visible: true,
                is_editable: true,
                is_hardcoded: true,
                is_readonly: false,
            },
            AttributeSchema {
                name: "uuid".into(),
                aliases: vec!["entryuuid".into()],
                attribute_type: AttributeType::String,
                is_list: false,
                is_visible: true,
                is_editable: false,
                is_hardcoded: true,
                is_readonly: true,
            },
            AttributeSchema {
                name: "displayname".into(),
                aliases: vec!["display_name".into(), "cn".into()],
                attribute_type: AttributeType::String,
                is_list: false,
                is_visible: true,
                is_editable: true,
                is_hardcoded: true,
                is_readonly: false,
            },

            // === Our Kerberos/POSIX attributes - single source of truth ===
            AttributeSchema {
                name: "uidnumber".into(),
                aliases: vec!["uid_number".into(), "uidNumber".into()],
                attribute_type: AttributeType::Integer,
                is_list: false,
                is_visible: false,
                is_editable: true,
                is_hardcoded: true,
                is_readonly: false,
            },
            AttributeSchema {
                name: "gidnumber".into(),
                aliases: vec!["gid_number".into(), "gidNumber".into()],
                attribute_type: AttributeType::Integer,
                is_list: false,
                is_visible: false,
                is_editable: true,
                is_hardcoded: true,
                is_readonly: false,
            },
            AttributeSchema {
                name: "loginshell".into(),
                aliases: vec!["login_shell".into(), "loginShell".into()],
                attribute_type: AttributeType::String,
                is_list: false,
                is_visible: true,
                is_editable: false,
                is_hardcoded: true,
                is_readonly: true,
            },
            AttributeSchema {
                name: "kerberossync".into(),
                aliases: vec!["kerberos_sync".into(), "kerberosSync".into()],
                attribute_type: AttributeType::Integer,
                is_list: false,
                is_visible: true,
                is_editable: true,
                is_hardcoded: true,
                is_readonly: false,
            },
        ]);

        schema.user_attributes.attributes.sort_by(|a, b| a.name.cmp(&b.name));

        // Group attributes (unchanged for now)
        schema.group_attributes.attributes.extend_from_slice(&[
            AttributeSchema {
                name: "groupid".into(),
                aliases: vec!["group_id".into()],
                attribute_type: AttributeType::Integer,
                is_list: false,
                is_visible: true,
                is_editable: false,
                is_hardcoded: true,
                is_readonly: true,
            },
            AttributeSchema {
                name: "creationdate".into(),
                aliases: vec!["creation_date".into(), "createtimestamp".into()],
                attribute_type: AttributeType::DateTime,
                is_list: false,
                is_visible: true,
                is_editable: false,
                is_hardcoded: true,
                is_readonly: true,
            },
            AttributeSchema {
                name: "modifieddate".into(),
                aliases: vec!["modified_date".into(), "modifytimestamp".into()],
                attribute_type: AttributeType::DateTime,
                is_list: false,
                is_visible: true,
                is_editable: false,
                is_hardcoded: true,
                is_readonly: true,
            },
            AttributeSchema {
                name: "uuid".into(),
                aliases: vec!["entryuuid".into()],
                attribute_type: AttributeType::String,
                is_list: false,
                is_visible: true,
                is_editable: false,
                is_hardcoded: true,
                is_readonly: true,
            },
            AttributeSchema {
                name: "displayname".into(),
                aliases: vec!["display_name".into(), "cn".into()],
                attribute_type: AttributeType::String,
                is_list: false,
                is_visible: true,
                is_editable: true,
                is_hardcoded: true,
                is_readonly: false,
            },
        ]);

        schema.group_attributes.attributes.sort_by(|a, b| a.name.cmp(&b.name));

        PublicSchema(schema)
    }
}
