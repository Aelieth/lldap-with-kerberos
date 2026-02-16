// crates/schema/src/public_schema.rs
use crate::schema::{AttributeList, AttributeSchema, AttributeType, Schema};
use serde::{Deserialize, Serialize};

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct PublicSchema(pub Schema);

impl PublicSchema {
    /// Single source of truth for the entire schema (user + group + Kerberos/POSIX)
    pub fn get() -> Self {
        PublicSchema(Schema {
            user_attributes: AttributeList {
                attributes: vec![
                    // ==================== CORE LLDAP ATTRIBUTES ====================
                    AttributeSchema {
                        name: "avatar".into(),
                        aliases: vec!["jpegphoto".into(), "jpegPhoto".into()],
                        attribute_type: AttributeType::JpegPhoto,
                        is_list: false,
                        is_visible: true,
                        is_editable: true,
                        is_hardcoded: true,
                        is_readonly: false,
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
                        name: "displayname".into(),
                        aliases: vec!["display_name".into(), "cn".into()],
                        attribute_type: AttributeType::String,
                        is_list: false,
                        is_visible: true,
                        is_editable: true,
                        is_hardcoded: true,
                        is_readonly: false,
                    },
                    AttributeSchema {
                        name: "firstname".into(),
                        aliases: vec!["first_name".into(), "givenname".into(), "givenName".into()],
                        attribute_type: AttributeType::String,
                        is_list: false,
                        is_visible: true,
                        is_editable: true,
                        is_hardcoded: true,
                        is_readonly: false,
                    },
                    AttributeSchema {
                        name: "lastname".into(),
                        aliases: vec!["last_name".into(), "sn".into()],
                        attribute_type: AttributeType::String,
                        is_list: false,
                        is_visible: true,
                        is_editable: true,
                        is_hardcoded: true,
                        is_readonly: false,
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
                        name: "userid".into(),
                        aliases: vec!["user_id".into(), "uid".into(), "id".into()],
                        attribute_type: AttributeType::String,
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

                    // ==================== POSIX ATTRIBUTES (KDE/GNOME SSO) ====================
                    AttributeSchema {
                        name: "uidnumber".into(),
                        aliases: vec!["uid_number".into(), "uidNumber".into()],
                        attribute_type: AttributeType::Integer,
                        is_list: false,
                        is_visible: true,
                        is_editable: true,
                        is_hardcoded: true,
                        is_readonly: false,
                    },
                    AttributeSchema {
                        name: "gidnumber".into(),
                        aliases: vec!["gid_number".into(), "gidNumber".into()],
                        attribute_type: AttributeType::Integer,
                        is_list: false,
                        is_visible: true,
                        is_editable: true,
                        is_hardcoded: true,
                        is_readonly: false,
                    },
                    AttributeSchema {
                        name: "homedirectory".into(),
                        aliases: vec!["home_directory".into(), "homeDirectory".into()],
                        attribute_type: AttributeType::String,
                        is_list: false,
                        is_visible: true,
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

                    // ==================== KERBEROS ATTRIBUTES ====================
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
                    AttributeSchema {
                        name: "krbprincipalname".into(),
                        aliases: vec!["krb_principal_name".into(), "krbPrincipalName".into()],
                        attribute_type: AttributeType::String,
                        is_list: false,
                        is_visible: false,
                        is_editable: false,
                        is_hardcoded: true,
                        is_readonly: true,
                    },
                ],
            },
            group_attributes: AttributeList {
                attributes: vec![
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
                ],
            },
            extra_user_object_classes: vec![
                "inetOrgPerson".into(),
                "posixAccount".into(),
                // "krbPrincipalAux".into(),  // ← we'll add when Kerberos schema is wired
            ],
            extra_group_object_classes: vec![],
        })
    }

    pub fn get_schema(&self) -> &Schema {
        &self.0
    }
}
