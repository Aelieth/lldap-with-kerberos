#[derive(Clone, Debug, PartialEq)]
pub struct AttributeDescription<'a> {
    pub attribute_identifier: &'a str,
    pub attribute_name: &'a str,
    pub aliases: Vec<&'a str>,
}

pub mod group {
    use super::AttributeDescription;

    pub fn resolve_group_attribute_description(name: &'_ str) -> Option<AttributeDescription<'_>> {
        match name {
            "creation_date" => Some(AttributeDescription {
                attribute_identifier: name,
                attribute_name: "creationdate",
                aliases: vec![name, "createtimestamp"],
            }),
            "modified_date" => Some(AttributeDescription {
                attribute_identifier: name,
                attribute_name: "modifydate",
                aliases: vec![name, "modifytimestamp"],
            }),
            "display_name" => Some(AttributeDescription {
                attribute_identifier: name,
                attribute_name: "displayname",
                aliases: vec![name, "cn", "uid", "id"],
            }),
            "group_id" => Some(AttributeDescription {
                attribute_identifier: name,
                attribute_name: "groupid",
                aliases: vec![name],
            }),
            "uuid" => Some(AttributeDescription {
                attribute_identifier: name,
                attribute_name: name,
                aliases: vec!["entryuuid"],
            }),
            _ => None,
        }
    }

    pub fn resolve_group_attribute_description_or_default(name: &'_ str) -> AttributeDescription<'_> {
        match resolve_group_attribute_description(name) {
            Some(d) => d,
            None => AttributeDescription {
                attribute_identifier: name,
                attribute_name: name,
                aliases: vec![],
            },
        }
    }
}

pub mod user {
    use super::AttributeDescription;

    pub fn resolve_user_attribute_description(name: &'_ str) -> Option<AttributeDescription<'_>> {
        match name {
            // === Our Kerberos / POSIX attributes ===
            "uidnumber" => Some(AttributeDescription {
                attribute_identifier: name,
                attribute_name: "uidnumber",
                aliases: vec!["uid_number", "uidNumber"],
            }),
            "gidnumber" => Some(AttributeDescription {
                attribute_identifier: name,
                attribute_name: "gidnumber",
                aliases: vec!["gid_number", "gidNumber"],
            }),
            "loginshell" => Some(AttributeDescription {
                attribute_identifier: name,
                attribute_name: "loginshell",
                aliases: vec!["login_shell", "loginShell"],
            }),
            "kerberossync" => Some(AttributeDescription {
                attribute_identifier: name,
                attribute_name: "kerberossync",
                aliases: vec!["kerberos_sync", "kerberosSync"],
            }),

            // === Original upstream attributes ===
            "avatar" => Some(AttributeDescription {
                attribute_identifier: name,
                attribute_name: name,
                aliases: vec!["jpegphoto"],
            }),
            "creation_date" => Some(AttributeDescription {
                attribute_identifier: name,
                attribute_name: "creationdate",
                aliases: vec![name, "createtimestamp"],
            }),
            "modified_date" => Some(AttributeDescription {
                attribute_identifier: name,
                attribute_name: "modifydate",
                aliases: vec![name, "modifytimestamp"],
            }),
            "password_modified_date" => Some(AttributeDescription {
                attribute_identifier: name,
                attribute_name: "passwordmodifydate",
                aliases: vec![name, "pwdchangedtime"],
            }),
            "display_name" => Some(AttributeDescription {
                attribute_identifier: name,
                attribute_name: "displayname",
                aliases: vec![name, "cn"],
            }),
            "first_name" => Some(AttributeDescription {
                attribute_identifier: name,
                attribute_name: "firstname",
                aliases: vec![name, "givenname"],
            }),
            "last_name" => Some(AttributeDescription {
                attribute_identifier: name,
                attribute_name: "lastname",
                aliases: vec![name, "sn"],
            }),
            "mail" => Some(AttributeDescription {
                attribute_identifier: name,
                attribute_name: name,
                aliases: vec!["email"],
            }),
            "user_id" => Some(AttributeDescription {
                attribute_identifier: name,
                attribute_name: "userid",
                aliases: vec![name, "id"],
            }),
            "uuid" => Some(AttributeDescription {
                attribute_identifier: name,
                attribute_name: name,
                aliases: vec!["entryuuid"],
            }),
            _ => None,
        }
    }

    pub fn resolve_user_attribute_description_or_default(name: &'_ str) -> AttributeDescription<'_> {
        match resolve_user_attribute_description(name) {
            Some(d) => d,
            None => AttributeDescription {
                attribute_identifier: name,
                attribute_name: name,
                aliases: vec![],
            },
        }
    }
}
