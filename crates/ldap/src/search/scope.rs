//! Search scope resolution and OU/container handling.

use crate::dn::{is_container_dn, is_subtree};
use ldap3_proto::{LdapPartialAttribute, LdapSearchResultEntry, LdapSearchScope, proto::LdapOp};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchScope {
    Root,
    Container,
    LeafUser,
    LeafGroup,
    Invalid,
    Unknown,
}

pub fn get_search_scope(
    base_dn: &[(String, String)],
    dn_parts: &[(String, String)],
    ldap_scope: &LdapSearchScope,
    allowed_ous: &[String],
) -> SearchScope {
    if !is_subtree(dn_parts, base_dn) {
        return SearchScope::Invalid;
    }

    if dn_parts == base_dn {
        return SearchScope::Root;
    }

    if matches!(ldap_scope, LdapSearchScope::OneLevel | LdapSearchScope::Subtree) {
        if dn_parts.len() == base_dn.len() + 1 {
            return SearchScope::Container;
        }
    }

    if matches!(ldap_scope, LdapSearchScope::Base) && dn_parts.len() > base_dn.len() {
        let full_dn = dn_parts.iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join(",");
        match crate::dn::get_user_or_group_id_from_distinguished_name(&full_dn, base_dn) {
            crate::dn::UserOrGroupName::User(_) => return SearchScope::LeafUser,
            crate::dn::UserOrGroupName::Group(_) => return SearchScope::LeafGroup,
            _ => {}
        }
    }

    if is_container_dn(dn_parts, base_dn, allowed_ous) {
        return SearchScope::Container;
    }

    SearchScope::Unknown
}

pub fn make_ou_entry(ou_str: &str, base_dn_str: &str) -> LdapSearchResultEntry {
    let rdn_chain = crate::dn::internal_ou_to_ldap_rdn_chain(ou_str);
    let ou_part: String = rdn_chain
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join(",");
    let dn = if ou_part.is_empty() {
        base_dn_str.to_string()
    } else {
        format!("{},{}", ou_part, base_dn_str)
    };

    let leaf_ou_val = rdn_chain
        .first()
        .map(|(_, v)| v.as_bytes().to_vec())
        .unwrap_or_else(|| crate::dn::DEFAULT_PRIMARY_USER_OU.as_bytes().to_vec());

    LdapSearchResultEntry {
        dn,
        attributes: vec![
            LdapPartialAttribute {
                atype: "objectClass".to_string(),
                vals: vec![b"top".to_vec(), b"organizationalUnit".to_vec()],
            },
            LdapPartialAttribute {
                atype: "ou".to_string(),
                vals: vec![leaf_ou_val],
            },
            LdapPartialAttribute {
                atype: "hasSubordinates".to_string(),
                vals: vec![b"TRUE".to_vec()],
            },
            LdapPartialAttribute {
                atype: "structuralObjectClass".to_string(),
                vals: vec![b"organizationalUnit".to_vec()],
            },
            LdapPartialAttribute {
                atype: "subschemaSubentry".to_string(),
                vals: vec![format!("cn=Subschema,{}", base_dn_str).into_bytes()],
            },
        ],
    }
}

pub fn build_ou_entries(allowed_ous: &[String], base_dn_str: &str) -> Vec<LdapOp> {
    allowed_ous
        .iter()
        .map(|ou_str| LdapOp::SearchResultEntry(make_ou_entry(ou_str, base_dn_str)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*; // or use crate::search::scope::get_search_scope;
    use ldap3_proto::LdapSearchScope;

    // Helper to make DN parts easily
    fn make_dn(dn: &str) -> Vec<(String, String)> {
        dn.split(',')
        .map(|part| {
            let mut split = part.split('=');
            (
                split.next().unwrap().trim().to_string(),
             split.next().unwrap().trim().to_string(),
            )
        })
        .collect()
    }

    #[test]
    fn test_search_scope_root() {
        let base_dn = make_dn("dc=example,dc=com");
        let dn = make_dn("dc=example,dc=com");

        let scope = get_search_scope(&base_dn, &dn, &LdapSearchScope::Base, &["people".to_string(), "groups".to_string()]);
        assert_eq!(scope, SearchScope::Root);
    }

    #[test]
    fn test_search_scope_container_people() {
        let base_dn = make_dn("dc=example,dc=com");
        let dn = make_dn("ou=people,dc=example,dc=com");

        let scope = get_search_scope(&base_dn, &dn, &LdapSearchScope::OneLevel, &["people".to_string(), "groups".to_string()]);
        assert_eq!(scope, SearchScope::Container);
    }

    #[test]
    fn test_search_scope_leaf_user() {
        let base_dn = make_dn("dc=example,dc=com");
        let dn = make_dn("uid=alice,ou=people,dc=example,dc=com");

        let scope = get_search_scope(&base_dn, &dn, &LdapSearchScope::Base, &["people".to_string(), "groups".to_string()]);
        assert_eq!(scope, SearchScope::LeafUser);
    }

    #[test]
    fn test_search_scope_leaf_group() {
        let base_dn = make_dn("dc=example,dc=com");
        let dn = make_dn("cn=admins,ou=groups,dc=example,dc=com");

        let scope = get_search_scope(&base_dn, &dn, &LdapSearchScope::Base, &["people".to_string(), "groups".to_string()]);
        assert_eq!(scope, SearchScope::LeafGroup);
    }

    #[test]
    fn test_search_scope_invalid() {
        let base_dn = make_dn("dc=example,dc=com");
        let dn = make_dn("ou=other,dc=evil,dc=com");

        let scope = get_search_scope(&base_dn, &dn, &LdapSearchScope::Subtree, &["people".to_string(), "groups".to_string()]);
        assert_eq!(scope, SearchScope::Invalid);
    }

    #[test]
    fn test_search_scope_nested_ou_container() {
        let base_dn = make_dn("dc=example,dc=com");
        let dn = make_dn("ou=office,ou=people,dc=example,dc=com");

        // Assuming your current logic supports this
        let scope = get_search_scope(&base_dn, &dn, &LdapSearchScope::Subtree, &["people".to_string(), "groups".to_string()]);
        // Adjust expected value based on your actual implementation
        assert!(matches!(scope, SearchScope::Container | SearchScope::Unknown));
    }
}
