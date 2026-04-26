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
