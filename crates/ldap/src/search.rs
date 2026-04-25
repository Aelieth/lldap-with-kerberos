use crate::core::{
    error::{LdapError, LdapResult},
    group::{convert_groups_to_ldap_op, get_groups_list},
    user::{convert_users_to_ldap_op, get_user_list},
    utils::{
        get_group_id_from_distinguished_name, get_user_id_from_distinguished_name,
        get_user_or_group_id_from_distinguished_name, is_container_dn, LdapInfo,
        internal_ou_to_ldap_rdn_chain, is_subtree, parse_distinguished_name, UserOrGroupName,
        get_preferred_ldap_name, get_direct_child_ous, get_internal_ou_from_dn_parts,
    },
};
use chrono::Utc;
use ldap3_proto::{
    LdapFilter, LdapPartialAttribute, LdapResultCode, LdapSearchResultEntry, LdapSearchScope,
    proto::{
        LdapDerefAliases, LdapOp, LdapResult as LdapResultOp, LdapSearchRequest,
        OID_PASSWORD_MODIFY, OID_WHOAMI,
    },
};
use lldap_access_control::UserAndGroupListerBackendHandler;
use lldap_schema::{AttributeSchema, AttributeType, PublicSchema};

#[derive(Debug)]
enum SearchScope {
    Root,
    Container,
    LeafUser,
    LeafGroup,
    Invalid,
    Unknown,
}

fn build_ou_entries(allowed_ous: &[String], base_dn_str: &str) -> Vec<LdapOp> {
    let mut entries = vec![];
    for ou_str in allowed_ous {
        let rdn_chain = internal_ou_to_ldap_rdn_chain(ou_str);
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
            .unwrap_or_else(|| crate::core::utils::DEFAULT_PRIMARY_USER_OU.as_bytes().to_vec());

        entries.push(LdapOp::SearchResultEntry(LdapSearchResultEntry {
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
                    vals: vec![b"TRUE".to_vec()],  // Always TRUE for organizationalUnit containers — required for ADS tree expansion. True dynamic (with member count) can be added later without breaking anything.
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
        }));
    }
    entries
}

fn get_search_scope(
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
        match get_user_or_group_id_from_distinguished_name(&full_dn, base_dn) {
            UserOrGroupName::User(_) => return SearchScope::LeafUser,
            UserOrGroupName::Group(_) => return SearchScope::LeafGroup,
            _ => {}
        }
    }

    if is_container_dn(dn_parts, base_dn, allowed_ous) {
        return SearchScope::Container;
    }

    SearchScope::Unknown
}

pub(crate) fn make_search_request<S: Into<String>>(
    base: &str,
    filter: LdapFilter,
    attrs: Vec<S>,
) -> LdapSearchRequest {
    LdapSearchRequest {
        base: base.to_string(),
        scope: LdapSearchScope::Subtree,
        aliases: LdapDerefAliases::Never,
        sizelimit: 0,
        timelimit: 0,
        typesonly: false,
        filter,
        attrs: attrs.into_iter().map(Into::into).collect(),
    }
}

pub(crate) fn make_search_success() -> LdapOp {
    make_search_error(LdapResultCode::Success, "".to_string())
}

pub(crate) fn make_search_error(code: LdapResultCode, message: String) -> LdapOp {
    LdapOp::SearchResultDone(LdapResultOp {
        code,
        matcheddn: "".to_string(),
        message,
        referral: vec![],
    })
}

pub(crate) fn root_dse_response(base_dn: &str) -> LdapOp {
    let realm = {
        let base_dn = base_dn;
        let domain = base_dn
            .split(',')
            .filter_map(|part| part.strip_prefix("dc="))
            .collect::<Vec<_>>()
            .join(".")
            .to_lowercase();
        std::env::var("LLDAP_KERB_REALM_NAME")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| domain.to_uppercase())
            .to_uppercase()
    };

    let realm_bytes = realm.into_bytes();
    let full_subschema_dn = format!("cn=Subschema,{}", base_dn);

    LdapOp::SearchResultEntry(LdapSearchResultEntry {
        dn: "".to_string(),
        attributes: vec![
            LdapPartialAttribute {
                atype: "objectClass".to_string(),
                vals: vec![b"top".to_vec()],
            },
            LdapPartialAttribute {
                atype: "vendorName".to_string(),
                vals: vec![b"LLDAP".to_vec()],
            },
            LdapPartialAttribute {
                atype: "vendorVersion".to_string(),
                vals: vec![concat!("lldap_", env!("CARGO_PKG_VERSION")).to_string().into_bytes()],
            },
            LdapPartialAttribute {
                atype: "supportedLDAPVersion".to_string(),
                vals: vec![b"3".to_vec()],
            },
            LdapPartialAttribute {
                atype: "supportedExtension".to_string(),
                vals: vec![
                    OID_PASSWORD_MODIFY.as_bytes().to_vec(),
                    OID_WHOAMI.as_bytes().to_vec(),
                ],
            },
            LdapPartialAttribute {
                atype: "supportedControl".to_string(),
                vals: vec![
                    b"1.2.840.113556.1.4.319".to_vec(),
                    b"1.3.6.1.4.1.4203.1.9.1".to_vec(),
                ],
            },
            LdapPartialAttribute {
                atype: "defaultNamingContext".to_string(),
                vals: vec![base_dn.to_string().into_bytes()],
            },
            LdapPartialAttribute {
                atype: "namingContexts".to_string(),
                vals: vec![base_dn.to_string().into_bytes()],
            },
            LdapPartialAttribute {
                atype: "schemaNamingContext".to_string(),
                vals: vec![full_subschema_dn.clone().into_bytes()],
            },
            LdapPartialAttribute {
                atype: "configurationNamingContext".to_string(),
                vals: vec![base_dn.to_string().into_bytes()],
            },
            LdapPartialAttribute {
                atype: "isGlobalCatalogReady".to_string(),
                vals: vec![b"false".to_vec()],
            },
            LdapPartialAttribute {
                atype: "subschemaSubentry".to_string(),
                vals: vec![full_subschema_dn.into_bytes()],
            },
            LdapPartialAttribute {
                atype: "krb5RealmName".to_string(),
                vals: vec![realm_bytes.clone()],
            },
            LdapPartialAttribute {
                atype: "supportedSASLMechanisms".to_string(),
                vals: vec![
                        b"GSSAPI".to_vec(),
                        b"GSS-SPNEGO".to_vec(),
                        b"DIGEST-MD5".to_vec(),
                ],
            },
            LdapPartialAttribute {
                atype: "defaultRealm".to_string(),
                vals: vec![realm_bytes],
            },
        ],
    })
}

pub fn make_ldap_subschema_entry(schema: &PublicSchema, base_dn_str: &str) -> LdapOp {
    // =====================================================================
    // DYNAMIC SUBSCHEMA GENERATOR — Single Source of Truth from PublicSchema
    // =====================================================================
    // This function now builds the subschema at runtime by combining:
    // - Stable RFC standards (ldapSyntaxes, matchingRules, core attributeTypes, base objectClasses)
    // - Dynamically generated LLDAP-specific attributeTypes from schema.user_attributes + schema.group_attributes
    // - Dynamically extended MAY lists for inetOrgPerson, posixAccount, posixGroup
    //
    // Adding a new attribute to PublicSchema automatically makes it appear in subschema
    // with correct NAME, SYNTAX, SINGLE-VALUE, and operational flags.
    // =====================================================================
    // IMPORTANT: The entry DN must be the FULL DN (cn=Subschema,<base DN>) to match
    // what Apache Directory Studio (and most clients) read from Root DSE's
    // subschemaSubentry / schemaNamingContext attribute. Returning a relative "cn=Subschema"
    // causes "No schema information returned by server" fallback.

    let current_time_utc = Utc::now().format("%Y%m%d%H%M%SZ").to_string().into_bytes();

    // Helper: map our AttributeType to LDAP SYNTAX OID + flags
    // Now consistent with utils.rs always_operational list so operational attrs
    // (timestamps, entryUUID, etc.) are correctly marked and hidden by default.
    fn attr_type_to_ldap_syntax(attr: &AttributeSchema) -> (String, bool, bool) {
        let (syntax, is_single) = match attr.attribute_type {
            AttributeType::String => ("1.3.6.1.4.1.1466.115.121.1.15", !attr.is_list),
            AttributeType::Integer => ("1.3.6.1.4.1.1466.115.121.1.27", !attr.is_list),
            AttributeType::DateTime => ("1.3.6.1.4.1.1466.115.121.1.24", !attr.is_list),
            AttributeType::Avatar => ("1.3.6.1.4.1.1466.115.121.1.28", !attr.is_list),
        };
        let name_lower = attr.name.to_ascii_lowercase();
        let is_operational = attr.is_readonly
            || matches!(name_lower.as_str(), "creationdate" | "modifieddate" | "passwordmodifieddate" | "uuid" | "entryuuid");
        (syntax.to_string(), is_single, is_operational)
    }

    // Build dynamic attributeTypes from schema
    let mut dynamic_attr_types: Vec<Vec<u8>> = Vec::new();
    let mut seen_attr_oids: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Core RFC MUST attributes (bold in Studio) — DO NOT DUPLICATE THESE
    let core_entries: Vec<(&str, Vec<u8>)> = vec![
        ("2.5.4.0", b"( 2.5.4.0 NAME 'objectClass' DESC 'RFC4512' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )".to_vec()),
        ("2.5.4.3", b"( 2.5.4.3 NAME ( 'cn' 'commonName' 'displayname' 'display_name' ) DESC 'RFC4519' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} SINGLE-VALUE )".to_vec()),
        ("2.5.4.4", b"( 2.5.4.4 NAME ( 'sn' 'surname' 'lastname' 'last_name' ) DESC 'RFC2256' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} SINGLE-VALUE )".to_vec()),
        ("0.9.2342.19200300.100.1.1", b"( 0.9.2342.19200300.100.1.1 NAME ( 'uid' 'user_id' 'userid' 'id' ) DESC 'User identifier' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} SINGLE-VALUE )".to_vec()),
    ];
    for (oid, entry) in core_entries {
        if seen_attr_oids.insert(oid.to_string()) {
            dynamic_attr_types.push(entry);
        }
    }

    // Additional standard LDAP attributeTypes with proper registered OIDs (prevents 10.99 duplicates
    // and ensures ADS shows correct syntax, matching rules, and flags for givenName, mail, ou, POSIX attrs).
    // These are now the single source for these common attrs; schema aliases map via get_preferred_ldap_name.
    let std_entries: Vec<(&str, Vec<u8>)> = vec![
        ("2.5.4.42", b"( 2.5.4.42 NAME ( 'givenName' 'givenname' 'firstname' 'first_name' ) DESC 'RFC4519 givenName' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} SINGLE-VALUE )".to_vec()),
        ("0.9.2342.19200300.100.1.3", b"( 0.9.2342.19200300.100.1.3 NAME ( 'mail' 'email' 'rfc822Mailbox' ) DESC 'RFC1274/2307 mail' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} SINGLE-VALUE )".to_vec()),
        ("2.5.4.11", b"( 2.5.4.11 NAME ( 'ou' 'organizationalUnit' 'organizationalunit' 'organizationalUnitName' ) DESC 'RFC4519 ou' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} SINGLE-VALUE )".to_vec()),
        ("1.3.6.1.1.1.1.0", b"( 1.3.6.1.1.1.1.0 NAME ( 'uidNumber' 'uidnumber' 'uid_number' 'uidNumber' ) DESC 'RFC2307 uidNumber' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )".to_vec()),
        ("1.3.6.1.1.1.1.1", b"( 1.3.6.1.1.1.1.1 NAME ( 'gidNumber' 'gidnumber' 'gid_number' 'gidNumber' ) DESC 'RFC2307 gidNumber' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )".to_vec()),
        ("1.3.6.1.1.1.1.3", b"( 1.3.6.1.1.1.1.3 NAME ( 'homeDirectory' 'homedirectory' 'home_directory' 'homeDirectory' ) DESC 'RFC2307 homeDirectory' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} SINGLE-VALUE )".to_vec()),
        ("1.3.6.1.1.1.1.4", b"( 1.3.6.1.1.1.1.4 NAME ( 'loginShell' 'loginshell' 'login_shell' 'loginShell' ) DESC 'RFC2307 loginShell' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} SINGLE-VALUE )".to_vec()),
        ("1.3.6.1.1.1.1.8", b"( 1.3.6.1.1.1.1.8 NAME ( 'sshPublicKey' 'sshpublickey' 'sshPublicKey' 'ssHPublicKey' ) DESC 'OpenSSH/LDAP sshPublicKey' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )".to_vec()),
        ("1.3.6.1.4.1.5322.1.1.2", b"( 1.3.6.1.4.1.5322.1.1.2 NAME ( 'krbPrincipalName' 'krb_principal_name' 'krbPrincipalName' ) DESC 'Kerberos principal name' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )".to_vec()),
    ];
    for (oid, entry) in std_entries {
        if seen_attr_oids.insert(oid.to_string()) {
            dynamic_attr_types.push(entry);
        }
    }

    // Attributes that already have proper hardcoded definitions above (or operational below).
    // Skip them in the dynamic loop to eliminate ALL duplication (the root cause of
    // "subschema error", conflicting attributeTypes, and 10.99 spam in Apache Directory Studio).
    // Note: LLDAP-specific (avatar, kerberossync, groupid) are intentionally NOT here so dynamic
    // adds them with their custom OIDs. sshPublicKey now uses standard OID above.
    let already_covered: std::collections::HashSet<&str> = [
        "objectclass", "cn", "sn", "uid",
        "givenname", "mail", "ou", "uidnumber", "gidnumber", "homedirectory", "loginshell", "sshpublickey",
        "displayname", "firstname", "lastname", "jpegphoto",
        // Timestamps + operational (to prevent dynamic 10.99 + later duplicate push)
        "createtimestamp", "createTimestamp", "creationdate", "creation_date", "creationTimestamp",
        "modifytimestamp", "modifyTimestamp", "modifieddate", "modified_date", "modifydate",
        "pwdchangedtime", "pwdChangedTime", "passwordmodifieddate", "password_modified_date",
        "entryuuid", "entryUUID", "uuid",
        "hasSubordinates", "structuralObjectClass", "subschemaSubentry", "memberof", "memberOf",
        "krbprincipalname", "krb_principal_name", "krbPrincipalName",
    ].iter().cloned().collect();

    // Only add TRULY NEW / custom attributes from PublicSchema (future-proof)
    for attr in schema.user_attributes().attributes.iter().chain(schema.group_attributes().attributes.iter()) {
        let preferred = get_preferred_ldap_name(attr);
        if already_covered.contains(preferred.to_ascii_lowercase().as_str()) {
            continue; // already defined with correct OID, syntax, and flags
        }

        let (syntax, is_single, is_operational) = attr_type_to_ldap_syntax(attr);
        let single_str = if is_single { " SINGLE-VALUE" } else { "" };
        let op_str = if is_operational { " NO-USER-MODIFICATION USAGE directoryOperation" } else { "" };

        let name_list = if attr.aliases.is_empty() {
            format!("'{}'", preferred)
        } else {
            let mut names = vec![format!("'{}'", preferred)];
            for a in &attr.aliases {
                if a != &preferred {
                    names.push(format!("'{}'", a));
                }
            }
            names.join(" ")
        };

        let desc = format!("LLDAP {} ({})", attr.name, if attr.is_list { "multi" } else { "single" });
        let oid = match attr.name.as_str() {
            "avatar" => "10.0",
            "sshpublickey" => "10.1",
            "kerberossync" => "1.3.6.1.4.1.5322.1.1.1",
            "groupid" => "10.2",
            _ => "10.99", // only for future truly custom attrs
        };

        let entry = format!(
            "( {} NAME ( {} ) DESC '{}' EQUALITY {} SYNTAX {}{}{} )",
            oid,
            name_list,
            desc,
            if attr.attribute_type == AttributeType::Integer { "integerMatch" } else { "caseIgnoreMatch" },
            syntax,
            single_str,
            op_str
        );
        if seen_attr_oids.insert(oid.to_string()) {
            dynamic_attr_types.push(entry.into_bytes());
        }
    }

    // Add operational attributes (italic in Studio)
    let op_entries: Vec<(&str, Vec<u8>)> = vec![
        ("1.3.6.1.1.16.4", b"( 1.3.6.1.1.16.4 NAME ( 'entryUUID' 'uuid' ) DESC 'UUID' EQUALITY UUIDMatch ORDERING UUIDOrderingMatch SYNTAX 1.3.6.1.1.16.1 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )".to_vec()),
        ("2.5.18.1", b"( 2.5.18.1 NAME ( 'createTimestamp' 'creationdate' 'creation_date' 'creationTimestamp' ) DESC 'RFC4512' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )".to_vec()),
        ("2.5.18.2", b"( 2.5.18.2 NAME ( 'modifyTimestamp' 'modifieddate' 'modified_date' 'modifydate' 'modifyTimestamp' ) DESC 'RFC4512' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )".to_vec()),
        ("1.2.840.113556.1.2.102", b"( 1.2.840.113556.1.2.102 NAME 'memberOf' DESC 'Group membership' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 NO-USER-MODIFICATION USAGE dSAOperation )".to_vec()),
        ("1.3.6.1.4.1.1466.101.120.6", b"( 1.3.6.1.4.1.1466.101.120.6 NAME 'hasSubordinates' DESC 'X.500 Has Subordinates' EQUALITY booleanMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )".to_vec()),
        ("2.5.21.1", b"( 2.5.21.1 NAME 'structuralObjectClass' DESC 'X.500 Structural Object Class' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )".to_vec()),
        ("2.5.21.2", b"( 2.5.21.2 NAME 'subschemaSubentry' DESC 'X.500 Subschema Subentry' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )".to_vec()),
        ("1.3.6.1.4.1.42.2.27.8.1.16", b"( 1.3.6.1.4.1.42.2.27.8.1.16 NAME ( 'pwdChangedTime' 'passwordmodifieddate' 'password_modified_date' ) DESC 'Password last changed time' EQUALITY generalizedTimeMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE NO-USER-MODIFICATION USAGE dSAOperation )".to_vec()),
    ];
    for (oid, entry) in op_entries {
        if seen_attr_oids.insert(oid.to_string()) {
            dynamic_attr_types.push(entry);
        }
    }

    // Build dynamic MAY list for inetOrgPerson — clean, stable, and ADS-compatible.
    // Only include standard + LLDAP user attributes. Never pollute with operational attrs
    // (createTimestamp, entryUUID, etc.) or core MUST attrs (cn, sn) — those are handled elsewhere.
    // This prevents the "No schema information returned by server" regression in Apache Directory Studio.
    let mut inet_may: Vec<String> = vec![
        "givenName".into(), "mail".into(), "uid".into(), "displayName".into(),
        "employeeNumber".into(), "employeeType".into(), "jpegPhoto".into(), "labeledURI".into(),
        "manager".into(), "mobile".into(), "pager".into(), "photo".into(), "roomNumber".into(),
        "secretary".into(), "uidNumber".into(), "gidNumber".into(), "homeDirectory".into(),
        "loginShell".into(), "sshPublicKey".into(), "krbPrincipalName".into(), "ou".into(),
        "avatar".into(), "description".into(), "kerberosSync".into(),
    ];
    // Add any truly extra custom schema attrs (case-insensitive dedup)
    let mut seen: std::collections::HashSet<String> = inet_may.iter().map(|s| s.to_ascii_lowercase()).collect();
    for attr in schema.user_attributes().attributes.iter() {
        let pref = get_preferred_ldap_name(attr);
        let lower = pref.to_ascii_lowercase();
        if !seen.contains(&lower) {
            seen.insert(lower);
            inet_may.push(pref);
        }
    }
    let inet_may_str = inet_may.join(" $ ");

    // Build dynamic MAY for posixAccount / posixGroup (extend with schema)
    let posix_user_may = "userPassword $ loginShell $ gecos $ description $ sshPublicKey $ avatar $ kerberosSync".to_string();
    let posix_group_may = "userPassword $ memberUid $ description $ gidNumber".to_string();

    LdapOp::SearchResultEntry(LdapSearchResultEntry {
        dn: format!("cn=Subschema,{}", base_dn_str),
        attributes: vec![
            LdapPartialAttribute {
                atype: "structuralObjectClass".to_string(),
                vals: vec![b"subentry".to_vec()],
            },
            LdapPartialAttribute {
                atype: "objectClass".to_string(),
                vals: vec![b"top".to_vec(), b"subentry".to_vec(), b"subschema".to_vec(), b"extensibleObject".to_vec()],
            },
            LdapPartialAttribute {
                atype: "cn".to_string(),
                vals: vec![b"Subschema".to_vec()],
            },
            LdapPartialAttribute {
                atype: "createTimestamp".to_string(),
                vals: vec![current_time_utc.clone()],
            },
            LdapPartialAttribute {
                atype: "modifyTimestamp".to_string(),
                vals: vec![current_time_utc],
            },
            LdapPartialAttribute {
                atype: "ldapSyntaxes".to_string(),
                vals: vec![
                    b"( 1.3.6.1.1.16.1 DESC 'UUID' )".to_vec(),
                    b"( 1.3.6.1.4.1.1466.115.121.1.3 DESC 'Attribute Type Description' )".to_vec(),
                    b"( 1.3.6.1.4.1.1466.115.121.1.12 DESC 'Distinguished Name' )".to_vec(),
                    b"( 1.3.6.1.4.1.1466.115.121.1.15 DESC 'Directory String' )".to_vec(),
                    b"( 1.3.6.1.4.1.1466.115.121.1.24 DESC 'Generalized Time' )".to_vec(),
                    b"( 1.3.6.1.4.1.1466.115.121.1.27 DESC 'Integer' )".to_vec(),
                    b"( 1.3.6.1.4.1.1466.115.121.1.28 DESC 'JPEG' X-NOT-HUMAN-READABLE 'TRUE' )".to_vec(),
                    b"( 1.3.6.1.4.1.1466.115.121.1.34 DESC 'Name And Optional UID' )".to_vec(),
                    b"( 1.3.6.1.4.1.1466.115.121.1.37 DESC 'Object Class Description' )".to_vec(),
                    b"( 1.3.6.1.4.1.1466.115.121.1.38 DESC 'OID' )".to_vec(),
                    b"( 1.3.6.1.4.1.1466.115.121.1.54 DESC 'LDAP Syntax Description' )".to_vec(),
                    b"( 1.3.6.1.4.1.1466.115.121.1.58 DESC 'Substring Assertion' )".to_vec(),
                ],
            },
            LdapPartialAttribute {
                atype: "matchingRules".to_string(),
                vals: vec![
                    b"( 1.3.6.1.1.16.2 NAME 'UUIDMatch' SYNTAX 1.3.6.1.1.16.1 )".to_vec(),
                    b"( 1.3.6.1.1.16.3 NAME 'UUIDOrderingMatch' SYNTAX 1.3.6.1.1.16.1 )".to_vec(),
                    b"( 2.5.13.0 NAME 'objectIdentifierMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )".to_vec(),
                    b"( 2.5.13.1 NAME 'distinguishedNameMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )".to_vec(),
                    b"( 2.5.13.2 NAME 'caseIgnoreMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )".to_vec(),
                    b"( 2.5.13.4 NAME 'caseIgnoreSubstringsMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )".to_vec(),
                    b"( 2.5.13.23 NAME 'uniqueMemberMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.34 )".to_vec(),
                    b"( 2.5.13.27 NAME 'generalizedTimeMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 )".to_vec(),
                    b"( 2.5.13.28 NAME 'generalizedTimeOrderingMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 )".to_vec(),
                    b"( 2.5.13.30 NAME 'objectIdentifierFirstComponentMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )".to_vec(),
                ],
            },
            LdapPartialAttribute {
                atype: "attributeTypes".to_string(),
                vals: dynamic_attr_types,
            },
            LdapPartialAttribute {
                atype: "objectClasses".to_string(),
                vals: vec![
                    b"( 2.5.6.0 NAME 'top' DESC 'RFC4512' ABSTRACT MUST objectClass )".to_vec(),
                    b"( 2.5.6.6 NAME 'person' DESC 'RFC4519' STRUCTURAL MUST ( cn $ sn $ objectClass ) MAY ( userPassword $ telephoneNumber $ seeAlso $ description $ givenName $ mail ) )".to_vec(),
                    b"( 2.5.6.7 NAME 'organizationalPerson' DESC 'RFC4519' STRUCTURAL SUP person MAY ( title $ ou $ o $ l $ st $ postalAddress ) )".to_vec(),
                    // inetOrgPerson with DYNAMIC MAY list
                    format!(
                        "( 1.3.6.1.1.3.1 NAME 'inetOrgPerson' DESC 'RFC2798' STRUCTURAL SUP organizationalPerson MUST ( cn $ sn $ objectClass ) MAY ( {} ) )",
                        inet_may_str
                    ).into_bytes(),
                    // posixAccount with extended MAY
                    format!(
                        "( 1.3.6.1.1.1.2.0 NAME 'posixAccount' DESC 'RFC2307' STRUCTURAL MUST ( cn $ uid $ uidNumber $ gidNumber $ homeDirectory $ objectClass ) MAY ( {} ) )",
                        posix_user_may
                    ).into_bytes(),
                    b"( 2.5.6.9 NAME 'groupOfNames' DESC 'RFC4519' STRUCTURAL MUST ( member $ cn $ objectClass ) MAY ( businessCategory $ seeAlso $ owner $ ou $ o $ description ) )".to_vec(),
                    b"( 2.5.6.17 NAME 'groupOfUniqueNames' DESC 'RFC4519' STRUCTURAL MUST ( uniqueMember $ cn $ objectClass ) MAY ( businessCategory $ seeAlso $ owner $ ou $ o $ description ) )".to_vec(),
                    // posixGroup with extended MAY
                    format!(
                        "( 1.3.6.1.1.1.2.2 NAME 'posixGroup' DESC 'RFC2307' STRUCTURAL MUST ( cn $ gidNumber $ objectClass ) MAY ( {} ) )",
                        posix_group_may
                    ).into_bytes(),
                ],
            },
            LdapPartialAttribute {
                atype: "subschemaSubentry".to_string(),
                vals: vec![format!("cn=Subschema,{}", base_dn_str).into_bytes()],
            },
        ],
    })
}

pub(crate) fn is_root_dse_request(request: &LdapSearchRequest) -> bool {
    request.base.is_empty()
        && request.scope == LdapSearchScope::Base
        && matches!(&request.filter, LdapFilter::Present(attr) if attr.eq_ignore_ascii_case("objectclass"))
}

pub(crate) fn is_subschema_entry_request(request: &LdapSearchRequest) -> bool {
    let base_lower = request.base.to_ascii_lowercase();
    // Extremely tolerant detection for Apache Directory Studio + all major clients:
    // - Accepts "cn=Subschema" (relative) or full "cn=Subschema,dc=...,dc=..."
    // - Base or Subtree scope
    // - Any filter that mentions objectClass (Present, Equality to *, top, subschema, or complex And/Or)
    let base_matches = base_lower.contains("cn=subschema");
    let scope_ok = matches!(request.scope, LdapSearchScope::Base | LdapSearchScope::Subtree);
    let filter_ok = match &request.filter {
        LdapFilter::Present(attr) => attr.eq_ignore_ascii_case("objectclass"),
        LdapFilter::Equality(attr, val) => {
            attr.eq_ignore_ascii_case("objectclass")
                && (val == "*" || val.eq_ignore_ascii_case("top") || val.eq_ignore_ascii_case("subschema"))
        }
        LdapFilter::And(filters) | LdapFilter::Or(filters) => {
            filters.iter().any(|f| {
                if let LdapFilter::Equality(a, _v) = f {
                    a.eq_ignore_ascii_case("objectclass")
                } else {
                    false
                }
            })
        }
        _ => true,
    };
    base_matches && scope_ok && filter_ok
}

pub async fn do_search<Backend>(
    backend: &Backend,
    ldap_info: &LdapInfo,
    request: &LdapSearchRequest,
    allowed_ous: &[String],
) -> LdapResult<Vec<LdapOp>>
where
    Backend: UserAndGroupListerBackendHandler,
{
    let base_dn = &ldap_info.base_dn;
    let dn_parts = match parse_distinguished_name(&request.base) {
        Ok(p) => p,
        Err(_) => return Ok(vec![make_search_success()]),
    };

    let scope = get_search_scope(base_dn, &dn_parts, &request.scope, allowed_ous);

    match scope {
        SearchScope::Root => {
            if request.scope == LdapSearchScope::Base {
                // Return the root naming context entry for base searches
                // Derive dc and o dynamically from the live base_dn (no deployment hardcodes)
                let dc_val = base_dn.iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("dc"))
                    .map(|(_, v)| v.as_bytes().to_vec())
                    .unwrap_or_else(|| b"lldap".to_vec());
                let o_val = base_dn.iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("o"))
                    .map(|(_, v)| v.as_bytes().to_vec())
                    .unwrap_or_else(|| b"LLDAP Directory".to_vec());
                let root_entry = LdapSearchResultEntry {
                    dn: ldap_info.base_dn_str.clone(),
                    attributes: vec![
                        LdapPartialAttribute {
                            atype: "objectClass".to_string(),
                            vals: vec![b"top".to_vec(), b"dcObject".to_vec(), b"organization".to_vec()],
                        },
                        LdapPartialAttribute {
                            atype: "dc".to_string(),
                            vals: vec![dc_val],
                        },
                        LdapPartialAttribute {
                            atype: "o".to_string(),
                            vals: vec![o_val],
                        },
                        LdapPartialAttribute {
                            atype: "hasSubordinates".to_string(),
                            vals: vec![b"TRUE".to_vec()],
                        },
                        LdapPartialAttribute {
                            atype: "structuralObjectClass".to_string(),
                            vals: vec![b"organization".to_vec()],
                        },
                        LdapPartialAttribute {
                            atype: "subschemaSubentry".to_string(),
                            vals: vec![format!("cn=Subschema,{}", ldap_info.base_dn_str).into_bytes()],
                        },
                    ],
                };
                return Ok(vec![LdapOp::SearchResultEntry(root_entry), make_search_success()]);
            }
            // At the root level:
            // - OneLevel: only top-level OUs (standard "containers first" view)
            // - Subtree: top-level OUs + all users + all groups (so broad searches/filters work)
            let top_level_ous = get_direct_child_ous("", allowed_ous);
            let mut results = build_ou_entries(&top_level_ous, &ldap_info.base_dn_str);

            if request.scope == LdapSearchScope::Subtree {
                // Include matching users + groups under the entire tree
                let user_results = get_user_list(
                    ldap_info,
                    &request.filter,
                    true,
                    &request.base,
                    backend,
                    &PublicSchema::get(),
                ).await?;
                results.extend(convert_users_to_ldap_op(
                    user_results,
                    &request.attrs,
                    ldap_info,
                    &PublicSchema::get(),
                ));

                let group_results = get_groups_list(
                    ldap_info,
                    &request.filter,
                    &request.base,
                    backend,
                    &PublicSchema::get(),
                ).await?;
                results.extend(convert_groups_to_ldap_op(
                    group_results,
                    &request.attrs,
                    ldap_info,
                    &None,
                    &PublicSchema::get(),
                ));
            }

            results.push(make_search_success());
            Ok(results)
        }
        SearchScope::Container => {
            let mut results = vec![];

            // Robust internal OU computation (supports arbitrary nesting "office\floor1\room3")
            let internal_ou = get_internal_ou_from_dn_parts(&dn_parts);

            if request.scope == LdapSearchScope::Base {
                // Base search on a container OU: return ONLY the OU entry itself.
                // (Prevents "ou=people under ou=people" nesting loop when client does OneLevel/Subtree.)
                let rdn_chain = internal_ou_to_ldap_rdn_chain(&internal_ou);
                let ou_part: String = rdn_chain
                    .iter()
                    .map(|(k, v)| format!("{}={}", k, v))
                    .collect::<Vec<_>>()
                    .join(",");
                let dn = if ou_part.is_empty() {
                    ldap_info.base_dn_str.clone()
                } else {
                    format!("{},{}", ou_part, ldap_info.base_dn_str)
                };
                let leaf_ou_val = rdn_chain
                    .first()
                    .map(|(_, v)| v.as_bytes().to_vec())
                    .unwrap_or_else(|| crate::core::utils::DEFAULT_PRIMARY_USER_OU.as_bytes().to_vec());
                let ou_entry = LdapSearchResultEntry {
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
                            vals: vec![format!("cn=Subschema,{}", ldap_info.base_dn_str).into_bytes()],
                        },
                    ],
                };
                results.push(LdapOp::SearchResultEntry(ou_entry));
            } else {
                // OneLevel or Subtree on container:
                // - Always include direct (OneLevel) or all descendant (Subtree) OU *containers* first.
                //   This makes the hierarchy visible in ADS tree view / schema browser.
                // - Then include matching users/groups (trusting the per-entry "ou" attribute + backend).
                // Child OUs
                let child_ous: Vec<String> = if request.scope == LdapSearchScope::OneLevel {
                    get_direct_child_ous(&internal_ou, allowed_ous)
                } else {
                    // Subtree: all OUs under this container (deep nesting supported)
                    let curr_l = internal_ou.to_ascii_lowercase();
                    allowed_ous
                        .iter()
                        .filter(|ou| {
                            let ou_l = ou.to_ascii_lowercase();
                            !curr_l.is_empty() && ou_l.starts_with(&format!("{}\\", curr_l))
                        })
                        .cloned()
                        .collect()
                };
                if !child_ous.is_empty() {
                    results.extend(build_ou_entries(&child_ous, &ldap_info.base_dn_str));
                }

                // Users + Groups — trust the backend + the per-entry "ou" attribute.
                // The conversion layer already builds correct DNs using get_user_ou() / get_group_ou().
                // (Removed overzealous "uid"/"cn" presence guard — it dropped valid entries when
                // client (e.g. ADS tree expansion) did not request the naming attribute in attrs list.
                // User/group results are already type-safe; no OU containers can leak here.)
                let user_results = get_user_list(
                    ldap_info,
                    &request.filter,
                    true,
                    &request.base,
                    backend,
                    &PublicSchema::get(),
                ).await?;
                let mut user_ops: Vec<LdapOp> = convert_users_to_ldap_op(
                    user_results,
                    &request.attrs,
                    ldap_info,
                    &PublicSchema::get(),
                )
                .collect();

                let group_results = get_groups_list(
                    ldap_info,
                    &request.filter,
                    &request.base,
                    backend,
                    &PublicSchema::get(),
                ).await?;
                let mut group_ops: Vec<LdapOp> = convert_groups_to_ldap_op(
                    group_results,
                    &request.attrs,
                    ldap_info,
                    &None,
                    &PublicSchema::get(),
                )
                .collect();

                // Unified correct filtering for ADS compatibility (OneLevel + Subtree on containers).
                // - Always: only entries whose DN is under this subtree (ends_with base).
                // - OneLevel: additionally only direct children (RDN count == parent + 1).
                // - Subtree: includes descendants (nested OUs + their users/groups).
                // This fixes "primary OUs flat / nothing under them" when uid/cn not requested,
                // and prevents returning users/groups from sibling OUs on Subtree searches.
                {
                    let base_lower = request.base.to_ascii_lowercase();
                    let expected_rdn_count = dn_parts.len() + 1;

                    let is_one_level = request.scope == LdapSearchScope::OneLevel;

                    user_ops.retain(|op| {
                        if let LdapOp::SearchResultEntry(e) = op {
                            if let Ok(parts) = parse_distinguished_name(&e.dn) {
                                let under = e.dn.to_ascii_lowercase().ends_with(&base_lower);
                                if is_one_level {
                                    under && parts.len() == expected_rdn_count
                                } else {
                                    under
                                }
                            } else {
                                false
                            }
                        } else {
                            true
                        }
                    });

                    group_ops.retain(|op| {
                        if let LdapOp::SearchResultEntry(e) = op {
                            if let Ok(parts) = parse_distinguished_name(&e.dn) {
                                let under = e.dn.to_ascii_lowercase().ends_with(&base_lower);
                                if is_one_level {
                                    under && parts.len() == expected_rdn_count
                                } else {
                                    under
                                }
                            } else {
                                false
                            }
                        } else {
                            true
                        }
                    });
                }

                results.extend(user_ops);
                results.extend(group_ops);
            }
            results.push(make_search_success());
            Ok(results)
        }
        SearchScope::LeafUser => {
            let user_id = match get_user_id_from_distinguished_name(
                &request.base,
                base_dn,
                &ldap_info.base_dn_str,
            ) {
                Ok(id) => id,
                Err(_) => return Ok(vec![make_search_success()]),
            };
            let filter = LdapFilter::Equality("uid".to_string(), user_id.to_string());
            let users = get_user_list(
                ldap_info,
                &filter,
                true,
                &request.base,
                backend,
                &PublicSchema::get(),
            ).await?;
            let mut results: Vec<LdapOp> = convert_users_to_ldap_op(
                users,
                &request.attrs,
                ldap_info,
                &PublicSchema::get(),
            ).collect();
            if results.is_empty() {
                return Err(LdapError {
                    code: LdapResultCode::NoSuchObject,
                    message: "".to_string(),
                });
            }
            results.push(make_search_success());
            Ok(results)
        }
        SearchScope::LeafGroup => {
            let group_name = match get_group_id_from_distinguished_name(
                &request.base,
                base_dn,
                &ldap_info.base_dn_str,
            ) {
                Ok(name) => name,
                Err(_) => return Ok(vec![make_search_success()]),
            };
            let filter = LdapFilter::Equality("cn".to_string(), group_name.to_string());
            let groups = get_groups_list(
                ldap_info,
                &filter,
                &request.base,
                backend,
                &PublicSchema::get(),
            ).await?;
            let mut results: Vec<LdapOp> = convert_groups_to_ldap_op(
                groups,
                &request.attrs,
                ldap_info,
                &None,
                &PublicSchema::get(),
            ).collect();
            if results.is_empty() {
                return Err(LdapError {
                    code: LdapResultCode::NoSuchObject,
                    message: "".to_string(),
                });
            }
            results.push(make_search_success());
            Ok(results)
        }
        SearchScope::Invalid | SearchScope::Unknown => Ok(vec![make_search_success()]),
    }
}
