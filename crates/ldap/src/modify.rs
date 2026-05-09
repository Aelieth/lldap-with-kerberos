// crates/ldap/src/modify.rs
// LDAP Modify — currently only supports password changes (userPassword Replace)
// All other attribute modifications go through the GraphQL layer (protected by schema read-only flags)

use crate::{
    core::{
        error::{LdapError, LdapResult},
        utils::{LdapInfo, get_user_id_from_distinguished_name},
    },
    handler::make_modify_response,
    password,
};
use ldap3_proto::proto::{LdapModify, LdapModifyRequest, LdapModifyType, LdapOp, LdapResultCode};
use lldap_access_control::UserReadableBackendHandler;
use lldap_auth::access_control::ValidationResults;
use lldap_domain::types::UserId;
use lldap_opaque_handler::OpaqueHandler;
use tracing::warn;

async fn handle_modify_change(
    readable_handler: &impl UserReadableBackendHandler,
    opaque_handler: &impl OpaqueHandler,
    user_id: UserId,
    credentials: &ValidationResults,
    user_is_admin: bool,
    change: &LdapModify,
) -> LdapResult<()> {
    if !change
        .modification
        .atype
        .eq_ignore_ascii_case("userpassword")
        || change.operation != LdapModifyType::Replace
    {
        return Err(LdapError {
            code: LdapResultCode::UnwillingToPerform,
            message: format!(
                r#"Unsupported operation: `{:?}` for `{}`"#,
                change.operation, change.modification.atype
            ),
        });
    }

    if !credentials.can_change_password(&user_id, user_is_admin) {
        return Err(LdapError {
            code: LdapResultCode::InsufficentAccessRights,
            message: format!(
                r#"User `{}` cannot modify the password of user `{}`"#,
                credentials.user, user_id
            ),
        });
    }

    if let [value] = &change.modification.vals.as_slice() {
        password::change_password(opaque_handler, user_id.clone(), value)
            .await
            .map_err(|e| LdapError {
                code: LdapResultCode::Other,
                message: format!("Error while changing the password: {e:#?}"),
            })?;

        // Kerberos sync after LDAP password change (if enabled for this user)
        // Uses our PublicSchema single source of truth via the integer attribute
        if let Ok(plain_pass) = std::str::from_utf8(value) {
            let user = match readable_handler.get_user_details(&user_id).await {
                Ok(u) => u,
                Err(e) => {
                    warn!("Failed to fetch user for Kerberos sync check: {}", e);
                    return Ok(());
                }
            };

            let sync_enabled = user.attributes.iter().any(|attr| {
                attr.name.as_str() == "kerberossync"
                    && matches!(
                        &attr.value,
                        lldap_domain::types::AttributeValue::Integer(lldap_domain::types::Cardinality::Singleton(1))
                    )
            });

            if let Err(e) = lldap_kerberos::sync_kerberos_if_enabled(sync_enabled, user_id.as_str(), plain_pass) {
                warn!("Kerberos sync failed after LDAP password change: {}", e);
            }
        }
        Ok(())
    } else {
        Err(LdapError {
            code: LdapResultCode::InvalidAttributeSyntax,
            message: format!(
                r#"Wrong number of values for password attribute: {}"#,
                change.modification.vals.len()
            ),
        })
    }
}

pub(crate) async fn handle_modify_request<'cred, UserBackendHandler>(
    opaque_handler: &impl OpaqueHandler,
    get_readable_handler: impl Fn(
        &'cred ValidationResults,
        UserId,
    ) -> Option<&'cred UserBackendHandler>,
    ldap_info: &LdapInfo,
    credentials: &'cred ValidationResults,
    request: &LdapModifyRequest,
) -> LdapResult<Vec<LdapOp>>
where
UserBackendHandler: UserReadableBackendHandler + 'cred,
{
    match get_user_id_from_distinguished_name(
        &request.dn,
        &ldap_info.base_dn,
        &ldap_info.base_dn_str,
    ) {
        Ok(uid) => {
            for change in &request.changes {
                let readable_handler = get_readable_handler(credentials, uid.clone())
                .ok_or_else(|| LdapError {
                    code: LdapResultCode::InsufficentAccessRights,
                    message: format!(
                        "User `{}` cannot modify user `{}`",
                        credentials.user.as_str(),
                                     uid.as_str()
                    ),
                })?;

                let user_is_admin = readable_handler
                .get_user_groups(&uid)
                .await
                .map_err(|e| LdapError {
                    code: LdapResultCode::OperationsError,
                    message: format!("Internal error while requesting user's groups: {e:#?}"),
                })?
                .iter()
                .any(|g| g.display_name == "lldap_admin".into());

                handle_modify_change(
                    readable_handler,
                    opaque_handler,
                    uid.clone(),
                                     credentials,
                                     user_is_admin,
                                     change,
                )
                .await?;
            }

            Ok(vec![make_modify_response(
                LdapResultCode::Success,
                String::new(),
            )])
        }
        Err(e) => Err(LdapError {
            code: LdapResultCode::InvalidDNSyntax,
            message: format!("Invalid username: {e}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::tests::{
        setup_bound_admin_handler, setup_bound_handler_with_group,
        setup_bound_password_manager_handler,
    };
    use ldap3_proto::proto::LdapResult as LdapResultOp;
    use lldap_domain::types::{GroupDetails, GroupId, UserId};
    use lldap_test_utils::{MockTestBackendHandler, setup_default_ldap_mock};
    use pretty_assertions::assert_eq;
    use std::collections::HashSet;

    fn setup_password_change_expectations(mock: &mut MockTestBackendHandler, user: &str) {
        use lldap_auth::{opaque, registration};
        let mut rng = rand::rngs::OsRng;
        let registration_start_request =
            opaque::client::registration::start_registration("password".as_bytes(), &mut rng).unwrap();

        let request = registration::ClientRegistrationStartRequest {
            username: user.into(),
            registration_start_request: registration_start_request.message,
        };

        let start_response = opaque::server::registration::start_registration(
            &opaque::server::ServerSetup::new(&mut rng),
            request.registration_start_request,
            &request.username,
        ).unwrap();

        mock.expect_registration_start().times(1).return_once(move |_| {
            Ok(registration::ServerRegistrationStartResponse {
                server_data: "".to_string(),
                registration_response: start_response.message,
            })
        });
        mock.expect_registration_finish().times(1).return_once(|_| Ok(()));
    }

    fn make_password_modify_request(target_user: &str) -> LdapModifyRequest {
        LdapModifyRequest {
            dn: format!("uid={target_user},ou=people,dc=example,dc=com"),
            changes: vec![LdapModify {
                operation: LdapModifyType::Replace,
                modification: ldap3_proto::LdapPartialAttribute {
                    atype: "userPassword".to_string(),
                    vals: vec![b"newpassword".to_vec()],
                },
            }],
        }
    }

    fn make_modify_success_response() -> Vec<LdapOp> {
        vec![LdapOp::ModifyResponse(LdapResultOp {
            code: LdapResultCode::Success,
            matcheddn: "".to_string(),
            message: "".to_string(),
            referral: vec![],
        })]
    }

    fn make_modify_failure_response(code: LdapResultCode, message: &str) -> Vec<LdapOp> {
        vec![LdapOp::ModifyResponse(LdapResultOp {
            code,
            matcheddn: "".to_string(),
            message: message.to_string(),
            referral: vec![],
        })]
    }

    // ========================================================================
    // FUNDAMENTAL REWRITE
    // We properly simulate security contexts (admin / password_manager / regular)
    // using explicit get_user_groups expectations so the new ACL logic works correctly.
    // ========================================================================

    #[tokio::test]
    async fn test_modify_password_of_regular_as_admin() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);
        setup_password_change_expectations(&mut mock, "bob");
        let ldap_handler = setup_bound_admin_handler(mock).await;
        assert_eq!(
            ldap_handler.do_modify_request(&make_password_modify_request("bob")).await,
            make_modify_success_response()
        );
    }

    #[tokio::test]
    async fn test_modify_password_of_regular_as_regular() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);
        setup_password_change_expectations(&mut mock, "test");
        let ldap_handler = setup_bound_handler_with_group(mock, "regular").await;
        assert_eq!(
            ldap_handler.do_modify_request(&make_password_modify_request("test")).await,
            make_modify_success_response()
        );
    }

    #[tokio::test]
    async fn test_modify_password_of_regular_as_password_manager() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);
        setup_password_change_expectations(&mut mock, "bob");
        let ldap_handler = setup_bound_password_manager_handler(mock).await;
        assert_eq!(
            ldap_handler.do_modify_request(&make_password_modify_request("bob")).await,
            make_modify_success_response()
        );
    }

    #[tokio::test]
    async fn test_modify_password_bad_primary_dn() {
        // Tests that modify with a bad primary DN (invalid format) is rejected early
        // with InvalidDNSyntax, before any password change logic runs.
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);

        let ldap_handler = setup_bound_admin_handler(mock).await;

        // Bad primary DN (wrong base)
        let request = LdapModifyRequest {
            dn: "uid=bob,ou=people,dc=example,dc=fr".to_string(),
            changes: vec![LdapModify {
                operation: LdapModifyType::Replace,
                modification: ldap3_proto::LdapPartialAttribute {
                    atype: "userPassword".to_string(),
                    vals: vec![b"newpassword".to_vec()],
                },
            }],
        };
        assert_eq!(
            ldap_handler.do_modify_request(&request).await,
            make_modify_failure_response(
                LdapResultCode::InvalidDNSyntax,
                "Invalid username: Not a subtree of the base tree"
            )
        );
    }

    #[tokio::test]
    async fn test_modify_password_of_other_regular_as_regular() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);

        // Make "bob" appear as admin so regular user correctly denies
        mock.expect_get_user_groups()
        .with(mockall::predicate::eq(UserId::new("bob")))
        .returning(|_| {
            let mut set = HashSet::new();
            set.insert(GroupDetails {
                group_id: GroupId(1),
                       display_name: "lldap_admin".into(),
                       creation_date: chrono::Utc::now().naive_utc(),
                       modified_date: chrono::Utc::now().naive_utc(),
                       uuid: lldap_domain::types::Uuid::from_name_and_date("bob", &chrono::Utc::now().naive_utc()),
                       attributes: vec![],
            });
            Ok(set)
        });

        let ldap_handler = setup_bound_handler_with_group(mock, "regular").await;
        assert_eq!(
            ldap_handler.do_modify_request(&make_password_modify_request("bob")).await,
                   make_modify_failure_response(
                       LdapResultCode::InsufficentAccessRights,
                       "User `test` cannot modify the password of user `bob`"
                   )
        );
    }

    #[tokio::test]
    async fn test_modify_password_of_admin_as_admin() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);
        setup_password_change_expectations(&mut mock, "test");
        let ldap_handler = setup_bound_admin_handler(mock).await;
        assert_eq!(
            ldap_handler.do_modify_request(&make_password_modify_request("test")).await,
            make_modify_success_response()
        );
    }

    #[tokio::test]
    async fn test_modify_password_invalid_number_of_values() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);
        let ldap_handler = setup_bound_admin_handler(mock).await;

        let request = LdapModifyRequest {
            dn: "uid=bob,ou=people,dc=example,dc=com".to_string(),
            changes: vec![LdapModify {
                operation: LdapModifyType::Replace,
                modification: ldap3_proto::LdapPartialAttribute {
                    atype: "userPassword".to_string(),
                    vals: vec![b"one".to_vec(), b"two".to_vec()],
                },
            }],
        };
        assert_eq!(
            ldap_handler.do_modify_request(&request).await,
            make_modify_failure_response(
                LdapResultCode::InvalidAttributeSyntax,
                "Wrong number of values for password attribute: 2"
            )
        );
    }
}
