// crates/kerberos/src/keycloak_client.rs
use anyhow::{Context, Result};
use reqwest::Client as HttpClient;
use serde_json::json;
use tracing::info;

use crate::keycloak_config::KeycloakConfig;

#[derive(Clone)]
pub struct KeycloakClient {
    config: KeycloakConfig,
    admin_pass: String,
    http_client: HttpClient,
}

impl KeycloakClient {
    pub fn new(config: KeycloakConfig, admin_pass: String) -> Self {
        Self {
            config,
            admin_pass,
            http_client: HttpClient::new(),
        }
    }

    pub fn from_test_input(
        url: String,
        realm: String,
        admin_user: String,
        admin_pass: String,
    ) -> Self {
        let pass = if admin_pass.trim().is_empty() {
            crate::keycloak_config::get_keycloak_admin_password()
        } else {
            admin_pass
        };
        Self {
            config: KeycloakConfig { url, realm, admin_user },
            admin_pass: pass,
            http_client: HttpClient::new(),
        }
    }

    pub async fn setup_realm(
        &self,
        lldap_url: String,
        sync_username: String,
        sync_password: String,
    ) -> Result<String> {
        info!("🔄 PushRealm starting - Realm: '{}', LLDAP URL: '{}'", self.config.realm, lldap_url);
        let token = self.acquire_token().await?;

        self.create_realm(&token).await?;
        self.add_ldap_kerberos_component(&token, &lldap_url, &sync_username, &sync_password).await?;
        self.add_lldap_web_client(&token).await?;

        let msg = format!("🎉 Realm '{}' fully set up with LLDAP + Kerberos! SPNEGO ready for KDE/Gnome SSO.", self.config.realm);
        info!("{}", msg);
        Ok(msg)
    }

    async fn acquire_token(&self) -> Result<String> {
        info!("   → Acquiring admin token...");
        let resp = self.http_client
        .post(format!("{}/realms/master/protocol/openid-connect/token", self.config.url))
        .form(&[
            ("client_id", "admin-cli"),
              ("username", &self.config.admin_user),
              ("password", &self.admin_pass),
              ("grant_type", "password"),
        ])
        .send()
        .await
        .context("Failed to connect to Keycloak")?;

        let json: serde_json::Value = resp.json().await.context("Invalid token response")?;
        let token = json["access_token"].as_str()
        .ok_or_else(|| anyhow::anyhow!("No access_token in response (wrong admin password?)"))?
        .to_string();

        info!("   → Token acquired successfully");
        Ok(token)
    }

    async fn create_realm(&self, token: &str) -> Result<()> {
        info!("   → Creating realm '{}'...", self.config.realm);
        let realm_json = json!({
            "realm": self.config.realm,
            "enabled": true,
            "sslRequired": "none",
            "registrationAllowed": false,
            "resetPasswordAllowed": false,
            "rememberMe": true,
            "editUsernameAllowed": false,
            "verifyEmail": false,
            "loginWithEmailAllowed": false,
            "duplicateEmailsAllowed": false,
            "ssoSessionMaxLifespan": 43200,
            "accessTokenLifespan": 900,
            "browserSecurityHeaders": {
                "strictTransportSecurity": "",
                "xFrameOptions": "SAMEORIGIN",
                "contentSecurityPolicy": "frame-src 'self'; frame-ancestors 'self'; object-src 'none';",
                "xContentTypeOptions": "nosniff",
                "referrerPolicy": "no-referrer"
            },
            "bruteForceProtected": false
        });

        let resp = self.http_client
        .post(format!("{}/admin/realms", self.config.url))
        .bearer_auth(token)
        .header("Content-Type", "application/json")
        .json(&realm_json)
        .send()
        .await?;

        let status = resp.status();
        if status.is_success() || status.as_u16() == 409 {
            Ok(())
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(anyhow::anyhow!("Realm creation failed: {} - {}", status, body))
        }
    }

    async fn add_ldap_kerberos_component(
        &self,
        token: &str,
        lldap_url: &str,
        sync_username: &str,
        sync_password: &str,
    ) -> Result<()> {
        info!("   → Adding LDAP+Kerberos provider...");
        let base_dn = format!("dc={}", self.config.realm.replace('.', ",dc="));
        let component_json = json!({
            "name": "lldap-with-kerberos",
            "providerId": "ldap",
            "providerType": "org.keycloak.storage.UserStorageProvider",
            "config": {
                "vendor": ["other"],
                "connectionUrl": [lldap_url],
                "bindDn": [format!("uid={},ou=people,{}", sync_username, base_dn)],
                                   "bindCredential": [sync_password],
                                   "usersDn": [format!("ou=people,{}", base_dn)],
                                   "groupsDn": [format!("ou=groups,{}", base_dn)],
                                   "userObjectClasses": ["inetOrgPerson","organizationalPerson"],
                                   "rdnLDAPAttribute": ["uid"],
                                   "uuidLDAPAttribute": ["entryUUID"],
                                   "usernameLDAPAttribute": ["uid"],
                                   "searchScope": ["2"],
                                   "validatePasswordPolicy": ["false"],
                                   "trustEmail": ["true"],
                                   "syncRegistrations": ["true"],
                                   "editMode": ["READ_ONLY"],
                                   "importEnabled": ["true"],
                                   "pagination": ["true"],
                                   "allowKerberosAuthentication": ["true"],
                                   "kerberosRealm": [self.config.realm.to_uppercase()],
                                   "serverPrincipal": [format!("HTTP/keycloak.{}@{}", self.config.realm, self.config.realm.to_uppercase())],
                                   "keyTab": ["/keytab/keycloak-http.keytab"],
                                   "krbPrincipalAttribute": ["krbPrincipalName"],
                                   "useKerberosForPasswordAuthentication": ["false"],
                                   "useTruststoreSpi": ["always"],
                                   "connectionPooling": ["true"],
                                   "cachePolicy": ["DEFAULT"],
                                   "usePasswordModifyExtendedOp": ["false"],
                                   "connectionTrace": ["false"]
            }
        });

        let resp = self.http_client
        .post(format!("{}/admin/realms/{}/components", self.config.url, self.config.realm))
        .bearer_auth(token)
        .header("Content-Type", "application/json")
        .json(&component_json)
        .send()
        .await?;

        let status = resp.status();
        if status.is_success() || status.as_u16() == 409 {
            Ok(())
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(anyhow::anyhow!("Component creation failed: {} - {}", status, body))
        }
    }

    async fn add_lldap_web_client(&self, token: &str) -> Result<()> {
        info!("   → Adding lldap-web client...");
        let client_json = json!({
            "clientId": "lldap-web",
            "name": "LLDAP Web Apps",
            "enabled": true,
            "protocol": "openid-connect",
            "publicClient": true,
            "standardFlowEnabled": true,
            "implicitFlowEnabled": true,
            "directAccessGrantsEnabled": true,
            "redirectUris": ["*"],
            "webOrigins": ["+"]
        });

        let resp = self.http_client
        .post(format!("{}/admin/realms/{}/clients", self.config.url, self.config.realm))
        .bearer_auth(token)
        .header("Content-Type", "application/json")
        .json(&client_json)
        .send()
        .await?;

        let status = resp.status();
        if status.is_success() || status.as_u16() == 409 {
            Ok(())
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(anyhow::anyhow!("Client creation failed: {} - {}", status, body))
        }
    }

    pub async fn test_connection(&self) -> Result<String> {
        info!("🔍 Testing Keycloak connection...");
        let token = self.acquire_token().await?;
        let resp = self.http_client
        .get(format!("{}/admin/realms/{}", self.config.url, self.config.realm))
        .bearer_auth(token)
        .send()
        .await?;

        if resp.status().is_success() {
            let msg = format!("✅ Connected to Keycloak at {} — realm '{}' is ready", self.config.url, self.config.realm);
            info!("{}", msg);
            Ok(msg)
        } else {
            Err(anyhow::anyhow!("Test failed: HTTP {}", resp.status()))
        }
    }
}
