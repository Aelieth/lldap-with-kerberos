use anyhow::{Context, Result};
use keycloak::{KeycloakAdmin, KeycloakAdminToken, KeycloakTokenSupplier};
use reqwest::Client as HttpClient;
use tracing::{info, error};
use crate::keycloak_config::{KeycloakConfig, load_full_keycloak_config};

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

    pub fn from_env() -> Result<Self> {
        let (config, admin_pass) = load_full_keycloak_config()?;
        Ok(Self::new(config, admin_pass))
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
            config: KeycloakConfig {
                url,
                realm,
                admin_user,
            },
            admin_pass: pass,
            http_client: HttpClient::new(),
        }
    }

    pub fn with_test_overrides(
        mut self,
        url: String,
        realm: String,
        admin_user: String,
        admin_pass: String,
    ) -> Self {
        self.config.url = url;
        self.config.realm = realm;
        self.config.admin_user = admin_user;

        if !admin_pass.trim().is_empty() {
            self.admin_pass = admin_pass;
            tracing::info!("Using password provided from UI for one-time test");
        } else {
            tracing::info!("Using password from LLDAP_KEYCLOAK_ADMIN_PASS environment variable");
        }

        self
    }

    pub async fn test_connection(&self) -> Result<String> {
        let token = KeycloakAdminToken::acquire(
            &self.config.url,
            &self.config.admin_user,
            &self.admin_pass,
            &self.http_client,
        )
        .await
        .context("Failed to acquire Keycloak admin token")?;

        let admin = KeycloakAdmin::new(&self.config.url, token, self.http_client.clone());

        let _realm_info = admin
        .realm_get(&self.config.realm)
        .await
        .context("Failed to fetch realm")?;

        info!("Keycloak connection test successful for realm {}", self.config.realm);
        Ok(format!(
            "✅ Connected to Keycloak at {} — realm '{}' is ready",
            self.config.url, self.config.realm
        ))
    }

    pub async fn create_realm(&self, realm_json: String) -> Result<String> {
        info!("🔄 PushRealm starting - URL: '{}', AdminUser: '{}', PassLen: {}",
              self.config.url,
              self.config.admin_user,
              self.admin_pass.len());

        let admin_token = match KeycloakAdminToken::acquire(
            &self.config.url,
            &self.config.admin_user,
            &self.admin_pass,
            &self.http_client,
        ).await {
            Ok(token) => token,
            Err(e) => {
                error!("❌ KeycloakAdminToken::acquire FAILED: {:?}", e);
                return Err(anyhow::anyhow!("Failed to acquire admin token for realm creation: {}", e));
            }
        };

        let token_str = admin_token
        .get(&self.config.url)
        .await
        .context("Failed to extract token string")?;

        let url = format!("{}/admin/realms", self.config.url);

        let resp = self.http_client
        .post(&url)
        .bearer_auth(token_str)
        .header("Content-Type", "application/json")
        .body(realm_json)
        .send()
        .await
        .context("Failed to send realm creation request to Keycloak")?;

        if resp.status().is_success() {
            info!("✅ Realm '{}' created successfully via API", self.config.realm);
            Ok(format!("✅ Realm '{}' created in Keycloak!", self.config.realm))
        } else {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            error!("❌ Keycloak rejected realm creation: {} - {}", status, body);
            Err(anyhow::anyhow!("Keycloak returned {}: {}", status, body))
        }
    }
}
