use anyhow::{Context, Result};
use keycloak::{KeycloakAdmin, KeycloakAdminToken};
use reqwest::Client as HttpClient;
use tracing::info;
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

        // If UI password box is left empty → keep the one from LLDAP_KEYCLOAK_ADMIN_PASS env var
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
        .context("Failed to acquire Keycloak admin token — check URL, credentials, or Keycloak health")?;

        let admin = KeycloakAdmin::new(&self.config.url, token, self.http_client.clone());

        let _realm_info = admin
        .realm_get(&self.config.realm)
        .await
        .context("Failed to fetch realm — does the realm exist in Keycloak?")?;

        info!("Keycloak connection test successful for realm {}", self.config.realm);
        Ok(format!(
            "✅ Connected to Keycloak at {} — realm '{}' is ready",
            self.config.url, self.config.realm
        ))
    }
}
