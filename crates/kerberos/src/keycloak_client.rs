use anyhow::{Context, Result};
use keycloak::{KeycloakAdmin, KeycloakAdminToken};
use reqwest::Client as HttpClient;
use tracing::info;

#[derive(Clone)]
pub struct KeycloakClient {
    url: String,
    realm: String,
    admin_user: String,
    admin_pass: String,
    http_client: HttpClient,
}

impl KeycloakClient {
    pub fn new(url: String, realm: String, admin_user: String, admin_pass: String) -> Self {
        Self {
            url,
            realm,
            admin_user,
            admin_pass,
            http_client: HttpClient::new(),
        }
    }

    pub async fn test_connection(&self) -> Result<String> {
        let token = KeycloakAdminToken::acquire(
            &self.url,
            &self.admin_user,
            &self.admin_pass,
            &self.http_client,
        )
        .await
        .context("Failed to acquire Keycloak admin token — check URL, credentials, or Keycloak health")?;

        let admin = KeycloakAdmin::new(&self.url, token, self.http_client.clone());

        let _realm_info = admin
        .realm_get(&self.realm)
        .await
        .context("Failed to fetch realm — does the realm exist in Keycloak?")?;

        info!("Keycloak connection test successful for realm {}", self.realm);
        Ok(format!(
            "✅ Connected to Keycloak at {} — realm '{}' is ready",
            self.url, self.realm
        ))
    }
}
