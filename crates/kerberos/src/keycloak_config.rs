use anyhow::{Context, Result};
use std::path::Path;

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct KeycloakSuggestedConfig {
    pub url: String,
    pub realm: String,
    pub admin_username: String,
    pub keycloak_hostname: String,
}

pub fn get_keycloak_suggested_config() -> KeycloakSuggestedConfig {
    let realm = crate::derive_realm_from_base_dn();
    let domain = crate::derive_domain_from_base_dn();

    KeycloakSuggestedConfig {
        url: format!("http://keycloak.{}", domain),
        realm: realm.to_lowercase(),
        admin_username: "admin".to_string(),
        keycloak_hostname: "keycloak".to_string(),
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct KeycloakConfig {
    pub url: String,
    pub realm: String,
    pub admin_user: String,
}

pub fn load_keycloak_config() -> Result<KeycloakConfig> {
    let config_path = "/data/keycloak_config.toml";
    if Path::new(config_path).exists() {
        let toml_str = std::fs::read_to_string(config_path)
        .context("Failed to read keycloak_config.toml")?;
        toml::from_str(&toml_str).context("Failed to parse keycloak_config.toml")
    } else {
        let realm = crate::derive_realm_from_base_dn();
        let domain = crate::derive_domain_from_base_dn();
        Ok(KeycloakConfig {
            url: format!("http://keycloak.{}", domain),
           realm: realm.to_lowercase(),
           admin_user: "admin".to_string(),
        })
    }
}

pub fn save_keycloak_config(config: &KeycloakConfig) -> Result<()> {
    let config_path = "/data/keycloak_config.toml";
    let toml_str = toml::to_string_pretty(config)
    .context("Failed to serialize keycloak config")?;
    std::fs::write(config_path, toml_str)
    .context("Failed to write keycloak_config.toml")
}
