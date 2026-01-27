use anyhow::{Context, Result};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde::Deserialize;
use std::env;
use std::fs;
use std::path::Path;

#[derive(Deserialize, Debug)]
struct KerberosConfig {
    realm_name: String,
    base_dn: String,
    master_pass: String,
    admin_pass: String,
    dm_pass: String,
    ticket_lifetime: String,
    renew_lifetime: String,
    forwardable: bool,
        rdns: bool,
}

fn main() -> Result<()> {
    println!("Kerberos manager starting...");

    // Paths
    let config_path = "/data/kerberos_config.toml";
    let template_path = "/app/kerberos_config.template.toml";

    // One-time: Copy template if config missing
    if !Path::new(config_path).exists() {
        println!("Kerberos config not found. Copying template...");
        fs::copy(template_path, config_path).context("Failed to copy config template")?;
    }

    // Load TOML
    let toml_str = fs::read_to_string(config_path).context("Failed to read kerberos_config.toml")?;
    let mut config: KerberosConfig = toml::from_str(&toml_str).context("Failed to parse TOML")?;

    // Override with env vars (LLDAP_KERB_ prefix)
    if let Ok(val) = env::var("LLDAP_KERB_REALM_NAME") {
        config.realm_name = val;
    }
    if let Ok(val) = env::var("LLDAP_KERB_BASE_DN") {
        config.base_dn = val;
    }
    if let Ok(val) = env::var("LLDAP_KERB_MASTER_PASS") {
        config.master_pass = val;
    }
    if let Ok(val) = env::var("LLDAP_KERB_ADMIN_PASS") {
        config.admin_pass = val;
    }
    if let Ok(val) = env::var("LLDAP_KERB_DM_PASS") {
        config.dm_pass = val;
    }
    if let Ok(val) = env::var("LLDAP_KERB_TICKET_LIFETIME") {
        config.ticket_lifetime = val;
    }
    if let Ok(val) = env::var("LLDAP_KERB_RENEW_LIFETIME") {
        config.renew_lifetime = val;
    }
    if let Ok(val) = env::var("LLDAP_KERB_FORWARDABLE") {
        config.forwardable = val.parse().unwrap_or(true);
    }
    if let Ok(val) = env::var("LLDAP_KERB_RDNS") {
        config.rdns = val.parse().unwrap_or(false);
    }

    // Derive DOMAIN from base_dn
    let domain = config.base_dn.replace("dc=", "").replace(",", ".").to_lowercase();
    println!("Calculated DOMAIN: {}", domain);

    // Generate/set LLDAP_KERB_ENCODE_KEY if missing (32 chars alphanumeric)
    let encode_key = match env::var("LLDAP_KERB_ENCODE_KEY") {
        Ok(key) => key,
        Err(_) => {
            let rand_key: String = thread_rng().sample_iter(&Alphanumeric).take(32).map(char::from).collect();
            println!("Generated LLDAP_KERB_ENCODE_KEY: {} (save this if needed!)", rand_key);
            unsafe { env::set_var("LLDAP_KERB_ENCODE_KEY", &rand_key) };
            rand_key
        }
    };

    // For now, just print effective config (later: use for templates/init)
    println!("Effective config: {:?}", config);
    println!("Effective ENCODE_KEY length: {}", encode_key.len());

    // TODO: Rest of the logic (templates, schema, KDC init, start daemons)

    // Block forever (simulate running services)
    std::thread::park();

    Ok(())
}
