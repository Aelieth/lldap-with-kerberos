use anyhow::{Context, Result};
use minijinja::{context, Environment};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde::Deserialize;
use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;
use reqwest::blocking::Client;
use serde_json::json;

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

    // Load TOML robustly (handles leading comments, extra stuff like LLDAP)
    let toml_str = fs::read_to_string(config_path).context("Failed to read kerberos_config.toml")?;
    let full_config: toml::Table = toml::from_str(&toml_str).context("Failed to parse TOML file (check syntax/comments)")?;

    let kerberos_value = full_config.get("kerberos").context("Missing [kerberos] table in config")?.clone();
    let mut config: KerberosConfig = kerberos_value.try_into().context("Failed to deserialize [kerberos] table")?;

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

    // Sync consistency with LLDAP/entrypoint
    if let Ok(base_dn) = env::var("LLDAP_LDAP_BASE_DN") {
        config.base_dn = base_dn;
    }
    if let Ok(realm) = env::var("REALM_NAME") {
        config.realm_name = realm;
    }

    // Derive DOMAIN from (possibly overridden) base_dn
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

    println!("Effective config: {:?}", config);
    println!("Effective ENCODE_KEY length: {}", encode_key.len());

    // Create necessary directories
    fs::create_dir_all("/var/lib/krb5kdc").context("Failed to create /var/lib/krb5kdc")?;
    fs::create_dir_all("/var/log/krb5").context("Failed to create /var/log/krb5")?;
    fs::create_dir_all("/var/run").context("Failed to create /var/run")?;
    fs::create_dir_all("/tmp").context("Failed to create /tmp")?;

    // Render templates
    println!("Generating /etc/krb5.conf...");
    render_template("/app/krb5.template.conf", "/etc/krb5.conf", &config, &domain)?;

    println!("Generating /var/lib/krb5kdc/kdc.conf...");
    render_template("/app/kdc.template.conf", "/var/lib/krb5kdc/kdc.conf", &config, &domain)?;

    // TODO: Schema extension, KDC init, start daemons
    // One-time KDC database initialization
    let db_path = "/var/lib/krb5kdc/principal";
    if !Path::new(db_path).exists() {
        println!("Kerberos database not found. Initializing with kdb5_util...");

        let output = Command::new("/usr/sbin/kdb5_util")
        .arg("create")
        .arg("-s")
        .arg("-r")
        .arg(&config.realm_name)
        .arg("-P")
        .arg(&config.master_pass)
        .output()
        .context("Failed to run kdb5_util create")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("kdb5_util failed: {}", stderr));
        }
        println!("Kerberos database initialized successfully.");
    } else {
        println!("Kerberos database already exists—skipping init.");
    }

    // Add/admin principal (idempotent)
    println!("Ensuring admin/admin principal...");
    let admin_principal = format!("admin/admin@{}", config.realm_name);

    // Try change password first (updates if exists)
    let cpw_status = Command::new("/usr/sbin/kadmin.local")
    .arg("-q")
    .arg(format!("cpw -pw {} -e aes256-cts-hmac-sha1-96:normal {}", config.admin_pass, admin_principal))
    .status()
    .context("Failed to run kadmin.local cpw")?;

    if cpw_status.success() {
        println!("Updated existing admin principal password.");
    } else {
        println!("Admin principal does not exist—creating new one...");

        let add_output = Command::new("/usr/sbin/kadmin.local")
        .arg("-q")
        .arg(format!("addprinc -pw {} -e aes256-cts-hmac-sha1-96:normal {}", config.admin_pass, admin_principal))
        .output()
        .context("Failed to run kadmin.local addprinc")?;

        if add_output.status.success() {
            println!("Created new admin principal successfully.");
        } else {
            let stderr = String::from_utf8_lossy(&add_output.stderr);
            println!("Warning: Failed to create admin principal: {}", stderr.trim());
        }
    }

    // Create keytab
    println!("Creating kadm5.keytab...");
    fs::write("/var/lib/krb5kdc/kadm5.acl", format!("*/admin@{} *\n", config.realm_name))
    .context("Failed to write kadm5.acl")?;

    let ktadd_output = Command::new("/usr/sbin/kadmin.local")
    .arg("-q")
    .arg(format!("ktadd -norandkey -k /var/lib/krb5kdc/kadm5.keytab {}", admin_principal))
    .output()
    .context("Failed to run ktadd")?;

    if !ktadd_output.status.success() {
        let stderr = String::from_utf8_lossy(&ktadd_output.stderr);
        return Err(anyhow::anyhow!("ktadd failed: {}", stderr));
    }
    println!("kadm5.keytab created.");

    // Start KDC services (foreground, monitor)
    println!("Starting krb5kdc and kadmind...");

    let mut kdc_child = Command::new("/usr/sbin/krb5kdc")
    .arg("-P")
    .arg("/var/run/krb5kdc.pid")
    .spawn()
    .context("Failed to start krb5kdc")?;

    let mut kadmind_child = Command::new("/usr/sbin/kadmind")
    .arg("-P")
    .arg("/var/run/kadmind.pid")
    .spawn()
    .context("Failed to start kadmind")?;

    println!("Kerberos services running. Blocking forever...");

    // One-time schema extension for POSIX/Kerberos compatibility
    let schema_flag = "/var/lib/krb5kdc/schema_extended.flag";
    if !Path::new(schema_flag).exists() {
        println!("Extending LLDAP schema for POSIX/Kerberos...");

        let client = Client::new();
        let login_url = "http://localhost:17170/auth/simple/login";

        let login_body = json!({
            "username": "admin",
            "password": config.dm_pass
        });

        let login_resp = client.post(login_url)
        .json(&login_body)
        .send()
        .context("Failed to login to LLDAP for token")?;

        if !login_resp.status().is_success() {
            let err_text = login_resp.text().unwrap_or_default();
            return Err(anyhow::anyhow!("LLDAP login failed: {}", err_text));
        }

        let login_json: serde_json::Value = login_resp.json().context("Failed to parse login JSON")?;
        let token = login_json["token"].as_str().context("No token in login response")?;

        let graphql_url = "http://localhost:17170/api/graphql";

        let mutations = vec![
            // Attributes
            json!({
                "query": "mutation AddUserAttribute($name: String!, $type: AttributeType!, $isList: Boolean!, $isVisible: Boolean!, $isEditable: Boolean!) { addUserAttribute(name: $name, attributeType: $type, isList: $isList, isVisible: $isVisible, isEditable: $isEditable) { __typename }}",
                  "variables": { "name": "uidNumber", "type": "INTEGER", "isList": false, "isVisible": false, "isEditable": true }
            }),
            json!({
                "query": "mutation AddUserAttribute($name: String!, $type: AttributeType!, $isList: Boolean!, $isVisible: Boolean!, $isEditable: Boolean!) { addUserAttribute(name: $name, attributeType: $type, isList: $isList, isVisible: $isVisible, isEditable: $isEditable) { __typename }}",
                  "variables": { "name": "gidNumber", "type": "INTEGER", "isList": false, "isVisible": false, "isEditable": true }
            }),
            json!({
                "query": "mutation AddUserAttribute($name: String!, $type: AttributeType!, $isList: Boolean!, $isVisible: Boolean!, $isEditable: Boolean!) { addUserAttribute(name: $name, attributeType: $type, isList: $isList, isVisible: $isVisible, isEditable: $isEditable) { __typename }}",
                  "variables": { "name": "loginShell", "type": "STRING", "isList": false, "isVisible": true, "isEditable": false }
            }),
            // Object classes
            json!({
                "query": "mutation AddUserObjectClass($name: String!) { addUserObjectClass(name: $name) { __typename } }",
                  "variables": { "name": "inetOrgPerson" }
            }),
            json!({
                "query": "mutation AddUserObjectClass($name: String!) { addUserObjectClass(name: $name) { __typename } }",
                  "variables": { "name": "posixAccount" }
            }),
        ];

        for mutation in mutations {
            let resp = client.post(graphql_url)
            .header("Authorization", format!("Bearer {}", token))
            .json(&mutation)
            .send()
            .context("Failed to send GraphQL mutation")?;

            if !resp.status().is_success() {
                let err_text = resp.text().unwrap_or_default();
                println!("Warning: Schema mutation failed (non-fatal): {}", err_text);
            } else {
                println!("Schema extension mutation succeeded.");
            }
        }

        fs::write(schema_flag, "extended").context("Failed to write schema flag")?;
        println!("LLDAP schema extended successfully.");
    } else {
        println!("Schema already extended—skipping.");
    }

    // Wait for either to exit (error)
    let kdc_status = kdc_child.wait().context("krb5kdc exited unexpectedly")?;
    let kadmind_status = kadmind_child.wait().context("kadmind exited unexpectedly")?;

    if !kdc_status.success() || !kadmind_status.success() {
        return Err(anyhow::anyhow!("Kerberos service failed"));
    }

    Ok(())
}

fn render_template(template_path: &str, output_path: &str, config: &KerberosConfig, domain: &str) -> Result<()> {
    let template_str = fs::read_to_string(template_path).context(format!("Failed to read template: {}", template_path))?;

    let mut env = Environment::new();
    env.add_template("template", &template_str).context("Failed to add template")?;

    let tmpl = env.get_template("template").unwrap();
    let rendered = tmpl.render(context! {
        TICKET_LIFETIME => config.ticket_lifetime,
        RENEW_LIFETIME => config.renew_lifetime,
        FORWARDABLE => config.forwardable,
        RDNS => config.rdns,
        REALM_NAME => config.realm_name,
        DOMAIN => domain,
    }).context("Failed to render template")?;

    fs::write(output_path, rendered).context(format!("Failed to write output: {}", output_path))?;
    println!("Generated {} successfully.", output_path);
    println!("Content:\n{}", fs::read_to_string(output_path)?);

    Ok(())
}
