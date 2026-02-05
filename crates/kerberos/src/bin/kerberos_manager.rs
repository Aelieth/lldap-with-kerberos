use anyhow::{Context, Result};
use minijinja::{context, Environment};
use serde::Deserialize;
use std::env;
use std::fs;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use reqwest::blocking::Client;
use serde_json::json;
use std::thread;
use std::time::Duration;
use std::net::TcpStream;
use std::io::{Write};

#[derive(Deserialize, Debug)]
struct KerberosConfig {
    realm_name: String,
    base_dn: String,
    ticket_lifetime: String,
    renew_lifetime: String,
    forwardable: bool,
        rdns: bool,
}

/// Run a single kadmin.local query non-interactively (with explicit krb5.conf)
fn run_kadmin_local(query: &str) -> Result<Output> {
    println!("Running kadmin.local -q \"{}\"", query);

    let output = Command::new("/usr/sbin/kadmin.local")
    .env("KRB5_CONFIG", "/etc/krb5.conf")
    .arg("-q")
    .arg(query)
    .output()
    .context("Failed to spawn kadmin.local")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    println!("kadmin.local stdout: {}", stdout.trim());
    if !stderr.is_empty() {
        println!("kadmin.local stderr: {}", stderr.trim());
    }

    Ok(output)
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

    // Derive DOMAIN from (possibly overridden) base_dn
    let domain = config.base_dn.replace("dc=", "").replace(",", ".").to_lowercase();
    println!("Calculated DOMAIN: {}", domain);
    println!("Effective config: {:?}", config);

    // Render templates
    fs::create_dir_all("/var/kerberos/krb5kdc").context("Failed to create /var/kerberos/krb5kdc")?;
    render_template("/app/krb5.template.conf", "/etc/krb5.conf", &config, &domain)?;
    render_template("/app/kdc.template.conf", "/var/kerberos/krb5kdc/kdc.conf", &config, &domain)?;
    render_template("/app/kadm5.template.acl", "/var/kerberos/krb5kdc/kadm5.acl", &config, &domain)?;

    // --- Password-less Kerberos Bootstrap Part 1 (DB and keytab before daemons) ---
    let db_principal_path = "/var/lib/krb5kdc/principal";
    let keytab_path = "/data/kadm5.keytab";
    let realm_upper = config.realm_name.to_uppercase();

    let needs_bootstrap = !Path::new(db_principal_path).exists();

    if needs_bootstrap {
        println!("First run detected—no KDC database. Bootstrapping password-less...");

        // Generate random master password
        let master_pass_output = Command::new("openssl")
        .arg("rand")
        .arg("-hex")
        .arg("32")
        .output()
        .context("Failed to generate random master password")?;
        let master_pass = String::from_utf8_lossy(&master_pass_output.stdout).trim().to_string();
        println!("Generated random master password (length: {} chars).", master_pass.len());

        // Create DB with pipe
        println!("Creating KDC database with piped password...");
        let mut kdb_child = Command::new("/usr/sbin/kdb5_util")
        .arg("create")
        .arg("-s")
        .arg("-r")
        .arg(&realm_upper)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to spawn kdb5_util")?;

        {
            let stdin = kdb_child.stdin.as_mut().context("Failed to take stdin")?;
            stdin.write_all(master_pass.as_bytes())?;
            stdin.write_all(b"\n")?;
            stdin.flush()?;
            stdin.write_all(master_pass.as_bytes())?;
            stdin.write_all(b"\n")?;
            stdin.flush()?;
        }

        let kdb_output = kdb_child.wait_with_output().context("Failed to wait for kdb5_util")?;
        if !kdb_output.status.success() {
            anyhow::bail!("kdb5_util failed: STDOUT: {}\nSTDERR: {}",
                          String::from_utf8_lossy(&kdb_output.stdout), String::from_utf8_lossy(&kdb_output.stderr));
        }
        println!("KDC database created successfully.");

        // Admin principal with random key
        let admin_princ = format!("admin/admin@{}", realm_upper);
        println!("Creating admin principal with random key: {}", admin_princ);
        run_kadmin_local(&format!("addprinc -randkey {}", admin_princ))?;

        // Export keytab
        fs::create_dir_all("/data")?;
        println!("Exporting admin principal to keytab: {}", keytab_path);
        run_kadmin_local(&format!("ktadd -k {} {}", keytab_path, admin_princ))?;
        println!("Keytab created.");

        Command::new("chmod").arg("600").arg(keytab_path).status()?;
        Command::new("chown").arg("lldap:lldap").arg(keytab_path).status()?;
    } else {
        println!("KDC database exists—skipping bootstrap.");
    }
    // --- End Part 1 ---

    // One-time schema extension for POSIX/Kerberos compatibility
    let schema_flag = "/var/lib/krb5kdc/schema_extended.flag";
    if !Path::new(schema_flag).exists() {
        println!("Extending LLDAP schema for POSIX/Kerberos...");

        let initial_admin_pass = env::var("LLDAP_LDAP_USER_PASS")
        .context("LLDAP_LDAP_USER_PASS env var required for first-run schema extension")?;

        let client = Client::new();
        let login_url = "http://localhost:17170/auth/simple/login";

        let login_body = json!({
            "username": "admin",
            "password": initial_admin_pass
        });

        let login_resp = client.post(login_url)
        .json(&login_body)
        .send()
        .context("Failed to login to LLDAP for token")?;

        if !login_resp.status().is_success() {
            let err_text = login_resp.text().unwrap_or_default();
            println!("Warning: LLDAP login failed for schema extension (non-fatal): {}", err_text);
        } else {
            let token: String = login_resp.json::<serde_json::Value>()
            .context("Failed to parse login response")?
            .get("token")
            .and_then(|v| v.as_str())
            .context("No token in login response")?
            .to_string();

            let graphql_url = "http://localhost:17170/api/graphql";

            let mutations = vec![
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
        }
    } else {
        println!("Schema already extended—skipping.");
    }

    // Start Kerberos daemons
    println!("Starting krb5kdc...");
    let mut kdc_child = Command::new("/usr/sbin/krb5kdc")
    .spawn()
    .context("Failed to start krb5kdc")?;

    println!("Starting kadmind...");
    let mut kadmind_child = Command::new("/usr/sbin/kadmind")
    .spawn()
    .context("Failed to start kadmind")?;

    // Wait for KDC readiness (port 88)
    println!("Waiting for KDC on port 88...");
    for _ in 0..60 {
        if TcpStream::connect(("localhost", 88)).is_ok() {
            println!("KDC ready on port 88.");
            break;
        }
        thread::sleep(Duration::from_secs(1));
    }

    // --- Password-less Kerberos Bootstrap Part 2 (ccache after daemons ready) ---
    if Path::new("/data/kadm5.keytab").exists() {
        let admin_princ = format!("admin/admin@{}", config.realm_name.to_uppercase());
        println!("Populating ccache with keytab (daemons ready): {}", admin_princ);
        let kinit_output = Command::new("/usr/bin/kinit")
        .env("KRB5_CONFIG", "/etc/krb5.conf")
        .arg("-k")
        .arg("-t")
        .arg("/data/kadm5.keytab")
        .arg(&admin_princ)
        .output()
        .context("Failed kinit")?;

        if !kinit_output.status.success() {
            anyhow::bail!("kinit failed: STDOUT: {}\nSTDERR: {}",
                          String::from_utf8_lossy(&kinit_output.stdout), String::from_utf8_lossy(&kinit_output.stderr));
        }
        println!("ccache populated—Kerberos sync fully password-less.");
    }
    // --- End Part 2 ---

    // Block on children
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
