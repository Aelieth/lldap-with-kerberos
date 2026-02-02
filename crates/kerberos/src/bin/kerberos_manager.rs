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
use std::io::{BufRead, BufReader};

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
    if let Ok(realm) = env::var("REALM_NAME") {
        config.realm_name = realm;
    }

    // Derive DOMAIN from (possibly overridden) base_dn
    let domain = config.base_dn.replace("dc=", "").replace(",", ".").to_lowercase();
    println!("Calculated DOMAIN: {}", domain);
    println!("Effective config: {:?}", config);

    // Create necessary directories
    fs::create_dir_all("/var/lib/krb5kdc").context("Failed to create /var/lib/krb5kdc")?;
    fs::create_dir_all("/var/log/krb5").context("Failed to create /var/log/krb5")?;
    fs::create_dir_all("/var/kerberos/krb5kdc").context("Failed to create /var/kerberos/krb5kdc")?;
    fs::create_dir_all("/var/run").context("Failed to create /var/run")?;
    fs::create_dir_all("/tmp").context("Failed to create /tmp")?;

    // Render templates
    println!("Generating /etc/krb5.conf...");
    render_template("/app/krb5.template.conf", "/etc/krb5.conf", &config, &domain)?;

    println!("Generating /var/lib/krb5kdc/kdc.conf...");
    render_template("/app/kdc.template.conf", "/var/lib/krb5kdc/kdc.conf", &config, &domain)?;

    println!("Generating /var/lib/krb5kdc/kadm5.acl...");
    render_template("/app/kadm5.template.acl", "/var/lib/krb5kdc/kadm5.acl", &config, &domain)?;

    // One-time KDC database initialization (password-less with stashed master key)
    let db_principal_path = "/var/lib/krb5kdc/principal";
    if !Path::new(db_principal_path).exists() {
        println!("Kerberos database not found. Initializing with kdb5_util (stashed master key)...");

        let realm_upper = config.realm_name.to_uppercase();
        let output = Command::new("/usr/sbin/kdb5_util")
        .arg("create")
        .arg("-s")  // Stash master key automatically (no user password)
        .arg("-r")
        .arg(&realm_upper)
        .output()
        .context("Failed to run kdb5_util create")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("kdb5_util failed: {}", stderr));
        }
        println!("Kerberos database initialized successfully (stashed master key).");
    } else {
        println!("Kerberos database already exists—skipping init.");
    }

    // --- Password-less Kerberos Bootstrap and Keytab Setup ---
    let db_principal_path = "/var/lib/krb5kdc/principal";
    let keytab_path = "/data/kadm5.keytab";
    let realm_upper = config.realm_name.to_uppercase();

    let needs_bootstrap = !Path::new(db_principal_path).exists();

    if needs_bootstrap {
        println!("First run detected—no KDC database. Bootstrapping Kerberos password-less...");

        // 1. Create KDC database with stashed master key (no user password)
        println!("Creating KDC database with stashed master key...");
        let kdb_status = Command::new("/usr/sbin/kdb5_util")
        .arg("create")
        .arg("-s")  // Stash master key automatically
        .arg("-r")
        .arg(&realm_upper)
        .status()
        .context("Failed to run kdb5_util create")?;

        if !kdb_status.success() {
            anyhow::bail!("kdb5_util create failed (exit code: {:?})", kdb_status.code());
        }
        println!("KDC database created successfully (stashed master key).");

        // 2. Create admin principal with random key (no password)
        let admin_princ = format!("admin/admin@{}", realm_upper);
        println!("Creating admin principal with random key: {}", admin_princ);
        run_kadmin_local(&format!("addprinc -randkey {}", admin_princ))
        .context("Failed to create admin principal with random key")?;

        // 3. Export admin principal to persistent keytab
        fs::create_dir_all("/data").context("Failed to create /data directory")?;
        println!("Exporting admin principal to keytab: {}", keytab_path);
        run_kadmin_local(&format!("ktadd -k {} {}", keytab_path, admin_princ))
        .context("Failed to export admin principal to keytab")?;
        println!("Keytab created successfully at {}", keytab_path);

        // Secure keytab permissions (readable only by lldap user)
        Command::new("chmod")
        .arg("600")
        .arg(keytab_path)
        .status()
        .context("Failed to set keytab permissions")?;
        Command::new("chown")
        .arg("lldap:lldap")
        .arg(keytab_path)
        .status()
        .context("Failed to chown keytab to lldap user")?;
    } else {
        println!("KDC database exists—skipping bootstrap.");
    }

    // Always: Populate default credential cache with keytab for password-less runtime sync
    if Path::new(keytab_path).exists() {
        let admin_princ = format!("admin/admin@{}", realm_upper);
        println!("Populating credential cache with keytab for password-less auth: {}", admin_princ);
        let kinit_status = Command::new("/usr/bin/kinit")
        .env("KRB5_CONFIG", "/etc/krb5.conf")
        .arg("-k")  // Use keytab
        .arg("-t")
        .arg(keytab_path)
        .arg(&admin_princ)
        .status()
        .context("Failed to run kinit with keytab")?;

        if !kinit_status.success() {
            anyhow::bail!("kinit with keytab failed (exit code: {:?})", kinit_status.code());
        }
        println!("Credential cache populated successfully—runtime Kerberos sync is fully password-less.");
    } else {
        anyhow::bail!("Keytab missing at {}—bootstrap failed or volume issue", keytab_path);
    }
    // --- End Bootstrap ---

    // Start daemons (foreground with piped logs)
    println!("Starting krb5kdc...");
    let mut kdc_child = Command::new("/usr/sbin/krb5kdc")
    .arg("-n")
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .context("Failed to start krb5kdc")?;

    println!("Generating /var/kerberos/krb5kdc/kadm5.acl...");
    render_template("/app/kadm5.template.acl", "/var/kerberos/krb5kdc/kadm5.acl", &config, &domain)?;

    Command::new("chmod")
    .arg("644")
    .arg("/var/kerberos/krb5kdc/kadm5.acl")
    .output()
    .context("Failed to chmod ACL")?;
    Command::new("chown")
    .arg("root:root")
    .arg("/var/kerberos/krb5kdc/kadm5.acl")
    .output()
    .context("Failed to chown ACL to root")?;

    // Bootstrap check: is this the first run?
    let db_principal_path = "/var/lib/krb5kdc/principal";
    let keytab_path = "/data/kadm5.keytab";
    let needs_bootstrap = !Path::new(db_principal_path).exists();

    if needs_bootstrap {
        println!("First run detected—no KDC database. Bootstrapping Kerberos...");

        // 1. Create the KDC database (stashed master key, no user password needed)
        println!("Creating KDC database with kdb5_util...");
        let realm_upper = config.realm_name.to_uppercase();
        let kdb_output = Command::new("/usr/sbin/kdb5_util")
        .arg("create")
        .arg("-s")  // Stash master key
        .arg("-r")
        .arg(&realm_upper)
        .output()
        .context("Failed to run kdb5_util create")?;

        if !kdb_output.status.success() {
            let stderr = String::from_utf8_lossy(&kdb_output.stderr);
            anyhow::bail!("kdb5_util create failed: {}", stderr);
        }
        println!("KDC database created successfully.");

        // 2. Create admin principal with random key (no password)
        let admin_princ = format!("admin/admin@{}", realm_upper);
        println!("Creating admin principal: {}", admin_princ);
        run_kadmin_local(&format!("addprinc -randkey {}", admin_princ))?;

        // 3. Export admin principal to persistent keytab
        println!("Exporting admin principal to keytab: {}", keytab_path);
        fs::create_dir_all("/data")?;  // Ensure /data exists
        run_kadmin_local(&format!("ktadd -k {} {}", keytab_path, admin_princ))?;
        println!("Keytab created successfully at {}", keytab_path);
    } else {
        println!("KDC database exists—skipping bootstrap.");
    }

    // Always ensure keytab exists and populate ccache for runtime password-less auth
    if Path::new(keytab_path).exists() {
        let admin_princ = format!("admin/admin@{}", config.realm_name.to_uppercase());
        println!("Populating credential cache with keytab for {}", admin_princ);
        let kinit_output = Command::new("/usr/bin/kinit")
        .env("KRB5_CONFIG", "/etc/krb5.conf")
        .arg("-k")  // Keytab auth
        .arg("-t")
        .arg(keytab_path)
        .arg(&admin_princ)
        .output()
        .context("Failed to run kinit with keytab")?;

        if !kinit_output.status.success() {
            let stderr = String::from_utf8_lossy(&kinit_output.stderr);
            anyhow::bail!("kinit with keytab failed: {}", stderr);
        }
        println!("Credential cache populated successfully—runtime sync will be password-less.");
    } else {
        anyhow::bail!("Keytab missing at {}—cannot proceed without admin auth", keytab_path);
    }

    println!("Starting kadmind with strace for deep debug...");
    let mut kadmind_child = Command::new("strace")
    .arg("-f")
    .arg("-e")
    .arg("trace=open,openat,read,access")
    .arg("-o")
    .arg("/tmp/kadmind.trace")
    .arg("/usr/sbin/kadmind")
    .arg("-nofork")
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .context("Failed to start kadmind with strace")?;

    // Log stderr line by line (non-blocking, shows crash reason)
    if let Some(stderr) = kadmind_child.stderr.take() {
        thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
                if let Ok(line) = line {
                    println!("kadmind stderr: {}", line.trim());
                }
            }
        });
    }

    // TCP readiness waits
    let mut attempts = 0;
    println!("Waiting for krb5kdc port 88...");
    loop {
        attempts += 1;
        if TcpStream::connect(("localhost", 88)).is_ok() {
            println!("krb5kdc ready after {} attempt(s)", attempts);
            break;
        }
        if attempts >= 30 {
            return Err(anyhow::anyhow!("krb5kdc port 88 timeout"));
        }
        thread::sleep(Duration::from_millis(500));
    }

    attempts = 0;
    println!("Waiting for kadmind port 749...");
    loop {
        attempts += 1;
        if TcpStream::connect(("localhost", 749)).is_ok() {
            println!("kadmind ready after {} attempt(s)", attempts);
            break;
        }
        if attempts >= 30 {
            return Err(anyhow::anyhow!("kadmind port 749 timeout"));
        }
        thread::sleep(Duration::from_millis(500));
    }

    println!("Kerberos services fully ready!");

    // One-time schema extension for POSIX/Kerberos compatibility
    let schema_flag = "/var/lib/krb5kdc/schema_extended.flag";
    if !Path::new(schema_flag).exists() {
        println!("Extending LLDAP schema for POSIX/Kerberos...");

        // Get initial LLDAP admin password from env (only used on first run)
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
            // Continue anyway—schema extension is best-effort
        } else {
            let token: String = login_resp.json::<serde_json::Value>()
            .context("Failed to parse login response")?
            .get("token")
            .and_then(|v| v.as_str())
            .context("No token in login response")?
            .to_string();

            let graphql_url = "http://localhost:17170/api/graphql";

            let mutations = vec![
                // User attributes
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
        }
    } else {
        println!("Schema already extended—skipping.");
    }

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
