use anyhow::{Context, Result};
use minijinja::{context, Environment};
use serde::Deserialize;
use std::env;
use std::fs;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::Duration;
use std::net::TcpStream;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;

// Import the shared helper from our own lib crate
use lldap_kerberos::derive_realm_from_base_dn;

#[derive(Deserialize, Debug)]
struct KerberosConfig {
    realm_name: String,
    base_dn: String,
    ticket_lifetime: String,
    renew_lifetime: String,
    forwardable: bool,
        rdns: bool,
}

/// Run kadmin.local — only show output on error
fn run_kadmin_local(query: &str) -> Result<Output> {
    let output = Command::new("sudo")
    .arg("/usr/sbin/kadmin.local")
    .env("KRB5_CONFIG", "/etc/krb5.conf")
    .arg("-q")
    .arg(query)
    .output()
    .context("Failed to spawn sudo kadmin.local")?;

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("kadmin.local failed!");
        if !stdout.trim().is_empty() {
            println!("stdout: {}", stdout.trim());
        }
        if !stderr.trim().is_empty() {
            println!("stderr: {}", stderr.trim());
        }
    }

    Ok(output)
}

fn main() -> Result<()> {
    println!("Kerberos manager starting...");

    // Paths
    let config_path = "/data/kerberos_config.toml";
    let template_path = "/app/kerberos_config.template.toml";

    if !Path::new(config_path).exists() {
        println!("Kerberos config not found. Copying template...");
        fs::copy(template_path, config_path).context("Failed to copy config template")?;
    }

    // Load TOML
    let toml_str = fs::read_to_string(config_path).context("Failed to read kerberos_config.toml")?;
    let full_config: toml::Table = toml::from_str(&toml_str).context("Failed to parse TOML")?;

    let kerberos_value = full_config.get("kerberos").context("Missing [kerberos] table")?.clone();
    let mut config: KerberosConfig = kerberos_value.try_into().context("Failed to deserialize [kerberos]")?;

    // Realm derivation (shared helper — no duplication)
    let realm_name = derive_realm_from_base_dn();
    config.realm_name = realm_name.clone();

    let base_dn = env::var("LLDAP_LDAP_BASE_DN").unwrap_or_else(|_| config.base_dn.clone());
    config.base_dn = base_dn.clone();

    let domain = base_dn
    .split(',')
    .filter_map(|part| part.strip_prefix("dc="))
    .collect::<Vec<_>>()
    .join(".")
    .to_lowercase();

    println!("Calculated DOMAIN: {}", domain);
    println!("Effective REALM_NAME: {}", config.realm_name);

    // Render templates
    fs::create_dir_all("/var/kerberos/krb5kdc").context("Failed to create krb5kdc dir")?;
    render_template("/app/krb5.template.conf", "/etc/krb5.conf", &config, &domain)?;
    render_template("/app/kdc.template.conf", "/var/kerberos/krb5kdc/kdc.conf", &config, &domain)?;
    render_template("/app/kadm5.template.acl", "/var/kerberos/krb5kdc/kadm5.acl", &config, &domain)?;

    // Keycloak config
    let keycloak_config_path = "/data/keycloak_config.toml";
    let keycloak_template_path = "/app/keycloak_config.template.toml";

    if !Path::new(keycloak_config_path).exists() {
        println!("Keycloak config not found. Copying template...");
        fs::copy(keycloak_template_path, keycloak_config_path)
        .context("Failed to copy keycloak_config.template.toml")?;
        Command::new("sudo")
        .arg("chown")
        .arg("lldap:lldap")
        .arg(keycloak_config_path)
        .status()
        .context("Failed to chown keycloak_config.toml")?;
        println!("Created default keycloak_config.toml in /data");
    } else {
        println!("Existing keycloak_config.toml found — skipping template copy.");
    }

    // --- Kerberos Bootstrap ---
    let db_path = Path::new("/var/kerberos/krb5kdc/principal");

    if !db_path.exists() {
        println!("First run detected — no KDC database. Bootstrapping password-less...");

        // Generate random master password (in-memory only)
        let master_pass_output = Command::new("openssl")
        .arg("rand")
        .arg("-hex")
        .arg("32")
        .output()
        .context("Failed to generate random master password")?;
        let master_pass = String::from_utf8_lossy(&master_pass_output.stdout).trim().to_string();
        println!("Generated random master password (length: {} chars).", master_pass.len());

        println!("Creating KDC database with piped password...");
        let mut child = Command::new("sudo")
        .arg("kdb5_util")
        .env("KRB5_CONFIG", "/etc/krb5.conf")
        .arg("create")
        .arg("-s")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to spawn sudo kdb5_util")?;

        if let Some(mut stdin) = child.stdin.take() {
            writeln!(stdin, "{}", master_pass)?;
            writeln!(stdin, "{}", master_pass)?;
        }

        let output = child.wait_with_output().context("Failed to wait on kdb5_util")?;
        if !output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("kdb5_util failed!\nstdout: {}\nstderr: {}", stdout.trim(), stderr.trim());
        }
        println!("KDC database created successfully.");

        // Create admin principal + keytab
        let admin_princ = format!("admin/admin@{}", config.realm_name.to_uppercase());
        println!("Creating admin principal with random key: {}", admin_princ);
        let add_output = run_kadmin_local(&format!("addprinc -randkey {}", admin_princ))?;
        if !add_output.status.success() {
            anyhow::bail!("addprinc failed");
        }

        let keytab_path = "/data/kadm5.keytab";
        println!("Exporting admin principal to keytab: {}", keytab_path);
        let ktadd_output = run_kadmin_local(&format!("ktadd -k {} {}", keytab_path, admin_princ))?;
        if !ktadd_output.status.success() {
            anyhow::bail!("ktadd failed");
        }
        println!("Keytab created.");

        // Ownership (once only)
        Command::new("sudo")
        .arg("chown")
        .arg("lldap:lldap")
        .arg(keytab_path)
        .status()
        .context("Failed to chown keytab")?;
        Command::new("sudo")
        .arg("chown")
        .arg("-R")
        .arg("lldap:lldap")
        .arg("/var/kerberos/krb5kdc")
        .status()
        .context("Failed to chown DB dir")?;
        println!("Ownership set on keytab and DB files.");
    } else {
        println!("Existing KDC database detected — skipping bootstrap.");
    }

    // Start daemons
    println!("Starting krb5kdc...");
    let mut kdc_child = Command::new("/usr/sbin/krb5kdc").spawn().context("Failed to start krb5kdc")?;

    println!("Starting kadmind...");
    let mut kadmind_child = Command::new("/usr/sbin/kadmind").spawn().context("Failed to start kadmind")?;

    // Wait for KDC
    println!("Waiting for KDC on port 88...");
    for _ in 0..60 {
        if TcpStream::connect(("localhost", 88)).is_ok() {
            println!("KDC ready on port 88.");
            break;
        }
        thread::sleep(Duration::from_secs(1));
    }

    // Populate ccache
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
            anyhow::bail!("kinit failed");
        }
        println!("ccache populated — Kerberos sync fully password-less.");
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
    env.add_template("template", &template_str)?;

    let tmpl = env.get_template("template").unwrap();
    let rendered = tmpl.render(context! {
        TICKET_LIFETIME => config.ticket_lifetime,
        RENEW_LIFETIME => config.renew_lifetime,
        FORWARDABLE => config.forwardable,
        RDNS => config.rdns,
        REALM_NAME => config.realm_name,
        DOMAIN => domain,
    })?;

    fs::write(output_path, rendered).context(format!("Failed to write {}", output_path))?;
    println!("Generated {} successfully.", output_path);

    Ok(())
}
