use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use std::env;
use std::process::Command;
use tracing::{debug, error, info, warn};

/// Obfuscate the plain password (XOR + base64) using ENCODE_KEY env.
pub fn obfuscate_password(password: &str) -> Result<String> {
    let encode_key = env::var("ENCODE_KEY").context("ENCODE_KEY env missing for obfuscation")?;
    let key_bytes = encode_key.as_bytes();
    let xored: Vec<u8> = password
    .as_bytes()
    .iter()
    .enumerate()
    .map(|(i, &b)| b ^ key_bytes[i % key_bytes.len()])
    .collect();
    debug!("Obfuscated password length: {} chars", password.len());  // Safe debug
    Ok(STANDARD.encode(&xored))
}

/// Deobfuscate (reverse XOR + base64) — internal for sync.
fn deobfuscate_password(obfuscated: &str) -> Result<String> {
    let encode_key = env::var("ENCODE_KEY").context("ENCODE_KEY env missing")?;
    let key_bytes = encode_key.as_bytes();
    let xored = STANDARD.decode(obfuscated).context("Base64 decode failed")?;
    let plain: Vec<u8> = xored
    .iter()
    .enumerate()
    .map(|(i, &b)| b ^ key_bytes[i % key_bytes.len()])
    .collect();
    String::from_utf8(plain).context("UTF-8 decode failed")
}

/// Sync Kerberos principal with deobfuscated password (local kadmin.local).
pub fn sync_kerberos_principal(username: &str, obfuscated_password: &str) -> Result<()> {
    let realm = env::var("REALM_NAME").unwrap_or_else(|_| "TESTLAB.COM".to_string());
    let principal = format!("{}@{}", username, realm);

    let plain_password = deobfuscate_password(obfuscated_password)?;
    debug!("Syncing principal: {} (pw length: {})", principal, plain_password.len());

    // Try change pw first (update if exists)
    let cpw_output = Command::new("kadmin.local")
    .arg("-q")
    .arg(format!("cpw -pw \"{}\" {}", plain_password, principal))
    .output()
    .context("Failed to run kadmin.local cpw")?;

    if cpw_output.status.success() {
        info!("Updated password for principal: {}", principal);
        return Ok(());
    }

    let cpw_err = String::from_utf8_lossy(&cpw_output.stderr);
    if cpw_err.contains("Principal does not exist") {
        // Fallback: create new
        let add_output = Command::new("kadmin.local")
        .arg("-q")
        .arg(format!("addprinc -pw \"{}\" {}", plain_password, principal))
        .output()
        .context("Failed to run kadmin.local addprinc")?;

        if add_output.status.success() {
            info!("Created new principal: {}", principal);
            return Ok(());
        }

        error!("addprinc failed: {}", String::from_utf8_lossy(&add_output.stderr));
        bail!("Failed to create principal {}", principal);
    }

    error!("cpw failed: {}", cpw_err);
    bail!("Failed to update principal {}", principal);
}

/// NEW: Delete Kerberos principal (local kadmin.local, non-fatal for LLDAP delete)
pub fn delete_kerberos_principal(username: &str) -> Result<()> {
    let realm = env::var("REALM_NAME").unwrap_or_else(|_| "TESTLAB.COM".to_string());
    let principal = format!("{}@{}", username, realm);

    let del_output = Command::new("kadmin.local")
    .arg("-q")
    .arg(format!("delprinc -force {}", principal))
    .output()
    .context("Failed to run kadmin.local delprinc")?;

    if del_output.status.success() {
        info!("Deleted Kerberos principal: {}", principal);
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&del_output.stderr);
        warn!("Kerberos principal delete warning (non-fatal): {}", err);
        Ok(())  // Non-fatal—return Ok to not block LLDAP delete
    }
}

pub fn is_kerberos_enabled() -> bool {
    env::var("ENCODE_KEY").is_ok() && env::var("REALM_NAME").is_ok()
}

pub fn get_encode_key() -> Option<String> {
    if is_kerberos_enabled() {
        env::var("ENCODE_KEY").ok()
    } else {
        None
    }
}
