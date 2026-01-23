use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use std::env;
use std::process::Command;
use tracing::{debug, info, warn};

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
    debug!("Obfuscated password length: {} chars", password.len());
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

/// Sync Kerberos principal with deobfuscated password (local kadmin.local via sh -c single query with ' pw).
pub fn sync_kerberos_principal(username: &str, obfuscated_password: &str) -> Result<()> {
    let realm = env::var("REALM_NAME").unwrap_or_else(|_| "TESTLAB.COM".to_string());
    let principal = format!("{}@{}", username, realm);

    let plain_password = deobfuscate_password(obfuscated_password)?;
    debug!("Syncing principal: {} (pw length: {})", principal, plain_password.len());

    // Try cpw first (sh -c single query, single quotes pw safe)
    let cpw_cmd = format!("kadmin.local -q \"cpw -pw '{}' {}\"", plain_password, principal);
    debug!("Running kadmin cpw cmd: {}", cpw_cmd);

    let cpw_output = Command::new("sh")
    .arg("-c")
    .arg(&cpw_cmd)
    .output()
    .context("Failed to run kadmin.local cpw via sh")?;

    let cpw_stdout = String::from_utf8_lossy(&cpw_output.stdout);
    let cpw_stderr = String::from_utf8_lossy(&cpw_output.stderr);
    debug!("cpw stdout: {}", cpw_stdout.trim());
    debug!("cpw stderr: {}", cpw_stderr.trim());

    if cpw_output.status.success() && !cpw_stderr.contains("Principal does not exist") {
        info!("Updated password for principal: {}", principal);
        return Ok(());
    }

    // Fallback addprinc (sh -c single query)
    let add_cmd = format!("kadmin.local -q \"addprinc -pw '{}' {}\"", plain_password, principal);
    debug!("Running kadmin addprinc cmd: {}", add_cmd);

    let add_output = Command::new("sh")
    .arg("-c")
    .arg(&add_cmd)
    .output()
    .context("Failed to run kadmin.local addprinc via sh")?;

    let add_stdout = String::from_utf8_lossy(&add_output.stdout);
    let add_stderr = String::from_utf8_lossy(&add_output.stderr);
    debug!("addprinc stdout: {}", add_stdout.trim());
    debug!("addprinc stderr: {}", add_stderr.trim());

    if add_output.status.success() {
        info!("Created new principal: {}", principal);
        Ok(())
    } else {
        warn!("addprinc failed (non-fatal): {}", add_stderr);
        Ok(())
    }
}

/// Delete Kerberos principal (local kadmin.local via sh -c).
pub fn delete_kerberos_principal(username: &str) -> Result<()> {
    let realm = env::var("REALM_NAME").unwrap_or_else(|_| "TESTLAB.COM".to_string());
    let principal = format!("{}@{}", username, realm);

    let del_cmd = format!("kadmin.local -q \"delprinc -force {}\"", principal);
    debug!("Running kadmin delprinc cmd: {}", del_cmd);

    let del_output = Command::new("sh")
    .arg("-c")
    .arg(&del_cmd)
    .output()
    .context("Failed to run kadmin.local delprinc via sh")?;

    let del_stdout = String::from_utf8_lossy(&del_output.stdout);
    let del_stderr = String::from_utf8_lossy(&del_output.stderr);
    debug!("delprinc stdout: {}", del_stdout.trim());
    debug!("delprinc stderr: {}", del_stderr.trim());

    if del_output.status.success() {
        info!("Deleted Kerberos principal: {}", principal);
        Ok(())
    } else {
        warn!("Kerberos principal delete warning (non-fatal): {}", del_stderr);
        Ok(())
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
