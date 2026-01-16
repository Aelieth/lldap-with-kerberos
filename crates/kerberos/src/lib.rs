use anyhow::{anyhow, Result, Context, bail};  // Updated: Add anyhow for the macro  // Import bail! macro here
use base64::engine::general_purpose::STANDARD;  // Fixed: Use STANDARD for general-purpose base64
use base64::Engine;  // New: Brings the trait into scope for encode method
use std::env;
use std::process::Command;
use tracing::{debug, error};

/// Obfuscate the plain password (XOR + base64) using ENCODE_KEY env.
pub fn obfuscate_password(password: &str) -> Result<String> {
    let encode_key = env::var("ENCODE_KEY").context("ENCODE_KEY env missing for obfuscation")?;
    let key_bytes = encode_key.as_bytes();
    let xored: Vec<u8> = password.as_bytes().iter().enumerate().map(|(i, &b)| b ^ key_bytes[i % key_bytes.len()]).collect();
    Ok(STANDARD.encode(&xored))  // Unchanged: Now works with Engine trait
}

/// Call the external hook script if enabled, with username and obfuscated password.
pub fn sync_kerberos_hook(username: &str, plain_password: &str) -> Result<()> {
    if let Some(hook_path) = env::var_os("LLDAP_PASSWORD_CHANGE_HOOK") {
        let obfuscated = obfuscate_password(plain_password)?;
        debug!("Calling Kerberos hook for user: {}", username);
        let output = Command::new(hook_path)
        .arg(username)
        .arg(&obfuscated)
        .output()
        .context("Failed to execute hook")?;
        if !output.status.success() {
            error!("Hook failed: {}", String::from_utf8_lossy(&output.stderr));
            bail!("Kerberos sync failed");
        }
        Ok(())
    } else {
        debug!("Kerberos hook not enabled—skipping sync");
        Ok(())
    }
}

pub fn is_kerberos_enabled() -> bool {
    std::env::var("LLDAP_PASSWORD_CHANGE_HOOK").is_ok()
}

pub fn get_encode_key() -> Option<String> {
    if is_kerberos_enabled() {
        std::env::var("ENCODE_KEY").ok()
    } else {
        None
    }
}

pub fn sync_kerberos_hook_obfuscated(user: &str, obfuscated: &str) -> anyhow::Result<()> {
    if let Ok(hook) = std::env::var("LLDAP_PASSWORD_CHANGE_HOOK") {
        let output = Command::new(&hook)
        .arg(user)
        .arg(obfuscated)
        .output()
        .context(format!("Failed to execute Kerberos hook '{}'", hook))?;
        if !output.status.success() {
            return Err(anyhow!(
                "Kerberos hook failed: stdout: {}, stderr: {}",
                String::from_utf8_lossy(&output.stdout),
                               String::from_utf8_lossy(&output.stderr)
            ));
        }
    }
    Ok(())
}
