use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use lazy_static::lazy_static;
use rand::rngs::OsRng;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1::EncodeRsaPublicKey;
use std::env;
use std::process::Command;
use tracing::{debug, info, warn};

lazy_static! {
    static ref KEYPAIR: Option<(RsaPrivateKey, RsaPublicKey)> = {
        if is_kerberos_enabled() {
            match generate_keypair() {
                Ok(pair) => Some(pair),
                Err(e) => {
                    warn!("Failed to generate RSA keypair: {}", e);
                    None
                }
            }
        } else {
            None
        }
    };
}

fn generate_keypair() -> Result<(RsaPrivateKey, RsaPublicKey)> {
    let mut rng = OsRng;
    let bits = 2048;
    let priv_key = RsaPrivateKey::new(&mut rng, bits).context("Failed to generate private key")?;
    let pub_key = RsaPublicKey::from(&priv_key);
    Ok((priv_key, pub_key))
}

fn decrypt_password(encrypted: &str) -> Result<String> {
    let keypair = KEYPAIR.as_ref().context("Kerberos not enabled or keypair missing")?;
    let priv_key = &keypair.0;
    let dec_data = STANDARD.decode(encrypted).context("Base64 decode failed")?;
    let plain_data = priv_key.decrypt(Pkcs1v15Encrypt, &dec_data).context("Decryption failed")?;
    String::from_utf8(plain_data).context("UTF-8 decode failed")
}

/// Sync Kerberos principal with decrypted password (local kadmin.local via sh -c single query with ' pw).
pub fn sync_kerberos_principal(username: &str, encrypted_password: &str) -> Result<()> {
    let realm = env::var("LLDAP_KERB_REALM_NAME").unwrap_or_else(|_| "TESTLAB.COM".to_string());
    let principal = format!("{}@{}", username, realm);

    info!("Kerberos sync triggered for principal: {}", principal);
    debug!("Received encrypted password from LLDAP: {}", encrypted_password);

    let plain_password = decrypt_password(encrypted_password)?;
    debug!("Decrypted password length: {} chars", plain_password.len());

    // Try cpw first
    let cpw_cmd = format!("sudo kadmin.local -q \"cpw -keepold -pw {} -e aes256-cts-hmac-sha1-96:normal {}\"", plain_password, principal);
    debug!("Running kadmin cpw (update existing principal)");

    let cpw_output = Command::new("sh")
    .arg("-c")
    .arg(&cpw_cmd)
    .output()
    .context("Failed to run sudo kadmin.local cpw via sh")?;

    let cpw_stdout = String::from_utf8_lossy(&cpw_output.stdout);
    let cpw_stderr = String::from_utf8_lossy(&cpw_output.stderr);
    debug!("cpw stdout: {}", cpw_stdout.trim());
    debug!("cpw stderr: {}", cpw_stderr.trim());
    debug!("cpw exit status: {}", cpw_output.status);

    if cpw_output.status.success() && !cpw_stderr.contains("Principal does not exist") {
        info!("Updated password for principal: {}", principal);
        return Ok(());
    }

    // Fallback addprinc
    let add_cmd = format!("sudo kadmin.local -q \"addprinc -pw {} -e aes256-cts-hmac-sha1-96:normal {}\"", plain_password, principal);
    debug!("Running kadmin addprinc (create new principal)");

    let add_output = Command::new("sh")
    .arg("-c")
    .arg(&add_cmd)
    .output()
    .context("Failed to run sudo kadmin.local addprinc via sh")?;

    let add_stdout = String::from_utf8_lossy(&add_output.stdout);
    let add_stderr = String::from_utf8_lossy(&add_output.stderr);
    debug!("addprinc stdout: {}", add_stdout.trim());
    debug!("addprinc stderr: {}", add_stderr.trim());
    debug!("addprinc exit status: {}", add_output.status);

    if add_output.status.success() {
        info!("Created new principal: {}", principal);
        Ok(())
    } else {
        warn!("addprinc failed (non-fatal): {}", add_stderr.trim());
        Ok(())
    }
}

/// Delete Kerberos principal (local kadmin.local via sh -c).
pub fn delete_kerberos_principal(username: &str) -> Result<()> {
    let realm = env::var("LLDAP_KERB_REALM_NAME").unwrap_or_else(|_| "TESTLAB.COM".to_string());
    let principal = format!("{}@{}", username, realm);

    let del_cmd = format!("sudo kadmin.local -q \"delprinc -force {}\"", principal);
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
    env::var("LLDAP_KERB_ENABLED").unwrap_or_else(|_| "false".to_string()) == "true"
}

pub fn get_public_key_der_base64() -> Option<String> {
    if is_kerberos_enabled() {
        let keypair = KEYPAIR.as_ref()?;
        let der = keypair.1.to_pkcs1_der().ok()?;
        Some(STANDARD.encode(der.as_bytes()))
    } else {
        None
    }
}
