use anyhow::{Context, Result};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use tracing::{debug, info, warn};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use lazy_static::lazy_static;
use rand::rngs::OsRng;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1::EncodeRsaPublicKey;
use std::env;  // Keep for realm

lazy_static! {
    static ref KEYPAIR: (RsaPrivateKey, RsaPublicKey) = {
        match generate_keypair() {
            Ok(pair) => pair,
            Err(e) => {
                warn!("Failed to generate RSA keypair for Kerberos—sync will fail: {}", e);
                let mut rng = OsRng;
                let dummy_priv = RsaPrivateKey::new(&mut rng, 128).expect("Failed to generate dummy private key");
                let dummy_pub = RsaPublicKey::from(&dummy_priv);
                (dummy_priv, dummy_pub)  // Dummy pair, will fail decrypt later
            }
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

pub fn decrypt_password(encrypted: &str) -> Result<String> {
    let priv_key = &KEYPAIR.0;
    let dec_data = STANDARD.decode(encrypted).context("Base64 decode failed")?;
    let plain_data = priv_key.decrypt(Pkcs1v15Encrypt, &dec_data).context("Decryption failed")?;
    String::from_utf8(plain_data).context("UTF-8 decode failed")
}

fn run_kadmin_interactive<F>(mut cmd_handler: F) -> Result<()>
where
F: FnMut(&mut std::process::ChildStdin, &mut BufReader<std::process::ChildStdout>) -> Result<()>,
{
    let mut child = Command::new("/usr/sbin/kadmin.local")
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .context("Failed to spawn kadmin.local")?;

    let mut stdin = child.stdin.take().context("Failed to take stdin")?;
    let stdout = child.stdout.take().context("Failed to take stdout")?;
    let mut reader = BufReader::new(stdout);

    cmd_handler(&mut stdin, &mut reader)?;

    writeln!(stdin, "quit")?;
    stdin.flush()?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("kadmin.local failed: {}", stderr));
    }
    Ok(())
}

pub fn sync_kerberos_principal(username: &str, plain_password: &str) -> Result<()> {
    let realm = env::var("LLDAP_KERB_REALM_NAME").unwrap_or_else(|_| "TESTLAB.COM".to_string());
    let principal = format!("{}@{}", username, realm);

    info!("Kerberos sync triggered for principal: {}", principal);

    run_kadmin_interactive(|stdin, reader| {
        // Check if exists with getprinc
        writeln!(stdin, "getprinc {}", principal)?;
        stdin.flush()?;

        let mut exists = false;
        let mut line = String::new();
        while reader.read_line(&mut line)? > 0 {
            if line.contains("Principal does not exist") {
                break;
            }
            if line.starts_with("Principal: ") {
                exists = true;
                break;
            }
            line.clear();
        }

        // cpw or addprinc
        if exists {
            writeln!(stdin, "cpw {}", principal)?;
        } else {
            writeln!(stdin, "addprinc -e aes256-cts-hmac-sha1-96:normal {}", principal)?;
        }
        stdin.flush()?;

        // Send pw twice (prompt + confirm)
        for _ in 0..2 {
            line.clear();
            reader.read_line(&mut line)?;
            debug!("kadmin prompt: {}", line.trim());
            if line.to_lowercase().contains("password") {
                writeln!(stdin, "{}", plain_password)?;
                stdin.flush()?;
            }
        }

        // Check result
        line.clear();
        reader.read_line(&mut line)?;
        debug!("kadmin result: {}", line.trim());
        if line.contains("changed") || line.contains("created") {
            info!("Synced principal: {}", principal);
        } else {
            warn!("Sync issue: {}", line.trim());
        }
        Ok(())
    })
}

pub fn delete_kerberos_principal(username: &str) -> Result<()> {
    let realm = env::var("LLDAP_KERB_REALM_NAME").unwrap_or_else(|_| "TESTLAB.COM".to_string());
    let principal = format!("{}@{}", username, realm);

    run_kadmin_interactive(|stdin, _reader| {
        writeln!(stdin, "delprinc -force {}", principal)?;
        stdin.flush()?;
        Ok(())
    })?;

    info!("Deleted principal: {}", principal);
    Ok(())
}

pub fn get_public_key_der_base64() -> String {
    let der = KEYPAIR.1.to_pkcs1_der().ok();
    der.map(|d| STANDARD.encode(d.as_bytes())).unwrap_or_default()
}
