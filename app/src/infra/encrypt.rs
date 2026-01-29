use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
use rsa::pkcs1::DecodeRsaPublicKey;

/// Encrypt the plain password using the RSA public key (DER base64 input, base64 output).
pub fn encrypt_password(pub_key_der_base64: &str, plain: &str) -> Result<String> {
    let der_bytes = STANDARD.decode(pub_key_der_base64).context("Base64 decode of public key failed")?;
    let pub_key = RsaPublicKey::from_pkcs1_der(&der_bytes).context("Failed to load public key from DER")?;

    let encrypted_data = pub_key.encrypt(&mut rand::thread_rng(), Pkcs1v15Encrypt, plain.as_bytes())
    .context("Encryption failed")?;

    Ok(STANDARD.encode(encrypted_data))
}
