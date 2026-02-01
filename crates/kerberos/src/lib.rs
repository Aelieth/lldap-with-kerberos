use anyhow::{Context, Result};
use std::io::{BufReader, Write};
use std::process::{Command, Stdio};
use tracing::{info, warn};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use lazy_static::lazy_static;
use rand::rngs::OsRng;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1::EncodeRsaPublicKey;
use std::ffi::{CString, CStr};
use std::os::raw::{c_void, c_long};
use std::mem;
use std::{env, ptr};

// Generated FFI bindings — created at compile time by build.rs
#[allow(non_camel_case_types)]
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(dead_code)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub use bindings::*; // Re-export so kerberos_manager can see them too

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
    let admin_principal = format!("admin/admin@{}", realm);  // Change to "admin/admin/admin@{}" if manual test shows instance needed

    info!("Kerberos sync triggered for principal: {}", principal);

    let handle = Kadm5Handle::init_with_keytab("/data/kadm5.keytab", &admin_principal, &realm)
    .context(format!("Failed to init keytab handle for sync of {}", principal))?;

    match handle.chpass_principal(username, plain_password, &realm) {
        Ok(()) => {
            info!("Kerberos password updated for {}", principal);
            Ok(())
        }
        Err(e) => {
            let err_str = e.to_string();
            warn!("chpass failed for {}: {}", principal, err_str);
            if err_str.contains("Principal does not exist") || err_str.contains("No such principal") {
                match handle.create_principal(username, plain_password, &realm) {
                    Ok(()) => {
                        info!("Kerberos principal created for {}", principal);
                        Ok(())
                    }
                    Err(create_e) => {
                        warn!("create fallback failed for {}: {}", principal, create_e);
                        Err(create_e)
                    }
                }
            } else {
                Err(e)
            }
        }
    }
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

pub struct Kadm5Handle {
    pub handle: *mut c_void,
    pub context: krb5_context,
}

impl Kadm5Handle {
    pub fn init_with_keytab(keytab_path: &str, client_principal: &str, realm: &str) -> Result<Self> {
        let mut handle: *mut c_void = ptr::null_mut();
        let mut context: krb5_context = ptr::null_mut();

        let ret = unsafe { krb5_init_context(&mut context) };
        if ret != 0 {
            return Err(anyhow::anyhow!("krb5_init_context failed with code {}", ret));
        }

        let client_cstr = CString::new(client_principal)?;
        let keytab_cstr = CString::new(keytab_path)?;
        let realm_cstr = CString::new(realm)?;

        let mut params: kadm5_config_params = unsafe { mem::zeroed() };
        params.mask = KADM5_CONFIG_REALM as i64;  // i64 for Fedora bindings
        params.realm = realm_cstr.as_ptr() as *mut i8;

        let ret = unsafe {
            kadm5_init_with_skey(
                context,
                client_cstr.as_ptr() as *mut i8,
                                 keytab_cstr.as_ptr() as *mut i8,
                                 ptr::null_mut(),  // service_name (null for default kadmin/admin)
            &mut params,
            1,  // struct_version
            4,  // api_version
            ptr::null_mut(),  // db_args
                                 &mut handle as *mut *mut c_void,
            )
        };

        if ret != 0 {
            let code = ret as i32;
            let msg_ptr = unsafe { krb5_get_error_message(context, code) };
            let err_msg = if msg_ptr.is_null() {
                format!("code {}", ret)
            } else {
                let s = unsafe { CStr::from_ptr(msg_ptr).to_string_lossy().into_owned() };
                unsafe { krb5_free_error_message(context, msg_ptr) };
                s
            };
            unsafe { krb5_free_context(context) };
            return Err(anyhow::anyhow!("kadm5_init_with_skey failed: {}", err_msg));
        }

        Ok(Kadm5Handle { handle, context })
    }

    /// Create principal with password (uses policy from kdc.conf for aes256 keys)
    pub fn create_principal(&self, username: &str, password: &str, realm: &str) -> Result<()> {
        let principal_name = format!("{}@{}", username, realm);
        let principal_cstr = CString::new(principal_name)?;

        let mut princ: krb5_principal = ptr::null_mut();
        let ret = unsafe { krb5_parse_name(self.context, principal_cstr.as_ptr(), &mut princ) };
        if ret != 0 {
            return Err(anyhow::anyhow!("krb5_parse_name failed with code {}", ret));
        }

        let mut ent: kadm5_principal_ent_rec = unsafe { mem::zeroed() };
        ent.principal = princ;

        // Mask: create the principal (password generates keys via policy)
        let mask = 1 as c_long;  // KADM5_PRINCIPAL = 1 (hardcoded safe value)

        let pass_cstr = CString::new(password)?;

        let ret = unsafe {
            kadm5_create_principal(
                self.handle,
                &mut ent,
                mask,
                pass_cstr.as_ptr() as *mut i8,
            )
        };

        unsafe { krb5_free_principal(self.context, princ) };

        if ret != 0 {
            let code = ret as i32;
            let msg_ptr = unsafe { krb5_get_error_message(self.context, code) };
            let err_msg = if msg_ptr.is_null() {
                format!("code {}", ret)
            } else {
                let s = unsafe { CStr::from_ptr(msg_ptr).to_string_lossy().into_owned() };
                unsafe { krb5_free_error_message(self.context, msg_ptr) };
                s
            };
            return Err(anyhow::anyhow!("kadm5_create_principal failed: {}", err_msg));
        }

        Ok(())
    }

    /// Change password on existing principal (core sync operation)
    pub fn chpass_principal(&self, username: &str, password: &str, realm: &str) -> Result<()> {
        let principal_name = format!("{}@{}", username, realm);
        let principal_cstr = CString::new(principal_name)?;

        let mut princ: krb5_principal = ptr::null_mut();
        let ret = unsafe { krb5_parse_name(self.context, principal_cstr.as_ptr(), &mut princ) };
        if ret != 0 {
            return Err(anyhow::anyhow!("krb5_parse_name failed with code {}", ret));
        }

        let pass_cstr = CString::new(password)?;

        let ret = unsafe {
            kadm5_chpass_principal(
                self.handle,
                princ,
                pass_cstr.as_ptr() as *mut i8,
            )
        };

        unsafe { krb5_free_principal(self.context, princ) };

        if ret != 0 {
            let code = ret as i32;
            let msg_ptr = unsafe { krb5_get_error_message(self.context, code) };
            let err_msg = if msg_ptr.is_null() {
                format!("code {}", ret)
            } else {
                let s = unsafe { CStr::from_ptr(msg_ptr).to_string_lossy().into_owned() };
                unsafe { krb5_free_error_message(self.context, msg_ptr) };
                s
            };
            return Err(anyhow::anyhow!("kadm5_chpass_principal failed: {}", err_msg));
        }

        Ok(())
    }
}

impl Drop for Kadm5Handle {
    fn drop(&mut self) {
        unsafe {
            let _ = kadm5_destroy(self.handle as *mut c_void);
            let _ = krb5_free_context(self.context);
        }
    }
}
