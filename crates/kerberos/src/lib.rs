use anyhow::{Context, Result};
use tracing::{info, warn};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use lazy_static::lazy_static;
use rand::rngs::OsRng;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};  // Removed old Pkcs1v15Encrypt — upgraded to modern OAEP
use rsa::pkcs1::EncodeRsaPublicKey;
use sha2::Sha256;  // New for secure OAEP padding (this is the security upgrade)
use std::ffi::{CString, CStr};
use std::os::raw::{c_int, c_void, c_long, c_char};
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

// Shared helper — eliminates duplication between lib.rs and kerberos_manager.rs
// Uses exact same logic as before (LLDAP_LDAP_BASE_DN → domain → realm)
pub fn derive_realm_from_base_dn() -> String {
    let base_dn = env::var("LLDAP_LDAP_BASE_DN")
    .unwrap_or_else(|_| "dc=example,dc=com".to_string());
    let domain = base_dn
    .split(',')
    .filter_map(|part| part.strip_prefix("dc="))
    .collect::<Vec<_>>()
    .join(".")
    .to_lowercase();
    env::var("LLDAP_KERB_REALM_NAME")
    .ok()
    .filter(|s| !s.is_empty())
    .unwrap_or_else(|| domain.to_uppercase())
    .to_uppercase()
}

lazy_static! {
    static ref KEYPAIR: (RsaPrivateKey, RsaPublicKey) = {
        match generate_keypair() {
            Ok(pair) => pair,
            Err(e) => {
                warn!("Failed to generate RSA keypair for Kerberos—sync will fail: {}", e);
                let mut rng = OsRng;
                let dummy_priv = RsaPrivateKey::new(&mut rng, 128).expect("Failed to generate dummy private key");
                let dummy_pub = RsaPublicKey::from(&dummy_priv);
                (dummy_priv, dummy_pub)
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
    // Security upgrade: OAEP + SHA-256 (modern, recommended padding)
    let padding = Oaep::new::<Sha256>();
    let plain_data = priv_key.decrypt(padding, &dec_data).context("Decryption failed")?;
    String::from_utf8(plain_data).context("UTF-8 decode failed")
}

pub fn delete_kerberos_principal(username: &str) -> Result<()> {
    // Uses new shared helper — no more duplicated realm logic!
    // Matches exactly what kerberos_manager.rs and GraphQL mutations use.
    let realm_upper = derive_realm_from_base_dn();

    let full_principal = format!("{}@{}", username, realm_upper);
    info!("Attempting to delete Kerberos principal via FFI: {}", full_principal);

    let admin_principal = format!("admin/admin@{}", realm_upper);
    let keytab_path = "/data/kadm5.keytab";

    let handle = Kadm5Handle::init_with_keytab(keytab_path, &admin_principal, &realm_upper)
    .context("Failed to initialize Kerberos admin handle with keytab for delete")?;

    handle.delete_principal(&full_principal)
}

pub fn sync_kerberos_principal(username: &str, plain_password: &str) -> Result<()> {
    // Uses new shared helper — single source of truth for realm derivation
    // (LLDAP_LDAP_BASE_DN → domain → realm, with LLDAP_KERB_REALM_NAME override)
    let realm_upper = derive_realm_from_base_dn();

    let full_principal = format!("{}@{}", username, realm_upper);
    info!("Kerberos sync started for principal: {}", full_principal);

    let admin_principal = format!("admin/admin@{}", realm_upper);
    let keytab_path = "/data/kadm5.keytab";

    info!("Using direct keytab auth for admin: {} (keytab: {})", admin_principal, keytab_path);

    let handle = Kadm5Handle::init_with_keytab(keytab_path, &admin_principal, &realm_upper)
    .context("Failed to initialize Kerberos admin handle with keytab (check keytab exists/permissions)")?;

    // Try change password first (most common case after user already exists)
    if handle.chpass_principal(username, plain_password, &realm_upper).is_ok() {
        info!("Kerberos password updated successfully for {}", full_principal);
        return Ok(());
    }

    warn!("Change password failed (likely principal does not exist)—creating new principal...");

    handle.create_principal(username, plain_password, &realm_upper)
    .context("Failed to create new Kerberos principal")?;

    info!("Kerberos principal created and password set for {}", full_principal);

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
    /// Initialize a Kadm5 handle using either a password (for first-time setup) or NULL password (uses default ccache for keytab auth later)
    pub fn init_with_password_or_ccache(pass: Option<&str>, admin_principal: &str, realm: &str) -> Result<Self> {
        let mut context: krb5_context = ptr::null_mut();
        let ret = unsafe { krb5_init_context(&mut context) };
        if ret != 0 {
            return Err(anyhow::anyhow!("krb5_init_context failed with code {}", ret));
        }

        let mut handle: *mut c_void = ptr::null_mut();

        let client_name_cstr = CString::new(admin_principal).context("Invalid admin principal")?;
        let service_name_ptr: *mut c_char = ptr::null_mut();

        let realm_cstr = CString::new(realm).context("Invalid realm")?;

        let mut params: kadm5_config_params = unsafe { mem::zeroed() };
        params.mask = KADM5_CONFIG_REALM as c_long;
        params.realm = realm_cstr.into_raw() as *mut i8;

        let pass_ptr = match pass {
            Some(p) => CString::new(p)?.into_raw() as *mut i8,
            None => ptr::null_mut(),
        };

        let struct_version: krb5_ui_4 = KADM5_STRUCT_VERSION;
        let api_version: krb5_ui_4 = KADM5_API_VERSION_4;

        let db_args_ptr: *mut *mut c_char = ptr::null_mut();

        let ret = unsafe {
            kadm5_init_with_password(
                context,
                client_name_cstr.as_ptr() as *mut c_char,
                                     pass_ptr,
                                     service_name_ptr,
                                     &mut params,
                                     struct_version,
                                     api_version,
                                     db_args_ptr,
                                     &mut handle,
            )
        };

        if pass.is_some() {
            unsafe { let _ = CString::from_raw(pass_ptr); }
        }
        unsafe { let _ = CString::from_raw(params.realm); }

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
            warn!("kadm5_init_with_password failed with code {}: {}", ret, err_msg);
            unsafe { krb5_free_context(context) };
            return Err(anyhow::anyhow!("kadm5_init_with_password failed: {}", err_msg));
        }

        Ok(Kadm5Handle { handle, context })
    }

    pub fn init_with_keytab(keytab_path: &str, admin_principal: &str, realm: &str) -> Result<Self> {
        let mut context: krb5_context = ptr::null_mut();
        let ret = unsafe { krb5_init_context(&mut context) };
        if ret != 0 {
            return Err(anyhow::anyhow!("krb5_init_context failed with code {}", ret));
        }

        let mut handle: *mut c_void = ptr::null_mut();

        let client_name_cstr = CString::new(admin_principal).context("Invalid admin principal")?;
        let keytab_cstr = CString::new(keytab_path).context("Invalid keytab path")?;
        let service_name_ptr: *mut c_char = ptr::null_mut();

        let realm_cstr = CString::new(realm).context("Invalid realm")?;

        let mut params: kadm5_config_params = unsafe { mem::zeroed() };
        params.mask = KADM5_CONFIG_REALM as c_long;
        params.realm = realm_cstr.into_raw() as *mut i8;

        let struct_version: krb5_ui_4 = KADM5_STRUCT_VERSION;
        let api_version: krb5_ui_4 = KADM5_API_VERSION_4;

        let db_args_ptr: *mut *mut c_char = ptr::null_mut();

        let ret = unsafe {
            kadm5_init_with_skey(
                context,
                client_name_cstr.as_ptr() as *mut c_char,
                                 keytab_cstr.as_ptr() as *mut c_char,
                                 service_name_ptr,
                                 &mut params,
                                 struct_version,
                                 api_version,
                                 db_args_ptr,
                                 &mut handle,
            )
        };

        unsafe { let _ = CString::from_raw(params.realm); }

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
            warn!("kadm5_init_with_skey failed with code {}: {}", ret, err_msg);
            unsafe { krb5_free_context(context) };
            return Err(anyhow::anyhow!("kadm5_init_with_skey failed: {}", err_msg));
        }

        Ok(Kadm5Handle { handle, context })
    }

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

        let mask = KADM5_PRINCIPAL as c_long;

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
            warn!("kadm5_create_principal failed with code {}: {}", ret, err_msg);
            return Err(anyhow::anyhow!("kadm5_create_principal failed: {}", err_msg));
        }

        Ok(())
    }

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

    pub fn delete_principal(&self, principal_str: &str) -> Result<()> {
        let principal_c = CString::new(principal_str).context("Invalid principal string for CString")?;

        let mut principal: krb5_principal = ptr::null_mut();

        let ret = unsafe { bindings::krb5_parse_name(self.context, principal_c.as_ptr(), &mut principal) };
        if ret != 0 {
            return Err(anyhow::anyhow!("Failed to parse principal {}: krb5_parse_name ret {}", principal_str, ret));
        }

        let ret = unsafe { bindings::kadm5_delete_principal(self.handle as *mut c_void, principal) };

        unsafe { bindings::krb5_free_principal(self.context, principal) };

        if ret == 0 {
            info!("Deleted principal via FFI: {}", principal_str);
            Ok(())
        } else if ret == bindings::KADM5_UNK_PRINC as i64 {
            info!("Principal {} does not exist, skipping delete", principal_str);
            Ok(())
        } else {
            warn!("FFI delete principal failed for {} (code {})", principal_str, ret);
            Err(anyhow::anyhow!("FFI delete principal failed (code {})", ret))
        }
    }

    pub fn set_random_key_for_service(&self, principal_name: &str) -> Result<()> {
        let principal_cstr = CString::new(principal_name).context("Invalid principal name")?;

        let mut princ: krb5_principal = ptr::null_mut();
        let ret = unsafe { krb5_parse_name(self.context, principal_cstr.as_ptr(), &mut princ) };
        if ret != 0 {
            return Err(anyhow::anyhow!("krb5_parse_name failed with code {}", ret));
        }

        let mut keyblocks = ptr::null_mut::<krb5_keyblock>();
        let mut n_keys: c_int = 0;
        let ret = unsafe { kadm5_randkey_principal(self.handle, princ, &mut keyblocks, &mut n_keys) };

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

            if err_msg.contains("Principal does not exist") || err_msg.contains("No such principal") {
                let mut ent: kadm5_principal_ent_rec = unsafe { mem::zeroed() };
                ent.principal = princ;

                const KADM5_PRINCIPAL: c_long = 0x00000001;
                const KADM5_KEY: c_long = 0x00000020;
                let mask = (KADM5_PRINCIPAL | KADM5_KEY) as c_long;

                let ret = unsafe { kadm5_create_principal(self.handle, &mut ent, mask, ptr::null_mut()) };

                if ret != 0 {
                    let code = ret as i32;
                    let msg_ptr = unsafe { krb5_get_error_message(self.context, code) };
                    let create_err = if msg_ptr.is_null() {
                        format!("code {}", ret)
                    } else {
                        let s = unsafe { CStr::from_ptr(msg_ptr).to_string_lossy().into_owned() };
                        unsafe { krb5_free_error_message(self.context, msg_ptr) };
                        s
                    };
                    unsafe { krb5_free_principal(self.context, princ) };
                    return Err(anyhow::anyhow!("Failed to create service principal with random key: {}", create_err));
                }

                info!("Created new service principal with random key: {}", principal_name);
            } else {
                unsafe { krb5_free_principal(self.context, princ) };
                return Err(anyhow::anyhow!("kadm5_randkey_principal failed: {}", err_msg));
            }
        } else {
            info!("Rotated random key for existing service principal: {}", principal_name);
        }

        unsafe { krb5_free_principal(self.context, princ) };
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

/// Central call for Kerberos sync—callers pass if sync is enabled (from attr check).
pub fn sync_kerberos_if_enabled(
    sync_enabled: bool,
    user_id: &str,
    plain_password: &str,
) -> Result<()> {
    if sync_enabled {
        info!("Kerberos sync enabled for user {}; triggering principal sync", user_id);
        sync_kerberos_principal(user_id, plain_password)
    } else {
        info!("Kerberos sync disabled for user {}; skipping", user_id);
        Ok(())
    }
}
