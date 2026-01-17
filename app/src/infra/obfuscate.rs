use base64::{Engine as _, engine::general_purpose};

pub fn obfuscate_password(pw: &str, key: &str) -> String {
    let key_bytes = key.as_bytes();
    let pw_bytes = pw.as_bytes();
    let xored = pw_bytes.iter().enumerate().map(|(i, &b)| b ^ key_bytes[i % key_bytes.len()]).collect::<Vec<u8>>();
    general_purpose::STANDARD.encode(xored)
}
