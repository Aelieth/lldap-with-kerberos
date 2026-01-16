use base64::encode;

pub fn obfuscate_password(pw: &str, key: &str) -> String {
    let key_bytes = key.as_bytes();
    let xored = pw.as_bytes().iter().enumerate().map(|(i, &b) | b ^ key_bytes[i % key_bytes.len()]).collect::<Vec<u8>>();
    encode(&xored)
}
