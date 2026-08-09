use std::error::Error;

/// Turn DER encoded bytes into a PEM string
pub fn to_pem(der: &[u8], label: &str) -> String {
    use std::fmt::Write;
    let b64 = base64_encode(der);
    let mut out = String::new();
    let _ = writeln!(out, "-----BEGIN {label}-----");
    for line in b64.as_bytes().chunks(64) {
        let _ = writeln!(out, "{}", std::str::from_utf8(line).unwrap());
    }
    let _ = writeln!(out, "-----END {label}-----");
    out
}

// Minimal base64 encoder (standard alphabet, with padding) to avoid pulling
// in an extra crate just for PEM wrapping.
fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        out.push(TABLE[((n >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((n >> 6) & 0x3F) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(n & 0x3F) as usize] as char
        } else {
            '='
        });
    }
    out
}

// tiny inline hex encoder so we don't need an extra crate just for this
pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Builds a SubjectPublicKeyInfo PEM string from a raw RSA modulus + exponent.
pub fn rsa_public_key_to_pem(modulus: &[u8], exponent: u32) -> Result<String, Box<dyn Error>> {
    use rsa::pkcs8::EncodePublicKey;
    use rsa::{BigUint, RsaPublicKey};

    let n = BigUint::from_bytes_be(modulus);
    let e = BigUint::from(exponent);
    let pub_key = RsaPublicKey::new(n, e)?;
    Ok(pub_key.to_public_key_pem(Default::default())?)
}
