//! High-level timelock decryption for drand BLS12-381 (quicknet/fastnet).

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

use super::crypto::{Bls12381G1Signature, Bls12381G2PublicKey};
use crate::tlock::TLockError;

/// Age file header information extracted from tlock stanza.
#[derive(Debug)]
pub struct AgeHeader {
    pub round: u64,
    pub chain_hash: String,
}

/// Parse age file format and extract header information.
///
/// Decodes the ASCII-armored age file header and extracts the tlock stanza
/// containing the drand round number and chain hash.
pub fn parse_age_header(age_content: &str) -> Result<AgeHeader, String> {
    let lines: Vec<&str> = age_content
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();

    if lines.is_empty() {
        return Err("No content lines found".to_string());
    }

    let base64_content: String = lines.join("");
    let decoded = BASE64
        .decode(base64_content.as_bytes())
        .map_err(|_| "Invalid base64 content")?;
    let decoded_str = String::from_utf8_lossy(&decoded);

    let mut round = 0u64;
    let mut chain_hash = String::new();

    for line in decoded_str.lines() {
        if line.starts_with("-> tlock") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                round = parts[2].parse().map_err(|_| "Invalid round number")?;
                chain_hash = parts[3].to_string();
            } else {
                return Err("Invalid tlock stanza format".to_string());
            }
            break;
        }
    }

    if round == 0 || chain_hash.is_empty() {
        return Err("No valid tlock stanza found".to_string());
    }

    Ok(AgeHeader { round, chain_hash })
}

/// Decrypt an age file using tlock_age with BLS12-381 signatures.
///
/// Parses the header, validates the round, and decrypts the content.
/// Supports optional precomputed file key for on-chain optimization.
pub fn decrypt_age_file(
    age_file_content: &str,
    signature: &Bls12381G1Signature,
    _public_key: &Bls12381G2PublicKey,
    round: u64,
    precomputed_file_key: Option<[u8; 16]>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let header = parse_age_header(age_file_content)?;

    if header.round != round {
        return Err(format!("Round mismatch: expected {}, got {}", round, header.round).into());
    }

    let signature_bytes = hex::decode(&signature.to_string())?;
    let mut decrypted = Vec::new();
    crate::decrypt(
        &mut decrypted,
        age_file_content.as_bytes(),
        &hex::decode(&header.chain_hash).unwrap(),
        &signature_bytes,
        precomputed_file_key,
    )?;

    Ok(decrypted)
}

/// Extract the tlock ciphertext bytes from an age file stanza body.
///
/// Returns the raw ciphertext bytes ready for IBE decryption or precomputation.
pub fn extract_tlock_ciphertext_from_age_file(age_content: &str) -> Result<Vec<u8>, String> {
    let base64_content: String = age_content
        .lines()
        .filter(|line| !line.starts_with("-----") && !line.starts_with("age-encryption.org"))
        .collect::<Vec<_>>()
        .join("");
    let decoded =
        base64::decode(&base64_content).map_err(|e| format!("Base64 decode failed: {e}"))?;
    let decoded_str = String::from_utf8_lossy(&decoded);
    let lines: Vec<&str> = decoded_str.lines().collect();
    let stanza_start = lines
        .iter()
        .position(|line| line.starts_with("-> tlock"))
        .ok_or("No tlock stanza found")?;
    let stanza_body_lines: Vec<&str> = lines
        .iter()
        .skip(stanza_start + 1)
        .take_while(|line| {
            !line.is_empty()
                && !line.starts_with("->")
                && !line.starts_with("---")
                && !line.starts_with("-----")
        })
        .copied()
        .collect();
    let stanza_body_base64 = stanza_body_lines.join("");
    let padded_base64 = if stanza_body_base64.len() % 4 != 0 {
        let mut padded = stanza_body_base64.clone();
        while padded.len() % 4 != 0 {
            padded.push('=');
        }
        padded
    } else {
        stanza_body_base64
    };
    let full_ciphertext_bytes = base64::decode(&padded_base64)
        .map_err(|e| format!("Stanza body base64 decode failed: {e}"))?;
    if full_ciphertext_bytes.len() < 96 {
        return Err(format!(
            "Ciphertext too short: expected at least 96 bytes, got {}",
            full_ciphertext_bytes.len()
        ));
    }
    Ok(full_ciphertext_bytes.to_vec())
}

/// Precompute the file key from an age file and drand signature (BLS12-381).
///
/// This performs the expensive IBE decryption off-chain. The resulting 16-byte
/// file key can be passed to `decrypt_age_file()` with `precomputed_file_key`
/// to skip IBE on-chain and only run ChaCha20-Poly1305.
pub fn precompute_file_key(signature_bytes: &[u8], age_content: &str) -> Result<[u8; 16], String> {
    let ciphertext_bytes = extract_tlock_ciphertext_from_age_file(age_content)?;

    let c = match signature_bytes.len() {
        crate::tlock::ibe::G1_SIZE => {
            if ciphertext_bytes.len() < 128 {
                return Err(format!(
                    "Ciphertext too short for G1 signature flow: expected at least 128 bytes, got {}",
                    ciphertext_bytes.len()
                ));
            }
            let u_bytes = &ciphertext_bytes[0..96];
            let v = ciphertext_bytes[96..112].to_vec();
            let w = ciphertext_bytes[112..128].to_vec();
            let u = crate::tlock::ibe::GAffine::try_from(u_bytes).map_err(|e| {
                format!("Failed to parse GAffine (G2 compressed 96 bytes) from ciphertext: {e}")
            })?;
            crate::tlock::ibe::Ciphertext { u, v, w }
        }
        96 => {
            if ciphertext_bytes.len() < 80 {
                return Err(format!(
                    "Ciphertext too short for G2 signature flow: expected at least 80 bytes, got {}",
                    ciphertext_bytes.len()
                ));
            }
            let u_bytes = &ciphertext_bytes[0..48];
            let v = ciphertext_bytes[48..64].to_vec();
            let w = ciphertext_bytes[64..80].to_vec();
            let u = crate::tlock::ibe::GAffine::try_from(u_bytes).map_err(|e| {
                format!("Failed to parse GAffine (G1 compressed 48 bytes) from ciphertext: {e}")
            })?;
            crate::tlock::ibe::Ciphertext { u, v, w }
        }
        _ => {
            return Err(format!(
                "Unsupported signature size: {} bytes. Expected 48 or 96 bytes.",
                signature_bytes.len()
            ));
        }
    };

    let file_key = crate::tlock::time_unlock(signature_bytes, &c)
        .map_err(|e: TLockError| format!("Time unlock failed: {e}"))?;
    let arr: [u8; 16] = file_key
        .as_slice()
        .try_into()
        .map_err(|_| format!("Invalid file key length: expected 16, got {}", file_key.len()))?;
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_parse_age_header() {
        let age_content = "-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHRsb2NrIDE5OTk0MjEyIDUyZGI5YmE3
MGUwY2MwZjZlYWY3ODAzZGQwNzQ0N2ExZjU0Nzc3MzVmZDNmNjYxNzkyYmE5NDYw
MGM4NGU5NzEgY2IzYjMyZjkzZmU4M2ZhODhmOWMxNTQ4MzViMDM2NzJmMWIzOGI0
ZWJkYmYyZDlmOGZmZDM4YmVjZWIyOGI4YgpzMk9sQW1kWXJieFVYeWlJSlFVUFFx
ZkthM0xIUDNVY0k3dEE2ZWdDYUg4MWMwYU1JRVM0Y1MrWGJ5VEc3WGZHCkFycVRt
R201MUFjRzBNMHNJVFNOcG9sb3BhRUFOZjJXemRaTFZ6VUZrdXVzTXd6Qjh2ZUNw
WSs0MDh4eDlCYlIKU0FmMmR1WjZyQ0l4Vk1SZTdlRjVkT2ZZMU1HWDg4UjZ4ZWR3
dXpxcUVibwotLS0gRy9XS0gvN1U3MGZPdjhYYjVUQ2dzeXBkcjBrU2FsSVlWMkZK
V2ZaVVdWOApXNAbsz3vckaTMzs/dxagPEeR20a1NEHgOHI4fsNLahNuBVfM=
-----END AGE ENCRYPTED FILE-----";

        let header = parse_age_header(age_content).expect("Should parse header");
        assert_eq!(header.round, 19994212);
        assert_eq!(
            header.chain_hash,
            "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
        );
    }

    #[test]
    fn test_decrypt_with_precomputed_file_key() {
        let age_content = "-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHRsb2NrIDE5OTk0MjEyIDUyZGI5YmE3
MGUwY2MwZjZlYWY3ODAzZGQwNzQ0N2ExZjU0Nzc3MzVmZDNmNjYxNzkyYmE5NDYw
MGM4NGU5NzEgY2IzYjMyZjkzZmU4M2ZhODhmOWMxNTQ4MzViMDM2NzJmMWIzOGI0
ZWJkYmYyZDlmOGZmZDM4YmVjZWIyOGI4YgpzMk9sQW1kWXJieFVYeWlJSlFVUFFx
ZkthM0xIUDNVY0k3dEE2ZWdDYUg4MWMwYU1JRVM0Y1MrWGJ5VEc3WGZHCkFycVRt
R201MUFjRzBNMHNJVFNOcG9sb3BhRUFOZjJXemRaTFZ6VUZrdXVzTXd6Qjh2ZUNw
WSs0MDh4eDlCYlIKU0FmMmR1WjZyQ0l4Vk1SZTdlRjVkT2ZZMU1HWDg4UjZ4ZWR3
dXpxcUVibwotLS0gRy9XS0gvN1U3MGZPdjhYYjVUQ2dzeXBkcjBrU2FsSVlWMkZK
V2ZaVVdWOApXNAbsz3vckaTMzs/dxagPEeR20a1NEHgOHI4fsNLahNuBVfM=
-----END AGE ENCRYPTED FILE-----";
        let signature_hex = "988fe4d05b8400864502475fb8021ea8ea28193ed31806641c5dfa438b142a4ccdaf0eac8eaeafa75e4adaef7d514ce2";
        let public_key_hex = "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a";

        let signature_bytes = hex::decode(signature_hex).unwrap();
        let signature = Bls12381G1Signature::try_from(signature_bytes.as_slice()).unwrap();
        let public_key = Bls12381G2PublicKey::from_str(public_key_hex).unwrap();

        let precomputed = precompute_file_key(&signature_bytes, age_content).unwrap();

        let decrypted = decrypt_age_file(age_content, &signature, &public_key, 19994212, Some(precomputed)).unwrap();
        assert_eq!(String::from_utf8_lossy(&decrypted), "test");
    }

    #[test]
    fn test_decrypt_without_precomputed_file_key() {
        let age_content = "-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHRsb2NrIDIwMDE4NTkwIDUyZGI5YmE3
MGUwY2MwZjZlYWY3ODAzZGQwNzQ0N2ExZjU0Nzc3MzVmZDNmNjYxNzkyYmE5NDYw
MGM4NGU5NzEgYmYxNDAxZjg2ZjBmOWNmZGFmZjIwMDE3MTRjY2Q4MDM2ODJjOGM0
YmM1MTU3ZjY5YThiZmNkMWE4ZjhlYTlkNwpxQVR6SWwrMFNDSWcyUUtycHJoRWN3
WTNDeEhPMlJWbVhjWEp4L2xPTFQxYnRLZkFJeXBkOEdJakZ1OHdzaFEyCkVXOHl4
aTVDaXlDcEtISTFLdktWa0JHcmYrejlBWEkzVHRncDllN2pablYyR052b1VaNU93
UDF3QUFoOTVwNWsKV2hhRUJNdTI3Tm8zZjlWRjBqU25DNERZY1UrMTZlYWRGMlQr
RllvaTVoVQotLS0gNFM4Mm5Jd3VVZmlReXpSWlRxK09WRDA1S1hHRjU5d0ZiSGRv
RHQyNU9ZWQpo5Hy7Xti4SFQHm5nlXsbCqaVtv9K7OsjjL7LN/U0k4vL0bmxPlOL7
hvcQK7VUK7Xk/zKn5nOIQ2VDkJ2uHOf9
-----END AGE ENCRYPTED FILE-----";
        let signature_hex = "8eec1bdc72fd95735d37dc2f6897d02af6291acdeee5dea6e522e434d16f0e79a2240b91a1de763e6bf8b33b6ecd881c";
        let public_key_hex = "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a";

        let signature_bytes = hex::decode(signature_hex).unwrap();
        let signature = Bls12381G1Signature::try_from(signature_bytes.as_slice()).unwrap();
        let public_key = Bls12381G2PublicKey::from_str(public_key_hex).unwrap();

        let decrypted = decrypt_age_file(age_content, &signature, &public_key, 20018590, None).unwrap();
        assert_eq!(String::from_utf8_lossy(&decrypted), "18-07-2025 20:18 when we made it");
    }
}
