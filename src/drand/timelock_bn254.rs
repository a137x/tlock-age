//! High-level timelock decryption for drand BN254 (evmnet).

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

use crate::tlock::bn254::decrypt_bn254;
use super::timelock::extract_tlock_ciphertext_from_age_file;

/// Age file header information extracted from tlock stanza (BN254 variant with file_key_hash).
#[derive(Debug)]
pub struct AgeHeaderBn254 {
    pub round: u64,
    pub chain_hash: String,
    pub file_key_hash: String,
}

/// Parse age file header for BN254 variant.
///
/// BN254 encrypted files use a modified stanza with an additional file_key_hash field:
/// `-> tlock <round> <chain_hash> <file_key_hash>`
pub fn parse_age_header(age_content: &str) -> Result<AgeHeaderBn254, String> {
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
    let mut file_key_hash = String::new();

    for line in decoded_str.lines() {
        if line.starts_with("-> tlock") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 {
                round = parts[2].parse().map_err(|_| "Invalid round number")?;
                let chain_hash_str = parts[3].to_string();
                if chain_hash_str.len() != 64 {
                    return Err(format!(
                        "Invalid chain hash length: expected 64 hex chars, got {}",
                        chain_hash_str.len()
                    ));
                }
                if hex::decode(&chain_hash_str).is_err() {
                    return Err("Invalid chain hash format: not valid hex".to_string());
                }
                chain_hash = chain_hash_str;
                file_key_hash = parts[4].to_string();
                if file_key_hash.len() != 64 {
                    return Err(format!(
                        "Invalid file key hash length: expected 64 hex chars, got {}",
                        file_key_hash.len()
                    ));
                }
                if hex::decode(&file_key_hash).is_err() {
                    return Err("Invalid file key hash format: not valid hex".to_string());
                }
            } else {
                return Err("Invalid tlock stanza format".to_string());
            }
            break;
        }
    }

    if round == 0 || chain_hash.is_empty() || file_key_hash.is_empty() {
        return Err("No valid tlock stanza found".to_string());
    }

    Ok(AgeHeaderBn254 {
        round,
        chain_hash,
        file_key_hash,
    })
}

/// Decrypt an age file using BN254 tlock (drand evmnet).
///
/// Supports optional precomputed file key for on-chain optimization.
pub fn decrypt_age_file_bn254(
    age_file_content: &str,
    signature_bytes: &[u8],
    precomputed_file_key: Option<[u8; 16]>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let header = parse_age_header(age_file_content)
        .map_err(|e| format!("Header parse failed: {e}"))?;
    let chain_hash_bytes = hex::decode(header.chain_hash)
        .map_err(|e| format!("Chain hash decode failed: {e}"))?;
    let mut decrypted = Vec::new();
    crate::decrypt_bn254(
        &mut decrypted,
        age_file_content.as_bytes(),
        &chain_hash_bytes,
        signature_bytes,
        precomputed_file_key,
    )
    .map_err(|e| format!("BN254 decryption failed: {e}"))?;

    Ok(decrypted)
}

/// Precompute the file key from an age file and drand signature (BN254).
///
/// Performs the expensive BN254 IBE decryption off-chain. The resulting 16-byte
/// file key can be passed to `decrypt_age_file_bn254()` to skip IBE on-chain.
pub fn precompute_file_key_bn254(
    signature_bytes: &[u8],
    age_content: &str,
) -> Result<[u8; 16], String> {
    let ciphertext_bytes = extract_tlock_ciphertext_from_age_file(age_content)?;
    if ciphertext_bytes.len() < 160 {
        return Err(format!(
            "Ciphertext too short for BN254 precompute: expected at least 160 bytes, got {}",
            ciphertext_bytes.len()
        ));
    }
    let file_key = decrypt_bn254(signature_bytes, &ciphertext_bytes)
        .map_err(|e| format!("BN254 time unlock failed: {e}"))?;
    let arr: [u8; 16] = file_key
        .as_slice()
        .try_into()
        .map_err(|_| format!("Invalid file key length: expected 16, got {}", file_key.len()))?;
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bn254_age_header() {
        let age_content = "-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHRsb2NrIDczMjQyIDA0ZjFlOTA2MmI4
YTgxZjg0OGZkZWQ5YzEyMzA2NzMzMjgyYjI3MjdlY2NlZDUwMDMyMTg3NzUxMTY2
ZWM4YzMgZTkwMDYwZjZiOTc0MTE0OTJkZDE3MzYyZDE1MjY4NTI2NTIzY2ZmNmZk
ZmExN2MzYTAzZjVkMTEwNzUzZWVhNwpLV0dycVZNZjFVOXhocEZSTkFFVzBiTEhk
cmhWck5McFpTSWg3U0txaEs0S3RBcDRuZDBQVFdnUVo3N0JValR2CmRzOGlHaDE0
dkdtandSOHRXZUlocHl6RjRWZ0ZSQlV5TGxHS1BXK00wRXdhcXpNYSt5NjRIcG80
Mkg2WnRLa3YKTFJ6cjVUSHgrR3dmTjR6UDNtUEFqejJ5R21SNGxEUm90OEptTHdK
cWJzWndtc0hyOTNQVEFySlhhUEx2M0pibgpoemJmeXNxdzNodnhEQmVnWExDQmtR
Ci0tLSBNN1ByOTIzdWNYUW1FYUVqTmRETWhSdjJmK0lYaUhTZ09mOGFseW1zeTNv
Ci4SnjfH2yu8hgK4x3zdXZ3Oq2jbdixfHtYGBZT6kIPdRHdb
-----END AGE ENCRYPTED FILE-----";

        let header = parse_age_header(age_content).expect("Should parse BN254 header");
        assert_eq!(header.round, 73242);
        assert_eq!(
            header.chain_hash,
            "04f1e9062b8a81f848fded9c12306733282b2727ecced50032187751166ec8c3"
        );
        assert_eq!(header.file_key_hash.len(), 64, "file_key_hash should be 64 hex chars");
    }

    #[test]
    fn test_decrypt_bn254_with_precomputed_key() {
        let age_content = "-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHRsb2NrIDczMjQyIDA0ZjFlOTA2MmI4
YTgxZjg0OGZkZWQ5YzEyMzA2NzMzMjgyYjI3MjdlY2NlZDUwMDMyMTg3NzUxMTY2
ZWM4YzMgZTkwMDYwZjZiOTc0MTE0OTJkZDE3MzYyZDE1MjY4NTI2NTIzY2ZmNmZk
ZmExN2MzYTAzZjVkMTEwNzUzZWVhNwpLV0dycVZNZjFVOXhocEZSTkFFVzBiTEhk
cmhWck5McFpTSWg3U0txaEs0S3RBcDRuZDBQVFdnUVo3N0JValR2CmRzOGlHaDE0
dkdtandSOHRXZUlocHl6RjRWZ0ZSQlV5TGxHS1BXK00wRXdhcXpNYSt5NjRIcG80
Mkg2WnRLa3YKTFJ6cjVUSHgrR3dmTjR6UDNtUEFqejJ5R21SNGxEUm90OEptTHdK
cWJzWndtc0hyOTNQVEFySlhhUEx2M0pibgpoemJmeXNxdzNodnhEQmVnWExDQmtR
Ci0tLSBNN1ByOTIzdWNYUW1FYUVqTmRETWhSdjJmK0lYaUhTZ09mOGFseW1zeTNv
Ci4SnjfH2yu8hgK4x3zdXZ3Oq2jbdixfHtYGBZT6kIPdRHdb
-----END AGE ENCRYPTED FILE-----";
        let signature_hex = "17e7c00c7f74f8ebb5bc252fa6d9f78dc0583ef1be07e413db46c05bb7f51501115a68c583806d02dd93a9c08999ce959adf930a1d90b85d455743311e05f11f";
        let signature_bytes = hex::decode(signature_hex).unwrap();

        let precomputed = precompute_file_key_bn254(&signature_bytes, age_content).unwrap();

        let decrypted = decrypt_age_file_bn254(age_content, &signature_bytes, Some(precomputed)).unwrap();
        assert_eq!(String::from_utf8_lossy(&decrypted), "yes");
    }
}
