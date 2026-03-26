use thiserror::Error;

use crate::kyber::{decrypt_cca_on_g2, BN254Suite, Ciphertext};

#[derive(Error, Debug)]
pub enum BN254Error {
    #[error("invalid signature length: expected 64, got {0}")]
    InvalidSignatureLength(usize),
    #[error("invalid ciphertext length: expected 96, got {0}")]
    InvalidCiphertextLength(usize),
    #[error("failed to deserialize G2 point: {0}")]
    G2DeserializationError(String),
    #[error("failed to serialize pairing result")]
    PairingSerializationError,
    #[error("signature point is not on curve")]
    InvalidSignaturePoint,
    #[error("signature point not in correct subgroup")]
    InvalidSignatureSubgroup,
    #[error("failed to generate scalar")]
    ScalarGenerationError,
    #[error("validation failed")]
    ValidationError,
    #[error("malformed signature: {0}")]
    MalformedSignature(String),
}

/// Decrypt BN254 ciphertext using CCA-secure IBE decryption algorithm (matching Go DecryptCCAonG2 exactly)
pub fn decrypt_bn254(
    signature_bytes: &[u8],
    ciphertext_bytes: &[u8],
) -> Result<Vec<u8>, BN254Error> {
    let u_bytes = &ciphertext_bytes[0..128];
    let v_bytes = &ciphertext_bytes[128..144];
    let w_bytes = &ciphertext_bytes[144..160];

    let suite = BN254Suite::new();

    // Parse signature as G1 point
    let mut sig = suite.g1().point();
    if let Err(e) = sig.unmarshal_binary(&signature_bytes.to_vec()) {
        panic!("Failed to parse signature: {}", e);
    }
    // assert that the signature that we have in GO test

    // Parse ciphertext as G2 point
    let mut u = suite.g2().point();
    if let Err(e) = u.unmarshal_binary(&u_bytes) {
        panic!("Failed to parse ciphertext: {}", e);
    }
    // assert that the Ciphertext U point that we have in GO test

    // Construct ciphertext struct
    let ciphertext = Ciphertext::new(u, v_bytes.to_vec(), w_bytes.to_vec());

    // Call real decryption function
    let file_key_bytes = match decrypt_cca_on_g2(&suite, &sig, &ciphertext) {
        Ok(m) => m,
        Err(e) => panic!("Decryption failed: {}", e),
    };
    Ok(file_key_bytes)
}
