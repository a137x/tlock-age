//! High-level drand decryption API.
//!
//! This module provides drand-specific types, signature verification,
//! and convenient decrypt/precompute functions for both BLS12-381 and BN254 curves.
//!
//! Enable with the `drand` feature flag. For Scrypto smart contract compatibility
//! (Sbor derives), enable the `scrypto-support` feature instead.

pub mod crypto;
pub mod crypto_bn254;
pub mod timelock;
pub mod timelock_bn254;

pub use crypto::{
    Bls12381G1Signature, Bls12381G2PublicKey, ParseBlsPublicKeyError, ParseBlsSignatureError,
    verify_bls12381_v1_min_sig, verify_drand_beacon_signature,
};
pub use crypto_bn254::{Bn254G1Signature, Bn254G2PublicKey};
pub use timelock::{AgeHeader, decrypt_age_file, extract_tlock_ciphertext_from_age_file, parse_age_header, precompute_file_key};
pub use timelock_bn254::{
    decrypt_age_file_bn254, parse_age_header as parse_age_header_bn254,
    precompute_file_key_bn254,
};
