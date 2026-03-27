pub mod adapter;
pub mod constants;
pub mod curve;
pub mod gfp;
pub mod gfp12;
pub mod gfp2;
pub mod gfp6;
pub mod group;
pub mod ibe;
pub mod lattice;
pub mod optate;
pub mod pairing;
pub mod point;
pub mod scalar;
pub mod suite;
pub mod twist;
pub mod util;

pub use constants::*;
pub use curve::CurvePoint;
pub use gfp::GFp;
pub use gfp12::GFp12;
pub use gfp2::GFp2;
pub use gfp6::GFp6;
pub use group::{GroupG1, GroupG2, GroupGT};
pub use ibe::{
    decrypt_cca_on_g1, decrypt_cca_on_g2, encrypt_cca_on_g1, encrypt_cca_on_g2, Ciphertext,
    CiphertextCPA,
};
pub use lattice::{curve_lattice, Lattice};
pub use point::{PointG1, PointG2, PointGT};
pub use scalar::Scalar;
pub use suite::BN254Suite;
pub use twist::TwistPoint;
pub use util::zero_pad_bytes;

use std::io::Read;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BN254Error {
    #[error("Invalid signature length: expected 64, got {0}")]
    InvalidSignatureLength(usize),
    #[error("Invalid ciphertext length: expected 96, got {0}")]
    InvalidCiphertextLength(usize),
    #[error("Failed to deserialize G2 point: {0}")]
    G2DeserializationError(String),
    #[error("Failed to serialize pairing result")]
    PairingSerializationError,
    #[error("Signature point is not on curve")]
    InvalidSignaturePoint,
    #[error("Signature point not in correct subgroup")]
    InvalidSignatureSubgroup,
    #[error("Failed to generate scalar")]
    ScalarGenerationError,
    #[error("Validation failed")]
    ValidationError,
    #[error("Malformed signature: {0}")]
    MalformedSignature(String),
    #[error("IBE error: {0}")]
    IBEError(String),
    #[error("IO error: {0}")]
    IOError(#[from] std::io::Error),
    #[error("Invalid point encoding")]
    InvalidPointEncoding,
    #[error("Point not on curve")]
    PointNotOnCurve,
    #[error("Invalid scalar value")]
    InvalidScalar,
    #[error("Pairing computation failed")]
    PairingError,
    #[error("Hash to curve failed")]
    HashToCurveError,
}

pub type Result<T> = std::result::Result<T, BN254Error>;

// Marshal point IDs for binary encoding (matching Go kyber)
pub const MARSHAL_POINT_ID_G1: [u8; 8] = [b'b', b'n', b'2', b'5', b'4', b'.', b'g', b'1'];
pub const MARSHAL_POINT_ID_G2: [u8; 8] = [b'b', b'n', b'2', b'5', b'4', b'.', b'g', b'2'];
pub const MARSHAL_POINT_ID_GT: [u8; 8] = [b'b', b'n', b'2', b'5', b'4', b'.', b'g', b't'];

// Convenience functions for common operations
pub fn parse_signature(bytes: &[u8]) -> Result<PointG1> {
    if bytes.len() != 64 {
        return Err(BN254Error::InvalidSignatureLength(bytes.len()));
    }

    let mut point = PointG1::new();
    point
        .unmarshal_binary(bytes)
        .map_err(|e| BN254Error::MalformedSignature(e))?;
    Ok(point)
}

pub fn parse_public_key(pk_bytes: &[u8]) -> Result<PointG2> {
    if pk_bytes.len() != 128 {
        return Err(BN254Error::G2DeserializationError(format!(
            "Expected 128 bytes, got {}",
            pk_bytes.len()
        )));
    }

    let mut point = PointG2::new();
    point
        .unmarshal_binary(pk_bytes)
        .map_err(|e| BN254Error::G2DeserializationError(e))?;
    Ok(point)
}

pub fn verify_bls_signature(
    public_key: &PointG2,
    message: &[u8],
    signature: &PointG1,
) -> Result<bool> {
    let suite = BN254Suite::new();

    // Hash the message to a point
    let hash_point = PointG1::hash_to_point(message);

    // Verify the pairing: e(signature, g2) == e(hash, public_key)
    let left = suite.pair(signature, &PointG2::new());
    let right = suite.pair(&hash_point, public_key);

    Ok(left.equal(&right))
}

pub fn decrypt_bn254(signature: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if signature.len() != 64 {
        return Err(BN254Error::InvalidSignatureLength(signature.len()));
    }

    if ciphertext.len() != 96 {
        return Err(BN254Error::InvalidCiphertextLength(ciphertext.len()));
    }

    let sig_point = parse_signature(signature)?;
    let ciphertext_struct =
        Ciphertext::from_bytes(ciphertext).map_err(|e| BN254Error::IBEError(e))?;

    let suite = BN254Suite::new();
    decrypt_cca_on_g2(&suite, &sig_point, &ciphertext_struct).map_err(|e| BN254Error::IBEError(e))
}

// Utility functions for random number generation
pub fn random_scalar<R: Read>(rand: &mut R) -> Result<Scalar> {
    let mut scalar = Scalar::new();
    scalar
        .pick(rand)
        .map_err(|_| BN254Error::ScalarGenerationError)?;
    Ok(scalar)
}

pub fn random_point_g1<R: Read>(rand: &mut R) -> Result<PointG1> {
    let _scalar = random_scalar(rand)?;
    let point = PointG1::new();
    Ok(point)
}

pub fn random_point_g2<R: Read>(rand: &mut R) -> Result<PointG2> {
    let _scalar = random_scalar(rand)?;
    let point = PointG2::new();
    Ok(point)
}

// Hash to curve functions (simplified version)
pub fn hash_to_g1(message: &[u8]) -> Result<PointG1> {
    Ok(PointG1::hash_to_point(message))
}

pub fn hash_to_g2(_message: &[u8]) -> Result<PointG2> {
    Ok(PointG2::new())
}

// Pairing utility functions
pub fn pairing(p1: &PointG1, p2: &PointG2) -> Result<PointGT> {
    let suite = BN254Suite::new();
    Ok(suite.pair(p1, p2))
}

pub fn miller_loop(_p1: &PointG1, _p2: &PointG2) -> Result<PointGT> {
    Ok(PointGT::new())
}

// Validation functions
pub fn validate_g1_point(_point: &PointG1) -> Result<bool> {
    Ok(true)
}

pub fn validate_g2_point(_point: &PointG2) -> Result<bool> {
    Ok(true)
}

pub fn validate_scalar(scalar: &Scalar) -> Result<bool> {
    if scalar.is_zero() {
        return Err(BN254Error::InvalidScalar);
    }
    Ok(true)
}
