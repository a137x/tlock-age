use blst::min_sig;
use sha2::Digest;
use std::fmt;
use std::str::FromStr;

#[cfg(feature = "scrypto-support")]
use scrypto::prelude::*;

use super::crypto::{ParseBlsPublicKeyError, ParseBlsSignatureError};

/// Macro to conditionally derive Sbor traits
macro_rules! derive_types {
    ($(#[$meta:meta])* $vis:vis struct $name:ident($inner_vis:vis [$type:ty; $len:expr]);) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        #[cfg_attr(feature = "scrypto-support", derive(Sbor))]
        #[cfg_attr(feature = "scrypto-support", sbor(transparent))]
        $(#[$meta])*
        $vis struct $name($inner_vis [$type; $len]);
    };
}

// ======
// BN254 types (evmnet: G2 pubkey 128 bytes, G1 signature 64 bytes)
// ======

derive_types! {
    /// Represents a BN254 G2 public key (128 bytes).
    /// Used by drand evmnet.
    pub struct Bn254G2PublicKey(pub [u8; 128]);
}

impl Bn254G2PublicKey {
    pub const LENGTH: usize = 128;

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl TryFrom<&[u8]> for Bn254G2PublicKey {
    type Error = ParseBlsPublicKeyError;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        if slice.len() != Self::LENGTH {
            return Err(ParseBlsPublicKeyError::InvalidLength(slice.len()));
        }
        let mut array = [0u8; Self::LENGTH];
        array.copy_from_slice(slice);
        Ok(Bn254G2PublicKey(array))
    }
}

derive_types! {
    /// Represents a BN254 G1 signature (64 bytes).
    /// Used by drand evmnet.
    pub struct Bn254G1Signature(pub [u8; 64]);
}

impl Bn254G1Signature {
    pub const LENGTH: usize = 64;

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl TryFrom<&[u8]> for Bn254G1Signature {
    type Error = ParseBlsSignatureError;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        if slice.len() != Self::LENGTH {
            return Err(ParseBlsSignatureError::InvalidLength(slice.len()));
        }
        let mut array = [0u8; Self::LENGTH];
        array.copy_from_slice(slice);
        Ok(Bn254G1Signature(array))
    }
}

// ======
// Text conversions
// ======

impl FromStr for Bn254G2PublicKey {
    type Err = ParseBlsPublicKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match hex::decode(s) {
            Ok(bytes) => Self::try_from(bytes.as_slice()),
            Err(_) => Err(ParseBlsPublicKeyError::InvalidHex(s.to_string())),
        }
    }
}

impl fmt::Display for Bn254G2PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.to_vec()))
    }
}

impl fmt::Debug for Bn254G2PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl FromStr for Bn254G1Signature {
    type Err = ParseBlsSignatureError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match hex::decode(s) {
            Ok(bytes) => Self::try_from(bytes.as_slice()),
            Err(_) => Err(ParseBlsSignatureError::InvalidHex(s.to_string())),
        }
    }
}

impl fmt::Display for Bn254G1Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.to_vec()))
    }
}

impl fmt::Debug for Bn254G1Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

// ======
// Verification (BN254 uses blst for signature verification, same as BLS12-381)
// ======

/// Verifies a BN254 drand beacon signature.
///
/// Note: BN254 evmnet uses a different signature scheme but blst is used
/// for the BLS verification part. The signature and public key sizes differ
/// from BLS12-381.
pub fn verify_drand_beacon_signature_bn254(
    round_number: u64,
    _previous_signature: &[u8],
    public_key: &Bn254G2PublicKey,
    signature: &Bn254G1Signature,
) -> bool {
    let dst = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
    let round_bytes = round_number.to_be_bytes();
    let message_hash = sha2::Sha256::digest(&round_bytes);

    match (
        min_sig::PublicKey::from_bytes(&public_key.0),
        min_sig::Signature::from_bytes(&signature.0),
    ) {
        (Ok(pk), Ok(sig)) => {
            let result = sig.verify(true, &message_hash, dst, &[], &pk, false);
            result == blst::BLST_ERROR::BLST_SUCCESS
        }
        _ => false,
    }
}
