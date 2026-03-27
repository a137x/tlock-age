use blst::min_sig;
use sha2::Digest;
use std::fmt;
use std::str::FromStr;

#[cfg(feature = "scrypto-support")]
use scrypto::prelude::*;

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
// BLS12-381 types (quicknet: G2 pubkey 96 bytes, G1 signature 48 bytes)
// ======

derive_types! {
    /// Represents a BLS12-381 G2 public key (96 bytes).
    /// Used by drand quicknet/fastnet (unchained, min-sig variant).
    pub struct Bls12381G2PublicKey(pub [u8; 96]);
}

impl Bls12381G2PublicKey {
    pub const LENGTH: usize = 96;

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl TryFrom<&[u8]> for Bls12381G2PublicKey {
    type Error = ParseBlsPublicKeyError;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        if slice.len() != Self::LENGTH {
            return Err(ParseBlsPublicKeyError::InvalidLength(slice.len()));
        }
        let mut array = [0u8; Self::LENGTH];
        array.copy_from_slice(slice);
        Ok(Bls12381G2PublicKey(array))
    }
}

derive_types! {
    /// Represents a BLS12-381 G1 signature (48 bytes).
    /// Used by drand quicknet/fastnet (unchained, min-sig variant).
    pub struct Bls12381G1Signature(pub [u8; 48]);
}

impl Bls12381G1Signature {
    pub const LENGTH: usize = 48;

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl TryFrom<&[u8]> for Bls12381G1Signature {
    type Error = ParseBlsSignatureError;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        if slice.len() != Self::LENGTH {
            return Err(ParseBlsSignatureError::InvalidLength(slice.len()));
        }
        let mut array = [0u8; Self::LENGTH];
        array.copy_from_slice(slice);
        Ok(Bls12381G1Signature(array))
    }
}

// ======
// Errors
// ======

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "scrypto-support", derive(ScryptoSbor))]
pub enum ParseBlsPublicKeyError {
    InvalidHex(String),
    InvalidLength(usize),
    NoPublicKeysGiven,
    BlsError(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "scrypto-support", derive(ScryptoSbor))]
pub enum ParseBlsSignatureError {
    InvalidHex(String),
    InvalidLength(usize),
    NoSignatureGiven,
    BlsError(String),
}

// ======
// Text conversions
// ======

impl FromStr for Bls12381G2PublicKey {
    type Err = ParseBlsPublicKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match hex::decode(s) {
            Ok(bytes) => Self::try_from(bytes.as_slice()),
            Err(_) => Err(ParseBlsPublicKeyError::InvalidHex(s.to_string())),
        }
    }
}

impl fmt::Display for Bls12381G2PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.to_vec()))
    }
}

impl fmt::Debug for Bls12381G2PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl FromStr for Bls12381G1Signature {
    type Err = ParseBlsSignatureError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match hex::decode(s) {
            Ok(bytes) => Self::try_from(bytes.as_slice()),
            Err(_) => Err(ParseBlsSignatureError::InvalidHex(s.to_string())),
        }
    }
}

impl fmt::Display for Bls12381G1Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.to_vec()))
    }
}

impl fmt::Debug for Bls12381G1Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

// ======
// Verification
// ======

/// Verifies a BLS signature using the min_sig variant (G2 public key + G1 signature).
/// This is the variant used by unchained drand networks.
///
/// Domain separation tag: `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_`
pub fn verify_bls12381_v1_min_sig(
    message: &[u8],
    public_key: &Bls12381G2PublicKey,
    signature: &Bls12381G1Signature,
) -> bool {
    let dst = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

    match (
        min_sig::PublicKey::from_bytes(&public_key.0),
        min_sig::Signature::from_bytes(&signature.0),
    ) {
        (Ok(pk), Ok(sig)) => {
            let result = sig.verify(true, message, dst, &[], &pk, false);
            result == blst::BLST_ERROR::BLST_SUCCESS
        }
        _ => false,
    }
}

/// Verifies a drand beacon signature for a given round.
///
/// For unchained drand, the message format is: `SHA256(round_number_as_big_endian_bytes)`.
pub fn verify_drand_beacon_signature(
    round_number: u64,
    _previous_signature: &[u8],
    public_key: &Bls12381G2PublicKey,
    signature: &Bls12381G1Signature,
) -> bool {
    let round_bytes = round_number.to_be_bytes();
    let message_hash = sha2::Sha256::digest(&round_bytes);
    verify_bls12381_v1_min_sig(&message_hash, public_key, signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unchained_drand_verification_with_real_data() {
        let public_key_hex = "b15b65b46fb29104f6a4b5d1e11a8da6344463973d423661bb0804846a0ecd1ef93c25057f1c0baab2ac53e56c662b66072f6d84ee791a3382bfb055afab1e6a375538d8ffc451104ac971d2dc9b168e2d3246b0be2015969cbaac298f6502da";
        let signature_hex = "8efe63d9d422fe71713c7f7695e0ac5c0c501ef2677dc72e0e46b1367edef469498d6047e3fea743b0cb4fc123489f80";
        let round_number: u64 = 21180130;

        let public_key = Bls12381G2PublicKey::from_str(public_key_hex).unwrap();
        let signature = Bls12381G1Signature::from_str(signature_hex).unwrap();

        assert!(verify_drand_beacon_signature(round_number, &[], &public_key, &signature));
    }

    #[test]
    fn test_additional_unchained_drand_round() {
        let public_key_hex = "b15b65b46fb29104f6a4b5d1e11a8da6344463973d423661bb0804846a0ecd1ef93c25057f1c0baab2ac53e56c662b66072f6d84ee791a3382bfb055afab1e6a375538d8ffc451104ac971d2dc9b168e2d3246b0be2015969cbaac298f6502da";
        let signature_hex = "940e15057f79821e34f977b7996a64815dd70601b66b0f781f94e7f58e86082266aeba31eafb5f849d310132b7f02e50";
        let round_number: u64 = 21180131;

        let public_key = Bls12381G2PublicKey::from_str(public_key_hex).unwrap();
        let signature = Bls12381G1Signature::from_str(signature_hex).unwrap();

        assert!(verify_drand_beacon_signature(round_number, &[], &public_key, &signature));
    }

    #[test]
    fn test_invalid_inputs() {
        let valid_pk = Bls12381G2PublicKey::from_str("b15b65b46fb29104f6a4b5d1e11a8da6344463973d423661bb0804846a0ecd1ef93c25057f1c0baab2ac53e56c662b66072f6d84ee791a3382bfb055afab1e6a375538d8ffc451104ac971d2dc9b168e2d3246b0be2015969cbaac298f6502da").unwrap();
        let valid_sig = Bls12381G1Signature::from_str("8efe63d9d422fe71713c7f7695e0ac5c0c501ef2677dc72e0e46b1367edef469498d6047e3fea743b0cb4fc123489f80").unwrap();
        let valid_msg = sha2::Sha256::digest(&21180130u64.to_be_bytes());

        assert!(verify_bls12381_v1_min_sig(&valid_msg, &valid_pk, &valid_sig));
        assert!(!verify_bls12381_v1_min_sig(&[], &valid_pk, &valid_sig));
        assert!(!verify_bls12381_v1_min_sig(&valid_msg, &Bls12381G2PublicKey([0u8; 96]), &valid_sig));
        assert!(!verify_bls12381_v1_min_sig(&valid_msg, &valid_pk, &Bls12381G1Signature([0u8; 48])));
    }
}
