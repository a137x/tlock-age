use ark_bls12_381::{Bls12_381, Fr as ScalarField, G1Affine, G2Affine};
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    AffineRepr, CurveGroup,
};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use serde_with::DeserializeAs;
use sha2::{digest::Update, Digest, Sha256};
use std::{marker::PhantomData, ops::Mul};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum IBEError {
    #[error("hash cannot be mapped to {0}")]
    _HashToCurve(String),
    #[error("cannot initialise mapper for {hash} to BLS12-381 {field}")]
    _MapperInitialisation { hash: String, field: String },
    #[error("sigma does not fit in 16 bytes")]
    _MessageSize,
    #[error("pairing requires affines to be on different curves")]
    Pairing,
    #[error("invalid public key size")]
    PublicKeySize,
    #[error("serialization failed")]
    Serialisation,
    #[error("verification failed: computed r*G does not match ciphertext U component")]
    VerificationFailed,
    #[error("unknown data store error")]
    _Unknown,
}

#[derive(Clone, Debug, PartialEq)]
pub enum GAffine {
    G1Affine(G1Affine),
    G2Affine(G2Affine),
}

impl Serialize for GAffine {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut bytes = vec![];
        match self {
            Self::G1Affine(g) => g
                .serialize_with_mode(&mut bytes, ark_serialize::Compress::Yes)
                .map_err(serde::ser::Error::custom)?,
            Self::G2Affine(g) => g
                .serialize_with_mode(&mut bytes, ark_serialize::Compress::Yes)
                .map_err(serde::ser::Error::custom)?,
        }

        serializer.serialize_bytes(&bytes)
    }
}

impl<'de> Deserialize<'de> for GAffine {
    fn deserialize<D>(deserializer: D) -> std::result::Result<GAffine, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde_with::Bytes::deserialize_as(deserializer)?;
        let reader = bytes.as_slice();
        let affine = match reader.len() {
            G1_SIZE => Self::G1Affine(
                G1Affine::deserialize_compressed(bytes.as_slice())
                    .map_err(serde::de::Error::custom)?,
            ),
            G2_SIZE => Self::G2Affine(
                G2Affine::deserialize_compressed(bytes.as_slice())
                    .map_err(serde::de::Error::custom)?,
            ),
            _ => return Err(serde::de::Error::custom("Invalid len Should be 48 of 96")),
        };
        Ok(affine)
    }
}

impl GAffine {
    pub fn pairing(
        &self,
        other: &GAffine,
    ) -> anyhow::Result<PairingOutput<ark_bls12_381::Bls12_381>, IBEError> {
        match (self, other) {
            (GAffine::G1Affine(s), GAffine::G2Affine(o)) => Ok(Bls12_381::pairing(s, o)),
            (GAffine::G2Affine(s), GAffine::G1Affine(o)) => Ok(Bls12_381::pairing(o, s)),
            _ => Err(IBEError::Pairing),
        }
    }

    pub fn generator(&self) -> Self {
        match self {
            GAffine::G1Affine(_) => GAffine::G1Affine(G1Affine::generator()),
            GAffine::G2Affine(_) => GAffine::G2Affine(G2Affine::generator()),
        }
    }

    pub fn mul(&self, s: ScalarField) -> Self {
        match self {
            GAffine::G1Affine(g) => GAffine::G1Affine(g.mul(s).into_affine()),
            GAffine::G2Affine(g) => GAffine::G2Affine(g.mul(s).into_affine()),
        }
    }
}

impl TryFrom<&[u8]> for GAffine {
    type Error = IBEError;

    fn try_from(bytes: &[u8]) -> anyhow::Result<Self, Self::Error> {
        if bytes.len() == G1_SIZE {
            let g = G1Affine::deserialize_compressed(bytes).map_err(|_| IBEError::PublicKeySize)?;
            Ok(GAffine::G1Affine(g))
        } else if bytes.len() == G2_SIZE {
            let g = G2Affine::deserialize_compressed(bytes).map_err(|_| IBEError::PublicKeySize)?;
            Ok(GAffine::G2Affine(g))
        } else {
            Err(IBEError::PublicKeySize)
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ciphertext {
    pub u: GAffine,
    pub v: Vec<u8>,
    pub w: Vec<u8>,
}

const BLOCK_SIZE: usize = 32;

pub const G1_SIZE: usize = 48;
pub const G2_SIZE: usize = 96;

pub fn decrypt(private: GAffine, c: &Ciphertext) -> anyhow::Result<Vec<u8>, IBEError> {
    assert!(
        c.w.len() <= BLOCK_SIZE,
        "ciphertext too long for the block size"
    );

    // 1. Compute sigma = V XOR H2(e(rP,private))
    let sigma = {
        let r_gid_out = private.pairing(&c.u)?;
        let mut r_gid = vec![];
        r_gid_out
            .serialize_with_mode(&mut r_gid, ark_serialize::Compress::Yes)
            .map_err(|_| IBEError::Serialisation)?;
        let r_gid = &r_gid.into_iter().rev().collect_vec();

        let hash = sha2::Sha256::new().chain(b"IBE-H2").chain(r_gid).finalize();
        let h_r_git = &hash.to_vec()[0..16];
        xor(h_r_git, &c.v[c.v.len() - 16..])
    };

    // 2. Compute Msg = W XOR H4(sigma)
    let msg = {
        let hash = sha2::Sha256::new()
            .chain(b"IBE-H4")
            .chain(&sigma)
            .finalize();
        let h_sigma = &hash.to_vec()[0..16];
        xor(h_sigma, &c.w[c.w.len() - 16..])
    };

    // 3. Check U = G^r
    let r_g = {
        let hash = sha2::Sha256::new()
            .chain(b"IBE-H3")
            .chain(&sigma)
            .chain(&msg)
            .finalize();
        let r = hash.as_slice();
        let mut buf = [0u8; BLOCK_SIZE];
        ExpandMsgDrand::<Sha256>::expand_message(r, &[], &mut buf);
        let r = ScalarField::from_le_bytes_mod_order(&buf);
        c.u.generator().mul(r)
    };
    
    if c.u != r_g {
        return Err(IBEError::VerificationFailed);
    }

    Ok(msg)
}

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    if a.len() != b.len() {
        panic!("array length should be the same");
    }
    a.iter().zip(b.iter()).map(|(a, b)| a ^ b).collect()
}

/// Placeholder type for implementing expand_message_drand based on a hash function
#[derive(Debug)]
pub struct ExpandMsgDrand<HashT> {
    phantom: PhantomData<HashT>,
}

/// ExpandMsgXmd implements expand_message_drand for the ExpandMsg trait
impl<HashT> ExpandMsgDrand<HashT>
where
    HashT: Digest + Update,
{
    fn expand_message(msg: &[u8], _dst: &[u8], buf: &mut [u8]) {
        // drand "hash"
        const BITS_TO_MASK_FOR_BLS12381: usize = 1;
        for i in 1..u16::MAX {
            // We hash iteratively: H(i || H("IBE-H3" || sigma || msg)) until we get a
            // value that is suitable as a scalar.
            let mut h = HashT::new()
                .chain(i.to_le_bytes())
                .chain(msg)
                .finalize()
                .to_vec();
            *h.first_mut().unwrap() = h.first().unwrap() >> BITS_TO_MASK_FOR_BLS12381;
            // test if we can build a valid scalar out of n
            // this is a hash method to be compatible with the existing implementation
            let rev: Vec<u8> = h.iter().copied().rev().collect();
            if ScalarField::from_le_bytes_mod_order(&rev)
                .serialized_size(ark_serialize::Compress::Yes)
                > 0
            {
                buf.copy_from_slice(&rev);
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_extended_truth_table() {
        let a = vec![0b00000000u8, 0b11111111, 0b00000000, 0b11111111];
        let b = vec![0b11111111u8, 0b00000000, 0b00000000, 0b11111111];
        let x = vec![0b11111111u8, 0b11111111, 0b00000000, 0b00000000];
        assert_eq!(xor(&a, &b), x);
    }

    #[test]
    fn test_xor_empty() {
        let a = vec![];
        let b = vec![];
        let x: Vec<u8> = vec![];
        assert_eq!(xor(&a, &b), x);
    }
}
