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
            // `h` is the candidate in BIG-endian order (matching tlock-js's
            // `bytesToNumberBE(data)`); ark-ff wants little-endian, so reverse.
            let rev: Vec<u8> = h.iter().copied().rev().collect();
            // Rejection sampling, bit-for-bit as tlock-js `h3` does it:
            //
            //     data[0] = data[0] >> BitsToMaskForBLS12381
            //     const n = bytesToNumberBE(data)
            //     if (n < bls12_381.fields.Fr.ORDER) { return n }
            //     // else: bump the counter and re-hash
            //
            // A candidate is ACCEPTED only when it is already canonical (i.e.
            // strictly less than the scalar field order). Anything else is
            // REJECTED and we re-hash with the next counter value.
            //
            // The previous accept-test here was
            // `from_le_bytes_mod_order(&rev).serialized_size(Compress::Yes) > 0`,
            // which is a constant 32 for BLS12-381 Fr and therefore can never
            // reject: it silently reduced out-of-range candidates mod order
            // instead of re-sampling. Since the top bit is masked off, a
            // candidate lands in [ORDER, 2^255) roughly 9.5% of the time, and
            // for those ballots the Rust decryptor derived a *different* scalar
            // than the browser encryptor -> `c.u != r_g` -> decrypt failure.
            if is_canonical_scalar_le(&rev) {
                buf.copy_from_slice(&rev);
                return;
            }
        }
    }
}

/// Returns true when `le` (little-endian bytes) encodes a value strictly less
/// than the BLS12-381 scalar field order, i.e. when reducing it mod order is a
/// no-op. This is the Rust equivalent of tlock-js's `n < Fr.ORDER` test.
///
/// Implemented by round-tripping through the field: `from_le_bytes_mod_order`
/// reduces, and re-serializing yields the canonical little-endian encoding. If
/// that canonical encoding is byte-identical to the input, no reduction
/// happened and the candidate was in range.
fn is_canonical_scalar_le(le: &[u8]) -> bool {
    let reduced = ScalarField::from_le_bytes_mod_order(le);
    let mut canonical = Vec::with_capacity(le.len());
    if reduced.serialize_compressed(&mut canonical).is_err() {
        return false;
    }
    canonical == le
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

    /// Recomputes `r = H("IBE-H3" || sigma || msg)` exactly as `decrypt` does,
    /// then runs `expand_message` over it and returns the 32 little-endian
    /// bytes it produced.
    fn h3_expand(sigma: &[u8], msg: &[u8]) -> [u8; BLOCK_SIZE] {
        let r = sha2::Sha256::new()
            .chain(b"IBE-H3")
            .chain(sigma)
            .chain(msg)
            .finalize();
        let mut buf = [0u8; BLOCK_SIZE];
        ExpandMsgDrand::<Sha256>::expand_message(r.as_slice(), &[], &mut buf);
        buf
    }

    /// Regression test for the tlock-js / tlock-age h3 divergence.
    ///
    /// `sigma` below was found by brute force such that the FIRST candidate
    /// (counter i = 1) is >= the BLS12-381 scalar field order. tlock-js
    /// REJECTS that candidate and re-hashes with i = 2; the old Rust
    /// accept-test (`serialized_size(Compress::Yes) > 0`, a constant 32) could
    /// never reject, so it reduced the i = 1 candidate mod order instead and
    /// derived a different scalar. Ground truth below was computed with
    /// tlock-js's own @noble/hashes + @noble/curves dependencies running its
    /// verbatim `h3` (src/crypto/ibe.ts:156-181).
    #[test]
    fn test_h3_rejection_sampling_matches_tlock_js() {
        let sigma = hex::decode("0000000b000000000000000000000000").unwrap();
        let msg = b"OTER-TASK-8.5-RE";

        // The i = 1 candidate, big-endian, top bit already masked off.
        let first_candidate_be =
            hex::decode("7f69685246a9587588d983c2a308c93b363493f0532f0fb43e62153ae2b85b75")
                .unwrap();
        let mut first_candidate_le = first_candidate_be.clone();
        first_candidate_le.reverse();
        assert!(
            !is_canonical_scalar_le(&first_candidate_le),
            "test vector is stale: the first h3 candidate must be >= Fr::ORDER"
        );

        // What tlock-js actually returns: the i = 2 candidate.
        let expected_le =
            hex::decode("c39923d1ea5fcb9133ee7de850f1131f6c023c1ed58fa8589b67fd59388f3d1f")
                .unwrap();
        assert_eq!(
            h3_expand(&sigma, msg).to_vec(),
            expected_le,
            "expand_message must re-sample (i=2), not reduce the i=1 candidate mod order"
        );

        // And it must NOT be what the broken accept-test produced.
        let wrong = ScalarField::from_le_bytes_mod_order(&first_candidate_le);
        let derived = ScalarField::from_le_bytes_mod_order(&h3_expand(&sigma, msg));
        assert_ne!(derived, wrong, "regressed to reduce-mod-order behaviour");
    }

    /// Control: an input whose first candidate is already in range must still
    /// be accepted at i = 1 (this is the ~90% path that always worked).
    #[test]
    fn test_h3_accepts_first_candidate_when_in_range() {
        let sigma = [0u8; 16];
        let msg = b"OTER-TASK-8.5-RE";
        let expected_le =
            hex::decode("898be83ec981d06131fb3bcbfe6211f3f63eda2c4989ea6e1eda92665548dc15")
                .unwrap();
        assert_eq!(h3_expand(&sigma, msg).to_vec(), expected_le);
    }

    #[test]
    fn test_is_canonical_scalar_le_boundaries() {
        // 0 is canonical.
        assert!(is_canonical_scalar_le(&[0u8; 32]));
        // ORDER - 1 is canonical; ORDER itself is not.
        let order_minus_one_be =
            hex::decode("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000")
                .unwrap();
        let mut le = order_minus_one_be.clone();
        le.reverse();
        assert!(is_canonical_scalar_le(&le));

        let order_be =
            hex::decode("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001")
                .unwrap();
        let mut le = order_be.clone();
        le.reverse();
        assert!(!is_canonical_scalar_le(&le));
    }
}
