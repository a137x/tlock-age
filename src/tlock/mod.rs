pub mod ibe;
pub mod bn254;

use ibe::{Ciphertext, GAffine};
use bn254::{decrypt_bn254, BN254Error};
use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TLockError {
    #[error(transparent)]
    IBE(#[from] ibe::IBEError),
    #[error(transparent)]
    BN254(#[from] BN254Error),
    #[error(transparent)]
    IOError(#[from] io::Error),
}

/// Supported curves for tlock
#[derive(Debug, Clone, PartialEq)]
pub enum TlockCurve {
    Bls12381,
    Bn254,
}

impl TlockCurve {
    /// Detect curve from chain hash or scheme
    pub fn from_chain_hash(chain_hash: &[u8]) -> Self {
        // BN254 chain hash for evmnet: "04f1e9062b8a81f848fded9c12306733282b2727ecced50032187751166ec8c3"
        let evmnet_hash = hex::decode("04f1e9062b8a81f848fded9c12306733282b2727ecced50032187751166ec8c3").unwrap();
        
        if chain_hash == evmnet_hash.as_slice() {
            TlockCurve::Bn254
        } else {
            // Default to BLS12-381 for other chains (mainnet, fastnet, etc.)
            TlockCurve::Bls12381
        }
    }
}

/// Decrypt 16 bytes using tlock encryption scheme.
///
/// tlock relies on BLS, content private key is a BLS signature.
/// Signature group is assessed based on the public key size.
pub fn decrypt<W: io::Write, R: io::Read>(
    mut dst: W,
    mut src: R,
    signature: &[u8],
    curve: TlockCurve,
) -> Result<(), TLockError> {
    match curve {
        TlockCurve::Bls12381 => {
            // Original BLS12-381 implementation
            let c = {
                let u = if signature.len() == ibe::G1_SIZE {
                    let mut u = [0u8; ibe::G2_SIZE];
                    src.read_exact(&mut u).map_err(TLockError::IOError)?;
                    u.to_vec()
                } else {
                    let mut u = [0u8; ibe::G1_SIZE];
                    src.read_exact(&mut u).map_err(TLockError::IOError)?;
                    u.to_vec()
                };
                let mut v = [0u8; 16];
                src.read_exact(&mut v).map_err(TLockError::IOError)?;
                let v = [[0u8; 16], v].concat().to_vec();
                let mut w = [0u8; 16];
                src.read_exact(&mut w).map_err(TLockError::IOError)?;
                let w = [[0u8; 16], w].concat().to_vec();
                Ciphertext {
                    u: u.as_slice().try_into()?,
                    v,
                    w,
                }
            };

            let mut pt = time_unlock(signature, &c)?;

            // Remove trailing zeros
            if let Some(i) = pt.iter().rposition(|x| *x != 0) {
                pt.truncate(i + 1);
            }

            dst.write_all(&pt).map_err(TLockError::IOError)?;
            Ok(())
        }
        TlockCurve::Bn254 => {
            // BN254 implementation - use same approach as Go implementation
            let c = {
                // For BN254, signature is G1 (64 bytes), so U should be G2 (64 bytes compressed)
                let mut u = [0u8; 128]; // G2 compressed size
                src.read_exact(&mut u).map_err(TLockError::IOError)?;
                let u = u.to_vec();
                
                let mut v = [0u8; 16];
                src.read_exact(&mut v).map_err(TLockError::IOError)?;
                
                let mut w = [0u8; 16];
                src.read_exact(&mut w).map_err(TLockError::IOError)?;
                
                // Convert to BN254 format (160 bytes: 128 U + 16 V + 16 W)
                let mut ciphertext_bytes = Vec::new();
                ciphertext_bytes.extend_from_slice(&u);
                ciphertext_bytes.extend_from_slice(&v);
                ciphertext_bytes.extend_from_slice(&w);
                ciphertext_bytes
            };

            let pt = decrypt_bn254(signature, &c)?;

            // Return the result directly (should be 16 bytes, matching Go implementation and age file format)
            dst.write_all(&pt).map_err(TLockError::IOError)?;
            Ok(())
        }
    }
}

pub fn time_unlock(signature: &[u8], c: &Ciphertext) -> Result<Vec<u8>, TLockError> {
    let private: GAffine = signature.try_into()?;
    ibe::decrypt(private, c).map_err(TLockError::IBE)
}