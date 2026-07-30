use std::{
    io,
    sync::{Arc, Mutex},
};

use crate::age::DecryptError;
use crate::age_core::format::{FileKey, Stanza};
use crate::tlock::{decrypt, TlockCurve};
use sha2::Digest;

pub const STANZA_TAG: &str = "tlock";

// Identity implements the age Identity interface. This is used to decrypt
// data with the age Decrypt API.
pub struct Identity {
    hash: Vec<u8>,
    signature: Vec<u8>,
}

impl Identity {
    pub fn new(hash: &[u8], signature: &[u8]) -> Self {
        Self {
            hash: hash.to_vec(),
            signature: signature.to_vec(),
        }
    }
}

impl crate::age::Identity for Identity {
    // Unwrap is called by the age Decrypt API and is provided the DEK that was time
    // lock encrypted by the Wrap function via the Stanza. Inside of Unwrap we decrypt
    // the DEK and provide back to age.
    fn unwrap_stanza(
        &self,
        stanza: &Stanza,
        precomputed_file_key: Option<[u8; 16]>,
    ) -> Option<Result<FileKey, DecryptError>> {
        if stanza.tag != STANZA_TAG {
            return None;
        }
        if stanza.args.len() != 3 {
            return Some(Err(DecryptError::InvalidHeader));
        }
        let args: [String; 3] = [
            stanza.args[0].clone(), // round
            stanza.args[1].clone(), // chain hash
            stanza.args[2].clone(), // file key hash
        ];

        match precomputed_file_key {
            Some(file_key) => {
                // checking if the precomputed file key is valid
                let file_key_hash = sha2::Sha256::digest(file_key.as_slice());
                let file_key_hash_hex = hex::encode(file_key_hash);
                if args[2] != file_key_hash_hex {
                    return Some(Err(DecryptError::InvalidFileKeyHash));
                }
                return Some(Ok(file_key.into()));
            }
            None => {}
        }
        // if precomputed file key is not provided, we need to decrypt the file key
        let _round = args[0]
            .parse::<u64>()
            .map_err(|_| DecryptError::InvalidHeader)
            .ok()?;

        if self.hash != hex::decode(&args[1]).ok()? {
            return Some(Err(DecryptError::InvalidHeader));
        }

        let dst = InMemoryWriter::new();

        // Detect curve based on chain hash
        let curve = TlockCurve::from_chain_hash(&self.hash);

        // Use the parent crate's tlock module with curve detection
        let decryption = decrypt(
            dst.to_owned(),
            stanza.body.as_slice(),
            &self.signature,
            curve,
        );
        decryption
            .map_err(|_| DecryptError::DecryptionFailed)
            .ok()?;
        let mut dst = dst.memory();
        dst.resize(16, 0);
        let file_key: [u8; 16] = dst[..].try_into().ok()?;
        Some(Ok(file_key.into()))
    }
}

// Identity implements the age Identity interface. This is used to decrypt
// data with the age Decrypt API.
pub struct HeaderIdentity {
    hash: Mutex<Option<Vec<u8>>>,
    round: Mutex<Option<u64>>,
}

impl HeaderIdentity {
    pub fn new() -> Self {
        Self {
            hash: Mutex::new(None),
            round: Mutex::new(None),
        }
    }

    pub fn hash(&self) -> Option<Vec<u8>> {
        self.hash.lock().unwrap().clone()
    }

    pub fn round(&self) -> Option<u64> {
        *self.round.lock().unwrap()
    }
}

impl Default for HeaderIdentity {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::age::Identity for HeaderIdentity {
    // Unwrap is called by the age Decrypt API and is provided the DEK that was time
    // lock encrypted by the Wrap function via the Stanza. Inside of Unwrap we extract
    // tlock header and assign it to the identity.
    fn unwrap_stanza(
        &self,
        stanza: &Stanza,
        _precomputed_file_key: Option<[u8; 16]>,
    ) -> Option<Result<FileKey, DecryptError>> {
        if stanza.tag != STANZA_TAG {
            return None;
        }
        if stanza.args.len() != 3 {
            return Some(Err(DecryptError::InvalidHeader));
        }
        let args: [String; 3] = [
            stanza.args[0].clone(),
            stanza.args[1].clone(),
            stanza.args[2].clone(), // file key hash
        ];

        let round = args[0]
            .parse::<u64>()
            .map_err(|_| DecryptError::InvalidHeader)
            .ok()?;
        let hash = hex::decode(&args[1])
            .map_err(|_| DecryptError::InvalidHeader)
            .ok()?;

        *self.round.lock().unwrap() = Some(round);
        *self.hash.lock().unwrap() = Some(hash);
        None
    }
}

#[derive(Clone)]
struct InMemoryWriter {
    memory: Arc<Mutex<Vec<u8>>>,
}

impl InMemoryWriter {
    pub fn new() -> Self {
        Self {
            memory: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn memory(&self) -> Vec<u8> {
        self.memory.lock().unwrap().clone()
    }
}

impl io::Write for InMemoryWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.memory.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
