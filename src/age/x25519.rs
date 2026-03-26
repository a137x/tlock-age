//! The "x25519" recipient type, native to age.

use crate::age_core::{
    format::{FileKey, Stanza, FILE_KEY_BYTES},
    primitives::{aead_decrypt, hkdf},
};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::{
    age::error::DecryptError,
    age::util::{parse_bech32, read::base64_arg},
};

// Use lower-case HRP to avoid https://github.com/rust-bitcoin/rust-bech32/issues/40
const SECRET_KEY_PREFIX: &str = "age-secret-key-";

pub(super) const X25519_RECIPIENT_TAG: &str = "X25519";
const X25519_RECIPIENT_KEY_LABEL: &[u8] = b"age-encryption.org/v1/X25519";

pub(super) const EPK_LEN_BYTES: usize = 32;
pub(super) const ENCRYPTED_FILE_KEY_BYTES: usize = FILE_KEY_BYTES + 16;

/// The standard age identity type, which can decrypt files encrypted to the corresponding
/// [`Recipient`].
#[derive(Clone)]
pub struct Identity(StaticSecret);

impl std::str::FromStr for Identity {
    type Err = &'static str;

    /// Parses an X25519 identity from a string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_bech32(s)
            .ok_or("invalid Bech32 encoding")
            .and_then(|(hrp, bytes)| {
                if hrp == SECRET_KEY_PREFIX {
                    TryInto::<[u8; 32]>::try_into(&bytes[..])
                        .map_err(|_| "incorrect identity length")
                        .map(StaticSecret::from)
                        .map(Identity)
                } else {
                    Err("incorrect HRP")
                }
            })
    }
}

impl Identity {}

impl crate::age::Identity for Identity {
    fn unwrap_stanza(
        &self,
        stanza: &Stanza,
        _precomputed_file_key: Option<[u8; 16]>,
    ) -> Option<Result<FileKey, DecryptError>> {
        if stanza.tag != X25519_RECIPIENT_TAG {
            return None;
        }

        // Enforce valid and canonical stanza format.
        // https://c2sp.org/age#x25519-recipient-stanza
        let ephemeral_share = match &stanza.args[..] {
            [arg] => match base64_arg::<_, EPK_LEN_BYTES, 33>(arg) {
                Some(ephemeral_share) => ephemeral_share,
                None => return Some(Err(DecryptError::InvalidHeader)),
            },
            _ => return Some(Err(DecryptError::InvalidHeader)),
        };
        if stanza.body.len() != ENCRYPTED_FILE_KEY_BYTES {
            return Some(Err(DecryptError::InvalidHeader));
        }

        let epk: PublicKey = ephemeral_share.into();
        let encrypted_file_key: [u8; ENCRYPTED_FILE_KEY_BYTES] = stanza.body[..]
            .try_into()
            .expect("Length should have been checked above");

        let pk: PublicKey = (&self.0).into();
        let shared_secret = self.0.diffie_hellman(&epk);
        // Replace with `SharedSecret::was_contributory` once x25519-dalek supports newer
        // zeroize (https://github.com/dalek-cryptography/x25519-dalek/issues/74#issuecomment-1159481280).
        if shared_secret
            .as_bytes()
            .iter()
            .fold(0, |acc, b| acc | b)
            .ct_eq(&0)
            .into()
        {
            return Some(Err(DecryptError::InvalidHeader));
        }

        let mut salt = [0; 64];
        salt[..32].copy_from_slice(epk.as_bytes());
        salt[32..].copy_from_slice(pk.as_bytes());

        let enc_key = hkdf(&salt, X25519_RECIPIENT_KEY_LABEL, shared_secret.as_bytes());

        // A failure to decrypt is non-fatal (we try to decrypt the recipient
        // stanza with other X25519 keys), because we cannot tell which key
        // matches a particular stanza.
        aead_decrypt(&enc_key, FILE_KEY_BYTES, &encrypted_file_key)
            .ok()
            .map(|mut pt| {
                // It's ours!
                let file_key: [u8; FILE_KEY_BYTES] = pt[..].try_into().unwrap();
                pt.zeroize();
                Ok(file_key.into())
            })
    }
}
