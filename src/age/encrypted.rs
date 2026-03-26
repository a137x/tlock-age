//! The "encrypted age identity file" identity type.

use std::{cell::Cell, io};

use crate::age::{
    decryptor::PassphraseDecryptor, i18n::fl, Callbacks, DecryptError, IdentityFile,
    IdentityFileEntry,
};

/// The state of the encrypted age identity.
enum IdentityState<R: io::Read> {
    Encrypted {
        decryptor: PassphraseDecryptor<R>,
        max_work_factor: Option<u8>,
    },
    Decrypted(Vec<IdentityFileEntry>),

    /// The file was not correctly encrypted, or did not contain age identities. We cache
    /// this error in case the caller tries to use this identity again. The `Option` is to
    /// enable implementing `Default` so we can use `Cell::take`, but we don't ever allow
    /// the `None` case to persist.
    Poisoned(Option<DecryptError>),
}

impl<R: io::Read> Default for IdentityState<R> {
    fn default() -> Self {
        Self::Poisoned(None)
    }
}

impl<R: io::Read> IdentityState<R> {
    /// Decrypts this encrypted identity if necessary.
    ///
    /// Returns the (possibly cached) identities, and a boolean marking if the identities
    /// were not cached (and we just asked the user for a passphrase).
    fn decrypt<C: Callbacks>(
        self,
        filename: Option<&str>,
        callbacks: C,
        precomputed_file_key: Option<[u8; 16]>,
    ) -> Result<(Vec<IdentityFileEntry>, bool), DecryptError> {
        match self {
            Self::Encrypted {
                decryptor,
                max_work_factor,
            } => {
                let passphrase = match callbacks.request_passphrase(&fl!(
                    "encrypted-passphrase-prompt",
                    filename = filename.unwrap_or_default()
                )) {
                    Some(passphrase) => passphrase,
                    None => todo!(),
                };

                decryptor
                    .decrypt(&passphrase, max_work_factor, precomputed_file_key)
                    .map_err(|e| {
                        if matches!(e, DecryptError::DecryptionFailed) {
                            DecryptError::KeyDecryptionFailed
                        } else {
                            e
                        }
                    })
                    .and_then(|stream| {
                        let file = IdentityFile::from_buffer(io::BufReader::new(stream))?;
                        Ok((file.into_identities(), true))
                    })
            }
            Self::Decrypted(identities) => Ok((identities, false)),
            // `IdentityState::decrypt` is only ever called with `Some`.
            Self::Poisoned(e) => Err(e.unwrap()),
        }
    }
}

/// An encrypted age identity file.
pub struct Identity<R: io::Read, C: Callbacks> {
    state: Cell<IdentityState<R>>,
    filename: Option<String>,
    callbacks: C,
}

impl<R: io::Read, C: Callbacks> Identity<R, C> {
    /// Attempts to unwrap stanzas with the identities contained within this encrypted
    /// identity.
    ///
    /// We don't want to ask the user for the passphrase on every stanza decryption, and
    /// we don't want to store the entire encrypted age identity file in memory. Instead,
    /// the first time that an encrypted identity is decrypted with, we ask the caller for
    /// the passphrase, and perform validity checks on the decrypted data. We then cache
    /// the decrypted identities for subsequent calls.
    ///
    /// Because the `age::Identity` trait requires immutable references, this means that
    /// we need to use interior mutability here.
    fn unwrap_stanzas_base<F>(
        &self,
        filter: F,
        precomputed_file_key: Option<[u8; 16]>,
    ) -> Option<Result<crate::age_core::format::FileKey, DecryptError>>
    where
        F: Fn(
            Result<Box<dyn crate::age::Identity>, DecryptError>,
        ) -> Option<Result<crate::age_core::format::FileKey, DecryptError>>,
    {
        match self.state.take().decrypt(
            self.filename.as_deref(),
            self.callbacks.clone(),
            precomputed_file_key,
        ) {
            Ok((identities, requested_passphrase)) => {
                let result = identities
                    .iter()
                    .map(|entry| entry.clone().into_identity(self.callbacks.clone()))
                    .find_map(filter);

                // If we requested a passphrase to decrypt, and none of the identities
                // matched, warn the user.
                if requested_passphrase && result.is_none() {
                    self.callbacks.display_message(&fl!(
                        "encrypted-warn-no-match",
                        filename = self.filename.as_deref().unwrap_or_default()
                    ));
                }

                self.state.set(IdentityState::Decrypted(identities));
                result
            }
            Err(e) => {
                self.state.set(IdentityState::Poisoned(Some(e.clone())));
                Some(Err(e))
            }
        }
    }
}

impl<R: io::Read, C: Callbacks> crate::age::Identity for Identity<R, C> {
    fn unwrap_stanza(
        &self,
        stanza: &crate::age_core::format::Stanza,
        precomputed_file_key: Option<[u8; 16]>,
    ) -> Option<Result<crate::age_core::format::FileKey, DecryptError>> {
        self.unwrap_stanzas_base(
            |identity| match identity {
                Ok(i) => i.unwrap_stanza(stanza, precomputed_file_key.clone()),
                Err(e) => Some(Err(e)),
            },
            precomputed_file_key.clone(),
        )
    }

    fn unwrap_stanzas(
        &self,
        stanzas: &[crate::age_core::format::Stanza],
        precomputed_file_key: Option<[u8; 16]>,
    ) -> Option<Result<crate::age_core::format::FileKey, DecryptError>> {
        self.unwrap_stanzas_base(
            |identity| match identity {
                Ok(i) => i.unwrap_stanzas(stanzas, precomputed_file_key.clone()),
                Err(e) => Some(Err(e)),
            },
            precomputed_file_key.clone(),
        )
    }
}
