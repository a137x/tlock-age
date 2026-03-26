//! Error type.

use std::fmt;
use std::io;

/// The various errors that can be returned during the encryption process.
#[derive(Debug)]
pub enum EncryptError {
    /// An error occured while decrypting passphrase-encrypted identities.
    EncryptedIdentities(DecryptError),
    /// An I/O error occurred during encryption.
    Io(io::Error),
}

impl From<io::Error> for EncryptError {
    fn from(e: io::Error) -> Self {
        EncryptError::Io(e)
    }
}

impl Clone for EncryptError {
    fn clone(&self) -> Self {
        match self {
            Self::EncryptedIdentities(e) => Self::EncryptedIdentities(e.clone()),
            Self::Io(e) => Self::Io(io::Error::new(e.kind(), e.to_string())),
        }
    }
}

impl fmt::Display for EncryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncryptError::EncryptedIdentities(e) => e.fmt(f),
            EncryptError::Io(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for EncryptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            EncryptError::EncryptedIdentities(inner) => Some(inner),
            EncryptError::Io(inner) => Some(inner),
        }
    }
}

/// The various errors that can be returned during the decryption process.
#[derive(Debug)]
pub enum DecryptError {
    /// The age file failed to decrypt.
    DecryptionFailed,
    /// The age file used an excessive work factor for passphrase encryption.
    ExcessiveWork {
        /// The work factor required to decrypt.
        required: u8,
        /// The target work factor for this device (around 1 second of work).
        target: u8,
    },
    /// The age header was invalid.
    InvalidHeader,
    /// The MAC in the age header was invalid.
    InvalidMac,
    /// An I/O error occurred during decryption.
    Io(io::Error),
    /// Failed to decrypt an encrypted key.
    KeyDecryptionFailed,

    /// None of the provided keys could be used to decrypt the age file.
    NoMatchingKeys,

    /// An unknown age format, probably from a newer version.
    UnknownFormat,

    /// The decrypted filekey hash does not match the expected hash from the age header.
    InvalidFileKeyHash,
}

impl Clone for DecryptError {
    fn clone(&self) -> Self {
        match self {
            Self::DecryptionFailed => Self::DecryptionFailed,
            Self::ExcessiveWork { required, target } => Self::ExcessiveWork {
                required: *required,
                target: *target,
            },
            Self::InvalidHeader => Self::InvalidHeader,
            Self::InvalidMac => Self::InvalidMac,
            Self::Io(e) => Self::Io(io::Error::new(e.kind(), e.to_string())),
            Self::KeyDecryptionFailed => Self::KeyDecryptionFailed,
            Self::NoMatchingKeys => Self::NoMatchingKeys,
            Self::UnknownFormat => Self::UnknownFormat,
            Self::InvalidFileKeyHash => Self::InvalidFileKeyHash,
        }
    }
}

impl fmt::Display for DecryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecryptError::DecryptionFailed => write!(f, "err-decryption-failed"),
            DecryptError::ExcessiveWork { required, target } => {
                write!(f, "Excessive work factor required")?;
                write!(f, " (requires {} seconds of work)", 1 << (required - target))
            }
            DecryptError::InvalidHeader => write!(f, "err-header-invalid"),
            DecryptError::InvalidMac => write!(f, "err-header-mac-invalid"),
            DecryptError::Io(e) => e.fmt(f),
            DecryptError::KeyDecryptionFailed => write!(f, "err-key-decryption"),

            DecryptError::NoMatchingKeys => write!(f, "err-no-matching-keys"),

            DecryptError::UnknownFormat => {
                write!(f, "err-unknown-format")?;
                write!(f, "rec-unknown-format")
            }
            DecryptError::InvalidFileKeyHash => write!(f, "err-file-key-hash-invalid"),
        }
    }
}

impl From<chacha20poly1305::aead::Error> for DecryptError {
    fn from(_: chacha20poly1305::aead::Error) -> Self {
        DecryptError::DecryptionFailed
    }
}

impl From<io::Error> for DecryptError {
    fn from(e: io::Error) -> Self {
        DecryptError::Io(e)
    }
}

impl From<hmac::digest::MacError> for DecryptError {
    fn from(_: hmac::digest::MacError) -> Self {
        DecryptError::InvalidMac
    }
}

impl std::error::Error for DecryptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DecryptError::Io(inner) => Some(inner),
            _ => None,
        }
    }
}
