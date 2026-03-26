//! Encryption and decryption routines for age.
use std::io::{self, BufRead, Read};

use crate::{
    age::error::DecryptError,
    age::format::{Header, HeaderV1},
    age::scrypt,
};

pub mod decryptor;

pub(crate) struct Nonce([u8; 16]);

impl AsRef<[u8]> for Nonce {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Nonce {
    fn read<R: Read>(input: &mut R) -> io::Result<Self> {
        let mut nonce = [0; 16];
        input.read_exact(&mut nonce)?;
        Ok(Nonce(nonce))
    }
}

/// Decryptor for an age file.
pub enum Decryptor<R> {
    /// Decryption with a list of identities.
    Recipients(decryptor::RecipientsDecryptor<R>),
}

impl<R> From<decryptor::RecipientsDecryptor<R>> for Decryptor<R> {
    fn from(decryptor: decryptor::RecipientsDecryptor<R>) -> Self {
        Decryptor::Recipients(decryptor)
    }
}

impl<R> Decryptor<R> {
    fn from_v1_header(input: R, header: HeaderV1, nonce: Nonce) -> Result<Self, DecryptError> {
        // Enforce structural requirements on the v1 header.
        let any_scrypt = header
            .recipients
            .iter()
            .any(|r| r.tag == scrypt::SCRYPT_RECIPIENT_TAG);

        if !any_scrypt {
            Ok(decryptor::RecipientsDecryptor::new(input, Header::V1(header), nonce).into())
        } else {
            Err(DecryptError::InvalidHeader)
        }
    }
}

impl<R: Read> Decryptor<R> {
    /// Attempts to create a decryptor for an age file.
    ///
    /// Returns an error if the input does not contain a valid age file.
    ///
    /// # Performance
    ///
    /// This constructor will work with any type implementing [`io::Read`], and uses a
    /// slower parser and internal buffering to ensure no overreading occurs. Consider
    /// using [`Decryptor::new_buffered`] for types implementing `std::io::BufRead`, which
    /// includes `&[u8]` slices.
    pub fn new(mut input: R) -> Result<Self, DecryptError> {
        let header = Header::read(&mut input)?;
        match header {
            Header::V1(v1_header) => {
                let nonce = Nonce::read(&mut input)?;
                Decryptor::from_v1_header(input, v1_header, nonce)
            }
            Header::Unknown(_) => Err(DecryptError::UnknownFormat),
        }
    }
}

impl<R: BufRead> Decryptor<R> {
    /// Attempts to create a decryptor for an age file.
    ///
    /// Returns an error if the input does not contain a valid age file.
    ///
    /// # Performance
    ///
    /// This constructor is more performant than [`Decryptor::new`] for types implementing
    /// [`io::BufRead`], which includes `&[u8]` slices.
    pub fn new_buffered(mut input: R) -> Result<Self, DecryptError> {
        let header = Header::read_buffered(&mut input)?;

        match header {
            Header::V1(v1_header) => {
                let nonce = Nonce::read(&mut input)?;
                Decryptor::from_v1_header(input, v1_header, nonce)
            }
            Header::Unknown(_) => Err(DecryptError::UnknownFormat),
        }
    }
}

