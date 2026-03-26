//! I/O helper structs for age file encryption and decryption.

use crate::{
    age::i18n::fl,
    age_core::secrecy::{ExposeSecret, SecretVec},
};
use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, KeyInit, KeySizeUser},
    ChaCha20Poly1305,
};
use std::cmp;
use std::io::{self, Read, Seek, SeekFrom};
use zeroize::Zeroize;

const CHUNK_SIZE: usize = 64 * 1024;
const TAG_SIZE: usize = 16;
const ENCRYPTED_CHUNK_SIZE: usize = CHUNK_SIZE + TAG_SIZE;

pub(crate) struct PayloadKey(
    pub(crate) GenericArray<u8, <ChaCha20Poly1305 as KeySizeUser>::KeySize>,
);

impl Drop for PayloadKey {
    fn drop(&mut self) {
        self.0.as_mut_slice().zeroize();
    }
}

/// The nonce used in age's STREAM encryption.
///
/// Structured as an 11 bytes of big endian counter, and 1 byte of last block flag
/// (`0x00 / 0x01`). We store this in the lower 12 bytes of a `u128`.
#[derive(Clone, Copy, Default)]
struct Nonce(u128);

impl Nonce {
    /// Unsets last-chunk flag.
    fn set_counter(&mut self, val: u64) {
        self.0 = u128::from(val) << 8;
    }

    fn increment_counter(&mut self) {
        // Increment the 11-byte counter
        self.0 += 1 << 8;
        if self.0 >> (8 * 12) != 0 {
            panic!("We overflowed the nonce!");
        }
    }

    fn is_last(&self) -> bool {
        self.0 & 1 != 0
    }

    fn set_last(&mut self, last: bool) -> Result<(), ()> {
        if !self.is_last() {
            self.0 |= u128::from(last);
            Ok(())
        } else {
            Err(())
        }
    }

    fn to_bytes(self) -> [u8; 12] {
        self.0.to_be_bytes()[4..]
            .try_into()
            .expect("slice is correct length")
    }
}

/// `STREAM[key](plaintext)`
///
/// The [STREAM] construction for online authenticated encryption, instantiated with
/// ChaCha20-Poly1305 in 64KiB chunks, and a nonce structure of 11 bytes of big endian
/// counter, and 1 byte of last block flag (0x00 / 0x01).
///
/// [STREAM]: https://eprint.iacr.org/2015/189.pdf
pub(crate) struct Stream {
    aead: ChaCha20Poly1305,
    nonce: Nonce,
}

impl Stream {
    fn new(key: PayloadKey) -> Self {
        Stream {
            aead: ChaCha20Poly1305::new(&key.0),
            nonce: Nonce::default(),
        }
    }

    /// Wraps `STREAM` decryption under the given `key` around a reader.
    ///
    /// `key` must **never** be repeated across multiple streams. In `age` this is
    /// achieved by deriving the key with [`HKDF`] from both a random file key and a
    /// random nonce.
    ///
    /// [`HKDF`]: age_core::primitives::hkdf
    pub(crate) fn decrypt<R: Read>(key: PayloadKey, inner: R) -> StreamReader<R> {
        StreamReader {
            stream: Self::new(key),
            inner,
            encrypted_chunk: vec![0; ENCRYPTED_CHUNK_SIZE],
            encrypted_pos: 0,
            start: StartPos::Implicit(0),
            plaintext_len: None,
            cur_plaintext_pos: 0,
            chunk: None,
        }
    }

    pub(crate) fn decrypt_bn254<R: Read>(key: PayloadKey, inner: R) -> StreamReader<R> {
        StreamReader {
            stream: Self::new(key),
            inner,
            encrypted_chunk: vec![0; ENCRYPTED_CHUNK_SIZE],
            encrypted_pos: 0,
            start: StartPos::Implicit(0),
            plaintext_len: None,
            cur_plaintext_pos: 0,
            chunk: None,
        }
    }

    fn decrypt_chunk(&mut self, chunk: &[u8], last: bool) -> io::Result<SecretVec<u8>> {
        assert!(chunk.len() <= ENCRYPTED_CHUNK_SIZE);

        self.nonce.set_last(last).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "last chunk has been processed")
        })?;

        let decrypted = self
            .aead
            .decrypt(&self.nonce.to_bytes().into(), chunk)
            .map(SecretVec::new)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "decryption error"))?;
        self.nonce.increment_counter();

        Ok(decrypted)
    }

    fn is_complete(&self) -> bool {
        self.nonce.is_last()
    }
}

/// The position in the underlying reader corresponding to the start of the stream.
///
/// To impl Seek for StreamReader, we need to know the point in the reader corresponding
/// to the first byte of the stream. But we can't query the reader for its current
/// position without having a specific constructor for `R: Read + Seek`, which makes the
/// higher-level API more complex. Instead, we count the number of bytes that have been
/// read from the reader until we first need to seek, and then inside `impl Seek` we can
/// query the reader's current position and figure out where the start was.
enum StartPos {
    /// An offset that we can subtract from the current position.
    Implicit(u64),
    /// The precise start position.
    Explicit(u64),
}

/// Provides access to a decrypted age file.

pub struct StreamReader<R> {
    stream: Stream,
    inner: R,
    encrypted_chunk: Vec<u8>,
    encrypted_pos: usize,
    start: StartPos,
    plaintext_len: Option<u64>,
    cur_plaintext_pos: u64,
    chunk: Option<SecretVec<u8>>,
}

impl<R> StreamReader<R> {
    fn count_bytes(&mut self, read: usize) {
        // We only need to count if we haven't yet worked out the start position.
        if let StartPos::Implicit(offset) = &mut self.start {
            *offset += read as u64;
        }
    }

    fn decrypt_chunk(&mut self) -> io::Result<()> {
        self.count_bytes(self.encrypted_pos);
        let chunk = &self.encrypted_chunk[..self.encrypted_pos];

        if chunk.is_empty() {
            if !self.stream.is_complete() {
                // Stream has ended before seeing the last chunk.
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "age file is truncated",
                ));
            }
        } else {
            // This check works for all cases except when the age file is an integer
            // multiple of the chunk size. In that case, we try decrypting twice on a
            // decryption failure.
            let last = chunk.len() < ENCRYPTED_CHUNK_SIZE;

            self.chunk = match (self.stream.decrypt_chunk(chunk, last), last) {
                (Ok(chunk), _)
                    if chunk.expose_secret().is_empty() && self.cur_plaintext_pos > 0 =>
                {
                    assert!(last);
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        fl!("err-stream-last-chunk-empty"),
                    ));
                }
                (Ok(chunk), _) => Some(chunk),
                (Err(_), false) => Some(self.stream.decrypt_chunk(chunk, true)?),
                (Err(e), true) => return Err(e),
            };
        }

        // We've finished with this encrypted chunk.
        self.encrypted_pos = 0;

        Ok(())
    }

    fn read_from_chunk(&mut self, buf: &mut [u8]) -> usize {
        if self.chunk.is_none() {
            return 0;
        }

        let chunk = self.chunk.as_ref().unwrap();
        let cur_chunk_offset = self.cur_plaintext_pos as usize % CHUNK_SIZE;

        let to_read = cmp::min(chunk.expose_secret().len() - cur_chunk_offset, buf.len());

        buf[..to_read]
            .copy_from_slice(&chunk.expose_secret()[cur_chunk_offset..cur_chunk_offset + to_read]);
        self.cur_plaintext_pos += to_read as u64;
        if self.cur_plaintext_pos % CHUNK_SIZE as u64 == 0 {
            // We've finished with the current chunk.
            self.chunk = None;
        }

        to_read
    }
}

impl<R: Read> Read for StreamReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.chunk.is_none() {
            while self.encrypted_pos < ENCRYPTED_CHUNK_SIZE {
                match self
                    .inner
                    .read(&mut self.encrypted_chunk[self.encrypted_pos..])
                {
                    Ok(0) => break,
                    Ok(n) => self.encrypted_pos += n,
                    Err(e) => match e.kind() {
                        io::ErrorKind::Interrupted => (),
                        _ => return Err(e),
                    },
                }
            }
            self.decrypt_chunk()?;
        }

        Ok(self.read_from_chunk(buf))
    }
}

impl<R: Read + Seek> StreamReader<R> {
    fn start(&mut self) -> io::Result<u64> {
        match self.start {
            StartPos::Implicit(offset) => {
                let current = self.inner.seek(SeekFrom::Current(0))?;
                let start = current - offset;

                // Cache the start for future calls.
                self.start = StartPos::Explicit(start);

                Ok(start)
            }
            StartPos::Explicit(start) => Ok(start),
        }
    }

    /// Returns the length of the plaintext
    fn len(&mut self) -> io::Result<u64> {
        match self.plaintext_len {
            None => {
                // Cache the current position and nonce, and then grab the start and end
                // ciphertext positions.
                let cur_pos = self.inner.seek(SeekFrom::Current(0))?;
                let cur_nonce = self.stream.nonce.0;
                let ct_start = self.start()?;
                let ct_end = self.inner.seek(SeekFrom::End(0))?;
                let ct_len = ct_end - ct_start;

                // Use ceiling division to determine the number of chunks.
                let num_chunks =
                    (ct_len + (ENCRYPTED_CHUNK_SIZE as u64 - 1)) / ENCRYPTED_CHUNK_SIZE as u64;

                // Authenticate the ciphertext length by checking that we can successfully
                // decrypt the last chunk _as_ a last chunk.
                let last_chunk_start = ct_start + ((num_chunks - 1) * ENCRYPTED_CHUNK_SIZE as u64);
                let mut last_chunk = Vec::with_capacity((ct_end - last_chunk_start) as usize);
                self.inner.seek(SeekFrom::Start(last_chunk_start))?;
                self.inner.read_to_end(&mut last_chunk)?;
                self.stream.nonce.set_counter(num_chunks - 1);
                self.stream.decrypt_chunk(&last_chunk, true).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Last chunk is invalid, stream might be truncated",
                    )
                })?;

                // Now that we have authenticated the ciphertext length, we can use it to
                // calculate the plaintext length.
                let total_tag_size = num_chunks * TAG_SIZE as u64;
                let pt_len = ct_len - total_tag_size;

                // Return to the original position and restore the nonce.
                self.inner.seek(SeekFrom::Start(cur_pos))?;
                self.stream.nonce = Nonce(cur_nonce);

                // Cache the length for future calls.
                self.plaintext_len = Some(pt_len);

                Ok(pt_len)
            }
            Some(pt_len) => Ok(pt_len),
        }
    }
}

impl<R: Read + Seek> Seek for StreamReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        // Convert the offset into the target position within the plaintext
        let start = self.start()?;
        let target_pos = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::Current(offset) => {
                let res = (self.cur_plaintext_pos as i64) + offset;
                if res >= 0 {
                    res as u64
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "cannot seek before the start",
                    ));
                }
            }
            SeekFrom::End(offset) => {
                let res = (self.len()? as i64) + offset;
                if res >= 0 {
                    res as u64
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "cannot seek before the start",
                    ));
                }
            }
        };

        let cur_chunk_index = self.cur_plaintext_pos / CHUNK_SIZE as u64;

        let target_chunk_index = target_pos / CHUNK_SIZE as u64;
        let target_chunk_offset = target_pos % CHUNK_SIZE as u64;

        if target_chunk_index == cur_chunk_index {
            // We just need to reposition ourselves within the current chunk.
            self.cur_plaintext_pos = target_pos;
        } else {
            // Clear the current chunk
            self.chunk = None;

            // Seek to the beginning of the target chunk
            self.inner.seek(SeekFrom::Start(
                start + (target_chunk_index * ENCRYPTED_CHUNK_SIZE as u64),
            ))?;
            self.stream.nonce.set_counter(target_chunk_index);
            self.cur_plaintext_pos = target_chunk_index * CHUNK_SIZE as u64;

            // Read and drop bytes from the chunk to reach the target position.
            if target_chunk_offset > 0 {
                let mut to_drop = vec![0; target_chunk_offset as usize];
                self.read_exact(&mut to_drop)?;
            }
            // We need to handle the edge case where the last chunk is not short, and
            // `target_pos == self.len()` (so `target_chunk_index` points to the chunk
            // after the last chunk). The next read would return no bytes, but because
            // `target_chunk_offset == 0` we weren't forced to read past any in-chunk
            // bytes, and thus have not set the `last` flag on the nonce.
            //
            // To handle this edge case, when `target_pos` is a multiple of the chunk
            // size (i.e. this conditional branch), we compute the length of the
            // plaintext. This is cached, so the overhead should be minimal.
            else if target_pos == self.len()? {
                self.stream
                    .nonce
                    .set_last(true)
                    .expect("We unset the last chunk flag earlier");
            }
        }

        // All done!
        Ok(target_pos)
    }
}
