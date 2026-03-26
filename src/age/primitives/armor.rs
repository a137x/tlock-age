//! I/O helper structs for the age ASCII armor format.

use base64::{prelude::BASE64_STANDARD, Engine};
use std::cmp;
use std::error;
use std::fmt;
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use zeroize::Zeroizing;

use crate::age::util::LINE_ENDING;

const ARMORED_COLUMNS_PER_LINE: usize = 64;
const ARMORED_BYTES_PER_LINE: usize = ARMORED_COLUMNS_PER_LINE / 4 * 3;
const ARMORED_BEGIN_MARKER: &str = "-----BEGIN AGE ENCRYPTED FILE-----";
const ARMORED_END_MARKER: &str = "-----END AGE ENCRYPTED FILE-----";

const MIN_ARMOR_LEN: usize = 36; // ARMORED_BEGIN_MARKER.len() + 2

const BASE64_CHUNK_SIZE_COLUMNS: usize = 8 * 1024;
const BASE64_CHUNK_SIZE_BYTES: usize = BASE64_CHUNK_SIZE_COLUMNS / 4 * 3;

/// Specifies the format that [`ArmoredWriter`] should apply to its output.
pub enum Format {
    /// ASCII armored format.
    AsciiArmor,
}

pub(crate) struct LineEndingWriter<W> {
    inner: W,
    buf: Vec<u8>,
    total_written: usize,
}

impl<W: Write> LineEndingWriter<W> {
    fn new(mut inner: W) -> io::Result<Self> {
        // Write the begin marker
        inner.write_all(ARMORED_BEGIN_MARKER.as_bytes())?;
        inner.write_all(LINE_ENDING.as_bytes())?;

        Ok(LineEndingWriter {
            inner,
            buf: Vec::with_capacity(8 * 1024),
            total_written: 0,
        })
    }

    fn flush_buffered(&mut self) -> io::Result<()> {
        self.inner.write_all(&self.buf)?;
        self.total_written += self.buf.len();
        self.buf.clear();
        Ok(())
    }

    fn finish(mut self) -> io::Result<W> {
        // Ensure all bytes have been written.
        self.flush_buffered()?;

        // Write the end marker
        self.inner.write_all(LINE_ENDING.as_bytes())?;
        self.inner.write_all(ARMORED_END_MARKER.as_bytes())?;
        self.inner.write_all(LINE_ENDING.as_bytes())?;

        Ok(self.inner)
    }
}

impl<W: Write> Write for LineEndingWriter<W> {
    fn write(&mut self, mut buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let written = buf.len();

        while !buf.is_empty() {
            let remaining =
                ARMORED_COLUMNS_PER_LINE - (self.total_written % ARMORED_COLUMNS_PER_LINE);

            // Write the next newline if we are at the end of the line.
            if remaining == ARMORED_COLUMNS_PER_LINE && self.total_written > 0 {
                self.buf.extend_from_slice(LINE_ENDING.as_bytes());
            }
            let to_write = cmp::min(remaining, buf.len());

            self.buf.extend_from_slice(&buf[..to_write]);
            buf = &buf[to_write..];
            self.total_written += to_write;
        }

        // Write the buffer to the inner writer, and drop the written bytes. We trigger
        // this when we are close to the buffer's capacity, to avoid reallocation.
        if self.buf.len() + 1024 > self.buf.capacity() {
            let inner_written = self.inner.write(&self.buf)?;
            let mut i = 0;
            self.buf.retain(|_| {
                let b = i >= inner_written;
                i += 1;
                b
            });
        }

        // We always return the number of bytes we consumed, not how many we actually
        // wrote to the inner writer. Any discrepancy is handled in self.flush().
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_buffered()?;
        self.inner.flush()
    }
}


enum ArmorIs<W> {
    Enabled {
        inner: LineEndingWriter<W>,
        byte_buf: Option<Vec<u8>>,
        encoded_buf: Box<[u8; BASE64_CHUNK_SIZE_COLUMNS]>,
    },

    _Disabled {
        inner: W,
    },
}

/// ArmoredWriter is a writer that writes age encrypted files.
pub struct ArmoredWriter<W>(ArmorIs<W>);

impl<W: Write> ArmoredWriter<W> {
    /// Wraps the given output in an `ArmoredWriter` that will apply the given [`Format`].
    pub fn wrap_output(output: W, format: Format) -> io::Result<Self> {
        match format {
            Format::AsciiArmor => LineEndingWriter::new(output).map(|w| {
                ArmoredWriter(ArmorIs::Enabled {
                    inner: w,
                    byte_buf: Some(Vec::with_capacity(BASE64_CHUNK_SIZE_BYTES)),
                    encoded_buf: Box::new([0; BASE64_CHUNK_SIZE_COLUMNS]),
                })
            })
        }
    }

    /// Writes the end marker of the age file, if armoring was enabled.
    ///
    /// You **MUST** call `finish` when you are done writing, in order to finish the
    /// armoring process. Failing to call `finish` will result in a truncated file that
    /// that will fail to decrypt.
    pub fn finish(self) -> io::Result<W> {
        match self.0 {
            ArmorIs::Enabled {
                mut inner,
                byte_buf,
                mut encoded_buf,
                ..
            } => {
                let byte_buf = byte_buf.unwrap();
                let encoded = BASE64_STANDARD
                    .encode_slice(&byte_buf, &mut encoded_buf[..])
                    .expect("byte_buf.len() <= BASE64_CHUNK_SIZE_BYTES");
                inner.write_all(&encoded_buf[..encoded])?;
                inner.finish()
            }
            ArmorIs::_Disabled { inner } => Ok(inner),
        }
    }
}

impl<W: Write> Write for ArmoredWriter<W> {
    fn write(&mut self, mut buf: &[u8]) -> io::Result<usize> {
        match &mut self.0 {
            ArmorIs::Enabled {
                inner,
                byte_buf,
                encoded_buf,
                ..
            } => {
                // Guaranteed to be Some (as long as async and sync writing isn't mixed),
                // because ArmoredWriter::finish consumes self.
                let byte_buf = byte_buf.as_mut().unwrap();

                let mut written = 0;
                loop {
                    let mut to_write = BASE64_CHUNK_SIZE_BYTES - byte_buf.len();
                    if to_write > buf.len() {
                        to_write = buf.len()
                    }

                    byte_buf.extend_from_slice(&buf[..to_write]);
                    buf = &buf[to_write..];
                    written += to_write;

                    // At this point, either buf is empty, or we have a full line.
                    assert!(buf.is_empty() || byte_buf.len() == BASE64_CHUNK_SIZE_BYTES);

                    // Only encode the line if we have more data to write, as the last
                    // (possibly-partial) line must be written in finish().
                    if buf.is_empty() {
                        break;
                    } else {
                        assert_eq!(
                            BASE64_STANDARD
                                .encode_slice(&byte_buf, &mut encoded_buf[..])
                                .expect("byte_buf.len() <= BASE64_CHUNK_SIZE_BYTES"),
                            BASE64_CHUNK_SIZE_COLUMNS
                        );
                        inner.write_all(&encoded_buf[..])?;
                        byte_buf.clear();
                    };
                }

                Ok(written)
            }
            ArmorIs::_Disabled { inner } => inner.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.0 {
            ArmorIs::Enabled { inner, .. } => inner.flush(),
            ArmorIs::_Disabled { inner } => inner.flush(),
        }
    }
}


/// The various errors that can be returned while parsing the armored format.
#[derive(Debug)]
pub enum ArmoredReadError {
    /// An error occurred while parsing Base64.
    Base64(base64::DecodeSliceError),
    /// The begin marker for the armor is invalid.
    InvalidBeginMarker,
    /// Invalid UTF-8 characters were encountered between the begin and end marker.
    InvalidUtf8,
    /// A line of the armor contains a `\r` character.
    LineContainsCr,
    /// The final Base64 line is non-canonical.
    MissingPadding,
    /// The armor is not wrapped at 64 characters.
    NotWrappedAt64Chars,
    /// There is a short line in the middle of the armor (only the final line may be short).
    ShortLineInMiddle,
    /// There are trailing non-whitespace characters after the end marker.
    TrailingGarbage,
}

impl fmt::Display for ArmoredReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArmoredReadError::Base64(e) => e.fmt(f),
            ArmoredReadError::InvalidBeginMarker => write!(f, "invalid armor begin marker"),
            ArmoredReadError::InvalidUtf8 => write!(f, "stream did not contain valid UTF-8"),
            ArmoredReadError::LineContainsCr => write!(f, "line contains CR"),
            ArmoredReadError::MissingPadding => {
                write!(f, "invalid armor (last line is missing padding)")
            }
            ArmoredReadError::NotWrappedAt64Chars => {
                write!(f, "invalid armor (not wrapped at 64 characters)")
            }
            ArmoredReadError::ShortLineInMiddle => {
                write!(f, "invalid armor (short line in middle of encoding)")
            }
            ArmoredReadError::TrailingGarbage => {
                write!(
                    f,
                    "invalid armor (non-whitespace characters after end marker)"
                )
            }
        }
    }
}

impl error::Error for ArmoredReadError {}

/// The position in the underlying reader corresponding to the start of the data inside
/// the armor.
///
/// To impl Seek for ArmoredReader, we need to know the point in the reader corresponding
/// to the first byte of the armored data. But we can't query the reader for its current
/// position without having a specific constructor for `R: Read + Seek`, which makes the
/// higher-level API more complex. Instead, we count the number of bytes that have been
/// read from the reader:
/// - If armor is enabled, we count starting from after the first line (which is the armor
///   begin marker).
/// - If armor is disabled, we count from the first byte we read.
///
/// Then when we first need to seek, inside `impl Seek` we can query the reader's current
/// position and figure out where the start was.
#[derive(Debug)]
enum StartPos {
    /// An offset that we can subtract from the current position.
    Implicit(u64),
    /// The precise start position.
    Explicit(u64),
}

/// Reader that will parse the age ASCII armor format if detected.
///
/// # Examples
///
/// ```
/// use std::io::Read;
/// # use std::io::Write;
/// use std::iter;
///
/// # fn run_main() -> Result<(), ()> {
/// # fn encrypt(recipient: age::x25519::Recipient, plaintext: &[u8]) -> Result<Vec<u8>, age::EncryptError> {
/// # let encrypted = {
/// #     let encryptor = age::Encryptor::with_recipients(vec![Box::new(recipient)])
/// #         .expect("we provided a recipient");
/// #     let mut encrypted = vec![];
/// #     let mut writer = encryptor.wrap_output(
/// #         age::armor::ArmoredWriter::wrap_output(
/// #             &mut encrypted,
/// #             age::armor::Format::AsciiArmor,
/// #         )?
/// #     )?;
/// #     writer.write_all(plaintext)?;
/// #     writer.finish()
/// #         .and_then(|armor| armor.finish())?;
/// #     encrypted
/// # };
/// # Ok(encrypted)
/// # }
/// # let load_identity = || Ok(age::x25519::Identity::generate());
/// let identity = load_identity()?;
/// # let plaintext = b"Hello world!";
/// # let load_encrypted_file = || encrypt(identity.to_public(), &plaintext[..]).map_err(|_| ());
/// let encrypted = load_encrypted_file()?;
///
/// # fn decrypt(identity: age::x25519::Identity, encrypted: Vec<u8>) -> Result<Vec<u8>, age::DecryptError> {
/// let decrypted = {
///     let decryptor = match age::Decryptor::new(
///         age::armor::ArmoredReader::new(&encrypted[..])
///     )? {
///         age::Decryptor::Recipients(d) => d,
///         _ => unreachable!(),
///     };
///
///     let mut decrypted = vec![];
///     let mut reader = decryptor.decrypt(iter::once(&identity as &dyn age::Identity))?;
///     reader.read_to_end(&mut decrypted);
///
///     decrypted
/// };
/// # Ok(decrypted)
/// # }
/// # let decrypted = decrypt(identity, encrypted).map_err(|_| ())?;
/// # assert_eq!(decrypted, plaintext);
/// # Ok(())
/// # }
/// # run_main().unwrap();
/// ```

pub struct ArmoredReader<R> {
    inner: R,
    start: StartPos,
    is_armored: Option<bool>,
    line_buf: Zeroizing<String>,
    byte_buf: Zeroizing<[u8; ARMORED_BYTES_PER_LINE]>,
    byte_start: usize,
    byte_end: usize,
    found_short_line: bool,
    found_end: bool,
    data_len: Option<u64>,
    data_read: usize,
}

impl<R: Read> ArmoredReader<BufReader<R>> {
    /// Wraps a reader that may contain an armored age file.
    pub fn new(reader: R) -> Self {
        ArmoredReader::with_buffered(BufReader::new(reader))
    }
}

impl<R> ArmoredReader<R> {
    fn with_buffered(inner: R) -> Self {
        ArmoredReader {
            inner,
            start: StartPos::Implicit(0),
            is_armored: None,
            line_buf: Zeroizing::new(String::with_capacity(ARMORED_COLUMNS_PER_LINE + 2)),
            byte_buf: Zeroizing::new([0; ARMORED_BYTES_PER_LINE]),
            byte_start: ARMORED_BYTES_PER_LINE,
            byte_end: ARMORED_BYTES_PER_LINE,
            found_short_line: false,
            found_end: false,
            data_len: None,
            data_read: 0,
        }
    }

    fn count_reader_bytes(&mut self, read: usize) -> usize {
        // We only need to count if we haven't yet worked out the start position.
        if let StartPos::Implicit(offset) = &mut self.start {
            *offset += read as u64;
        }

        // Return the counted bytes for convenience.
        read
    }

    /// Detects whether this is an armored age file.
    ///
    /// We only use ArmoredReader to read age files, so we can rely on the following
    /// properties:
    ///
    /// - The first line of an armored age file is 35-36 bytes, depending on whether CRLF
    ///   or LF is used.
    /// - A non-armored age file with a v1 header will be a minimum of 70 bytes (22-byte
    ///   version line, 48-byte MAC line).
    /// - A non-armored age file with an unknown header version will be a minimum of 21
    ///   bytes (for a one-character version). However, assuming that age continues to
    ///   target at least the 128-bit security level, any future header version must
    ///   contain at least 16 more bytes, for a total minimum of 37 bytes.
    ///
    /// We therefore read exactly 36 bytes from the underlying reader, and parse it within
    /// the internal buffer to determine whether this is an armored age file.
    fn detect_armor(&mut self) -> io::Result<()> {
        if self.is_armored.is_some() {
            panic!("ArmoredReader::detect_armor() called twice");
        }

        const MARKER_LEN: usize = MIN_ARMOR_LEN - 2;

        // The first line of armor is the armor marker followed by either
        // CRLF or LF.
        let is_armored = &self.byte_buf[..MARKER_LEN] == ARMORED_BEGIN_MARKER.as_bytes();
        if is_armored {
            match (
                &self.byte_buf[MARKER_LEN..=MARKER_LEN],
                &self.byte_buf[MARKER_LEN..MIN_ARMOR_LEN],
            ) {
                (b"\n", _) => {
                    // We read one extra byte. If this is a valid armored file, that byte
                    // is valid UTF-8, so we can move it into the line buffer.
                    self.line_buf.push_str(
                        std::str::from_utf8(&self.byte_buf[MARKER_LEN + 1..MIN_ARMOR_LEN])
                            .map_err(|_| {
                                io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    ArmoredReadError::InvalidUtf8,
                                )
                            })?,
                    );
                    self.count_reader_bytes(1);
                }
                (_, b"\r\n") => (),
                (_, _) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        ArmoredReadError::InvalidBeginMarker,
                    ))
                }
            }
        } else {
            // Not armored, so the first line is part of the data.
            self.byte_start = 0;
            self.byte_end = MIN_ARMOR_LEN;
            self.count_reader_bytes(MIN_ARMOR_LEN);
        }

        self.is_armored = Some(is_armored);
        Ok(())
    }

    /// Validates `self.line_buf` and parses it into `self.byte_buf`.
    ///
    /// Returns `true` if this was the last line.
    fn parse_armor_line(&mut self) -> io::Result<bool> {
        // Handle line endings
        let line = if self.line_buf.ends_with("\r\n") {
            // trim_end_matches will trim the pattern repeatedly, but because
            // BufRead::read_line splits on line endings, this will never occur.
            self.line_buf.trim_end_matches("\r\n")
        } else if self.line_buf.ends_with('\n') {
            self.line_buf.trim_end_matches('\n')
        } else {
            // If the line does not end in a `\n`, then it must be the final line in the
            // file, because we parse the file into lines by splitting on `\n`. This will
            // either be an invalid line (and be caught as a different error), or the end
            // marker (which we allow to omit a trailing `\n`).
            &self.line_buf
        };
        if line.contains('\r') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                ArmoredReadError::LineContainsCr,
            ));
        }

        // Enforce canonical armor format
        if line == ARMORED_END_MARKER {
            // This line is the EOF marker; we are done!
            self.found_end = true;
            return Ok(true);
        } else {
            match (self.found_short_line, line.len()) {
                (false, ARMORED_COLUMNS_PER_LINE) => (),
                (false, n) if n % 4 != 0 => {
                    // The `base64` crate does not (yet) support canonical decoding.
                    // Handle this ourselves until the upstream issue is closed:
                    // https://github.com/marshallpierce/rust-base64/issues/182
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        ArmoredReadError::MissingPadding,
                    ));
                }
                (false, n) if n < ARMORED_COLUMNS_PER_LINE => {
                    // The format may contain a single short line at the end.
                    self.found_short_line = true;
                }
                (true, ARMORED_COLUMNS_PER_LINE) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        ArmoredReadError::ShortLineInMiddle,
                    ));
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        ArmoredReadError::NotWrappedAt64Chars,
                    ));
                }
            }
        }

        // Decode the line
        self.byte_start = 0;
        self.byte_end = BASE64_STANDARD
            .decode_slice(line.as_bytes(), self.byte_buf.as_mut())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, ArmoredReadError::Base64(e)))?;

        // Finished with this buffered line!
        self.line_buf.clear();

        // We haven't found the end yet
        Ok(false)
    }
}

impl<R: BufRead> BufRead for ArmoredReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        loop {
            match self.is_armored {
                None => {
                    self.inner.read_exact(&mut self.byte_buf[..MIN_ARMOR_LEN])?;
                    self.detect_armor()?
                }
                Some(false) => {
                    break if self.byte_start >= self.byte_end {
                        self.inner.read(&mut self.byte_buf[..]).map(|read| {
                            self.byte_start = 0;
                            self.byte_end = read;
                            self.count_reader_bytes(read);
                            &self.byte_buf[..read]
                        })
                    } else {
                        Ok(&self.byte_buf[self.byte_start..self.byte_end])
                    }
                }
                Some(true) => {
                    break if self.found_end {
                        Ok(&[])
                    } else if self.byte_start >= self.byte_end {
                        if self.read_next_armor_line()? {
                            Ok(&[])
                        } else {
                            Ok(&self.byte_buf[self.byte_start..self.byte_end])
                        }
                    } else {
                        Ok(&self.byte_buf[self.byte_start..self.byte_end])
                    }
                }
            }
        }
    }

    fn consume(&mut self, amt: usize) {
        self.byte_start += amt;
        self.data_read += amt;
        assert!(self.byte_start <= self.byte_end);
    }
}

impl<R: BufRead> ArmoredReader<R> {
    /// Fills `self.byte_buf` with the next line of armored data.
    ///
    /// Returns `true` if this was the last line.
    fn read_next_armor_line(&mut self) -> io::Result<bool> {
        assert_eq!(self.is_armored, Some(true));

        // Read the next line
        self.inner
            .read_line(&mut self.line_buf)
            .map(|read| self.count_reader_bytes(read))?;

        // Parse the line into bytes
        if self.parse_armor_line()? {
            // This was the last line! Check for trailing garbage.
            loop {
                let amt = match self.inner.fill_buf()? {
                    &[] => break,
                    buf => {
                        if buf.iter().any(|b| !b.is_ascii_whitespace()) {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                ArmoredReadError::TrailingGarbage,
                            ));
                        }
                        buf.len()
                    }
                };
                self.inner.consume(amt);
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

impl<R: BufRead> Read for ArmoredReader<R> {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        let buf_len = buf.len();

        while !buf.is_empty() {
            match self.fill_buf()? {
                [] => break,
                next => {
                    let read = cmp::min(next.len(), buf.len());

                    if next.len() < buf.len() {
                        buf[..read].copy_from_slice(next);
                    } else {
                        buf.copy_from_slice(&next[..read]);
                    }

                    self.consume(read);
                    buf = &mut buf[read..];
                }
            }
        }

        Ok(buf_len - buf.len())
    }
}


impl<R: Read + Seek> ArmoredReader<R> {
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
}

impl<R: BufRead + Seek> Seek for ArmoredReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        loop {
            match self.is_armored {
                None => {
                    self.inner.read_exact(&mut self.byte_buf[..MIN_ARMOR_LEN])?;
                    self.detect_armor()?
                }
                Some(armored) => {
                    // Convert the offset into the target position within the data inside
                    // the (maybe) armor.
                    let start = self.start()?;
                    let target_pos = match pos {
                        SeekFrom::Start(offset) => offset,
                        SeekFrom::Current(offset) => {
                            let res = (self.data_read as i64) + offset;
                            if res >= 0_i64 {
                                res as u64
                            } else {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "cannot seek before the start",
                                ));
                            }
                        }
                        SeekFrom::End(offset) => {
                            let data_len = match self.data_len {
                                Some(n) => n,
                                None => {
                                    // Read from the source until we find the end.
                                    let mut buf = [0; 4096];
                                    while self.read(&mut buf)? > 0 {}
                                    let data_len = self.data_read as u64;

                                    // Cache the data length for future calls.
                                    self.data_len = Some(data_len);

                                    data_len
                                }
                            };

                            let res = (data_len as i64) + offset;
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

                    if !armored {
                        // We can seek directly on the inner reader.
                        self.inner.seek(SeekFrom::Start(start + target_pos))?;
                        self.byte_start = 0;
                        self.byte_end = 0;
                        self.data_read = target_pos as usize;
                        break Ok(self.data_read as u64);
                    }

                    // Jump back to the start of the armor data, and then read and drop
                    // until we reach the target position. This is very inefficient, but
                    // as armored files can have arbitrary line endings within the file,
                    // we can't determine where the armor line containing the target
                    // position begins within the reader.
                    self.inner.seek(SeekFrom::Start(start))?;
                    self.line_buf.clear();
                    self.byte_start = ARMORED_BYTES_PER_LINE;
                    self.byte_end = ARMORED_BYTES_PER_LINE;
                    self.found_short_line = false;
                    self.found_end = false;
                    self.data_read = 0;

                    let mut buf = [0; 4096];
                    let mut to_read = target_pos as usize;
                    while to_read > buf.len() {
                        self.read_exact(&mut buf)?;
                        to_read -= buf.len();
                    }
                    if to_read > 0 {
                        self.read_exact(&mut buf[..to_read])?;
                    }

                    // All done!
                    break Ok(target_pos);
                }
            }
        }
    }
}
