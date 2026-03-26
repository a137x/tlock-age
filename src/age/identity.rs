use std::fs::File;
use std::io;

use crate::{age::x25519, age::Callbacks, age::DecryptError};

/// The supported kinds of identities within an [`IdentityFile`].
#[derive(Clone)]
pub enum IdentityFileEntry {
    /// The standard age identity type.
    Native(x25519::Identity),
}

impl IdentityFileEntry {
    #[allow(unused_variables)]
    pub(crate) fn into_identity(
        self,
        callbacks: impl Callbacks,
    ) -> Result<Box<dyn crate::age::Identity>, DecryptError> {
        match self {
            IdentityFileEntry::Native(i) => Ok(Box::new(i)),
        }
    }
}

/// A list of identities that has been parsed from some input file.
pub struct IdentityFile {
    identities: Vec<IdentityFileEntry>,
}

impl IdentityFile {
    /// Parses one or more identities from a file containing valid UTF-8.
    pub fn from_file(filename: String) -> io::Result<Self> {
        File::open(&filename)
            .map(io::BufReader::new)
            .and_then(|data| IdentityFile::parse_identities(Some(filename), data))
    }

    /// Parses one or more identities from a buffered input containing valid UTF-8.
    pub fn from_buffer<R: io::BufRead>(data: R) -> io::Result<Self> {
        Self::parse_identities(None, data)
    }

    fn parse_identities<R: io::BufRead>(filename: Option<String>, data: R) -> io::Result<Self> {
        let mut identities = vec![];

        for (line_number, line) in data.lines().enumerate() {
            let line = line?;
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Ok(identity) = line.parse::<x25519::Identity>() {
                identities.push(IdentityFileEntry::Native(identity));
            } else if let Some(identity) = {
                None
            } {
                let _: () = identity;
            } else {
                // Return a line number in place of the line, so we don't leak the file
                // contents in error messages.
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    if let Some(filename) = filename {
                        format!(
                            "identity file {} contains non-identity data on line {}",
                            filename,
                            line_number + 1
                        )
                    } else {
                        format!(
                            "identity file contains non-identity data on line {}",
                            line_number + 1
                        )
                    },
                ));
            }
        }

        Ok(IdentityFile { identities })
    }

    /// Returns the identities in this file.
    pub fn into_identities(self) -> Vec<IdentityFileEntry> {
        self.identities
    }
}
