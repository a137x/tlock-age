use bech32::{FromBase32, Variant};

pub(crate) const LINE_ENDING: &str = "\n";

pub(crate) fn parse_bech32(s: &str) -> Option<(String, Vec<u8>)> {
    bech32::decode(s).ok().and_then(|(hrp, data, variant)| {
        if let Variant::Bech32 = variant {
            Vec::from_base32(&data).ok().map(|d| (hrp, d))
        } else {
            None
        }
    })
}

pub(crate) mod read {
    use std::str::FromStr;

    use base64::{prelude::BASE64_STANDARD_NO_PAD, Engine};
    use nom::{character::complete::digit1, combinator::verify, ParseTo};

    pub(crate) fn base64_arg<A: AsRef<[u8]>, const N: usize, const B: usize>(
        arg: &A,
    ) -> Option<[u8; N]> {
        if N > B {
            return None;
        }

        let mut buf = [0; B];
        match BASE64_STANDARD_NO_PAD.decode_slice(arg, buf.as_mut()) {
            Ok(n) if n == N => Some(buf[..N].try_into().unwrap()),
            _ => None,
        }
    }

    /// Parses a decimal number composed only of digits with no leading zeros.
    pub(crate) fn decimal_digit_arg<T: FromStr>(arg: &str) -> Option<T> {
        verify::<_, _, _, (), _, _>(digit1, |n: &str| !n.starts_with('0'))(arg)
            .ok()
            .and_then(|(_, n)| n.parse_to())
    }
}

pub(crate) mod write {
    use base64::{prelude::BASE64_STANDARD_NO_PAD, Engine};
    use cookie_factory::{combinator::string, SerializeFn};
    use std::io::Write;

    pub(crate) fn encoded_data<W: Write>(data: &[u8]) -> impl SerializeFn<W> {
        let encoded = BASE64_STANDARD_NO_PAD.encode(data);
        string(encoded)
    }
}
