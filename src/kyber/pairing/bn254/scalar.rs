use crate::kyber::pairing::bn254::constants::{big_from_base10, SCALAR_FIELD};
use crate::kyber::pairing::bn254::BN254Error;
use num_bigint::BigUint;
use num_traits::cast::ToPrimitive;
use std::io::{Read, Write};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scalar {
    value: BigUint,
    field: BigUint,
}

impl Scalar {
    pub fn new() -> Self {
        let field = big_from_base10(SCALAR_FIELD);
        Self {
            value: BigUint::from(0u64),
            field,
        }
    }

    pub fn from_u64(v: u64) -> Self {
        let field = big_from_base10(SCALAR_FIELD);
        Self {
            value: BigUint::from(v) % &field,
            field,
        }
    }

    pub fn from_bigint(v: BigUint) -> Self {
        let field = big_from_base10(SCALAR_FIELD);
        Self {
            value: v % &field,
            field,
        }
    }

    pub fn from_string(s: &str, base: u32) -> Result<Self, BN254Error> {
        let field = big_from_base10(SCALAR_FIELD);
        let value = BigUint::parse_bytes(s.as_bytes(), base)
            .ok_or(BN254Error::InvalidScalar)?;
        Ok(Self {
            value: value % &field,
            field,
        })
    }

    pub fn set(&mut self, other: &Scalar) {
        self.value = other.value.clone();
        self.field = other.field.clone();
    }

    pub fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            field: self.field.clone(),
        }
    }

    pub fn add(&mut self, a: &Scalar, b: &Scalar) {
        self.value = (a.value.clone() + b.value.clone()) % &self.field;
    }

    pub fn sub(&mut self, a: &Scalar, b: &Scalar) {
        let result = if a.value >= b.value {
            a.value.clone() - b.value.clone()
        } else {
            self.field.clone() - (b.value.clone() - a.value.clone())
        };
        self.value = result;
    }

    pub fn neg(&mut self, a: &Scalar) {
        if a.value == BigUint::from(0u64) {
            self.value = BigUint::from(0u64);
        } else {
            self.value = self.field.clone() - a.value.clone();
        }
    }

    pub fn mul(&mut self, a: &Scalar, b: &Scalar) {
        self.value = (a.value.clone() * b.value.clone()) % &self.field;
    }

    pub fn div(&mut self, a: &Scalar, b: &Scalar) {
        let b_inv = b.value.modpow(&(self.field.clone() - BigUint::from(2u64)), &self.field);
        self.value = (a.value.clone() * b_inv) % &self.field;
    }

    pub fn inv(&mut self, a: &Scalar) {
        self.value = a.value.modpow(&(self.field.clone() - BigUint::from(2u64)), &self.field);
    }

    pub fn exp(&mut self, a: &Scalar, e: &BigUint) {
        self.value = a.value.modpow(e, &self.field);
    }

    pub fn sqrt(&mut self, a: &Scalar) -> bool {
        // Since p = 4k+3, then e = f^(k+1) is a root of f.
        let p_plus_1_over_4 = (&self.field + BigUint::from(1u64)) / BigUint::from(4u64);
        self.value = a.value.modpow(&p_plus_1_over_4, &self.field);
        
        // Check if it's actually a square root
        let square = self.value.modpow(&BigUint::from(2u64), &self.field);
        square == a.value
    }

    pub fn pick<R: Read>(&mut self, rand: &mut R) -> Result<(), BN254Error> {
        // Generate a random scalar using the provided random source
        let mut bytes = vec![0u8; 32];
        rand.read_exact(&mut bytes)
            .map_err(|_| BN254Error::ScalarGenerationError)?;
        
        let mut value = BigUint::from_bytes_le(&bytes);
        value = value % &self.field;
        
        // Ensure the value is not zero
        if value == BigUint::from(0u64) {
            return self.pick(rand);
        }
        
        self.value = value;
        Ok(())
    }

    pub fn set_int64(&mut self, v: i64) {
        if v >= 0 {
            self.value = BigUint::from(v as u64) % &self.field;
        } else {
            let abs_v = BigUint::from((-v) as u64);
            self.value = self.field.clone() - (abs_v % &self.field);
        }
    }

    pub fn set_uint64(&mut self, v: u64) {
        self.value = BigUint::from(v) % &self.field;
    }

    pub fn zero(&mut self) {
        self.value = BigUint::from(0u64);
    }

    pub fn one(&mut self) {
        self.value = BigUint::from(1u64);
    }

    pub fn is_zero(&self) -> bool {
        self.value == BigUint::from(0u64)
    }

    pub fn is_one(&self) -> bool {
        self.value == BigUint::from(1u64)
    }

    pub fn equal(&self, other: &Scalar) -> bool {
        self.value == other.value
    }

    pub fn cmp(&self, other: &Scalar) -> std::cmp::Ordering {
        self.value.cmp(&other.value)
    }

    pub fn nonzero(&self) -> bool {
        self.value != BigUint::from(0u64)
    }

    pub fn int64(&self) -> i64 {
        self.value.to_i64().unwrap_or(0)
    }

    pub fn uint64(&self) -> u64 {
        self.value.to_u64().unwrap_or(0)
    }

    pub fn jacobi(&mut self, a: &Scalar) {
        // Compute Jacobi symbol (a/p)
        let mut n = a.value.clone();
        let mut p = self.field.clone();
        let mut result = 1i32;

        while n != BigUint::from(0u64) {
            while &n % BigUint::from(2u64) == BigUint::from(0u64) {
                n = n / BigUint::from(2u64);
                let p_mod_8 = &p % BigUint::from(8u64);
                if p_mod_8 == BigUint::from(3u64) || p_mod_8 == BigUint::from(5u64) {
                    result = -result;
                }
            }

            // Quadratic reciprocity
            if (&n % BigUint::from(4u64) == BigUint::from(3u64)) && 
               (&p % BigUint::from(4u64) == BigUint::from(3u64)) {
                result = -result;
            }

            let temp = n;
            n = p % &temp;
            p = temp;
        }

        if p == BigUint::from(1u64) {
            self.value = BigUint::from(result as u64);
        } else {
            self.value = BigUint::from(0u64);
        }
    }

    pub fn marshal_binary(&self) -> Result<Vec<u8>, BN254Error> {
        let size = self.marshal_size();
        let bytes = self.value.to_bytes_be();
        let mut result = vec![0u8; size];
        
        if bytes.len() > size {
            return Err(BN254Error::InvalidScalar);
        }
        
        let offset = size - bytes.len();
        result[offset..].copy_from_slice(&bytes);
        Ok(result)
    }

    pub fn marshal_binary_big_endian(&self) -> Result<Vec<u8>, BN254Error> {
        let size = self.marshal_size();
        let bytes = self.value.to_bytes_be();
        let mut result = vec![0u8; size];
        
        if bytes.len() > size {
            return Err(BN254Error::InvalidScalar);
        }
        
        let offset = size - bytes.len();
        result[offset..].copy_from_slice(&bytes);
        Ok(result)
    }

    pub fn unmarshal_binary(&mut self, buf: &[u8]) -> Result<(), BN254Error> {
        if buf.len() != self.marshal_size() {
            return Err(BN254Error::InvalidScalar);
        }
        
        self.value = BigUint::from_bytes_be(buf);
        
        if self.value >= self.field {
            return Err(BN254Error::InvalidScalar);
        }
        
        Ok(())
    }

    pub fn unmarshal_binary_big_endian(&mut self, buf: &[u8]) -> Result<(), BN254Error> {
        if buf.len() != self.marshal_size() {
            return Err(BN254Error::InvalidScalar);
        }
        
        self.value = BigUint::from_bytes_be(buf);
        
        if self.value >= self.field {
            return Err(BN254Error::InvalidScalar);
        }
        
        Ok(())
    }

    pub fn marshal_size(&self) -> usize {
        ((self.field.bits() + 7) / 8).try_into().unwrap()
    }

    pub fn marshal_id(&self) -> [u8; 8] {
        [b'm', b'o', b'd', b'.', b'i', b'n', b't', b' ']
    }

    pub fn marshal_to<W: Write>(&self, w: &mut W) -> Result<usize, BN254Error> {
        let data = self.marshal_binary()?;
        w.write_all(&data).map_err(|_| BN254Error::IOError(std::io::Error::new(
            std::io::ErrorKind::Other, "Failed to write scalar"
        )))?;
        Ok(data.len())
    }

    pub fn unmarshal_from<R: Read>(&mut self, r: &mut R) -> Result<usize, BN254Error> {
        let size = self.marshal_size();
        let mut buf = vec![0u8; size];
        r.read_exact(&mut buf).map_err(|_| BN254Error::IOError(std::io::Error::new(
            std::io::ErrorKind::Other, "Failed to read scalar"
        )))?;
        self.unmarshal_binary(&buf)?;
        Ok(size)
    }

    pub fn string(&self) -> String {
        format!("{:x}", self.value)
    }

    pub fn field(&self) -> &BigUint {
        &self.field
    }

    pub fn value(&self) -> &BigUint {
        &self.value
    }
}

impl fmt::Display for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.string())
    }
}

impl Default for Scalar {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_scalar_creation() {
        let scalar = Scalar::new();
        assert!(scalar.is_zero());
        assert_eq!(scalar.marshal_size(), 32);
    }

    #[test]
    fn test_scalar_from_u64() {
        let scalar = Scalar::from_u64(42);
        assert_eq!(scalar.uint64(), 42);
    }

    #[test]
    fn test_scalar_arithmetic() {
        let a = Scalar::from_u64(10);
        let b = Scalar::from_u64(5);
        let mut result = Scalar::new();

        // Test addition
        result.add(&a, &b);
        assert_eq!(result.uint64(), 15);

        // Test subtraction
        result.sub(&a, &b);
        assert_eq!(result.uint64(), 5);

        // Test multiplication
        result.mul(&a, &b);
        assert_eq!(result.uint64(), 50);

        // Test division
        result.div(&a, &b);
        assert_eq!(result.uint64(), 2);
    }

    #[test]
    fn test_scalar_marshaling() {
        let scalar = Scalar::from_u64(12345);
        let marshaled = scalar.marshal_binary().unwrap();
        let mut unmarshaled = Scalar::new();
        unmarshaled.unmarshal_binary(&marshaled).unwrap();
        assert!(scalar.equal(&unmarshaled));
    }

    #[test]
    fn test_scalar_random_generation() {
        let mut rand = Cursor::new(vec![1u8; 32]);
        let mut scalar = Scalar::new();
        scalar.pick(&mut rand).unwrap();
        assert!(scalar.nonzero());
    }

    #[test]
    fn test_scalar_sqrt() {
        let scalar = Scalar::from_u64(16);
        let mut result = Scalar::new();
        let success = result.sqrt(&scalar);
        assert!(success);
        assert_eq!(result.uint64(), 4);
    }
} 