//! Ciphertext structures for IBE operations
//! 
//! This module defines the ciphertext structures used in IBE encryption and decryption.

use crate::kyber::pairing::bn254::{ PointG2, BN254Error, Result};
use std::fmt;

/// Ciphertext structure for CCA-secure IBE
/// 
/// This matches the Go implementation's Ciphertext struct:
/// ```go
/// type Ciphertext struct {
///     U kyber.Point  // Random point rP
///     V []byte       // Sigma attached to ID: sigma XOR H(rG_id)
///     W []byte       // ciphertext of the message M XOR H(sigma)
/// }
/// ```
#[derive(Debug, Clone)]
pub struct Ciphertext {
    /// Random point rP (G2 point for DecryptCCAonG2)
    pub u: PointG2,
    /// Sigma attached to ID: sigma XOR H(rG_id)
    pub v: Vec<u8>,
    /// Ciphertext of the message M XOR H(sigma)
    pub w: Vec<u8>,
}

impl Ciphertext {
    /// Create a new ciphertext
    pub fn new(u: PointG2, v: Vec<u8>, w: Vec<u8>) -> Self {
        Self { u, v, w }
    }

    /// Get the U component (random point rP)
    pub fn u(&self) -> &PointG2 {
        &self.u
    }

    /// Get the V component (sigma XOR H(rG_id))
    pub fn v(&self) -> &[u8] {
        &self.v
    }

    /// Get the W component (message XOR H(sigma))
    pub fn w(&self) -> &[u8] {
        &self.w
    }

    /// Get mutable reference to U component
    pub fn u_mut(&mut self) -> &mut PointG2 {
        &mut self.u
    }

    /// Get mutable reference to V component
    pub fn v_mut(&mut self) -> &mut Vec<u8> {
        &mut self.v
    }

    /// Get mutable reference to W component
    pub fn w_mut(&mut self) -> &mut Vec<u8> {
        &mut self.w
    }

    /// Serialize the ciphertext to bytes
    pub fn marshal_binary(&self) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        
        // Marshal U point
        let u_bytes = self.u.marshal_binary()
            .map_err(|e| BN254Error::IBEError(e))?;
        result.extend_from_slice(&u_bytes);
        
        // Marshal V length and data
        let v_len = self.v.len() as u32;
        result.extend_from_slice(&v_len.to_le_bytes());
        result.extend_from_slice(&self.v);
        
        // Marshal W length and data
        let w_len = self.w.len() as u32;
        result.extend_from_slice(&w_len.to_le_bytes());
        result.extend_from_slice(&self.w);
        
        Ok(result)
    }

    /// Deserialize the ciphertext from bytes
    pub fn unmarshal_binary(&mut self, data: &[u8]) -> Result<()> {
        if data.len() < 8 {
            return Err(BN254Error::IBEError("insufficient data for ciphertext".to_string()));
        }

        let mut offset = 0;
        
        // Unmarshal U point (assuming 128 bytes for G2 point)
        if data.len() < offset + 128 {
            return Err(BN254Error::IBEError("insufficient data for U point".to_string()));
        }
        self.u.unmarshal_binary(&data[offset..offset + 128])
            .map_err(|e| BN254Error::IBEError(e))?;
        offset += 128;
        
        // Unmarshal V length and data
        if data.len() < offset + 4 {
            return Err(BN254Error::IBEError("insufficient data for V length".to_string()));
        }
        let v_len = u32::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
        ]) as usize;
        offset += 4;
        
        if data.len() < offset + v_len {
            return Err(BN254Error::IBEError("insufficient data for V".to_string()));
        }
        self.v = data[offset..offset + v_len].to_vec();
        offset += v_len;
        
        // Unmarshal W length and data
        if data.len() < offset + 4 {
            return Err(BN254Error::IBEError("insufficient data for W length".to_string()));
        }
        let w_len = u32::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
        ]) as usize;
        offset += 4;
        
        if data.len() < offset + w_len {
            return Err(BN254Error::IBEError("insufficient data for W".to_string()));
        }
        self.w = data[offset..offset + w_len].to_vec();
        
        Ok(())
    }

    /// Get the total size of the ciphertext in bytes
    pub fn size(&self) -> usize {
        128 + 4 + self.v.len() + 4 + self.w.len()
    }
}

impl fmt::Display for Ciphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ciphertext {{ U: {:?}, V: {:?}, W: {:?} }}", 
               self.u, self.v, self.w)
    }
}

impl PartialEq for Ciphertext {
    fn eq(&self, other: &Self) -> bool {
        self.u.equal(&other.u) && self.v == other.v && self.w == other.w
    }
}

impl Eq for Ciphertext {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kyber::pairing::bn254::BN254Suite;

    #[test]
    fn test_ciphertext_creation() {
        let suite = BN254Suite::new();
        let u = suite.g2().point();
        let v = vec![1, 2, 3];
        let w = vec![4, 5, 6];
        
        let ciphertext = Ciphertext::new(u, v.clone(), w.clone());
        
        assert_eq!(ciphertext.v(), &v);
        assert_eq!(ciphertext.w(), &w);
    }

    #[test]
    fn test_ciphertext_marshaling() {
        let suite = BN254Suite::new();
        // Use a null point instead of base() to avoid arithmetic overflow
        let u = suite.g2().point().null();
        let v = vec![1, 2, 3, 4];
        let w = vec![5, 6, 7, 8];
        
        let ciphertext = Ciphertext::new(u, v, w);
        let marshaled = ciphertext.marshal_binary().unwrap();
        
        let mut new_ciphertext = Ciphertext::new(
            suite.g2().point(),
            Vec::new(),
            Vec::new()
        );
        new_ciphertext.unmarshal_binary(&marshaled).unwrap();
        
        assert_eq!(ciphertext, new_ciphertext);
    }
} 