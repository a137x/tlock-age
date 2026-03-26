//! Hash functions for IBE operations
//! 
//! This module implements the hash functions H2, H3, H4, and gt_to_hash
//! used in the IBE encryption and decryption algorithms.

use crate::kyber::pairing::bn254::{
    PointGT, Scalar, BN254Suite, BN254Error, Result
};
use std::io::Write;
use sha3::Digest;
use hex;

/// Domain separation tags for hash functions
/// These match the Go implementation's H2Tag, H3Tag, and H4Tag functions

/// H2Tag returns the domain separation tag for the H2 hash function
pub fn h2_tag() -> &'static [u8] {
    b"IBE-H2"
}

/// H3Tag returns the domain separation tag for the H3 hash function
pub fn h3_tag() -> &'static [u8] {
    b"IBE-H3"
}

/// H4Tag returns the domain separation tag for the H4 hash function
pub fn h4_tag() -> &'static [u8] {
    b"IBE-H4"
}

/// gt_to_hash converts a GT point to a hash value
/// 
/// This function implements the same logic as the Go gtToHash function:
/// ```go
/// func gtToHash(s pairing.Suite, gt kyber.Point, length int) ([]byte, error) {
///     hash := s.Hash()
///     if _, err := hash.Write(H2Tag()); err != nil {
///         return nil, errors.New("err writing dst to gtHash")
///     }
///     if _, err := gt.MarshalTo(hash); err != nil {
///         return nil, errors.New("err marshalling gt to the hash function")
///     }
///     hashResult := hash.Sum(nil)
///     hashReader := bytes.NewReader(hashResult)
///     var b = make([]byte, length)
///     if _, err := hashReader.Read(b); err != nil {
///         return nil, errors.New("couldn't read from hash output")
///     }
///     return b[:], nil
/// }
/// ```
pub fn gt_to_hash(suite: &BN254Suite, gt: &PointGT, length: usize) -> Result<Vec<u8>> {
    let mut hash = suite.hash();
    
    // Write H2 tag
    hash.write_all(h2_tag())
        .map_err(|e| BN254Error::IBEError(format!("err writing dst to gtHash: {}", e)))?;
    
    // Marshal GT point to hash
    gt.marshal_to(&mut hash)
        .map_err(|e| BN254Error::IBEError(format!("err marshalling gt to the hash function: {}", e)))?;
    
    // Get hash result
    let hash_result = hash.finalize();
    
    // Truncate to requested length
    if hash_result.len() < length {
        return Err(BN254Error::IBEError(format!(
            "hash output too short: got {} bytes, need {} bytes",
            hash_result.len(),
            length
        )));
    }
    
    Ok(hash_result[..length].to_vec())
}

/// h3 generates a scalar from sigma and message using rejection sampling
/// 
/// This function implements the same logic as the Go h3 function:
/// ```go
/// func h3(s pairing.Suite, sigma, msg []byte) (kyber.Scalar, error) {
///     h := s.Hash()
///     if _, err := h.Write(H3Tag()); err != nil {
///         return nil, fmt.Errorf("err hashing h3 tag: %v", err)
///     }
///     if _, err := h.Write(sigma); err != nil {
///         return nil, fmt.Errorf("err hashing sigma: %v", err)
///     }
///     _, _ = h.Write(msg)
///     buffer := h.Sum(nil)
///     
///     hashable, ok := s.G1().Scalar().(*mod.Int)
///     if !ok {
///         return nil, fmt.Errorf("unable to instantiate scalar as a mod.Int")
///     }
///     canonicalBitLen := hashable.MarshalSize() * 8
///     actualBitLen := hashable.M.BitLen()
///     toMask := canonicalBitLen - actualBitLen
///     
///     for i := uint16(1); i < 65535; i++ {
///         h.Reset()
///         iter := make([]byte, 2)
///         binary.LittleEndian.PutUint16(iter, i)
///         _, _ = h.Write(iter)
///         _, _ = h.Write(buffer)
///         hashed := h.Sum(nil)
///         
///         if hashable.BO == mod.BigEndian {
///             hashed[0] = hashed[0] >> toMask
///         } else {
///             hashed[len(hashed)-1] = hashed[len(hashed)-1] >> toMask
///         }
///         
///         if err := hashable.UnmarshalBinary(hashed); err == nil {
///             return hashable, nil
///         }
///     }
///     return nil, fmt.Errorf("rejection sampling failure")
/// }
/// ```
pub fn h3(suite: &BN254Suite, sigma: &[u8], msg: &[u8]) -> Result<Scalar> {
    println!("DEBUG: H3 input - sigma: {}, msg: {}", hex::encode(sigma), hex::encode(msg));
    
    let mut hash = suite.hash();
    
    // Write H3 tag
    hash.write_all(h3_tag())
        .map_err(|e| BN254Error::IBEError(format!("err hashing h3 tag: {}", e)))?;
    
    // Write sigma
    hash.write_all(sigma)
        .map_err(|e| BN254Error::IBEError(format!("err hashing sigma: {}", e)))?;
    
    // Write message
    hash.write_all(msg)
        .map_err(|e| BN254Error::IBEError(format!("err hashing msg: {}", e)))?;
    
    // Get initial hash
    let buffer = hash.finalize();
    println!("DEBUG: H3 initial hash: {}", hex::encode(&buffer));
    
    // Get scalar for rejection sampling
    let mut scalar = suite.scalar();
    let scalar_size = scalar.marshal_size();
    let canonical_bit_len = scalar_size * 8;
    let actual_bit_len = scalar.field().bits() as usize;
    let to_mask = canonical_bit_len.saturating_sub(actual_bit_len);
    
    println!("DEBUG: H3 masking - canonicalBitLen: {}, actualBitLen: {}, toMask: {}", 
             canonical_bit_len, actual_bit_len, to_mask);
    
    // Try rejection sampling
    for i in 1u16..65535 {
        println!("DEBUG: H3 iteration: {}", i);
        let mut hash = suite.hash();
        // Write iteration counter as little-endian u16 (matches Go binary.LittleEndian.PutUint16)
        hash.write_all(&i.to_le_bytes())
            .map_err(|e| BN254Error::IBEError(format!("err writing iteration: {}", e)))?;
        hash.write_all(&buffer)
            .map_err(|e| BN254Error::IBEError(format!("err writing buffer: {}", e)))?;
        
        let mut hashed = hash.finalize().to_vec();
        
        // Apply masking - BN254 uses BigEndian byte order, so mask the first byte
        if to_mask > 0 && !hashed.is_empty() {
            hashed[0] = hashed[0] >> to_mask;
        }
        
        // Try to unmarshal as scalar
        if scalar.unmarshal_binary(&hashed).is_ok() {
            println!("DEBUG: H3 generated scalar at iteration {}: {}", i, scalar.string());
            println!("DEBUG: H3 scalar bytes: {}", hex::encode(&hashed));
            return Ok(scalar);
        }
    }
    
    Err(BN254Error::IBEError("rejection sampling failure".to_string()))
}

/// h4 generates a hash from sigma with specified length
/// 
/// This function implements the same logic as the Go h4 function:
/// ```go
/// func h4(s pairing.Suite, sigma []byte, length int) ([]byte, error) {
///     h4 := s.Hash()
///     if _, err := h4.Write(H4Tag()); err != nil {
///         return nil, fmt.Errorf("err writing h4tag: %v", err)
///     }
///     if _, err := h4.Write(sigma); err != nil {
///         return nil, fmt.Errorf("err writing sigma to h4: %v", err)
///     }
///     h4sigma := h4.Sum(nil)[:length]
///     return h4sigma, nil
/// }
/// ```
pub fn h4(suite: &BN254Suite, sigma: &[u8], length: usize) -> Result<Vec<u8>> {
    let mut hash = suite.hash();
    
    // Write H4 tag
    hash.write_all(h4_tag())
        .map_err(|e| BN254Error::IBEError(format!("err writing h4tag: {}", e)))?;
    
    // Write sigma
    hash.write_all(sigma)
        .map_err(|e| BN254Error::IBEError(format!("err writing sigma to h4: {}", e)))?;
    
    // Get hash result and truncate
    let hash_result = hash.finalize();
    
    if hash_result.len() < length {
        return Err(BN254Error::IBEError(format!(
            "hash output too short: got {} bytes, need {} bytes",
            hash_result.len(),
            length
        )));
    }
    
    Ok(hash_result[..length].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kyber::pairing::bn254::BN254Suite;

    #[test]
    fn test_hash_tags() {
        assert_eq!(h2_tag(), b"IBE-H2");
        assert_eq!(h3_tag(), b"IBE-H3");
        assert_eq!(h4_tag(), b"IBE-H4");
    }

    #[test]
    fn test_h4_function() {
        let suite = BN254Suite::new();
        let sigma = b"test sigma";
        let length = 16;
        
        let result = h4(&suite, sigma, length).unwrap();
        assert_eq!(result.len(), length);
        
        // Test that same input produces same output
        let result2 = h4(&suite, sigma, length).unwrap();
        assert_eq!(result, result2);
    }

    #[test]
    fn test_h3_function() {
        let suite = BN254Suite::new();
        let sigma = b"test sigma";
        let msg = b"test message";
        
        let result = h3(&suite, sigma, msg).unwrap();
        assert!(!result.is_zero());
        
        // Test that same input produces same output
        let result2 = h3(&suite, sigma, msg).unwrap();
        assert_eq!(result, result2);
    }

    #[test]
    fn test_gt_to_hash() {
        let suite = BN254Suite::new();
        let gt = suite.gt().point().base();
        let length = 32;
        
        let result = gt_to_hash(&suite, &gt, length).unwrap();
        assert_eq!(result.len(), length);
    }
} 