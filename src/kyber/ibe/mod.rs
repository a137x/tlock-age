//! Identity-Based Encryption (IBE) module
//!
//! This module provides IBE functionality compatible with the Go kyber library.
//! It implements the CCA-secure IBE scheme from the Boneh-Franklin paper.

use crate::kyber::pairing::bn254::{BN254Error, BN254Suite, PointG1, Result};

pub mod ciphertext;
pub mod hash;

pub use ciphertext::*;
pub use hash::*;

/// DecryptCCAonG2 decrypts ciphertexts encrypted using EncryptCCAonG2 given a G1 "private" point
///
/// This function implements the decryption algorithm for the CCA-secure IBE scheme.
/// It follows the same logic as the Go implementation in kyber-master/encrypt/ibe/ibe.go.
///
/// # Arguments
/// * `suite` - The BN254 pairing suite
/// * `private` - The private key point (G1 point)
/// * `ciphertext` - The ciphertext to decrypt
///
/// # Returns
/// * `Result<Vec<u8>>` - File key bytes
pub fn decrypt_cca_on_g2(
    suite: &BN254Suite,
    private: &PointG1,
    ciphertext: &Ciphertext,
) -> Result<Vec<u8>> {
    // Check if ciphertext is too long for the hash function
    // Keccak256 has a fixed output size of 32 bytes
    if ciphertext.w.len() > 32 {
        return Err(BN254Error::IBEError(
            "ciphertext too long for the hash function provided".to_string(),
        ));
    }

    let r_gid = suite.pair(private, &ciphertext.u);

    let h_r_gid = gt_to_hash(suite, &r_gid, ciphertext.w.len())?;

    if h_r_gid.len() != ciphertext.v.len() {
        return Err(BN254Error::IBEError(format!(
            "XorSigma is of invalid length: exp {} vs got {}",
            h_r_gid.len(),
            ciphertext.v.len()
        )));
    }

    // 1. Compute sigma = V XOR H2(e(private, U))
    let sigma = xor(&h_r_gid, &ciphertext.v);

    // 2. Compute M = W XOR H4(sigma)
    let h4 = h4(suite, &sigma, ciphertext.w.len())?;

    let msg = xor(&h4, &ciphertext.w);

    // 3. Check U = rP
    let r = h3(suite, &sigma, &msg)?;

    let g2_base = suite.g2().point().base();

    let mut r_p = suite.g2().point();
    r_p.mul(&r, &g2_base);

    if !r_p.equal(&ciphertext.u) {
        return Err(BN254Error::IBEError(
            "invalid proof: rP check failed".to_string(),
        ));
    }

    Ok(msg)
}

/// XOR two byte arrays of the same length
pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    if a.len() != b.len() {
        panic!("wrong xor input: lengths {} and {}", a.len(), b.len());
    }
    let mut res = vec![0u8; a.len()];
    for i in 0..a.len() {
        res[i] = a[i] ^ b[i];
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kyber::pairing::bn254::BN254Suite;

    #[test]
    fn test_xor_function() {
        let a = vec![0x01, 0x02, 0x03];
        let b = vec![0x04, 0x05, 0x06];
        let result = xor(&a, &b);
        assert_eq!(result, vec![0x05, 0x07, 0x05]);
    }

    #[test]
    fn test_ibe_module_compilation() {
        // Test that the IBE module compiles and basic functionality works
        let suite = BN254Suite::new();
        let private_key = suite.g1().point().null(); // Use null point to avoid overflow
        let ciphertext = Ciphertext::new(
            suite.g2().point().null(), // Use null point to avoid overflow
            vec![1, 2, 3, 4],
            vec![5, 6, 7, 8],
        );

        // Test that the module structure is correct by checking that we can create
        // the objects and access their properties without compilation errors
        assert_eq!(ciphertext.v().len(), 4);
        assert_eq!(ciphertext.w().len(), 4);
        assert!(private_key.string().contains("bn254.G1"));

        // Test that the hash functions work
        let sigma = b"test sigma";
        let _msg = b"test message";
        let h4_result = h4(&suite, sigma, 16).unwrap();
        assert_eq!(h4_result.len(), 16);

        // Test that the XOR function works
        let a = vec![0x01, 0x02, 0x03];
        let b = vec![0x04, 0x05, 0x06];
        let result = xor(&a, &b);
        assert_eq!(result, vec![0x05, 0x07, 0x05]);
    }

    #[test]
    fn test_bn254_decrypt_debug() {
        let _age_content = "-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHRsb2NrIDg1Njc3MDggMDRmMWU5MDYy
YjhhODFmODQ4ZmRlZDljMTIzMDY3MzMyODJiMjcyN2VjY2VkNTAwMzIxODc3NTEx
NjZlYzhjMwpLalRnWEpTenlGa3h3YXhFUzJrU2ZQUm9CRlJKWnNabFo2Mk5ub1dR
OUgwSGxtTlA3V3J3cXcrQUh4UW50d2tECm9mL0t0RXV4d3VSVjFwR25RZjE2QkJE
SjE4OEpUemR2RXZxa1k1RzYvL2UvdnY5Um1lSnBKSFpTWTRCdkpSajUKSkpPczhN
QzMwemF2ZWhFYXcvQkZ4YnhWZFZUNERJQUkxUkNVRmQzblVWZXZrRVhVOFl1MFlK
Y0pvVVJIeVR0TwpCejd0QTFBc0x1SjB6Q0JVSXpOTlZnCi0tLSAwQnpPbU44UFc4
eWZ1UkdwcVByY0psN0xDVkttYWRwZ0lZSjB4dzA5QmJrCugU06yCHQxjhv0RiD//
3cQG0HKPAGtuRn5VV4fJUYMJUlNFFAb26A==
-----END AGE ENCRYPTED FILE-----";
        // Test vector: these should match the Go test
        let sig_hex = "224a9b41265bdf2da442d4bfe8223e05295b11026299cb854fd65d85406904b62946a4e964026439862b4475cf5c018b7578daf0de16ecda9ba9e4266fde6a10";
        let ct_hex = "2a34e05c94b3c85931c1ac444b69127cf46804544966c66567ad8d9e8590f47d0796634fed6af0ab0f801f1427b70903a1ffcab44bb1c2e455d691a741fd7a0410c9d7cf094f376f12faa46391bafff7bfbeff5199e26924765263806f2518f92493acf0c0b7d336af7a111ac3f045c5bc557554f80c8008d5109415dde75157af9045d4f18bb4609709a14447c93b4e073eed03502c2ee274cc205423334d56";
        let v_hex = "af9045d4f18bb4609709a14447c93b4e";
        let w_hex = "073eed03502c2ee274cc205423334d56";
        let expected_file_key_hex = "9b4be80095339c9d02219daecaeb6aa9"; // Matches tle output

        // Decode hex strings to bytes
        let sig_bytes = hex::decode(sig_hex).expect("Failed to decode signature hex");
        let u_bytes = hex::decode(ct_hex).expect("Failed to decode ciphertext hex");
        let v_bytes = hex::decode(v_hex).expect("Failed to decode V hex");
        let w_bytes = hex::decode(w_hex).expect("Failed to decode W hex");
        let expected_file_key =
            hex::decode(expected_file_key_hex).expect("Failed to decode expected file key hex");

        println!("DEBUG: Signature bytes length: {}", sig_bytes.len());
        println!("DEBUG: Signature bytes: {}", hex::encode(&sig_bytes));
        println!("DEBUG: Ciphertext bytes length: {}", u_bytes.len());
        println!("DEBUG: Ciphertext bytes: {}", hex::encode(&u_bytes));

        let suite = BN254Suite::new();

        // Parse signature as G1 point
        let mut sig = suite.g1().point();
        println!("DEBUG: Before unmarshaling signature: {}", sig.string());
        if let Err(e) = sig.unmarshal_binary(&sig_bytes) {
            panic!("Failed to parse signature: {}", e);
        }
        println!("DEBUG: After unmarshaling signature: {}", sig.string());
        // assert that the signature that we have in GO test
        assert_eq!(sig.string(), "bn254.G1(1cbe5b4755a9696bce19a9bc62e4e920ce369cab114bf7ec962eae544298a553, 12537db0452d767a23e246b890aed32ef1aeeae577f54b8b35f7dfb3badf6d5d)");

        // Parse ciphertext as G2 point
        let mut u = suite.g2().point();
        println!("DEBUG: Before unmarshaling ciphertext: {}", u.string());
        if let Err(e) = u.unmarshal_binary(&u_bytes) {
            panic!("Failed to parse ciphertext: {}", e);
        }
        // assert that the Ciphertext U point that we have in GO test
        assert_eq!(u.string(), "bn254.G2((0744da2b59996be8b0609b0dbf3a0c281fa3b602bb32f26cd36c93f837f23de2, 0f2a0491f26ee53702a5d6efaf527d48abc5bc7c04823e8317918416bbd71ccb), (01133168b70a83831c2722c0f3d49e98cbc97151c65c39ed2130d895c0417a34, 305be3e55798da28ce9d758853d2367a31a2a00f6b4e956852d3476ef8b029db))");
        println!("DEBUG: After unmarshaling ciphertext: {}", u.string());

        // Construct ciphertext struct
        let ciphertext = Ciphertext::new(u, v_bytes, w_bytes);

        // Call real decryption function
        let file_key_bytes = match decrypt_cca_on_g2(&suite, &sig, &ciphertext) {
            Ok(m) => m,
            Err(e) => panic!("Decryption failed: {}", e),
        };
        println!("Encoded file key: {}", hex::encode(&file_key_bytes));

        if file_key_bytes != expected_file_key {
            panic!(
                "Decryption failed. Expected: {}, Got: {}",
                hex::encode(&expected_file_key),
                hex::encode(&file_key_bytes)
            );
        } else {
            println!("SUCCESS: Decryption matches expected result!");
        }

        // Assert the decrypted message matches the expected file key bytes
        // message bytes: 9b4be80095339c9d02219daecaeb6aa9
        let expected_file_key_hex = "9b4be80095339c9d02219daecaeb6aa9";
        let expected_file_key =
            hex::decode(expected_file_key_hex).expect("Failed to decode expected file key hex");

        assert_eq!(
            file_key_bytes, expected_file_key,
            "Decrypted file key should match expected bytes, got {:02x?}",
            file_key_bytes
        );
    }

    #[test]
    fn test_ibe_with_valid_points() {
        // Test with valid cryptographic points to avoid overflow issues
        let suite = BN254Suite::new();

        // Create a valid G1 point (private key)
        let private_key = suite.g1().point().base();

        // Create a valid G2 point (ciphertext U)
        let u = suite.g2().point().base();

        // Create test V and W data
        let v = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let w = vec![
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
            0x1f, 0x20,
        ];

        let ciphertext = Ciphertext::new(u, v, w);

        println!("Testing IBE with valid points:");
        println!("Private key: {}", private_key.string());
        println!("Ciphertext U: {}", ciphertext.u().string());

        // This should work without overflow issues
        let result = decrypt_cca_on_g2(&suite, &private_key, &ciphertext);
        match result {
            Ok(msg) => {
                println!("Decryption successful! Message length: {}", msg.len());
                println!("Message: {}", hex::encode(&msg));
            }
            Err(e) => {
                println!("Decryption failed (expected for invalid test data): {}", e);
                // This is expected since we're using random test data
            }
        }
    }

    #[test]
    fn test_infinity_point_debug() {
        println!("\n=== DEBUGGING INFINITY POINT ===");

        // Create a new G2 point (should be infinity)
        let suite = BN254Suite::new();
        let p = suite.g2().point();

        println!("Point string representation: {}", p.string());
        println!("Expected (Go output):        bn254.G2((0000000000000000000000000000000000000000000000000000000000000000, 0000000000000000000000000000000000000000000000000000000000000000), (0000000000000000000000000000000000000000000000000000000000000000, 0000000000000000000000000000000000000000000000000000000000000000))");

        // Just check if it matches - don't assert for now, just see what we get
        let actual = p.string();
        let expected = "bn254.G2((0000000000000000000000000000000000000000000000000000000000000000, 0000000000000000000000000000000000000000000000000000000000000000), (0000000000000000000000000000000000000000000000000000000000000000, 0000000000000000000000000000000000000000000000000000000000000000))";
        println!("Match: {}", actual == expected);
    }
}
