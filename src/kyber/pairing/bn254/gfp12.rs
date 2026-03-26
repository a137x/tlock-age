use crate::kyber::pairing::bn254::gfp6::GFp6;
use crate::kyber::pairing::bn254::gfp2::GFp2;
use crate::kyber::pairing::bn254::constants::{
    XI_TO_P_MINUS_1_OVER_6, XI_TO_P_SQUARED_MINUS_1_OVER_6, XI_TO_P_SQUARED_MINUS_1_OVER_3
};
use crate::kyber::pairing::bn254::gfp::GFp;
use num_bigint::BigUint;

#[derive(Debug, Clone, PartialEq)]
pub struct GFp12 {
    x: GFp6, // coefficient of ω
    y: GFp6, // coefficient of 1
}

impl GFp12 {
    pub fn new() -> Self {
        Self {
            x: GFp6::new(),
            y: GFp6::new(),
        }
    }

    pub fn set(&mut self, a: &GFp12) {
        self.x.set(&a.x);
        self.y.set(&a.y);
    }

    pub fn set_zero(&mut self) {
        self.x.set_zero();
        self.y.set_zero();
    }

    pub fn set_one(&mut self) {
        self.x.set_zero();
        self.y.set_one();
    }

    pub fn is_zero(&self) -> bool {
        self.x.is_zero() && self.y.is_zero()
    }

    pub fn is_one(&self) -> bool {
        self.x.is_zero() && self.y.is_one()
    }

    pub fn conjugate(&mut self, a: &GFp12) {
        self.x.neg(&a.x);
        self.y.set(&a.y);
    }

    pub fn neg(&mut self, a: &GFp12) {
        self.x.neg(&a.x);
        self.y.neg(&a.y);
    }

    // Frobenius computes (xω+y)^p = x^p ω·ξ^((p-1)/6) + y^p
    pub fn frobenius(&mut self, a: &GFp12) {
        self.x.frobenius(&a.x);
        self.y.frobenius(&a.y);
        
        let xi_to_p_minus_1_over_6 = GFp2::from_gfp(
            GFp::from_u64_array(XI_TO_P_MINUS_1_OVER_6[0]),
            GFp::from_u64_array(XI_TO_P_MINUS_1_OVER_6[1])
        );
        let temp_x = self.x.clone();
        self.x.mul_scalar(&temp_x, &xi_to_p_minus_1_over_6);
    }

    // FrobeniusP2 computes (xω+y)^p² = x^p² ω·ξ^((p²-1)/6) + y^p²
    pub fn frobenius_p2(&mut self, a: &GFp12) {
        self.x.frobenius_p2(&a.x);
        let xi_to_p_squared_minus_1_over_6 = GFp::from_u64_array(XI_TO_P_SQUARED_MINUS_1_OVER_6);
        let temp_x = self.x.clone();
        self.x.mul_gfp(&temp_x, &xi_to_p_squared_minus_1_over_6);
        self.y.frobenius_p2(&a.y);
    }

    pub fn frobenius_p4(&mut self, a: &GFp12) {
        self.x.frobenius_p4(&a.x);
        let xi_to_p_squared_minus_1_over_3 = GFp::from_u64_array(XI_TO_P_SQUARED_MINUS_1_OVER_3);
        let temp_x = self.x.clone();
        self.x.mul_gfp(&temp_x, &xi_to_p_squared_minus_1_over_3);
        self.y.frobenius_p4(&a.y);
    }

    pub fn add(&mut self, a: &GFp12, b: &GFp12) {
        self.x.add(&a.x, &b.x);
        self.y.add(&a.y, &b.y);
    }

    pub fn sub(&mut self, a: &GFp12, b: &GFp12) {
        self.x.sub(&a.x, &b.x);
        self.y.sub(&a.y, &b.y);
    }

    pub fn mul(&mut self, a: &GFp12, b: &GFp12) {
        let mut tx = GFp6::new();
        tx.mul(&a.x, &b.y);
        let mut t = GFp6::new();
        t.mul(&b.x, &a.y);
        let temp_tx = tx.clone();
        tx.add(&temp_tx, &t);

        let mut ty = GFp6::new();
        ty.mul(&a.y, &b.y);
        let mut t2 = GFp6::new();
        t2.mul(&a.x, &b.x);
        let temp_t2 = t2.clone();
        t2.mul_tau(&temp_t2);

        self.x.set(&tx);
        self.y.add(&ty, &t2);
    }

    pub fn mul_scalar(&mut self, a: &GFp12, b: &GFp6) {
        // This matches the Go implementation: MulScalar(a *gfP12, b *gfP6) *gfP12
        // The Go version multiplies a.x and a.y by b, storing result in e.x and e.y
        // In Rust, we multiply a.x and a.y by b, storing result in self.x and self.y
        self.x.mul(&a.x, b);
        self.y.mul(&a.y, b);
    }

    pub fn exp(&mut self, a: &GFp12, power: &BigUint) {
        let mut sum = GFp12::new();
        sum.set_one();
        let mut t = GFp12::new();

        for i in (0..power.bits()).rev() {
            t.square(&sum);
            if power.bit(i) {
                sum.mul(&t, a);
            } else {
                sum.set(&t);
            }
        }

        self.set(&sum);
    }

    pub fn square(&mut self, a: &GFp12) {
        // Complex squaring algorithm
        let mut v0 = GFp6::new();
        v0.mul(&a.x, &a.y);

        let mut t = GFp6::new();
        t.mul_tau(&a.x);
        let temp_t = t.clone();
        t.add(&a.y, &temp_t);
        let mut ty = GFp6::new();
        ty.add(&a.x, &a.y);
        let temp_ty = ty.clone();
        ty.mul(&temp_ty, &t);
        let temp_ty = ty.clone();
        ty.sub(&temp_ty, &v0);
        let mut t2 = GFp6::new();
        t2.mul_tau(&v0);
        let temp_ty = ty.clone();
        ty.sub(&temp_ty, &t2);

        self.x.add(&v0, &v0);
        self.y.set(&ty);
    }

    pub fn invert(&mut self, a: &GFp12) {
        // See "Implementing cryptographic pairings", M. Scott, section 3.2.
        // ftp://136.206.11.249/pub/crypto/pairings.pdf
        let mut t1 = GFp6::new();
        let mut t2 = GFp6::new();

        t1.square(&a.x);
        t2.square(&a.y);
        let temp_t1 = t1.clone();
        t1.mul_tau(&temp_t1);
        let temp_t2 = t2.clone();
        t2.sub(&temp_t2, &t1);
        let temp_t2 = t2.clone();
        t2.invert(&temp_t2);

        self.x.neg(&a.x);
        self.y.set(&a.y);
        let temp_self = self.clone();
        self.mul_scalar(&temp_self, &t2);
    }

    pub fn get_x(&self) -> &GFp6 {
        &self.x
    }

    pub fn get_y(&self) -> &GFp6 {
        &self.y
    }

    pub fn get_x_mut(&mut self) -> &mut GFp6 {
        &mut self.x
    }

    pub fn get_y_mut(&mut self) -> &mut GFp6 {
        &mut self.y
    }

    // Clone makes a hard copy of the field
    pub fn clone(&self) -> Self {
        Self {
            x: self.x.clone(),
            y: self.y.clone(),
        }
    }

    // Presentation conversion methods
    // Convert GFp12 to the most basic type: array of u64 values
    // GFp12 = x*ω + y where x,y are GFp6 elements
    // Each GFp6 element has 3 GFp2 elements (x,y,z)
    // Each GFp2 element has 2 GFp elements
    // Each GFp element is represented by 4 u64 values
    // Total: 2 * 3 * 2 * 4 = 48 u64 values
    pub fn to_u64_array(&self) -> [[[[u64; 4]; 2]; 3]; 2] {
        let x_coeffs = self.x.to_u64_array();
        let y_coeffs = self.y.to_u64_array();
        
        [
            x_coeffs, // coefficient of ω
            y_coeffs, // coefficient of 1
        ]
    }

    // Convert from the most basic type (u64 arrays) back to GFp12
    pub fn from_u64_array(arr: [[[[u64; 4]; 2]; 3]; 2]) -> Self {
        let x = GFp6::from_u64_array(arr[0]);
        let y = GFp6::from_u64_array(arr[1]);
        
        Self { x, y }
    }

    // Alternative: Convert to flat u64 array (48 elements)
    pub fn to_flat_u64_array(&self) -> [u64; 48] {
        let nested = self.to_u64_array();
        let mut flat = [0u64; 48];
        
        let mut idx = 0;
        for i in 0..2 {
            for j in 0..3 {
                for k in 0..2 {
                    for l in 0..4 {
                        flat[idx] = nested[i][j][k][l];
                        idx += 1;
                    }
                }
            }
        }
        
        flat
    }

    // Convert from flat u64 array back to GFp12
    pub fn from_flat_u64_array(arr: [u64; 48]) -> Self {
        let mut nested = [[[[0u64; 4]; 2]; 3]; 2];
        
        let mut idx = 0;
        for i in 0..2 {
            for j in 0..3 {
                for k in 0..2 {
                    for l in 0..4 {
                        nested[i][j][k][l] = arr[idx];
                        idx += 1;
                    }
                }
            }
        }
        
        Self::from_u64_array(nested)
    }

    // Convert to bytes representation (384 bytes = 48 * 8)
    pub fn to_bytes(&self) -> [u8; 384] {
        let u64_array = self.to_flat_u64_array();
        let mut bytes = [0u8; 384];
        
        for (i, &value) in u64_array.iter().enumerate() {
            let start = i * 8;
            bytes[start..start + 8].copy_from_slice(&value.to_le_bytes());
        }
        
        bytes
    }

    // Convert from bytes representation back to GFp12
    pub fn from_bytes(bytes: [u8; 384]) -> Self {
        let mut u64_array = [0u64; 48];
        
        for i in 0..48 {
            let start = i * 8;
            let mut value_bytes = [0u8; 8];
            value_bytes.copy_from_slice(&bytes[start..start + 8]);
            u64_array[i] = u64::from_le_bytes(value_bytes);
        }
        
        Self::from_flat_u64_array(u64_array)
    }

    // Convert to hex string representation
    pub fn to_hex_string(&self) -> String {
        let bytes = self.to_bytes();
        hex::encode(bytes)
    }

    // Convert from hex string representation back to GFp12
    pub fn from_hex_string(hex_str: &str) -> Result<Self, String> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| format!("Failed to decode hex string: {}", e))?;
        
        if bytes.len() != 384 {
            return Err(format!("Expected 384 bytes, got {}", bytes.len()));
        }
        
        let mut byte_array = [0u8; 384];
        byte_array.copy_from_slice(&bytes);
        
        Ok(Self::from_bytes(byte_array))
    }
}

impl std::fmt::Display for GFp12 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "({},{})", self.x, self.y)
    }
} 

// Add a simple test to verify the identity element
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_gfp12_identity() {
        let mut ret = GFp12::new();
        ret.set_one();
        println!("DEBUG: GFp12 identity = {}", ret);
        
        // Check what the expected string should be
        let expected = "(((0000000000000000000000000000000000000000000000000000000000000000, 0000000000000000000000000000000000000000000000000000000000000000), (0000000000000000000000000000000000000000000000000000000000000000, 0000000000000000000000000000000000000000000000000000000000000000), (0000000000000000000000000000000000000000000000000000000000000000, 0000000000000000000000000000000000000000000000000000000000000000)),((0000000000000000000000000000000000000000000000000000000000000000, 0000000000000000000000000000000000000000000000000000000000000000), (0000000000000000000000000000000000000000000000000000000000000000, 0000000000000000000000000000000000000000000000000000000000000000), (0000000000000000000000000000000000000000000000000000000000000000, 0000000000000000000000000000000000000000000000000000000000000001)))";
        
        println!("DEBUG: Expected = {}", expected);
        assert_eq!(ret.to_string(), expected, "GFp12 identity should match expected format");
    }

    #[test]
    fn test_presentation_conversion_u64_array() {
        let mut original = GFp12::new();
        original.set_one();
        
        // Convert to u64 array
        let u64_array = original.to_u64_array();
        
        // Convert back from u64 array
        let converted = GFp12::from_u64_array(u64_array);
        
        // Verify they are equal
        assert_eq!(original, converted, "GFp12 should be preserved through u64 array conversion");
    }

    #[test]
    fn test_presentation_conversion_flat_u64_array() {
        let mut original = GFp12::new();
        original.set_one();
        
        // Convert to flat u64 array
        let flat_array = original.to_flat_u64_array();
        
        // Convert back from flat u64 array
        let converted = GFp12::from_flat_u64_array(flat_array);
        
        // Verify they are equal
        assert_eq!(original, converted, "GFp12 should be preserved through flat u64 array conversion");
    }

    #[test]
    fn test_presentation_conversion_bytes() {
        let mut original = GFp12::new();
        original.set_one();
        
        // Convert to bytes
        let bytes = original.to_bytes();
        
        // Convert back from bytes
        let converted = GFp12::from_bytes(bytes);
        
        // Verify they are equal
        assert_eq!(original, converted, "GFp12 should be preserved through bytes conversion");
    }

    #[test]
    fn test_presentation_conversion_hex_string() {
        let mut original = GFp12::new();
        original.set_one();
        
        // Convert to hex string
        let hex_string = original.to_hex_string();
        
        // Convert back from hex string
        let converted = GFp12::from_hex_string(&hex_string).expect("Should decode hex string successfully");
        
        // Verify they are equal
        assert_eq!(original, converted, "GFp12 should be preserved through hex string conversion");
    }

    #[test]
    fn test_presentation_conversion_zero() {
        let mut original = GFp12::new();
        original.set_zero();
        
        // Test all conversion methods
        let u64_array = original.to_u64_array();
        let converted_u64 = GFp12::from_u64_array(u64_array);
        assert_eq!(original, converted_u64, "Zero GFp12 should be preserved through u64 array conversion");
        
        let flat_array = original.to_flat_u64_array();
        let converted_flat = GFp12::from_flat_u64_array(flat_array);
        assert_eq!(original, converted_flat, "Zero GFp12 should be preserved through flat u64 array conversion");
        
        let bytes = original.to_bytes();
        let converted_bytes = GFp12::from_bytes(bytes);
        assert_eq!(original, converted_bytes, "Zero GFp12 should be preserved through bytes conversion");
        
        let hex_string = original.to_hex_string();
        let converted_hex = GFp12::from_hex_string(&hex_string).expect("Should decode hex string successfully");
        assert_eq!(original, converted_hex, "Zero GFp12 should be preserved through hex string conversion");
    }

    #[test]
    fn test_hex_string_error_handling() {
        // Test with invalid hex string
        let result = GFp12::from_hex_string("invalid_hex");
        assert!(result.is_err(), "Should return error for invalid hex string");
        
        // Test with too short hex string
        let result = GFp12::from_hex_string("1234567890abcdef");
        assert!(result.is_err(), "Should return error for too short hex string");
    }

    #[test]
    fn test_conversion_consistency() {
        let mut original = GFp12::new();
        original.set_one();
        
        // Test that all conversion methods produce consistent results
        let u64_array = original.to_u64_array();
        let flat_array = original.to_flat_u64_array();
        let bytes = original.to_bytes();
        let hex_string = original.to_hex_string();
        
        // Convert back using different methods and verify they're all equal
        let converted_u64 = GFp12::from_u64_array(u64_array);
        let converted_flat = GFp12::from_flat_u64_array(flat_array);
        let converted_bytes = GFp12::from_bytes(bytes);
        let converted_hex = GFp12::from_hex_string(&hex_string).expect("Should decode hex string successfully");
        
        assert_eq!(converted_u64, converted_flat, "All conversion methods should produce consistent results");
        assert_eq!(converted_u64, converted_bytes, "All conversion methods should produce consistent results");
        assert_eq!(converted_u64, converted_hex, "All conversion methods should produce consistent results");
    }

    #[test]
    fn example_presentation_conversion_usage() {
        // Example demonstrating how to use the presentation-conversion methods
        
        // Create a GFp12 element (identity element)
        let mut gfp12_element = GFp12::new();
        gfp12_element.set_one();
        
        println!("Original GFp12 element: {}", gfp12_element);
        
        // 1. Convert to nested u64 array (most structured format)
        let nested_u64 = gfp12_element.to_u64_array();
        println!("Nested u64 array structure: [[[[u64; 4]; 2]; 3]; 2]");
        println!("Total u64 values: {}", 2 * 3 * 2 * 4);
        
        // 2. Convert to flat u64 array (easier to work with)
        let flat_u64 = gfp12_element.to_flat_u64_array();
        println!("Flat u64 array length: {}", flat_u64.len());
        
        // 3. Convert to bytes (for network transmission or storage)
        let bytes = gfp12_element.to_bytes();
        println!("Bytes length: {}", bytes.len());
        
        // 4. Convert to hex string (human-readable format)
        let hex_string = gfp12_element.to_hex_string();
        println!("Hex string: {}", hex_string);
        
        // 5. Convert back from each format
        let from_nested = GFp12::from_u64_array(nested_u64);
        let from_flat = GFp12::from_flat_u64_array(flat_u64);
        let from_bytes = GFp12::from_bytes(bytes);
        let from_hex = GFp12::from_hex_string(&hex_string).expect("Valid hex string");
        
        // Verify all conversions preserve the original value
        assert_eq!(gfp12_element, from_nested);
        assert_eq!(gfp12_element, from_flat);
        assert_eq!(gfp12_element, from_bytes);
        assert_eq!(gfp12_element, from_hex);
        
        println!("All conversion methods preserve the original GFp12 element!");
    }
} 