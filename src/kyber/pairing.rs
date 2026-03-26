//! Pairing interface for cryptographic suites
//! 
//! This module provides the interface for bilinear pairing operations.
//! It follows the same structure as the Go kyber pairing package.

pub mod bn254;

/// Re-export the BN254 suite for easy access
pub use bn254::BN254Suite;

/// Create a new BN254 pairing suite
/// This matches the Go bn254.NewSuite() function
pub fn new_suite() -> BN254Suite {
    BN254Suite::new()
}

/// Create a new BN254 G1 suite
/// This matches the Go bn254.NewSuiteG1() function
pub fn new_suite_g1() -> BN254Suite {
    BN254Suite::new_suite_g1()
}

/// Create a new BN254 G2 suite
/// This matches the Go bn254.NewSuiteG2() function
pub fn new_suite_g2() -> BN254Suite {
    BN254Suite::new_suite_g2()
}

/// Create a new BN254 GT suite
/// This matches the Go bn254.NewSuiteGT() function
pub fn new_suite_gt() -> BN254Suite {
    BN254Suite::new_suite_gt()
} 