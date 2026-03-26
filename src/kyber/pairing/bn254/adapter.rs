//! BN254 Adapter for kyber.Group interface
//!
//! This module provides an adapter that implements the kyber.Group interface
//! so that BN254 can be used as a common suite for generating key pairs
//! while preserving the properties of the pairing (e.g. the Pair function).
//!
//! It's important to note that the Point function will generate a point
//! compatible with public keys only (group G2) where the signature must be
//! used as a point from the group G1.

use crate::kyber::pairing::bn254::{BN254Suite, PointG2, Scalar};

/// Group trait that matches the Go kyber.Group interface
/// This represents a mathematical group usable for Diffie-Hellman key exchange,
/// ElGamal encryption, and related public-key cryptographic algorithms.
pub trait Group {
    /// String returns the name of the group
    fn string(&self) -> String;

    /// ScalarLen returns the maximum length of scalars in bytes
    fn scalar_len(&self) -> usize;

    /// Scalar creates a new scalar
    fn scalar(&self) -> Scalar;

    /// PointLen returns the maximum length of point in bytes
    fn point_len(&self) -> usize;

    /// Point creates a new point
    fn point(&self) -> PointG2;
}

/// SuiteBn254 is an adapter that implements the kyber.Group interface so that
/// BN254 can be used as a common suite to generate key pairs for instance but
/// still preserves the properties of the pairing (e.g. the Pair function).
///
/// It's important to note that the Point function will generate a point
/// compatible with public keys only (group G2) where the signature must be
/// used as a point from the group G1.
pub struct SuiteBn254 {
    suite: BN254Suite,
}

impl SuiteBn254 {
    /// NewSuiteBn254 makes a new BN254 suite adapter
    /// This matches the Go NewSuiteBn254() function
    pub fn new() -> Self {
        Self {
            suite: BN254Suite::new(),
        }
    }

    /// Point generates a point from the G2 group that can only be used
    /// for public keys
    /// This matches the Go Point() kyber.Point function
    pub fn point(&self) -> PointG2 {
        self.suite.g2().point()
    }

    /// PointLen returns the length of a G2 point
    /// This matches the Go PointLen() int function
    pub fn point_len(&self) -> usize {
        self.suite.g2().point_len()
    }

    /// Scalar generates a scalar
    /// This matches the Go Scalar() kyber.Scalar function
    pub fn scalar(&self) -> Scalar {
        self.suite.g1().scalar()
    }

    /// ScalarLen returns the length of a scalar
    /// This matches the Go ScalarLen() int function
    pub fn scalar_len(&self) -> usize {
        self.suite.g1().scalar_len()
    }

    /// String returns the name of the suite
    /// This matches the Go String() string function
    pub fn string(&self) -> String {
        "bn254.adapter".to_string()
    }

    /// Get the underlying suite for pairing operations
    /// This allows access to the full BN254 suite functionality
    pub fn suite(&self) -> &BN254Suite {
        &self.suite
    }

    /// Get a mutable reference to the underlying suite
    pub fn suite_mut(&mut self) -> &mut BN254Suite {
        &mut self.suite
    }
}

// Implement the Group trait for SuiteBn254 to match Go kyber.Group interface
impl Group for SuiteBn254 {
    fn string(&self) -> String {
        self.string()
    }

    fn scalar_len(&self) -> usize {
        self.scalar_len()
    }

    fn scalar(&self) -> Scalar {
        self.scalar()
    }

    fn point_len(&self) -> usize {
        self.point_len()
    }

    fn point(&self) -> PointG2 {
        self.point()
    }
}

impl Default for SuiteBn254 {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SuiteBn254 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.string())
    }
}

impl std::fmt::Debug for SuiteBn254 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SuiteBn254")
            .field("suite", &"BN254Suite")
            .finish()
    }
}

// Convenience function to create a new BN254 suite adapter
/// Create a new BN254 suite adapter
/// This matches the Go NewSuiteBn254() function
pub fn new_suite_bn254() -> SuiteBn254 {
    SuiteBn254::new()
}
