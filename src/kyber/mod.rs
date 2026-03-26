//! Kyber cryptographic library
//! 
//! This module provides cryptographic primitives including pairing-based cryptography.
//! It follows the same structure as the Go kyber library.

pub mod pairing;
pub mod ibe;

// Re-export the pairing module for easy access
pub use pairing::*;
// Re-export the IBE module for easy access
pub use ibe::*; 