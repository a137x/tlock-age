use crate::kyber::pairing::bn254::curve::CurvePoint;
use crate::kyber::pairing::bn254::twist::TwistPoint;
use crate::kyber::pairing::bn254::gfp12::GFp12;
use crate::kyber::pairing::bn254::optate;

/// Optimal Ate pairing implementation
/// This is the main pairing function that combines Miller loop and final exponentiation
pub fn optimal_ate(a: &TwistPoint, b: &CurvePoint) -> GFp12 {
    optate::optimal_ate(a, b)
}

/// Convenience function for pairing computation
/// This matches the Go implementation's Pair method
pub fn pair(g1_point: &CurvePoint, g2_point: &TwistPoint) -> GFp12 {
    optate::pair(g1_point, g2_point)
}

/// Validate pairing equation
/// This checks if e(p1, p2) == e(inv1, inv2)
pub fn validate_pairing(p1: &CurvePoint, p2: &TwistPoint, inv1: &CurvePoint, inv2: &TwistPoint) -> bool {
    optate::validate_pairing(p1, p2, inv1, inv2)
}

/// Miller loop for calculating the Optimal Ate pairing
/// See algorithm 1 from http://cryptojedi.org/papers/dclxvi-20100714.pdf
pub fn miller(q: &TwistPoint, p: &CurvePoint) -> GFp12 {
    optate::miller(q, p)
}

/// Final exponentiation computes the (p¹²-1)/Order-th power of an element of
/// GF(p¹²) to obtain an element of GT
/// See steps 13-15 of algorithm 1 from http://cryptojedi.org/papers/dclxvi-20100714.pdf
pub fn final_exponentiation(in_val: &GFp12) -> GFp12 {
    optate::final_exponentiation(in_val)
} 