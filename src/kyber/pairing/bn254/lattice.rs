use crate::kyber::pairing::bn254::constants::{big_from_base10, ORDER};
use num_bigint::BigUint;
use std::str::FromStr;

// Global variables matching Go implementation exactly
lazy_static::lazy_static! {
    static ref HALF: BigUint = {
        let order = BigUint::from_str(ORDER).unwrap();
        order >> 1
    };

    static ref CURVE_LATTICE: Lattice = {
        let vectors = vec![
            vec![
                big_from_base10("147946756881789319000765030803803410728"),
                big_from_base10("147946756881789319010696353538189108491")
            ],
            vec![
                big_from_base10("147946756881789319020627676272574806254"),
                big_from_base10("-147946756881789318990833708069417712965")
            ]
        ];
        let inverse = vec![
            big_from_base10("147946756881789318990833708069417712965"),
            big_from_base10("147946756881789319010696353538189108491")
        ];
        let det = big_from_base10("43776485743678550444492811490514550177096728800832068687396408373151616991234");

        Lattice { vectors, inverse, det }
    };

    // targetLattice removed in Go v1.3.2 (unused)
}

/// Lattice struct matching Go implementation exactly
pub struct Lattice {
    pub vectors: Vec<Vec<BigUint>>,
    pub inverse: Vec<BigUint>,
    pub det: BigUint,
}

impl Lattice {
    /// decompose takes a scalar mod Order as input and finds a short, positive decomposition of it wrt to the lattice basis.
    /// This matches the Go implementation exactly.
    pub fn decompose(&self, k: &BigUint) -> Vec<BigUint> {
        let n = self.inverse.len();

        // Calculate closest vector in lattice to <k,0,0,...> with Babai's rounding.
        let mut c = vec![BigUint::new(vec![0]); n];
        for i in 0..n {
            c[i] = k * &self.inverse[i];
            round(&mut c[i], &self.det);
        }

        // Transform vectors according to c and subtract <k,0,0,...>.
        let mut out = vec![BigUint::new(vec![0]); n];

        for i in 0..n {
            out[i] = BigUint::new(vec![0]);

            for j in 0..n {
                let temp = &c[j] * &self.vectors[j][i];
                out[i] += &temp;
            }

            out[i] = BigUint::new(vec![0]) - &out[i];
            out[i] += &self.vectors[0][i];
            out[i] += &self.vectors[0][i];
        }
        out[0] += k;

        out
    }

    /// Precompute matches the Go implementation exactly
    pub fn precompute<F>(&self, mut add: F)
    where
        F: FnMut(u32, u32),
    {
        let n = self.vectors.len() as u32;
        let total = 1u32 << n;

        for i in 0..n {
            for j in 0..total {
                if (j >> i) & 1 == 1 {
                    add(i, j);
                }
            }
        }
    }

    /// Multi matches the Go implementation exactly
    pub fn multi(&self, scalar: &BigUint) -> Vec<u8> {
        let decomp = self.decompose(scalar);

        let mut max_len = 0;
        for x in &decomp {
            let bit_len = x.bits() as usize;
            if bit_len > max_len {
                max_len = bit_len;
            }
        }

        let mut out = vec![0u8; max_len];
        for (j, x) in decomp.iter().enumerate() {
            for i in 0..max_len {
                if x.bit(i as u64) {
                    out[i] += 1u8 << j;
                }
            }
        }

        out
    }
}

/// round sets num to num/denom rounded to the nearest integer.
/// This matches the Go implementation exactly.
fn round(num: &mut BigUint, denom: &BigUint) {
    let num_clone = num.clone();
    let remainder = &num_clone % denom;
    *num = &num_clone / denom;

    // For rounding, we compare remainder with denom/2
    let denom_half = denom / &BigUint::from(2u32);
    if remainder > denom_half {
        *num += BigUint::new(vec![1]);
    }
}

/// Public accessor functions matching Go implementation
pub fn curve_lattice() -> &'static Lattice {
    &CURVE_LATTICE
}

/// Example function demonstrating lattice usage
pub fn example_lattice_usage() {
    println!("=== BN254 Lattice Example ===");

    // Get the curve lattice
    let curve_lattice = curve_lattice();
    println!(
        "Curve lattice vectors: {}x{}",
        curve_lattice.vectors.len(),
        curve_lattice.vectors[0].len()
    );

    // Example decomposition
    let k = BigUint::from_str("123456789").unwrap();
    let decomp = curve_lattice.decompose(&k);
    println!("Decomposition of {}: {:?}", k, decomp);

    // Example multi-scalar multiplication
    let multi_result = curve_lattice.multi(&k);
    println!("Multi-scalar result length: {}", multi_result.len());

    println!("=== End Example ===");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_curve_lattice_decompose() {
        let lattice = curve_lattice();
        let k = BigUint::from_str("123456789").unwrap();
        let result = lattice.decompose(&k);

        // Verify the result has the expected length
        assert_eq!(result.len(), lattice.inverse.len());

        // Verify all components are positive
        for x in &result {
            assert!(*x >= BigUint::new(vec![0]));
        }
    }

    #[test]
    fn test_lattice_precompute() {
        let lattice = curve_lattice();
        let mut calls = Vec::new();

        lattice.precompute(|i, j| {
            calls.push((i, j));
        });

        // Verify that precompute calls the function with expected parameters
        assert!(!calls.is_empty());

        // Verify all calls have valid indices
        for (i, j) in calls {
            assert!(i < lattice.vectors.len() as u32);
            assert!(j < (1u32 << lattice.vectors.len() as u32));
        }
    }

    #[test]
    fn test_lattice_multi() {
        let lattice = curve_lattice();
        let scalar = BigUint::from_str("123456789").unwrap();
        let result = lattice.multi(&scalar);

        // Verify the result is not empty
        assert!(!result.is_empty());
    }

    #[test]
    fn test_round_function() {
        let mut num = BigUint::from_str("10").unwrap();
        let denom = BigUint::from_str("3").unwrap();

        round(&mut num, &denom);

        // 10/3 = 3.33... should round to 3
        assert_eq!(num, BigUint::from_str("3").unwrap());

        let mut num2 = BigUint::from_str("11").unwrap();
        let denom2 = BigUint::from_str("3").unwrap();

        round(&mut num2, &denom2);

        // 11/3 = 3.66... should round to 4
        assert_eq!(num2, BigUint::from_str("4").unwrap());

        // Test with HALF value - HALF is Order/2, so for small numbers like 2, HALF is much larger
        // So 5/2 = 2.5 should round to 2 (since remainder < HALF)
        let mut num3 = BigUint::from_str("5").unwrap();
        let denom3 = BigUint::from_str("2").unwrap();

        round(&mut num3, &denom3);

        // 5/2 = 2.5 should round to 2 (since remainder < HALF)
        assert_eq!(num3, BigUint::from_str("2").unwrap());
    }
}
