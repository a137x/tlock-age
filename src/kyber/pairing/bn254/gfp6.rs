use crate::kyber::pairing::bn254::gfp2::GFp2;
use crate::kyber::pairing::bn254::constants::{
    XI_TO_2P_MINUS_2_OVER_3, XI_TO_P_MINUS_1_OVER_3, XI_TO_2P_SQUARED_MINUS_2_OVER_3, 
    XI_TO_P_SQUARED_MINUS_1_OVER_3
};
use crate::kyber::pairing::bn254::gfp::GFp;

#[derive(Debug, Clone, PartialEq)]
pub struct GFp6 {
    x: GFp2, // coefficient of τ²
    y: GFp2, // coefficient of τ
    z: GFp2, // coefficient of 1
}

impl GFp6 {
    pub fn new() -> Self {
        Self {
            x: GFp2::new(),
            y: GFp2::new(),
            z: GFp2::new(),
        }
    }

    pub fn from_u64_array(arr: [[[u64; 4]; 2]; 3]) -> Self {
        Self {
            x: GFp2::from_u64_array(arr[0]),
            y: GFp2::from_u64_array(arr[1]),
            z: GFp2::from_u64_array(arr[2]),
        }
    }

    pub fn to_u64_array(&self) -> [[[u64; 4]; 2]; 3] {
        [
            self.x.to_u64_array(),
            self.y.to_u64_array(),
            self.z.to_u64_array(),
        ]
    }

    pub fn set(&mut self, a: &GFp6) {
        self.x.set(&a.x);
        self.y.set(&a.y);
        self.z.set(&a.z);
    }

    pub fn set_zero(&mut self) {
        self.x.set_zero();
        self.y.set_zero();
        self.z.set_zero();
    }

    pub fn set_one(&mut self) {
        self.x.set_zero();
        self.y.set_zero();
        self.z.set_one();
    }

    pub fn is_zero(&self) -> bool {
        self.x.is_zero() && self.y.is_zero() && self.z.is_zero()
    }

    pub fn is_one(&self) -> bool {
        self.x.is_zero() && self.y.is_zero() && self.z.is_one()
    }

    pub fn neg(&mut self, a: &GFp6) {
        self.x.set(&a.x);
        self.x.neg();
        self.y.set(&a.y);
        self.y.neg();
        self.z.set(&a.z);
        self.z.neg();
    }

    pub fn frobenius(&mut self, a: &GFp6) {
        self.x.conjugate(&a.x);
        self.y.conjugate(&a.y);
        self.z.conjugate(&a.z);

        let xi_to_2p_minus_2_over_3 = GFp2::from_gfp(
            GFp::from_u64_array(XI_TO_2P_MINUS_2_OVER_3[0]),
            GFp::from_u64_array(XI_TO_2P_MINUS_2_OVER_3[1])
        );
        let xi_to_p_minus_1_over_3 = GFp2::from_gfp(
            GFp::from_u64_array(XI_TO_P_MINUS_1_OVER_3[0]),
            GFp::from_u64_array(XI_TO_P_MINUS_1_OVER_3[1])
        );

        let temp_x = self.x.clone();
        self.x.mul(&temp_x, &xi_to_2p_minus_2_over_3);
        let temp_y = self.y.clone();
        self.y.mul(&temp_y, &xi_to_p_minus_1_over_3);
    }

    // FrobeniusP2 computes (xτ²+yτ+z)^(p²) = xτ^(2p²) + yτ^(p²) + z
    pub fn frobenius_p2(&mut self, a: &GFp6) {
        // τ^(2p²) = τ²τ^(2p²-2) = τ²ξ^((2p²-2)/3)
        let xi_to_2p_squared_minus_2_over_3 = GFp::from_u64_array(XI_TO_2P_SQUARED_MINUS_2_OVER_3);
        self.x.mul_scalar(&a.x, &xi_to_2p_squared_minus_2_over_3);
        // τ^(p²) = ττ^(p²-1) = τξ^((p²-1)/3)
        let xi_to_p_squared_minus_1_over_3 = GFp::from_u64_array(XI_TO_P_SQUARED_MINUS_1_OVER_3);
        self.y.mul_scalar(&a.y, &xi_to_p_squared_minus_1_over_3);
        self.z.set(&a.z);
    }

    pub fn frobenius_p4(&mut self, a: &GFp6) {
        let xi_to_p_squared_minus_1_over_3 = GFp::from_u64_array(XI_TO_P_SQUARED_MINUS_1_OVER_3);
        let xi_to_2p_squared_minus_2_over_3 = GFp::from_u64_array(XI_TO_2P_SQUARED_MINUS_2_OVER_3);
        
        self.x.mul_scalar(&a.x, &xi_to_p_squared_minus_1_over_3);
        self.y.mul_scalar(&a.y, &xi_to_2p_squared_minus_2_over_3);
        self.z.set(&a.z);
    }

    pub fn add(&mut self, a: &GFp6, b: &GFp6) {
        self.x.add(&a.x, &b.x);
        self.y.add(&a.y, &b.y);
        self.z.add(&a.z, &b.z);
    }

    pub fn sub(&mut self, a: &GFp6, b: &GFp6) {
        self.x.sub(&a.x, &b.x);
        self.y.sub(&a.y, &b.y);
        self.z.sub(&a.z, &b.z);
    }

    pub fn mul(&mut self, a: &GFp6, b: &GFp6) {
        // "Multiplication and Squaring on Pairing-Friendly Fields"
        // Section 4, Karatsuba method.
        // http://eprint.iacr.org/2006/471.pdf
        let mut v0 = GFp2::new();
        v0.mul(&a.z, &b.z);
        let mut v1 = GFp2::new();
        v1.mul(&a.y, &b.y);
        let mut v2 = GFp2::new();
        v2.mul(&a.x, &b.x);

        let mut t0 = GFp2::new();
        t0.add(&a.x, &a.y);
        let mut t1 = GFp2::new();
        t1.add(&b.x, &b.y);
        let mut tz = GFp2::new();
        tz.mul(&t0, &t1);
        let temp_tz = tz.clone();
        tz.sub(&temp_tz, &v1);
        let temp_tz = tz.clone();
        tz.sub(&temp_tz, &v2);
        let temp_tz = tz.clone();
        tz.mul_xi(&temp_tz);
        let temp_tz = tz.clone();
        tz.add(&temp_tz, &v0);

        let mut t0_2 = GFp2::new();
        t0_2.add(&a.y, &a.z);
        let mut t1_2 = GFp2::new();
        t1_2.add(&b.y, &b.z);
        let mut ty = GFp2::new();
        ty.mul(&t0_2, &t1_2);
        let mut t0_3 = GFp2::new();
        t0_3.mul_xi(&v2);
        let temp_ty = ty.clone();
        ty.sub(&temp_ty, &v0);
        let temp_ty = ty.clone();
        ty.sub(&temp_ty, &v1);
        let temp_ty = ty.clone();
        ty.add(&temp_ty, &t0_3);

        let mut t0_4 = GFp2::new();
        t0_4.add(&a.x, &a.z);
        let mut t1_4 = GFp2::new();
        t1_4.add(&b.x, &b.z);
        let mut tx = GFp2::new();
        tx.mul(&t0_4, &t1_4);
        let temp_tx = tx.clone();
        tx.sub(&temp_tx, &v0);
        let temp_tx = tx.clone();
        tx.add(&temp_tx, &v1);
        let temp_tx = tx.clone();
        tx.sub(&temp_tx, &v2);

        self.x.set(&tx);
        self.y.set(&ty);
        self.z.set(&tz);
    }

    pub fn mul_scalar(&mut self, a: &GFp6, b: &GFp2) {
        self.x.mul(&a.x, b);
        self.y.mul(&a.y, b);
        self.z.mul(&a.z, b);
    }

    pub fn mul_gfp(&mut self, a: &GFp6, b: &GFp) {
        self.x.mul_scalar(&a.x, b);
        self.y.mul_scalar(&a.y, b);
        self.z.mul_scalar(&a.z, b);
    }

    // MulTau computes τ·(aτ²+bτ+c) = bτ²+cτ+aξ
    pub fn mul_tau(&mut self, a: &GFp6) {
        let mut tz = GFp2::new();
        tz.mul_xi(&a.x);
        let mut ty = GFp2::new();
        ty.set(&a.y);

        self.y.set(&a.z);
        self.x.set(&ty);
        self.z.set(&tz);
    }

    pub fn square(&mut self, a: &GFp6) {
        let mut v0 = GFp2::new();
        v0.square(&a.z);
        let mut v1 = GFp2::new();
        v1.square(&a.y);
        let mut v2 = GFp2::new();
        v2.square(&a.x);

        let mut c0 = GFp2::new();
        c0.add(&a.x, &a.y);
        let temp_c0 = c0.clone();
        c0.square(&temp_c0);
        let temp_c0 = c0.clone();
        c0.sub(&temp_c0, &v1);
        let temp_c0 = c0.clone();
        c0.sub(&temp_c0, &v2);
        let temp_c0 = c0.clone();
        c0.mul_xi(&temp_c0);
        let temp_c0 = c0.clone();
        c0.add(&temp_c0, &v0);

        let mut c1 = GFp2::new();
        c1.add(&a.y, &a.z);
        let temp_c1 = c1.clone();
        c1.square(&temp_c1);
        let temp_c1 = c1.clone();
        c1.sub(&temp_c1, &v0);
        let temp_c1 = c1.clone();
        c1.sub(&temp_c1, &v1);
        let mut xi_v2 = GFp2::new();
        xi_v2.mul_xi(&v2);
        let temp_c1 = c1.clone();
        c1.add(&temp_c1, &xi_v2);

        let mut c2 = GFp2::new();
        c2.add(&a.x, &a.z);
        let temp_c2 = c2.clone();
        c2.square(&temp_c2);
        let temp_c2 = c2.clone();
        c2.sub(&temp_c2, &v0);
        let temp_c2 = c2.clone();
        c2.add(&temp_c2, &v1);
        let temp_c2 = c2.clone();
        c2.sub(&temp_c2, &v2);

        self.x.set(&c2);
        self.y.set(&c1);
        self.z.set(&c0);
    }

    pub fn invert(&mut self, a: &GFp6) {
        // See "Implementing cryptographic pairings", M. Scott, section 3.2.
        // ftp://136.206.11.249/pub/crypto/pairings.pdf

        // Here we can give a short explanation of how it works: let j be a cubic root of
        // unity in GF(p²) so that 1+j+j²=0.
        // Then (xτ² + yτ + z)(xj²τ² + yjτ + z)(xjτ² + yj²τ + z)
        // = (xτ² + yτ + z)(Cτ²+Bτ+A)
        // = (x³ξ²+y³ξ+z³-3ξxyz) = F is an element of the base field (the norm).
        //
        // On the other hand (xj²τ² + yjτ + z)(xjτ² + yj²τ + z)
        // = τ²(y²-ξxz) + τ(ξx²-yz) + (z²-ξxy)
        //
        // So that's why A = (z²-ξxy), B = (ξx²-yz), C = (y²-ξxz)
        let mut t1 = GFp2::new();
        t1.mul(&a.x, &a.y);
        let temp_t1 = t1.clone();
        t1.mul_xi(&temp_t1);

        let mut a_coeff = GFp2::new();
        a_coeff.square(&a.z);
        let temp_a_coeff = a_coeff.clone();
        a_coeff.sub(&temp_a_coeff, &t1);

        let mut b_coeff = GFp2::new();
        b_coeff.square(&a.x);
        let temp_b_coeff = b_coeff.clone();
        b_coeff.mul_xi(&temp_b_coeff);
        let mut t1_2 = GFp2::new();
        t1_2.mul(&a.y, &a.z);
        let temp_b_coeff = b_coeff.clone();
        b_coeff.sub(&temp_b_coeff, &t1_2);

        let mut c_coeff = GFp2::new();
        c_coeff.square(&a.y);
        let mut t1_3 = GFp2::new();
        t1_3.mul(&a.x, &a.z);
        let temp_c_coeff = c_coeff.clone();
        c_coeff.sub(&temp_c_coeff, &t1_3);

        let mut f = GFp2::new();
        f.mul(&c_coeff, &a.y);
        let temp_f = f.clone();
        f.mul_xi(&temp_f);
        let mut t1_4 = GFp2::new();
        t1_4.mul(&a_coeff, &a.z);
        let temp_f = f.clone();
        f.add(&temp_f, &t1_4);
        let mut t1_5 = GFp2::new();
        t1_5.mul(&b_coeff, &a.x);
        let temp_t1_5 = t1_5.clone();
        t1_5.mul_xi(&temp_t1_5);
        let temp_f = f.clone();
        f.add(&temp_f, &t1_5);

        let temp_f = f.clone();
        f.invert(&temp_f);

        self.x.mul(&c_coeff, &f);
        self.y.mul(&b_coeff, &f);
        self.z.mul(&a_coeff, &f);
    }

    pub fn get_x(&self) -> &GFp2 {
        &self.x
    }

    pub fn get_y(&self) -> &GFp2 {
        &self.y
    }

    pub fn get_z(&self) -> &GFp2 {
        &self.z
    }

    pub fn get_x_mut(&mut self) -> &mut GFp2 {
        &mut self.x
    }

    pub fn get_y_mut(&mut self) -> &mut GFp2 {
        &mut self.y
    }

    pub fn get_z_mut(&mut self) -> &mut GFp2 {
        &mut self.z
    }

    // Clone makes a hard copy of the field
    pub fn clone(&self) -> Self {
        Self {
            x: self.x.clone(),
            y: self.y.clone(),
            z: self.z.clone(),
        }
    }
}

impl std::fmt::Display for GFp6 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "({}, {}, {})", self.x, self.y, self.z)
    }
} 