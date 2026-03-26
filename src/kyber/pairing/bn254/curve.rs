use crate::kyber::pairing::bn254::constants::CURVE_B;
use crate::kyber::pairing::bn254::gfp::{gfp_add, gfp_mul, gfp_neg, gfp_sub, GFp};
use num_bigint::BigUint;

#[derive(Debug, Clone, PartialEq)]
pub struct CurvePoint {
    x: GFp,
    y: GFp,
    z: GFp,
    t: GFp,
}

impl CurvePoint {
    pub fn new() -> Self {
        Self {
            x: GFp::new(0),
            y: GFp::new(0),
            z: GFp::new(0),
            t: GFp::new(0),
        }
    }

    pub fn set(&mut self, a: &CurvePoint) {
        self.x.set(&a.x);
        self.y.set(&a.y);
        self.z.set(&a.z);
        self.t.set(&a.t);
    }

    pub fn is_on_curve(&self) -> bool {
        let mut cpy = self.clone();
        cpy.make_affine();
        if cpy.is_infinity() {
            return true;
        }

        // Work entirely in Montgomery form, just like Go implementation
        // Don't decode the coordinates - keep them in Montgomery form
        let mut y2 = GFp::new(0);
        let mut x3 = GFp::new(0);
        gfp_mul(&mut y2, &cpy.y, &cpy.y);
        gfp_mul(&mut x3, &cpy.x, &cpy.x);
        let temp_x3 = x3.clone();
        gfp_mul(&mut x3, &temp_x3, &cpy.x);

        // Use curveB in Montgomery form (like Go's curveB = newGFp(3))
        let curve_b = GFp::new(3); // This is already in Montgomery form
        let temp_x3 = x3.clone();
        gfp_add(&mut x3, &temp_x3, &curve_b);

        y2 == x3
    }

    pub fn set_infinity(&mut self) {
        self.x = GFp::new(0);
        self.y = GFp::new(1);
        self.z = GFp::new(0);
        self.t = GFp::new(0);
    }

    pub fn is_infinity(&self) -> bool {
        self.z == GFp::new(0)
    }

    pub fn add(&mut self, a: &CurvePoint, b: &CurvePoint) {
        if a.is_infinity() {
            self.set(b);
            return;
        }
        if b.is_infinity() {
            self.set(a);
            return;
        }

        // See http://hyperelliptic.org/EFD/g1p/auto-code/shortw/jacobian-0/addition/add-2007-bl.op3

        // Normalize the points by replacing a = [x1:y1:z1] and b = [x2:y2:z2]
        // by [u1:s1:z1·z2] and [u2:s2:z1·z2]
        // where u1 = x1·z2², s1 = y1·z2³ and u1 = x2·z1², s2 = y2·z1³
        let mut z12 = GFp::new(0);
        let mut z22 = GFp::new(0);
        gfp_mul(&mut z12, &a.z, &a.z);
        gfp_mul(&mut z22, &b.z, &b.z);

        let mut u1 = GFp::new(0);
        let mut u2 = GFp::new(0);
        gfp_mul(&mut u1, &a.x, &z22);
        gfp_mul(&mut u2, &b.x, &z12);

        let mut t = GFp::new(0);
        let mut s1 = GFp::new(0);
        gfp_mul(&mut t, &b.z, &z22);
        gfp_mul(&mut s1, &a.y, &t);

        let mut s2 = GFp::new(0);
        gfp_mul(&mut t, &a.z, &z12);
        gfp_mul(&mut s2, &b.y, &t);

        // Compute x = (2h)²(s²-u1-u2)
        // where s = (s2-s1)/(u2-u1) is the slope of the line through
        // (u1,s1) and (u2,s2). The extra factor 2h = 2(u2-u1) comes from the value of z below.
        // This is also:
        // 4(s2-s1)² - 4h²(u1+u2) = 4(s2-s1)² - 4h³ - 4h²(2u1)
        //                        = r² - j - 2v
        // with the notations below.
        let mut h = GFp::new(0);
        gfp_sub(&mut h, &u2, &u1);
        let x_equal = h == GFp::new(0);

        gfp_add(&mut t, &h, &h);
        // i = 4h²
        let mut i = GFp::new(0);
        gfp_mul(&mut i, &t, &t);
        // j = 4h³
        let mut j = GFp::new(0);
        gfp_mul(&mut j, &h, &i);

        gfp_sub(&mut t, &s2, &s1);
        let y_equal = t == GFp::new(0);
        if x_equal && y_equal {
            self.double(a);
            return;
        }
        let mut r = GFp::new(0);
        gfp_add(&mut r, &t, &t);

        let mut v = GFp::new(0);
        gfp_mul(&mut v, &u1, &i);

        // t4 = 4(s2-s1)²
        let mut t4 = GFp::new(0);
        let mut t6 = GFp::new(0);
        gfp_mul(&mut t4, &r, &r);
        gfp_add(&mut t, &v, &v);
        gfp_sub(&mut t6, &t4, &j);

        gfp_sub(&mut self.x, &t6, &t);

        // Set y = -(2h)³(s1 + s*(x/4h²-u1))
        // This is also
        // y = - 2·s1·j - (s2-s1)(2x - 2i·u1) = r(v-x) - 2·s1·j
        gfp_sub(&mut t, &v, &self.x); // t7
        gfp_mul(&mut t4, &s1, &j); // t8
        gfp_add(&mut t6, &t4, &t4); // t9
        gfp_mul(&mut t4, &r, &t); // t10
        gfp_sub(&mut self.y, &t4, &t6);

        // Set z = 2(u2-u1)·z1·z2 = 2h·z1·z2
        gfp_add(&mut t, &a.z, &b.z); // t11
        gfp_mul(&mut t4, &t, &t); // t12
        gfp_sub(&mut t, &t4, &z12); // t13
        gfp_sub(&mut t4, &t, &z22); // t14
        gfp_mul(&mut self.z, &t4, &h);
    }

    pub fn double(&mut self, a: &CurvePoint) {
        // See http://hyperelliptic.org/EFD/g1p/auto-code/shortw/jacobian-0/doubling/dbl-2009-l.op3
        let mut a_coeff = GFp::new(0);
        let mut b_coeff = GFp::new(0);
        let mut c_coeff = GFp::new(0);
        gfp_mul(&mut a_coeff, &a.x, &a.x);
        gfp_mul(&mut b_coeff, &a.y, &a.y);
        gfp_mul(&mut c_coeff, &b_coeff, &b_coeff);

        let mut t = GFp::new(0);
        let mut t2 = GFp::new(0);
        gfp_add(&mut t, &a.x, &b_coeff);
        gfp_mul(&mut t2, &t, &t);
        gfp_sub(&mut t, &t2, &a_coeff);
        gfp_sub(&mut t2, &t, &c_coeff);

        let mut d = GFp::new(0);
        let mut e = GFp::new(0);
        let mut f = GFp::new(0);
        gfp_add(&mut d, &t2, &t2);
        gfp_add(&mut t, &a_coeff, &a_coeff);
        gfp_add(&mut e, &t, &a_coeff);
        gfp_mul(&mut f, &e, &e);

        gfp_add(&mut t, &d, &d);
        gfp_sub(&mut self.x, &f, &t);

        gfp_mul(&mut self.z, &a.y, &a.z);
        let temp_z = self.z.clone();
        gfp_add(&mut self.z, &temp_z, &temp_z);

        gfp_add(&mut t, &c_coeff, &c_coeff);
        gfp_add(&mut t2, &t, &t);
        gfp_add(&mut t, &t2, &t2);
        gfp_sub(&mut self.y, &d, &self.x);
        gfp_mul(&mut t2, &e, &self.y);
        gfp_sub(&mut self.y, &t2, &t);
    }

    pub fn mul(&mut self, a: &CurvePoint, scalar: &BigUint) {
        use crate::kyber::pairing::bn254::constants::XI_TO_2P_SQUARED_MINUS_2_OVER_3;
        use crate::kyber::pairing::bn254::gfp::GFp;
        use crate::kyber::pairing::bn254::lattice::curve_lattice;

        // Precompute 4 points: None, a, a*xi, a+a*xi
        let mut precomp: [Option<CurvePoint>; 4] = [None, None, None, None];
        precomp[1] = Some(a.clone());
        // a*xi
        let mut a_xi = a.clone();
        let xi_constant = GFp::from_u64_array(XI_TO_2P_SQUARED_MINUS_2_OVER_3);
        let temp_x = a_xi.x.clone();
        crate::kyber::pairing::bn254::gfp::gfp_mul(&mut a_xi.x, &temp_x, &xi_constant);
        precomp[2] = Some(a_xi);
        // a + a*xi
        let a_xi_ref = precomp[2].as_ref().unwrap();
        let mut a_plus_a_xi = a.clone();
        a_plus_a_xi.add(a, a_xi_ref);
        precomp[3] = Some(a_plus_a_xi);

        // Get the multi-scalar decomposition
        let multi_scalar = curve_lattice().multi(scalar);

        let mut sum = CurvePoint::new();
        sum.set_infinity();
        let mut t = CurvePoint::new();

        for i in (0..multi_scalar.len()).rev() {
            t.double(&sum);
            let idx = multi_scalar[i] as usize;
            if idx == 0 {
                sum.set(&t);
            } else {
                sum.add(&t, precomp[idx].as_ref().unwrap());
            }
        }
        self.set(&sum);
    }

    pub fn make_affine(&mut self) {
        if self.z == GFp::new(1) {
            return;
        } else if self.z == GFp::new(0) {
            self.x = GFp::new(0);
            self.y = GFp::new(1);
            self.t = GFp::new(0);
            return;
        }

        let mut z_inv = GFp::new(0);
        z_inv.invert(&self.z);

        let mut t = GFp::new(0);
        let mut z_inv2 = GFp::new(0);
        gfp_mul(&mut t, &self.y, &z_inv);
        gfp_mul(&mut z_inv2, &z_inv, &z_inv);

        let temp_x = self.x.clone();
        gfp_mul(&mut self.x, &temp_x, &z_inv2);
        gfp_mul(&mut self.y, &t, &z_inv2);

        self.z = GFp::new(1);
        self.t = GFp::new(1);
    }

    pub fn neg(&mut self, a: &CurvePoint) {
        self.x.set(&a.x);
        gfp_neg(&mut self.y, &a.y);
        self.z.set(&a.z);
        self.t = GFp::new(0);
    }

    pub fn get_x(&self) -> &GFp {
        &self.x
    }

    pub fn get_y(&self) -> &GFp {
        &self.y
    }

    pub fn get_z(&self) -> &GFp {
        &self.z
    }

    pub fn get_t(&self) -> &GFp {
        &self.t
    }

    pub fn get_x_mut(&mut self) -> &mut GFp {
        &mut self.x
    }

    pub fn get_y_mut(&mut self) -> &mut GFp {
        &mut self.y
    }

    pub fn get_z_mut(&mut self) -> &mut GFp {
        &mut self.z
    }

    pub fn get_t_mut(&mut self) -> &mut GFp {
        &mut self.t
    }

    pub fn get_coords(&self) -> (GFp, GFp) {
        let mut affine_copy = self.clone();
        affine_copy.make_affine();
        (affine_copy.x, affine_copy.y)
    }

    // Clone makes a hard copy of the curve point
    pub fn clone(&self) -> Self {
        Self {
            x: self.x.clone(),
            y: self.y.clone(),
            z: self.z.clone(),
            t: self.t.clone(),
        }
    }
}

impl std::fmt::Display for CurvePoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut cpy = self.clone();
        cpy.make_affine();
        let mut x_decoded = cpy.x.clone();
        let mut y_decoded = cpy.y.clone();
        crate::kyber::pairing::bn254::gfp::mont_decode(&mut x_decoded, &cpy.x);
        crate::kyber::pairing::bn254::gfp::mont_decode(&mut y_decoded, &cpy.y);
        write!(f, "({}, {})", x_decoded, y_decoded)
    }
}

// Helper function g(x) for curve operations
pub fn g(x: &GFp) -> GFp {
    let mut y = GFp::new(0);
    gfp_mul(&mut y, x, x);
    let temp_y = y.clone();
    gfp_mul(&mut y, &temp_y, x);
    let curve_b = GFp::from_base10(CURVE_B);
    let temp_y = y.clone();
    gfp_add(&mut y, &temp_y, &curve_b);
    y
}

// Generator point for G1
pub fn curve_gen() -> CurvePoint {
    let mut point = CurvePoint::new();
    point.x = GFp::new(1);
    point.y = GFp::new(2);
    point.z = GFp::new(1);
    point.t = GFp::new(1);
    point
}
