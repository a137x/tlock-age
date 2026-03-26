use crate::kyber::pairing::bn254::constants::ORDER;
use crate::kyber::pairing::bn254::gfp::GFp;
use crate::kyber::pairing::bn254::gfp2::GFp2;
use num_bigint::BigUint;

// twistB is the curve parameter for the twisted curve y²=x³+3/ξ over GF(p²)
// This matches Go's twistB constant
pub const TWIST_B: [[u64; 4]; 2] = [
    [
        0x38e7ecccd1dcff67,
        0x65f0b37d93ce0d3e,
        0xd749d0dd22ac00aa,
        0x0141b9ce4a688d4d,
    ],
    [
        0x3bf938e377b802a8,
        0x020b1b273633535d,
        0x26b7edf049755260,
        0x2514c6324384a86d,
    ],
];

// twistGen is the generator of group G₂
// This matches Go's twistGen constant
pub const TWIST_GEN: [[[u64; 4]; 2]; 4] = [
    // x coordinate
    [
        [
            0xafb4737da84c6140,
            0x6043dd5a5802d8c4,
            0x09e950fc52a02f86,
            0x14fef0833aea7b6b,
        ],
        [
            0x8e83b5d102bc2026,
            0xdceb1935497b0172,
            0xfbb8264797811adf,
            0x19573841af96503b,
        ],
    ],
    // y coordinate
    [
        [
            0x64095b56c71856ee,
            0xdc57f922327d3cbb,
            0x55f935be33351076,
            0x0da4a0e693fd6482,
        ],
        [
            0x619dfa9d886be9f6,
            0xfe7fd297f59e9b78,
            0xff9e1a62231b7dfe,
            0x28fd7eebae9e4206,
        ],
    ],
    // z coordinate (0, 1)
    [[0, 0, 0, 0], [1, 0, 0, 0]],
    // t coordinate (0, 1)
    [[0, 0, 0, 0], [1, 0, 0, 0]],
];

#[derive(Debug, Clone, PartialEq)]
pub struct TwistPoint {
    x: GFp2,
    y: GFp2,
    z: GFp2,
    t: GFp2,
}

impl TwistPoint {
    pub fn new() -> Self {
        Self {
            x: GFp2::new(), // zero
            y: {
                let mut y = GFp2::new();
                y.set_one(); // set to 1
                y
            },
            z: GFp2::new(), // zero
            t: GFp2::new(), // zero
        }
    }

    // Create the twist generator from constants - matches Go's twistGen
    pub fn twist_gen() -> Self {
        let twist_gen = Self {
            x: GFp2::from_gfp(
                GFp::from_u64_array(TWIST_GEN[0][0]),
                GFp::from_u64_array(TWIST_GEN[0][1]),
            ),
            y: GFp2::from_gfp(
                GFp::from_u64_array(TWIST_GEN[1][0]),
                GFp::from_u64_array(TWIST_GEN[1][1]),
            ),
            z: GFp2::from_gfp(
                GFp::new(0), // Montgomery-encoded 0
                GFp::new(1), // Montgomery-encoded 1
            ),
            t: GFp2::from_gfp(
                GFp::new(0), // Montgomery-encoded 0
                GFp::new(1), // Montgomery-encoded 1
            ),
        };
        twist_gen
    }

    pub fn set(&mut self, a: &TwistPoint) {
        self.x.set(&a.x);
        self.y.set(&a.y);
        self.z.set(&a.z);
        self.t.set(&a.t);
    }

    // IsOnCurve returns true iff c is on the curve - matches Go implementation
    pub fn is_on_curve(&self) -> bool {
        let mut cpy = self.clone();
        cpy.make_affine();
        if cpy.is_infinity() {
            return true;
        }
        let mut y2 = GFp2::new();
        y2.square(&cpy.y);
        let mut x3 = GFp2::new();
        x3.square(&cpy.x);
        let mut x3_cubed = GFp2::new();
        x3_cubed.mul(&x3, &cpy.x);
        let twist_b = GFp2::from_gfp(
            GFp::from_u64_array(TWIST_B[0]),
            GFp::from_u64_array(TWIST_B[1]),
        );
        let mut x3plusb = GFp2::new();
        x3plusb.add(&x3_cubed, &twist_b);
        if y2 != x3plusb {
            return false;
        }
        let mut cneg = TwistPoint::new();
        let order = crate::kyber::pairing::bn254::constants::big_from_base10(ORDER);
        cneg.mul(&cpy, &order);
        cneg.z.is_zero()
    }

    pub fn set_infinity(&mut self) {
        self.x.set_zero();
        self.y.set_one();
        self.z.set_zero();
        self.t.set_zero();
    }

    pub fn is_infinity(&self) -> bool {
        self.z.is_zero()
    }

    // Add(a, b *twistPoint) - matches Go implementation
    pub fn add(&mut self, a: &TwistPoint, b: &TwistPoint) {
        if a.is_infinity() {
            self.set(b);
            return;
        }
        if b.is_infinity() {
            self.set(a);
            return;
        }
        let mut z12 = GFp2::new();
        z12.square(&a.z);
        let mut z22 = GFp2::new();
        z22.square(&b.z);
        let mut u1 = GFp2::new();
        u1.mul(&a.x, &z22);
        let mut u2 = GFp2::new();
        u2.mul(&b.x, &z12);
        let mut t = GFp2::new();
        t.mul(&b.z, &z22);
        let mut s1 = GFp2::new();
        s1.mul(&a.y, &t);
        t.mul(&a.z, &z12);
        let mut s2 = GFp2::new();
        s2.mul(&b.y, &t);
        let mut h = GFp2::new();
        h.sub(&u2, &u1);
        let x_equal = h.is_zero();
        t.add(&h, &h);
        let mut i = GFp2::new();
        i.square(&t);
        let mut j = GFp2::new();
        j.mul(&h, &i);
        t.sub(&s2, &s1);
        let y_equal = t.is_zero();
        if x_equal && y_equal {
            self.double(a);
            return;
        }
        let mut r = GFp2::new();
        r.add(&t, &t);
        let mut v = GFp2::new();
        v.mul(&u1, &i);
        let mut t4 = GFp2::new();
        t4.square(&r);
        t.add(&v, &v);
        let mut t6 = GFp2::new();
        t6.sub(&t4, &j);
        self.x.sub(&t6, &t);
        t.sub(&v, &self.x);
        t4.mul(&s1, &j);
        t6.add(&t4, &t4);
        t4.mul(&r, &t);
        self.y.sub(&t4, &t6);
        t.add(&a.z, &b.z);
        t4.square(&t);
        t.sub(&t4, &z12);
        t4.sub(&t, &z22);
        self.z.mul(&t4, &h);
        // t coordinate is not used in Go's addition, so we leave it as is
    }

    // Double(a *twistPoint) - matches Go implementation
    pub fn double(&mut self, twist_point: &TwistPoint) {
        let mut a = GFp2::new();
        a.square(&twist_point.x);
        let mut b = GFp2::new();
        b.square(&twist_point.y);
        let mut c = GFp2::new();
        c.square(&b);
        let mut t = GFp2::new();
        t.add(&twist_point.x, &b);
        let mut t2 = GFp2::new();
        t2.square(&t);
        t.sub(&t2, &a);
        t2.sub(&t, &c);
        let mut d = GFp2::new();
        d.add(&t2, &t2);
        t.add(&a, &a);
        let mut e = GFp2::new();
        e.add(&t, &a);
        let mut f = GFp2::new();
        f.square(&e);
        t.add(&d, &d);
        self.x.sub(&f, &t);
        let mut ztmp = GFp2::new();
        ztmp.mul(&twist_point.y, &twist_point.z);
        let mut ztmp2 = GFp2::new();
        ztmp2.add(&ztmp, &ztmp);
        self.z.set(&ztmp2);
        t.add(&c, &c);
        t2.add(&t, &t);
        t.add(&t2, &t2);
        self.y.sub(&d, &self.x);
        t2.mul(&e, &self.y);
        self.y.sub(&t2, &t);
        // t coordinate is not used in Go's double, so we leave it as is
    }

    // Mul(a *twistPoint, scalar *big.Int) - matches Go implementation
    pub fn mul(&mut self, a: &TwistPoint, scalar: &BigUint) {
        let mut sum = TwistPoint::new();
        sum.set_infinity();
        let mut t = TwistPoint::new();
        let nbits = scalar.bits();
        for i in (0..nbits).rev() {
            t.double(&sum);
            if scalar.bit(i) {
                sum.add(&t, a);
            } else {
                sum.set(&t);
            }
        }
        self.set(&sum);
    }

    // MakeAffine() - matches Go implementation
    // NB: Not safe for concurrent calls
    pub fn make_affine(&mut self) {
        let mut g = self.clone();
        if g.z.is_one() {
            return;
        } else if g.z.is_zero() {
            g.x.set_zero();
            g.y.set_one();
            g.t.set_zero();
            self.set(&g);
            return;
        }
        let mut zinv = GFp2::new();
        zinv.invert(&g.z);
        let mut t = GFp2::new();
        t.mul(&g.y, &zinv);
        let mut zinv2 = GFp2::new();
        zinv2.square(&zinv);
        g.y.mul(&t, &zinv2);
        t.mul(&g.x, &zinv2);
        g.x.set(&t);
        g.z.set_one();
        g.t.set_one();
        self.set(&g);
    }

    // Neg(a *twistPoint) - matches Go implementation
    pub fn neg(&mut self, a: &TwistPoint) {
        self.x.set(&a.x);
        self.y.neg_from(&a.y);
        self.z.set(&a.z);
        self.t.set_zero();
    }

    // Clone makes a hard copy of the point - matches Go implementation
    pub fn clone(&self) -> Self {
        Self {
            x: self.x.clone(),
            y: self.y.clone(),
            z: self.z.clone(),
            t: self.t.clone(),
        }
    }

    // Getter methods for coordinates
    pub fn get_x(&self) -> &GFp2 {
        &self.x
    }

    pub fn get_y(&self) -> &GFp2 {
        &self.y
    }

    pub fn get_z(&self) -> &GFp2 {
        &self.z
    }

    pub fn get_t(&self) -> &GFp2 {
        &self.t
    }

    // Mutable getter methods for coordinates
    pub fn get_x_mut(&mut self) -> &mut GFp2 {
        &mut self.x
    }

    pub fn get_y_mut(&mut self) -> &mut GFp2 {
        &mut self.y
    }

    pub fn get_z_mut(&mut self) -> &mut GFp2 {
        &mut self.z
    }

    pub fn get_t_mut(&mut self) -> &mut GFp2 {
        &mut self.t
    }

    // Set point to generator (identity)
    pub fn set_one(&mut self) {
        self.x.set_one();
        self.y.set_one();
        self.z.set_one();
        self.t.set_one();
    }
}

impl std::fmt::Display for TwistPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Check if this is the point at infinity - Go shows all zeros for infinity
        if self.is_infinity() {
            write!(f, "((0000000000000000000000000000000000000000000000000000000000000000, 0000000000000000000000000000000000000000000000000000000000000000), (0000000000000000000000000000000000000000000000000000000000000000, 0000000000000000000000000000000000000000000000000000000000000000))")
        } else {
            let mut cpy = self.clone();
            cpy.make_affine();
            let x = crate::kyber::pairing::bn254::gfp2::gfp2_decode(&cpy.x);
            let y = crate::kyber::pairing::bn254::gfp2::gfp2_decode(&cpy.y);

            write!(f, "({}, {})", x, y)
        }
    }
}
