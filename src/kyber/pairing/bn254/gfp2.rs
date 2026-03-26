use crate::kyber::pairing::bn254::gfp::{gfp_add, gfp_mul, gfp_neg, gfp_sub, mont_decode, GFp};

#[derive(Debug, Clone, PartialEq)]
pub struct GFp2 {
    x: GFp, // coefficient of i
    y: GFp, // coefficient of 1
}

impl GFp2 {
    pub fn new() -> Self {
        Self {
            x: GFp::new(0),
            y: GFp::new(0),
        }
    }

    pub fn from_gfp(x: GFp, y: GFp) -> Self {
        Self { x, y }
    }

    pub fn from_u64_array(arr: [[u64; 4]; 2]) -> Self {
        Self {
            x: GFp::from_u64_array(arr[0]),
            y: GFp::from_u64_array(arr[1]),
        }
    }

    pub fn to_u64_array(&self) -> [[u64; 4]; 2] {
        [
            self.x.to_u64_array(),
            self.y.to_u64_array(),
        ]
    }

    pub fn set(&mut self, a: &GFp2) {
        self.x.set(&a.x);
        self.y.set(&a.y);
    }

    pub fn set_zero(&mut self) {
        self.x = GFp::new(0);
        self.y = GFp::new(0);
    }

    pub fn set_one(&mut self) {
        self.x = GFp::new(0);
        self.y = GFp::new(1);
    }

    pub fn is_zero(&self) -> bool {
        self.x == GFp::new(0) && self.y == GFp::new(0)
    }

    pub fn is_one(&self) -> bool {
        self.x == GFp::new(0) && self.y == GFp::new(1)
    }

    pub fn conjugate(&mut self, a: &GFp2) {
        self.y.set(&a.y);
        gfp_neg(&mut self.x, &a.x);
    }

    pub fn neg(&mut self) {
        let x_copy = self.x.clone();
        let y_copy = self.y.clone();
        gfp_neg(&mut self.x, &x_copy);
        gfp_neg(&mut self.y, &y_copy);
    }

    pub fn neg_from(&mut self, a: &GFp2) {
        gfp_neg(&mut self.x, &a.x);
        gfp_neg(&mut self.y, &a.y);
    }

    pub fn add(&mut self, a: &GFp2, b: &GFp2) {
        gfp_add(&mut self.x, &a.x, &b.x);
        gfp_add(&mut self.y, &a.y, &b.y);
    }

    pub fn sub(&mut self, a: &GFp2, b: &GFp2) {
        gfp_sub(&mut self.x, &a.x, &b.x);
        gfp_sub(&mut self.y, &a.y, &b.y);
    }

    // See "Multiplication and Squaring in Pairing-Friendly Fields",
    // http://eprint.iacr.org/2006/471.pdf
    pub fn mul(&mut self, a: &GFp2, b: &GFp2) {
        let mut tx = GFp::new(0);
        let mut t = GFp::new(0);
        gfp_mul(&mut tx, &a.x, &b.y);
        gfp_mul(&mut t, &b.x, &a.y);
        let temp_tx = tx.clone();
        let temp_t = t.clone();
        gfp_add(&mut tx, &temp_tx, &temp_t);

        let mut ty = GFp::new(0);
        gfp_mul(&mut ty, &a.y, &b.y);
        let mut t2 = GFp::new(0);
        gfp_mul(&mut t2, &a.x, &b.x);
        let temp_ty = ty.clone();
        let temp_t2 = t2.clone();
        gfp_sub(&mut ty, &temp_ty, &temp_t2);

        self.x.set(&tx);
        self.y.set(&ty);
    }

    pub fn mul_scalar(&mut self, a: &GFp2, b: &GFp) {
        gfp_mul(&mut self.x, &a.x, b);
        gfp_mul(&mut self.y, &a.y, b);
    }

    // MulXi sets e=ξa where ξ=i+9 and then returns e.
    pub fn mul_xi(&mut self, a: &GFp2) {
        // (xi+y)(i+9) = (9x+y)i+(9y-x)
        let mut tx = GFp::new(0);
        gfp_add(&mut tx, &a.x, &a.x);
        let temp_tx = tx.clone();
        gfp_add(&mut tx, &temp_tx, &temp_tx);
        let temp_tx = tx.clone();
        gfp_add(&mut tx, &temp_tx, &temp_tx);
        let temp_tx = tx.clone();
        gfp_add(&mut tx, &temp_tx, &a.x);
        let temp_tx = tx.clone();
        gfp_add(&mut tx, &temp_tx, &a.y);

        let mut ty = GFp::new(0);
        gfp_add(&mut ty, &a.y, &a.y);
        let temp_ty = ty.clone();
        gfp_add(&mut ty, &temp_ty, &temp_ty);
        let temp_ty = ty.clone();
        gfp_add(&mut ty, &temp_ty, &temp_ty);
        let temp_ty = ty.clone();
        gfp_add(&mut ty, &temp_ty, &a.y);
        let temp_ty = ty.clone();
        gfp_sub(&mut ty, &temp_ty, &a.x);

        self.x.set(&tx);
        self.y.set(&ty);
    }

    pub fn square(&mut self, a: &GFp2) {
        // Complex squaring algorithm:
        // (xi+y)² = (x+y)(y-x) + 2*i*x*y
        // println!("DEBUG: GFp2::square input a = ({}, {})", a.x, a.y);

        let mut tx = GFp::new(0);
        let mut ty = GFp::new(0);

        gfp_sub(&mut tx, &a.y, &a.x);
        // println!("DEBUG: after gfp_sub(tx, a.y, a.x): tx = {}", tx);

        gfp_add(&mut ty, &a.x, &a.y);
        // println!("DEBUG: after gfp_add(ty, a.x, a.y): ty = {}", ty);

        let temp_tx = tx.clone();
        let temp_ty = ty.clone();
        gfp_mul(&mut ty, &temp_tx, &temp_ty);
        // println!("DEBUG: after gfp_mul(ty, tx, ty): ty = {}", ty);

        gfp_mul(&mut tx, &a.x, &a.y);
        // println!("DEBUG: after gfp_mul(tx, a.x, a.y): tx = {}", tx);

        let temp_tx = tx.clone();
        gfp_add(&mut tx, &temp_tx, &temp_tx);
        // println!("DEBUG: after gfp_add(tx, tx, tx): tx = {}", tx);

        self.x.set(&tx);
        self.y.set(&ty);

        // println!("DEBUG: GFp2::square result = ({}, {})", self.x, self.y);
    }

    pub fn invert(&mut self, a: &GFp2) {
        // See "Implementing cryptographic pairings", M. Scott, section 3.2.
        // ftp://136.206.11.249/pub/crypto/pairings.pdf
        let mut t1 = GFp::new(0);
        let mut t2 = GFp::new(0);
        gfp_mul(&mut t1, &a.x, &a.x);
        gfp_mul(&mut t2, &a.y, &a.y);
        let temp_t1 = t1.clone();
        let temp_t2 = t2.clone();
        gfp_add(&mut t1, &temp_t1, &temp_t2);

        let mut inv = GFp::new(0);
        inv.invert(&t1);

        gfp_neg(&mut t1, &a.x);

        gfp_mul(&mut self.x, &t1, &inv);
        gfp_mul(&mut self.y, &a.y, &inv);
    }

    pub fn get_x(&self) -> &GFp {
        &self.x
    }

    pub fn get_y(&self) -> &GFp {
        &self.y
    }

    pub fn get_x_mut(&mut self) -> &mut GFp {
        &mut self.x
    }

    pub fn get_y_mut(&mut self) -> &mut GFp {
        &mut self.y
    }
}

impl std::fmt::Display for GFp2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "({}, {})", self.x, self.y)
    }
}

// Helper function for decoding GFp2
pub fn gfp2_decode(in_val: &GFp2) -> GFp2 {
    let mut out = GFp2::new();
    mont_decode(&mut out.x, &in_val.x);
    mont_decode(&mut out.y, &in_val.y);
    out
}
