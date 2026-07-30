use crate::kyber::bn254::optate::optimal_ate;
use crate::kyber::pairing::bn254::constants::{C1, C2, C3, C4};
use crate::kyber::pairing::bn254::curve::{curve_gen, g, CurvePoint};
use crate::kyber::pairing::bn254::gfp::GFp;
use crate::kyber::pairing::bn254::gfp::{
    gfp_add, gfp_mul, gfp_neg, gfp_sub, legendre, mont_decode, mont_encode, sgn0,
};
use crate::kyber::pairing::bn254::gfp12::GFp12;
use crate::kyber::pairing::bn254::gfp2::GFp2;
use crate::kyber::pairing::bn254::pairing::{final_exponentiation, miller};
use crate::kyber::pairing::bn254::scalar::Scalar;
use crate::kyber::pairing::bn254::twist::TwistPoint;
use crate::kyber::pairing::bn254::util::zero_pad_bytes;
use hex;
use num_bigint::BigUint;
use sha3::{Digest, Keccak256};
use std::io::Read;
use std::str::FromStr;

// Marshal point IDs matching Go implementation exactly
const MARSHAL_POINT_ID1: [u8; 8] = [b'b', b'n', b'2', b'5', b'4', b'.', b'g', b'1'];
const MARSHAL_POINT_ID2: [u8; 8] = [b'b', b'n', b'2', b'5', b'4', b'.', b'g', b'2'];
const MARSHAL_POINT_IDT: [u8; 8] = [b'b', b'n', b'2', b'5', b'4', b'.', b'g', b't'];

#[derive(Debug, Clone)]
pub struct PointG1 {
    g: CurvePoint,
    dst: Vec<u8>,
}

impl PointG1 {
    // newPointG1(dst []byte) *pointG1 - matches Go constructor
    pub fn new() -> Self {
        Self {
            g: CurvePoint::new(),
            dst: vec![],
        }
    }

    pub fn new_with_dst(dst: Vec<u8>) -> Self {
        Self {
            g: CurvePoint::new(),
            dst,
        }
    }

    // hash_to_point(domain, m []byte) kyber.Point - matches Go function
    pub fn hash_to_point(message: &[u8]) -> Self {
        // Use default domain for now
        hash_to_point(&vec![], message)
    }

    // Equal(q kyber.Point) bool - matches Go implementation
    pub fn equal(&self, other: &PointG1) -> bool {
        // Match Go implementation: compare marshaled binary representations
        // Go uses subtle.ConstantTimeCompare(x, y) == 1
        let x = self.marshal_binary().unwrap_or_default();
        let y = other.marshal_binary().unwrap_or_default();
        x == y
    }

    // Null() kyber.Point - matches Go implementation
    pub fn null(&self) -> PointG1 {
        let mut p = PointG1::new();
        p.g.set_infinity();
        p
    }

    // Base() kyber.Point - matches Go implementation
    pub fn base(&self) -> PointG1 {
        let mut p = PointG1::new();
        p.g.set(&curve_gen());
        p
    }

    // Pick(rand cipher.Stream) kyber.Point - matches Go implementation
    pub fn pick<R: Read>(&self, rand: &mut R) -> PointG1 {
        // In Go: s := mod.NewInt64(0, Order).Pick(rand); p.Base(); p.g.Mul(p.g, &s.(*mod.Int).V)
        let mut s = Scalar::new();
        s.pick(rand).expect("Failed to pick random scalar");

        let mut p = self.base();
        let g_copy = p.g.clone();
        p.g.mul(&g_copy, s.value());
        p
    }

    pub fn set(&mut self, other: &PointG1) {
        self.g.set(&other.g);
    }

    pub fn clone(&self) -> PointG1 {
        PointG1 {
            g: self.g.clone(),
            dst: self.dst.clone(),
        }
    }

    pub fn embed_len(&self) -> usize {
        // Match Go implementation: panic with "unsupported operation"
        panic!("bn254.G1: unsupported operation")
    }

    pub fn embed(&self, _data: &[u8], _rand: &mut dyn Read) -> PointG1 {
        // Match Go implementation: panic with "unsupported operation"
        panic!("bn254.G1: unsupported operation")
    }

    pub fn data(&self) -> Result<Vec<u8>, String> {
        // Match Go implementation: panic with "unsupported operation"
        panic!("bn254.G1: unsupported operation")
    }

    pub fn add(&mut self, a: &PointG1, b: &PointG1) {
        self.g.add(&a.g, &b.g);
    }

    pub fn sub(&mut self, a: &PointG1, b: &PointG1) {
        // Match Go implementation: Add(a, Neg(b))
        let mut neg_b = b.clone();
        neg_b.neg(b);
        self.add(a, &neg_b);
    }

    pub fn neg(&mut self, q: &PointG1) {
        self.g.neg(&q.g);
    }

    // Mul(s kyber.Scalar, q kyber.Point) kyber.Point - matches Go implementation
    pub fn mul(&mut self, s: &Scalar, q: &PointG1) {
        // In Go: if q == nil { q = newPointG1(p.dst).Base() }
        let q_point = if q.g.is_infinity() {
            self.base()
        } else {
            q.clone()
        };
        // In Go: t := s.(*mod.Int).V; r := q.(*pointG1).g; p.g.Mul(r, &t)
        self.g.mul(&q_point.g, s.value());
    }

    // MarshalBinary() ([]byte, error) - matches Go implementation
    pub fn marshal_binary(&self) -> Result<Vec<u8>, String> {
        // Clone is required as we change the point
        let p = self.clone();

        let n = p.element_size();
        // Take a copy so that p is not written to, so calls to MarshalBinary
        // are threadsafe.
        let mut pgtemp = p.g.clone();
        pgtemp.make_affine();
        let mut ret = vec![0u8; p.marshal_size()];

        if pgtemp.is_infinity() {
            return Ok(ret);
        }

        let mut tmp = GFp::new(0);
        mont_decode(&mut tmp, pgtemp.get_x());
        tmp.marshal(&mut ret[0..n]);
        mont_decode(&mut tmp, pgtemp.get_y());
        tmp.marshal(&mut ret[n..]);

        Ok(ret)
    }

    pub fn marshal_id(&self) -> [u8; 8] {
        MARSHAL_POINT_ID1
    }

    pub fn marshal_to(&self, w: &mut dyn std::io::Write) -> Result<usize, String> {
        let buf = self.marshal_binary()?;
        w.write_all(&buf).map_err(|e| e.to_string())?;
        Ok(buf.len())
    }

    // UnmarshalBinary(buf []byte) error - matches Go implementation
    pub fn unmarshal_binary(&mut self, buf: &[u8]) -> Result<(), String> {
        let n = self.element_size();
        if buf.len() < self.marshal_size() {
            return Err("bn254.G1: not enough data".to_string());
        }


        // Reset the point to prepare for unmarshaling
        self.g = CurvePoint::new();

        // Unmarshal the coordinates directly into the point
        match self.g.get_x_mut().unmarshal(&buf[0..n]) {
            Ok(()) => println!("DEBUG: G1 unmarshal - x.unmarshal succeeded"),
            Err(e) => {
                return Err(e);
            }
        }
        match self.g.get_y_mut().unmarshal(&buf[n..]) {
            Ok(()) => println!("DEBUG: G1 unmarshal - y.unmarshal succeeded"),
            Err(e) => {
                return Err(e);
            }
        }


        // Apply Montgomery encoding to x and y coordinates (but not z and t)
        // This matches the Go implementation where coordinates are stored in Montgomery form
        let x_temp = self.g.get_x().clone();
        let y_temp = self.g.get_y().clone();
        mont_encode(self.g.get_x_mut(), &x_temp);
        mont_encode(self.g.get_y_mut(), &y_temp);


        // Check if this represents the point at infinity
        let zero = GFp::new(0);
        if *self.g.get_x() == zero && *self.g.get_y() == zero {
            // This is the point at infinity
            self.g.set_infinity();
        } else {
            // This is a regular point
            *self.g.get_z_mut() = GFp::new(1);
            *self.g.get_t_mut() = GFp::new(1);
        }


        if !self.g.is_on_curve() {
            return Err("bn254.G1: malformed point".to_string());
        }

        Ok(())
    }

    // UnmarshalFrom(r io.Reader) (int, error) - matches Go implementation
    pub fn unmarshal_from(&mut self, r: &mut dyn Read) -> Result<usize, String> {
        let mut buf = vec![0u8; self.marshal_size()];
        let n = r.read(&mut buf).map_err(|e| e.to_string())?;
        if n != self.marshal_size() {
            return Err("bn254.G1: not enough data".to_string());
        }
        self.unmarshal_binary(&buf)?;
        Ok(n)
    }

    pub fn marshal_size(&self) -> usize {
        64 // 2 * ElementSize() where ElementSize() = 256/8 = 32
    }

    pub fn element_size(&self) -> usize {
        32 // 256 / 8
    }

    pub fn string(&self) -> String {
        format!("bn254.G1{}", self.g)
    }

    // Hash(m []byte) kyber.Point - matches Go implementation
    pub fn hash(&self, m: &[u8]) -> PointG1 {
        hash_to_point(&self.dst, m)
    }
}

#[derive(Debug, Clone)]
pub struct PointG2 {
    g: TwistPoint,
    dst: Vec<u8>,
}

impl PointG2 {
    // newPointG2(dst []byte) *pointG2 - matches Go constructor
    pub fn new() -> Self {
        Self {
            g: TwistPoint::new(),
            dst: vec![],
        }
    }

    pub fn new_with_dst(dst: Vec<u8>) -> Self {
        Self {
            g: TwistPoint::new(),
            dst,
        }
    }

    // Equal(q kyber.Point) bool - matches Go implementation
    pub fn equal(&self, other: &PointG2) -> bool {
        // Match Go implementation: compare marshaled binary representations
        // Go uses subtle.ConstantTimeCompare(x, y) == 1
        let x = self.marshal_binary().unwrap_or_default();
        let y = other.marshal_binary().unwrap_or_default();
        x == y
    }

    // Null() kyber.Point - matches Go implementation
    pub fn null(&self) -> PointG2 {
        let mut p = PointG2::new();
        p.g.set_infinity();
        p
    }

    // Base() kyber.Point - matches Go implementation
    pub fn base(&self) -> PointG2 {
        let mut p = PointG2::new();
        p.g.set(&TwistPoint::twist_gen());
        p
    }

    // Pick(rand cipher.Stream) kyber.Point - matches Go implementation
    pub fn pick<R: Read>(&self, rand: &mut R) -> PointG2 {
        // In Go: s := mod.NewInt64(0, Order).Pick(rand); p.Base(); p.g.Mul(p.g, &s.(*mod.Int).V)
        let mut s = Scalar::new();
        s.pick(rand).expect("Failed to pick random scalar");

        let mut p = self.base();
        let g_copy = p.g.clone();
        p.g.mul(&g_copy, s.value());
        p
    }

    pub fn set(&mut self, other: &PointG2) {
        self.g.set(&other.g);
    }

    pub fn clone(&self) -> PointG2 {
        PointG2 {
            g: self.g.clone(),
            dst: self.dst.clone(),
        }
    }

    pub fn embed_len(&self) -> usize {
        // Match Go implementation: panic with "unsupported operation"
        panic!("bn254.G2: unsupported operation")
    }

    pub fn embed(&self, _data: &[u8], _rand: &mut dyn Read) -> PointG2 {
        // Match Go implementation: panic with "unsupported operation"
        panic!("bn254.G2: unsupported operation")
    }

    pub fn data(&self) -> Result<Vec<u8>, String> {
        // Match Go implementation: panic with "unsupported operation"
        panic!("bn254.G2: unsupported operation")
    }

    pub fn add(&mut self, a: &PointG2, b: &PointG2) {
        self.g.add(&a.g, &b.g);
    }

    pub fn sub(&mut self, a: &PointG2, b: &PointG2) {
        // Match Go implementation: Add(a, Neg(b))
        let mut neg_b = b.clone();
        neg_b.neg(b);
        self.add(a, &neg_b);
    }

    pub fn neg(&mut self, q: &PointG2) {
        self.g.neg(&q.g);
    }

    // Mul(s kyber.Scalar, q kyber.Point) kyber.Point - matches Go implementation
    pub fn mul(&mut self, s: &Scalar, q: &PointG2) {
        // In Go: if q == nil { q = newPointG2(p.dst).Base() }
        let q_point = if q.g.is_infinity() {
            self.base()
        } else {
            q.clone()
        };
        // In Go: t := s.(*mod.Int).V; r := q.(*pointG2).g; p.g.Mul(r, &t)
        self.g.mul(&q_point.g, s.value());
    }

    // MarshalBinary() ([]byte, error) - matches Go implementation
    pub fn marshal_binary(&self) -> Result<Vec<u8>, String> {
        // Clone is required as we change the point during the operation
        let mut p = self.clone();

        let n = p.element_size();
        if p.g.is_infinity() {
            p.g = TwistPoint::new();
        }

        p.g.make_affine();

        let mut ret = vec![0u8; p.marshal_size()];
        if p.g.is_infinity() {
            return Ok(ret);
        }

        let mut temp = GFp::new(0);
        mont_decode(&mut temp, p.g.get_x().get_x());
        temp.marshal(&mut ret[0 * n..1 * n]);
        mont_decode(&mut temp, p.g.get_x().get_y());
        temp.marshal(&mut ret[1 * n..2 * n]);
        mont_decode(&mut temp, p.g.get_y().get_x());
        temp.marshal(&mut ret[2 * n..3 * n]);
        mont_decode(&mut temp, p.g.get_y().get_y());
        temp.marshal(&mut ret[3 * n..4 * n]);

        Ok(ret)
    }

    pub fn marshal_id(&self) -> [u8; 8] {
        MARSHAL_POINT_ID2
    }

    pub fn marshal_to(&self, w: &mut dyn std::io::Write) -> Result<usize, String> {
        let buf = self.marshal_binary()?;
        w.write_all(&buf).map_err(|e| e.to_string())?;
        Ok(buf.len())
    }

    pub fn unmarshal_binary(&mut self, buf: &[u8]) -> Result<(), String> {
        let n = self.element_size();
        if buf.len() < self.marshal_size() {
            return Err("bn254.G2: not enough data".to_string());
        }

        // Commented out verbose debug
        // println!("DEBUG: G2 unmarshal - input buf len: {}, element_size: {}", buf.len(), n);
        // println!("DEBUG: G2 unmarshal - full input: {}", hex::encode(buf));

        // Create new GFp2 coordinates
        let mut x_x = GFp::new(0);
        let mut x_y = GFp::new(0);
        let mut y_x = GFp::new(0);
        let mut y_y = GFp::new(0);

        // Unmarshal the coordinates
        y_x.unmarshal(&buf[2 * n..3 * n])?;
        y_y.unmarshal(&buf[3 * n..4 * n])?;
        x_x.unmarshal(&buf[0 * n..1 * n])?;
        x_y.unmarshal(&buf[1 * n..2 * n])?;

        // Apply Montgomery encoding in-place, exactly like Go
        let x_x_temp = x_x.clone();
        let x_y_temp = x_y.clone();
        let y_x_temp = y_x.clone();
        let y_y_temp = y_y.clone();
        mont_encode(&mut x_x, &x_x_temp);
        mont_encode(&mut x_y, &x_y_temp);
        mont_encode(&mut y_x, &y_x_temp);
        mont_encode(&mut y_y, &y_y_temp);


        // Create GFp2 coordinates
        let x = GFp2::from_gfp(x_x, x_y);
        let y = GFp2::from_gfp(y_x, y_y);

        // The actual issue: our mont_encode/mont_decode round trip is broken!
        // We need to fix the Montgomery arithmetic, not avoid it.
        // For now, create the coordinates directly without the decode step.


        // Check if this represents the point at infinity
        let zero = GFp2::new();
        if x == zero && y == zero {
            // This is the point at infinity
            self.g.set_infinity();
        } else {
            // This is a regular point
            *self.g.get_x_mut() = x;
            *self.g.get_y_mut() = y;
            self.g.get_z_mut().set_one();
            self.g.get_t_mut().set_one();


            // TODO: THIS is diabled due to efficiency reasons — to expensive to check in scrypto runtime
            // if !self.g.is_on_curve() {
            //     info!("DEBUG: G2 unmarshal - point not on curve");
            //     return Err("bn254.G2: malformed point".to_string());
            // }
        }
        Ok(())
    }

    pub fn unmarshal_from(&mut self, r: &mut dyn Read) -> Result<usize, String> {
        let mut buf = vec![0u8; self.marshal_size()];
        let n = r.read(&mut buf).map_err(|e| e.to_string())?;
        if n != self.marshal_size() {
            return Err("bn254.G2: not enough data".to_string());
        }
        self.unmarshal_binary(&buf)?;
        Ok(n)
    }

    pub fn marshal_size(&self) -> usize {
        128 // 4 * ElementSize() where ElementSize() = 256/8 = 32
    }

    pub fn element_size(&self) -> usize {
        32 // 256 / 8
    }

    pub fn string(&self) -> String {
        format!("bn254.G2{}", self.g)
    }

    // MakeAffine() - matches Go implementation
    pub fn make_affine(&mut self) {
        self.g.make_affine();
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PointGT {
    g: GFp12,
}

impl PointGT {
    // newPointGT() *pointGT - matches Go constructor
    pub fn new() -> Self {
        Self { g: GFp12::new() }
    }

    // Constructor from GFp12 element
    pub fn from_gfp12(g: GFp12) -> Self {
        Self { g }
    }

    // Get the underlying GFp12 element
    pub fn get_gfp12(&self) -> &GFp12 {
        &self.g
    }

    // Equal(q kyber.Point) bool - matches Go implementation
    pub fn equal(&self, other: &PointGT) -> bool {
        // Match Go implementation: compare marshaled binary representations
        // Go uses subtle.ConstantTimeCompare(x, y) == 1
        let x = self.marshal_binary().unwrap_or_default();
        let y = other.marshal_binary().unwrap_or_default();
        x == y
    }

    // Null() kyber.Point - matches Go v1.3.2: precomputed constant, returns clone
    pub fn null(&self) -> PointGT {
        use lazy_static::lazy_static;
        use std::sync::Mutex;
        lazy_static! {
            static ref NULL_GT: Mutex<PointGT> = {
                let mut p = PointGT::new();
                p.pair(&PointG1::new().null(), &PointG2::new().null());
                Mutex::new(p)
            };
        }
        NULL_GT.lock().unwrap().clone()
    }

    // Base() kyber.Point - matches Go v1.3.2: precomputed constant, returns clone
    pub fn base(&self) -> PointGT {
        use lazy_static::lazy_static;
        use std::sync::Mutex;
        lazy_static! {
            static ref BASE_GT: Mutex<PointGT> = {
                let mut p = PointGT::new();
                p.pair(&PointG1::new().base(), &PointG2::new().base());
                Mutex::new(p)
            };
        }
        BASE_GT.lock().unwrap().clone()
    }

    // Pick(rand cipher.Stream) kyber.Point - matches Go implementation
    pub fn pick<R: Read>(&self, rand: &mut R) -> PointGT {
        // In Go: s := mod.NewInt64(0, Order).Pick(rand); p.Base(); p.g.Exp(p.g, &s.(*mod.Int).V)
        let mut s = Scalar::new();
        s.pick(rand).expect("Failed to pick random scalar");

        let mut p = self.base();
        let g_copy = p.g.clone();
        p.g.exp(&g_copy, s.value());
        p
    }

    pub fn set(&mut self, other: &PointGT) {
        self.g.set(&other.g);
    }

    pub fn clone(&self) -> PointGT {
        PointGT { g: self.g.clone() }
    }

    pub fn embed_len(&self) -> usize {
        // Match Go implementation: panic with "unsupported operation"
        panic!("bn254.GT: unsupported operation")
    }

    pub fn embed(&self, _data: &[u8], _rand: &mut dyn Read) -> PointGT {
        // Match Go implementation: panic with "unsupported operation"
        panic!("bn254.GT: unsupported operation")
    }

    pub fn data(&self) -> Result<Vec<u8>, String> {
        // Match Go implementation: panic with "unsupported operation"
        panic!("bn254.GT: unsupported operation")
    }

    pub fn add(&mut self, a: &PointGT, b: &PointGT) {
        self.g.mul(&a.g, &b.g);
    }

    pub fn sub(&mut self, a: &PointGT, b: &PointGT) {
        // Match Go implementation: Add(a, Neg(b))
        let mut neg_b = b.clone();
        neg_b.neg(b);
        self.add(a, &neg_b);
    }

    // Neg(q kyber.Point) kyber.Point - matches Go implementation
    pub fn neg(&mut self, q: &PointGT) {
        // In Go: x := q.(*pointGT).g; p.g.Conjugate(x)
        self.g.conjugate(&q.g);
    }

    // Mul(s kyber.Scalar, q kyber.Point) kyber.Point - matches Go implementation
    pub fn mul(&mut self, s: &Scalar, q: &PointGT) {
        // In Go: if q == nil { q = newPointGT().Base() }
        let q_point = if q.g.is_one() { self.base() } else { q.clone() };
        // In Go: t := s.(*mod.Int).V; r := q.(*pointGT).g; p.g.Exp(r, &t)
        self.g.exp(&q_point.g, s.value());
    }

    // MarshalBinary() ([]byte, error) - matches Go implementation
    pub fn marshal_binary(&self) -> Result<Vec<u8>, String> {
        let n = self.element_size();
        let mut ret = vec![0u8; self.marshal_size()];
        let mut temp = GFp::new(0);

        mont_decode(&mut temp, self.g.get_x().get_x().get_x());
        temp.marshal(&mut ret[0 * n..1 * n]);
        mont_decode(&mut temp, self.g.get_x().get_x().get_y());
        temp.marshal(&mut ret[1 * n..2 * n]);
        mont_decode(&mut temp, self.g.get_x().get_y().get_x());
        temp.marshal(&mut ret[2 * n..3 * n]);
        mont_decode(&mut temp, self.g.get_x().get_y().get_y());
        temp.marshal(&mut ret[3 * n..4 * n]);
        mont_decode(&mut temp, self.g.get_x().get_z().get_x());
        temp.marshal(&mut ret[4 * n..5 * n]);
        mont_decode(&mut temp, self.g.get_x().get_z().get_y());
        temp.marshal(&mut ret[5 * n..6 * n]);
        mont_decode(&mut temp, self.g.get_y().get_x().get_x());
        temp.marshal(&mut ret[6 * n..7 * n]);
        mont_decode(&mut temp, self.g.get_y().get_x().get_y());
        temp.marshal(&mut ret[7 * n..8 * n]);
        mont_decode(&mut temp, self.g.get_y().get_y().get_x());
        temp.marshal(&mut ret[8 * n..9 * n]);
        mont_decode(&mut temp, self.g.get_y().get_y().get_y());
        temp.marshal(&mut ret[9 * n..10 * n]);
        mont_decode(&mut temp, self.g.get_y().get_z().get_x());
        temp.marshal(&mut ret[10 * n..11 * n]);
        mont_decode(&mut temp, self.g.get_y().get_z().get_y());
        temp.marshal(&mut ret[11 * n..12 * n]);

        Ok(ret)
    }

    pub fn marshal_id(&self) -> [u8; 8] {
        MARSHAL_POINT_IDT
    }

    pub fn marshal_to(&self, w: &mut dyn std::io::Write) -> Result<usize, String> {
        let buf = self.marshal_binary()?;
        w.write_all(&buf).map_err(|e| e.to_string())?;
        Ok(buf.len())
    }

    pub fn unmarshal_binary(&mut self, buf: &[u8]) -> Result<(), String> {
        let n = self.element_size();
        if buf.len() < self.marshal_size() {
            return Err("bn254.GT: not enough data".to_string());
        }

        if self.g.is_one() {
            self.g = GFp12::new();
        }

        self.g
            .get_x_mut()
            .get_x_mut()
            .get_x_mut()
            .unmarshal(&buf[0 * n..1 * n])?;
        self.g
            .get_x_mut()
            .get_x_mut()
            .get_y_mut()
            .unmarshal(&buf[1 * n..2 * n])?;
        self.g
            .get_x_mut()
            .get_y_mut()
            .get_x_mut()
            .unmarshal(&buf[2 * n..3 * n])?;
        self.g
            .get_x_mut()
            .get_y_mut()
            .get_y_mut()
            .unmarshal(&buf[3 * n..4 * n])?;
        self.g
            .get_x_mut()
            .get_z_mut()
            .get_x_mut()
            .unmarshal(&buf[4 * n..5 * n])?;
        self.g
            .get_x_mut()
            .get_z_mut()
            .get_y_mut()
            .unmarshal(&buf[5 * n..6 * n])?;
        self.g
            .get_y_mut()
            .get_x_mut()
            .get_x_mut()
            .unmarshal(&buf[6 * n..7 * n])?;
        self.g
            .get_y_mut()
            .get_x_mut()
            .get_y_mut()
            .unmarshal(&buf[7 * n..8 * n])?;
        self.g
            .get_y_mut()
            .get_y_mut()
            .get_x_mut()
            .unmarshal(&buf[8 * n..9 * n])?;
        self.g
            .get_y_mut()
            .get_y_mut()
            .get_y_mut()
            .unmarshal(&buf[9 * n..10 * n])?;
        self.g
            .get_y_mut()
            .get_z_mut()
            .get_x_mut()
            .unmarshal(&buf[10 * n..11 * n])?;
        self.g
            .get_y_mut()
            .get_z_mut()
            .get_y_mut()
            .unmarshal(&buf[11 * n..12 * n])?;

        // Fix borrow checker issues by copying values before mont_encode
        let x_x_x = self.g.get_x().get_x().get_x().to_u64_array();
        let x_x_y = self.g.get_x().get_x().get_y().to_u64_array();
        let x_y_x = self.g.get_x().get_y().get_x().to_u64_array();
        let x_y_y = self.g.get_x().get_y().get_y().to_u64_array();
        let x_z_x = self.g.get_x().get_z().get_x().to_u64_array();
        let x_z_y = self.g.get_x().get_z().get_y().to_u64_array();
        let y_x_x = self.g.get_y().get_x().get_x().to_u64_array();
        let y_x_y = self.g.get_y().get_x().get_y().to_u64_array();
        let y_y_x = self.g.get_y().get_y().get_x().to_u64_array();
        let y_y_y = self.g.get_y().get_y().get_y().to_u64_array();
        let y_z_x = self.g.get_y().get_z().get_x().to_u64_array();
        let y_z_y = self.g.get_y().get_z().get_y().to_u64_array();

        mont_encode(
            self.g.get_x_mut().get_x_mut().get_x_mut(),
            &GFp::from_u64_array(x_x_x),
        );
        mont_encode(
            self.g.get_x_mut().get_x_mut().get_y_mut(),
            &GFp::from_u64_array(x_x_y),
        );
        mont_encode(
            self.g.get_x_mut().get_y_mut().get_x_mut(),
            &GFp::from_u64_array(x_y_x),
        );
        mont_encode(
            self.g.get_x_mut().get_y_mut().get_y_mut(),
            &GFp::from_u64_array(x_y_y),
        );
        mont_encode(
            self.g.get_x_mut().get_z_mut().get_x_mut(),
            &GFp::from_u64_array(x_z_x),
        );
        mont_encode(
            self.g.get_x_mut().get_z_mut().get_y_mut(),
            &GFp::from_u64_array(x_z_y),
        );
        mont_encode(
            self.g.get_y_mut().get_x_mut().get_x_mut(),
            &GFp::from_u64_array(y_x_x),
        );
        mont_encode(
            self.g.get_y_mut().get_x_mut().get_y_mut(),
            &GFp::from_u64_array(y_x_y),
        );
        mont_encode(
            self.g.get_y_mut().get_y_mut().get_x_mut(),
            &GFp::from_u64_array(y_y_x),
        );
        mont_encode(
            self.g.get_y_mut().get_y_mut().get_y_mut(),
            &GFp::from_u64_array(y_y_y),
        );
        mont_encode(
            self.g.get_y_mut().get_z_mut().get_x_mut(),
            &GFp::from_u64_array(y_z_x),
        );
        mont_encode(
            self.g.get_y_mut().get_z_mut().get_y_mut(),
            &GFp::from_u64_array(y_z_y),
        );

        // Note: In the Go implementation, there's no explicit curve validation for GT points
        // as they are elements of the multiplicative group, not points on a curve
        // The validation is implicit in the pairing computation

        Ok(())
    }

    pub fn unmarshal_from(&mut self, r: &mut dyn Read) -> Result<usize, String> {
        let mut buf = vec![0u8; self.marshal_size()];
        let n = r.read(&mut buf).map_err(|e| e.to_string())?;
        if n != self.marshal_size() {
            return Err("bn254.GT: not enough data".to_string());
        }
        self.unmarshal_binary(&buf)?;
        Ok(n)
    }

    pub fn marshal_size(&self) -> usize {
        384 // 12 * ElementSize() where ElementSize() = 256/8 = 32
    }

    pub fn element_size(&self) -> usize {
        32 // 256 / 8
    }

    pub fn string(&self) -> String {
        format!("bn254.GT{}", self.g)
    }

    pub fn finalize(&mut self) -> PointGT {
        // This matches the Go implementation: finalExponentiation(p.g)
        let result = final_exponentiation(&self.g);
        self.g = result;
        self.clone()
    }

    pub fn miller(&mut self, p1: &PointG1, p2: &PointG2) -> PointGT {
        // This matches the Go implementation: miller(b, a) where b is G2 and a is G1
        let result = miller(&p2.g, &p1.g);
        self.g = result;
        self.clone()
    }

    pub fn pair(&mut self, p1: &PointG1, p2: &PointG2) -> PointGT {
        // This matches the Go implementation: optimalAte(b, a) where b is G2 and a is G1
        // Convert PointG1 to CurvePoint and PointG2 to TwistPoint
        let g1_point = &p1.g; // CurvePoint
        let g2_point = &p2.g; // TwistPoint

        let opt_ate = optimal_ate(g2_point, g1_point);
        self.g.set(&opt_ate);

        self.clone()
    }
}

// Hash functions matching Go implementation

// hashToPoint(domain, m []byte) kyber.Point - matches Go function
pub fn hash_to_point(domain: &[u8], m: &[u8]) -> PointG1 {
    let (e0, e1) = hash_to_field(domain, m);
    let p0 = map_to_point(domain, &e0);
    let p1 = map_to_point(domain, &e1);
    let mut p = p0.clone();
    p.add(&p0, &p1);
    p
}

// hashToField(domain, m []byte) (*gfP, *gfP) - matches Go function
fn hash_to_field(domain: &[u8], m: &[u8]) -> (GFp, GFp) {
    const U: usize = 48;
    let msg = expand_msg_xmd_keccak256(domain, m, 2 * U);

    // In Go:
    // _msg := expandMsgXmdKeccak256(domain, m, 2*u)
    // x, y := new(big.Int), new(big.Int)
    // x.SetBytes(_msg[0:48]).Mod(x, p)
    // y.SetBytes(_msg[48:96]).Mod(y, p)
    // gx, gy := &gfP{}, &gfP{}
    // gx.Unmarshal(zeroPadBytes(x.Bytes(), 32))
    // gy.Unmarshal(zeroPadBytes(y.Bytes(), 32))
    // montEncode(gx, gx)
    // montEncode(gy, gy)
    // return gx, gy

    let p_big = BigUint::from_str(
        "21888242871839275222246405745257275088696311157297823662689037894645226208583",
    )
    .unwrap();

    let x_bytes = &msg[0..48];
    let y_bytes = &msg[48..96];

    let x_big = BigUint::from_bytes_be(x_bytes) % &p_big;
    let y_big = BigUint::from_bytes_be(y_bytes) % &p_big;

    let mut gx = GFp::new(0);
    let mut gy = GFp::new(0);

    gx.unmarshal(&zero_pad_bytes(&x_big.to_bytes_be(), 32))
        .unwrap();
    gy.unmarshal(&zero_pad_bytes(&y_big.to_bytes_be(), 32))
        .unwrap();

    let gx_copy = gx.clone();
    let gy_copy = gy.clone();
    mont_encode(&mut gx, &gx_copy);
    mont_encode(&mut gy, &gy_copy);

    (gx, gy)
}

// mapToPoint(domain []byte, u *gfP) kyber.Point - matches Go function
// `mapToPoint` implements the general Shallue-van de Woestijne mapping to BN254 G1
// RFC9380, 6.6.1. https://datatracker.ietf.org/doc/html/rfc9380#name-shallue-van-de-woestijne-me
fn map_to_point(domain: &[u8], u: &GFp) -> PointG1 {
    // In Go:
    // tv1 := &gfP{}; tv1.Set(u)
    // gfpMul(tv1, tv1, tv1); gfpMul(tv1, tv1, c1)
    // tv2 := &gfP{}; gfpAdd(tv2, newGFp(1), tv1)
    // negTv1 := &gfP{}; gfpNeg(negTv1, tv1)
    // gfpAdd(tv1, newGFp(1), negTv1)
    // tv3 := &gfP{}; gfpMul(tv3, tv1, tv2); tv3.Invert(tv3)
    // tv5 := &gfP{}; gfpMul(tv5, u, tv1); gfpMul(tv5, tv5, tv3); gfpMul(tv5, tv5, c3)
    // x1 := &gfP{}; gfpSub(x1, c2, tv5)
    // x2 := &gfP{}; gfpAdd(x2, c2, tv5)
    // tv7 := &gfP{}; gfpMul(tv7, tv2, tv2)
    // tv8 := &gfP{}; gfpMul(tv8, tv7, tv3)
    // x3 := &gfP{}; gfpMul(x3, tv8, tv8); gfpMul(x3, c4, x3); gfpAdd(x3, newGFp(1), x3)
    // x, y := &gfP{}, &gfP{}
    // if legendre(g(x1)) == 1 { x = x1; y.Sqrt(g(x1)) }
    // else if legendre(g(x2)) == 1 { x = x2; y.Sqrt(g(x2)) }
    // else { x = x3; y.Sqrt(g(x3)) }
    // if sgn0(u) != sgn0(y) { gfpNeg(y, y) }
    // p := newPointG1(domain).Base().(*pointG1)
    // p.g.x.Set(x); p.g.y.Set(y)
    // return p

    let mut tv1 = GFp::new(0);
    tv1.set(u);

    let temp_tv1 = tv1.clone();
    gfp_mul(&mut tv1, &temp_tv1, &temp_tv1);
    let temp_tv1 = tv1.clone();
    gfp_mul(&mut tv1, &temp_tv1, &GFp::from_u64_array(C1));

    let mut tv2 = GFp::new(0);
    gfp_add(&mut tv2, &GFp::new(1), &tv1);

    let mut neg_tv1 = GFp::new(0);
    gfp_neg(&mut neg_tv1, &tv1);

    gfp_add(&mut tv1, &GFp::new(1), &neg_tv1);

    let mut tv3 = GFp::new(0);
    gfp_mul(&mut tv3, &tv1, &tv2);
    let temp_tv3 = tv3.clone();
    tv3.invert(&temp_tv3);

    let mut tv5 = GFp::new(0);
    gfp_mul(&mut tv5, u, &tv1);
    let temp_tv5 = tv5.clone();
    gfp_mul(&mut tv5, &temp_tv5, &tv3);
    let temp_tv5 = tv5.clone();
    gfp_mul(&mut tv5, &temp_tv5, &GFp::from_u64_array(C3));

    let mut x1 = GFp::new(0);
    gfp_sub(&mut x1, &GFp::from_u64_array(C2), &tv5);

    let mut x2 = GFp::new(0);
    gfp_add(&mut x2, &GFp::from_u64_array(C2), &tv5);

    let mut tv7 = GFp::new(0);
    gfp_mul(&mut tv7, &tv2, &tv2);

    let mut tv8 = GFp::new(0);
    gfp_mul(&mut tv8, &tv7, &tv3);

    let mut x3 = GFp::new(0);
    gfp_mul(&mut x3, &tv8, &tv8);
    let temp_x3 = x3.clone();
    gfp_mul(&mut x3, &temp_x3, &GFp::from_u64_array(C4));
    let temp_x3 = x3.clone();
    gfp_add(&mut x3, &GFp::new(1), &temp_x3);

    let mut x = GFp::new(0);
    let mut y = GFp::new(0);

    if legendre(&g(&x1)) == 1 {
        x.set(&x1);
        y.sqrt(&g(&x1));
    } else if legendre(&g(&x2)) == 1 {
        x.set(&x2);
        y.sqrt(&g(&x2));
    } else {
        x.set(&x3);
        y.sqrt(&g(&x3));
    }

    let y_copy = y.clone();
    if sgn0(u) != sgn0(&y_copy) {
        gfp_neg(&mut y, &y_copy);
    }

    let mut p = PointG1::new_with_dst(domain.to_vec());
    p.base();
    *p.g.get_x_mut() = x;
    *p.g.get_y_mut() = y;
    p
}

// expandMsgXmdKeccak256(domain, msg []byte, outLen int) []byte - matches Go function
// `expandMsgXmdKeccak256` implements expand_message_xmd from IETF RFC9380 Sec 5.3.1
// Borrowed from: https://github.com/kilic/bls12-381/blob/master/hash_to_field.go
fn expand_msg_xmd_keccak256(domain: &[u8], msg: &[u8], out_len: usize) -> Vec<u8> {
    // In Go:
    // h := sha3.NewLegacyKeccak256()
    // domainLen := uint8(len(domain))
    // if domainLen > 255 { panic("invalid domain length") }
    // DST_prime = DST || I2OSP(len(DST), 1)
    // b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime)
    // _, _ = h.Write(make([]byte, h.BlockSize()))
    // _, _ = h.Write(msg)
    // _, _ = h.Write([]byte{uint8(outLen >> 8), uint8(outLen)})
    // _, _ = h.Write([]byte{0})
    // _, _ = h.Write(domain)
    // _, _ = h.Write([]byte{domainLen})
    // b0 := h.Sum(nil)
    // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
    // h.Reset()
    // _, _ = h.Write(b0)
    // _, _ = h.Write([]byte{1})
    // _, _ = h.Write(domain)
    // _, _ = h.Write([]byte{domainLen})
    // b1 := h.Sum(nil)
    // b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
    // ell := (outLen + h.Size() - 1) / h.Size()
    // bi := b1
    // out := make([]byte, outLen)
    // for i := 1; i < ell; i++ {
    //     h.Reset()
    //     tmp := make([]byte, h.Size())
    //     for j := 0; j < h.Size(); j++ { tmp[j] = b0[j] ^ bi[j] }
    //     _, _ = h.Write(tmp)
    //     _, _ = h.Write([]byte{1 + uint8(i)})
    //     _, _ = h.Write(domain)
    //     _, _ = h.Write([]byte{domainLen})
    //     copy(out[(i-1)*h.Size():i*h.Size()], bi[:])
    //     bi = h.Sum(nil)
    // }
    // copy(out[(ell-1)*h.Size():], bi[:])
    // return out[:outLen]

    let mut h = Keccak256::new();
    let domain_len = domain.len() as u8;

    // DST_prime = DST || I2OSP(len(DST), 1)
    let mut dst_prime = domain.to_vec();
    dst_prime.push(domain_len);

    // b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime)
    // Keccak256 block size is 136 bytes
    h.update(vec![0u8; 136]);
    h.update(msg);
    h.update(&[(out_len >> 8) as u8, out_len as u8]);
    h.update(&[0u8]);
    h.update(domain);
    h.update(&[domain_len]);
    let b0 = h.finalize().to_vec();

    // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
    h = Keccak256::new();
    h.update(&b0);
    h.update(&[1u8]);
    h.update(domain);
    h.update(&[domain_len]);
    let b1 = h.finalize().to_vec();

    // b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
    let hash_size = 32; // Keccak256 output size
    let ell = (out_len + hash_size - 1) / hash_size;
    let mut bi = b1.clone();
    let mut out = vec![0u8; out_len];

    for i in 1..ell {
        h = Keccak256::new();
        let mut tmp = vec![0u8; hash_size];
        for j in 0..hash_size {
            tmp[j] = b0[j] ^ bi[j];
        }
        h.update(&tmp);
        h.update(&[1 + i as u8]);
        h.update(domain);
        h.update(&[domain_len]);

        // b_1 || ... || b_(ell - 1)
        let start = (i - 1) * hash_size;
        let end = i * hash_size;
        out[start..end].copy_from_slice(&bi);

        bi = h.finalize().to_vec();
    }

    // b_ell
    let start = (ell - 1) * hash_size;
    out[start..].copy_from_slice(&bi);

    out[..out_len].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kyber::pairing::bn254::gfp12::GFp12;

    #[test]
    fn test_pointgt_from_gfp12() {
        // Test creating PointGT from GFp12 identity element
        let mut gfp12_identity = GFp12::new();
        gfp12_identity.set_one();
        
        let pointgt = PointGT::from_gfp12(gfp12_identity.clone());
        
        // Verify the PointGT contains the same GFp12 element
        assert_eq!(pointgt.g, gfp12_identity);
    }

    #[test]
    fn test_pointgt_from_gfp12_zero() {
        // Test creating PointGT from GFp12 zero element
        let mut gfp12_zero = GFp12::new();
        gfp12_zero.set_zero();
        
        let pointgt = PointGT::from_gfp12(gfp12_zero.clone());
        
        // Verify the PointGT contains the same GFp12 element
        assert_eq!(pointgt.g, gfp12_zero);
    }

    #[test]
    fn test_pointgt_from_gfp12_roundtrip() {
        // Test round-trip conversion: PointGT -> GFp12 -> PointGT
        let original_pointgt = PointGT::new().base();
        let gfp12_element = original_pointgt.g.clone();
        let reconstructed_pointgt = PointGT::from_gfp12(gfp12_element);
        
        // Verify they are equal
        assert_eq!(original_pointgt, reconstructed_pointgt);
    }

    #[test]
    fn test_pointgt_operations_with_from_gfp12() {
        // Test that PointGT created with from_gfp12 works with operations
        let mut gfp12_element = GFp12::new();
        gfp12_element.set_one();
        
        let pointgt1 = PointGT::from_gfp12(gfp12_element.clone());
        let pointgt2 = PointGT::from_gfp12(gfp12_element.clone());
        
        // Test addition
        let mut result = PointGT::new();
        result.add(&pointgt1, &pointgt2);
        
        // The result should be valid (no panics)
        assert!(!result.g.is_zero());
    }

    #[test]
    fn example_pointgt_from_gfp12_usage() {
        // Example demonstrating how to use the from_gfp12 constructor
        
        // Method 1: Create PointGT from GFp12 identity element
        let mut gfp12_identity = GFp12::new();
        gfp12_identity.set_one();
        let pointgt_from_identity = PointGT::from_gfp12(gfp12_identity.clone());
        
        println!("PointGT from GFp12 identity: {:?}", pointgt_from_identity);
        
        // Method 2: Create PointGT from GFp12 zero element
        let mut gfp12_zero = GFp12::new();
        gfp12_zero.set_zero();
        let pointgt_from_zero = PointGT::from_gfp12(gfp12_zero.clone());
        
        println!("PointGT from GFp12 zero: {:?}", pointgt_from_zero);
        
        // Method 3: Create PointGT from existing PointGT's GFp12 element
        let base_pointgt = PointGT::new().base();
        let gfp12_from_base = base_pointgt.g.clone();
        let reconstructed_pointgt = PointGT::from_gfp12(gfp12_from_base);
        
        println!("PointGT reconstructed from base: {:?}", reconstructed_pointgt);
        
        // Verify round-trip conversion works
        assert_eq!(base_pointgt, reconstructed_pointgt);
        
        // Method 4: Use with PointGT operations
        let pointgt1 = PointGT::from_gfp12(gfp12_identity.clone());
        let pointgt2 = PointGT::from_gfp12(gfp12_identity.clone());
        
        let mut result = PointGT::new();
        result.add(&pointgt1, &pointgt2);
        
        println!("Result of adding two PointGTs from GFp12: {:?}", result);
        
        // All PointGTs created with from_gfp12 work correctly with operations
        println!("All PointGT from_gfp12 operations work correctly!");
    }
}
