use crate::kyber::pairing::bn254::constants::{
    big_from_base10, NP, P, P2, P_MINUS_1_OVER_2, P_PLUS_1_OVER_4, R2, R3, RN1,
};
use hex;
use std::ops::{Add, Mul, Neg, Sub};

// Helper function to zero-pad bytes to a specific length
fn zero_pad_bytes(bytes: &[u8], outlen: usize) -> Vec<u8> {
    if bytes.len() < outlen {
        let padlen = outlen - bytes.len();
        let mut result = vec![0u8; padlen];
        result.extend_from_slice(bytes);
        result
    } else {
        bytes.to_vec()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GFp {
    value: [u64; 4],
}

impl GFp {
    pub fn new(x: i64) -> Self {
        let mut value = [0u64; 4];
        if x >= 0 {
            value[0] = x as u64;
        } else {
            // Handle negative numbers by negating the absolute value
            value[0] = (-x) as u64;
            let mut result = Self { value };
            let temp = result.clone();
            gfp_neg(&mut result, &temp);
            let temp = result.clone();
            mont_encode(&mut result, &temp);
            return result;
        }
        let mut result = Self { value };
        let temp = result.clone();
        mont_encode(&mut result, &temp);
        result
    }

    pub fn from_base10(x: &str) -> Self {
        let big_int = big_from_base10(x);
        let p = big_from_base10(P);
        let reduced = big_int % p;
        let mut value = [0u64; 4];
        let bytes = zero_pad_bytes(&reduced.to_bytes_le(), 32);
        for (i, chunk) in bytes.chunks(8).enumerate().take(4) {
            let mut val = 0u64;
            for (j, &byte) in chunk.iter().enumerate() {
                val |= (byte as u64) << (j * 8);
            }
            value[i] = val;
        }
        let mut result = Self { value };
        let temp = result.clone();
        mont_encode(&mut result, &temp);
        result
    }

    pub fn set(&mut self, other: &GFp) {
        self.value = other.value;
    }

    pub fn invert(&mut self, f: &GFp) {
        let bits = [
            0x3c208c16d87cfd45,
            0x97816a916871ca8d,
            0xb85045b68181585d,
            0x30644e72e131a029,
        ];
        self.exp(f, bits);
    }

    pub fn exp(&mut self, f: &GFp, bits: [u64; 4]) {
        let mut sum = GFp::from_u64_array(RN1);
        let mut power = GFp::new(0);
        power.set(f);

        for word in 0..4 {
            for bit in 0..64 {
                if (bits[word] >> bit) & 1 == 1 {
                    let temp_sum = sum.clone();
                    let temp_power = power.clone();
                    gfp_mul(&mut sum, &temp_sum, &temp_power);
                }
                let temp_power = power.clone();
                gfp_mul(&mut power, &temp_power, &temp_power);
            }
        }

        let temp_sum = sum.clone();
        gfp_mul(&mut sum, &temp_sum, &GFp::from_u64_array(R3));
        self.set(&sum);
    }

    pub fn sqrt(&mut self, f: &GFp) {
        // Since p = 4k+3, then e = f^(k+1) is a root of f.
        self.exp(f, P_PLUS_1_OVER_4);
    }

    pub fn marshal(&self, out: &mut [u8]) {
        for w in 0..4 {
            for b in 0..8 {
                out[8 * w + b] = (self.value[3 - w] >> (56 - 8 * b)) as u8;
            }
        }
    }

    pub fn unmarshal(&mut self, input: &[u8]) -> Result<(), String> {
        if input.len() != 32 {
            return Err("Invalid input length".to_string());
        }

        println!("DEBUG: GFp unmarshal - input bytes: {}", hex::encode(input));

        // Unmarshal the bytes into little-endian u64 words, matching Go exactly
        for w in 0..4 {
            self.value[3 - w] = 0;
            for b in 0..8 {
                let byte = input[8 * w + b];
                self.value[3 - w] += (byte as u64) << (56 - 8 * b);
            }
            println!(
                "DEBUG: GFp unmarshal - word {} (index {}): {:016x}",
                w,
                3 - w,
                self.value[3 - w]
            );
        }

        println!(
            "DEBUG: GFp unmarshal - raw stored value: {:016x}{:016x}{:016x}{:016x}",
            self.value[3], self.value[2], self.value[1], self.value[0]
        );

        // Check if the value is less than the modulus
        for i in (0..4).rev() {
            if self.value[i] < P2[i] {
                println!("DEBUG: GFp unmarshal - modulus check passed");
                return Ok(());
            }
            if self.value[i] > P2[i] {
                return Err("bn254: coordinate exceeds modulus".to_string());
            }
        }
        Err("bn254: coordinate equals modulus".to_string())
    }

    pub fn from_u64_array(arr: [u64; 4]) -> Self {
        Self { value: arr }
    }

    pub fn to_u64_array(&self) -> [u64; 4] {
        self.value
    }
}

impl Add for GFp {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let mut result = Self::new(0);
        gfp_add(&mut result, &self, &other);
        result
    }
}

impl Sub for GFp {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        let mut result = Self::new(0);
        gfp_sub(&mut result, &self, &other);
        result
    }
}

impl Mul for GFp {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        let mut result = Self::new(0);
        gfp_mul(&mut result, &self, &other);
        result
    }
}

impl Neg for GFp {
    type Output = Self;

    fn neg(self) -> Self {
        let mut result = Self::new(0);
        gfp_neg(&mut result, &self);
        result
    }
}

// Montgomery encoding/decoding
pub fn mont_encode(c: &mut GFp, a: &GFp) {
    let r2 = GFp::from_u64_array(R2);
    gfp_mul(c, a, &r2);
}

pub fn mont_decode(c: &mut GFp, a: &GFp) {
    // Montgomery decode by multiplying by 1 (raw, not Montgomery-encoded)
    // This matches the Go implementation: gfpMul(c, a, &gfP{1})
    let one = GFp {
        value: [1, 0, 0, 0],
    }; // Raw 1, not Montgomery-encoded
    gfp_mul(c, a, &one);
}

pub fn sgn0(e: &GFp) -> i32 {
    let mut x = GFp::new(0);
    mont_decode(&mut x, e);
    (x.value[0] & 1) as i32
}

pub fn legendre(e: &GFp) -> i32 {
    let mut f = GFp::new(0);
    // Since p = 4k+3, then e^(2k+1) is the Legendre symbol of e.
    f.exp(e, P_MINUS_1_OVER_2);
    let temp_f = f.clone();
    mont_decode(&mut f, &temp_f);

    if f.value != [0u64; 4] {
        return 2 * (f.value[0] & 1) as i32 - 1;
    }
    0
}

// Helper functions for modular arithmetic
fn gfp_carry(a: &mut [u64; 4], head: u64) {
    let mut b = [0u64; 4];
    let mut carry = 0u64;

    for i in 0..4 {
        let ai = a[i];
        let pi = P2[i];
        let bi = ai.wrapping_sub(pi).wrapping_sub(carry);
        b[i] = bi;
        carry = (pi & !ai | (pi | !ai) & bi) >> 63;
    }
    carry = carry & !head;

    // If b is negative, then return a.
    // Else return b.
    carry = (!carry).wrapping_add(1);
    let ncarry = !carry;
    for i in 0..4 {
        a[i] = (a[i] & carry) | (b[i] & ncarry);
    }
}

pub fn gfp_neg(c: &mut GFp, a: &GFp) {
    let mut carry = 0u64;
    for i in 0..4 {
        let ai = a.value[i];
        let pi = P2[i];
        let ci = pi.wrapping_sub(ai).wrapping_sub(carry);
        c.value[i] = ci;
        carry = (ai & !pi | (ai | !pi) & ci) >> 63;
    }
    gfp_carry(&mut c.value, 0);
}

pub fn gfp_add(c: &mut GFp, a: &GFp, b: &GFp) {
    let mut carry = 0u64;
    for i in 0..4 {
        let ai = a.value[i];
        let bi = b.value[i];
        let ci = ai.wrapping_add(bi).wrapping_add(carry);
        c.value[i] = ci;
        carry = (ai & bi | (ai | bi) & !ci) >> 63;
    }
    gfp_carry(&mut c.value, carry);
}

pub fn gfp_sub(c: &mut GFp, a: &GFp, b: &GFp) {
    let mut t = [0u64; 4];
    let mut carry = 0u64;

    for i in 0..4 {
        let pi = P2[i];
        let bi = b.value[i];
        let ti = pi.wrapping_sub(bi).wrapping_sub(carry);
        t[i] = ti;
        carry = (bi & !pi | (bi | !pi) & ti) >> 63;
    }

    carry = 0;
    for i in 0..4 {
        let ai = a.value[i];
        let ti = t[i];
        let ci = ai.wrapping_add(ti).wrapping_add(carry);
        c.value[i] = ci;
        carry = (ai & ti | (ai | ti) & !ci) >> 63;
    }
    gfp_carry(&mut c.value, carry);
}

fn mul(a: [u64; 4], b: [u64; 4]) -> [u64; 8] {
    const MASK16: u64 = 0x0000ffff;
    const MASK32: u64 = 0xffffffff;

    let mut buff = [0u64; 32];

    for i in 0..4 {
        let ai = a[i];
        let a0 = ai & MASK16;
        let a1 = (ai >> 16) & MASK16;
        let a2 = (ai >> 32) & MASK16;
        let a3 = ai >> 48;

        for j in 0..4 {
            let bj = b[j];
            let b0 = bj & MASK32;
            let b2 = bj >> 32;

            let off = 4 * (i + j);
            buff[off + 0] += a0 * b0;
            buff[off + 1] += a1 * b0;
            buff[off + 2] += a2 * b0 + a0 * b2;
            buff[off + 3] += a3 * b0 + a1 * b2;
            buff[off + 4] += a2 * b2;
            buff[off + 5] += a3 * b2;
        }
    }

    for i in 1..4 {
        let shift = 16 * i;
        let mut head = 0u64;
        let mut carry = 0u64;

        for j in 0..8 {
            let block = 4 * j;
            let xi = buff[block];
            let yi = (buff[block + i] << shift) + head;
            let zi = xi.wrapping_add(yi).wrapping_add(carry);
            buff[block] = zi;
            carry = (xi & yi | (xi | yi) & !zi) >> 63;
            head = buff[block + i] >> (64 - shift);
        }
    }

    [
        buff[0], buff[4], buff[8], buff[12], buff[16], buff[20], buff[24], buff[28],
    ]
}

fn half_mul(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    const MASK16: u64 = 0x0000ffff;
    const MASK32: u64 = 0xffffffff;

    let mut buff = [0u64; 18];

    for i in 0..4 {
        let ai = a[i];
        let a0 = ai & MASK16;
        let a1 = (ai >> 16) & MASK16;
        let a2 = (ai >> 32) & MASK16;
        let a3 = ai >> 48;

        for j in 0..4 {
            if i + j > 3 {
                break;
            }
            let bj = b[j];
            let b0 = bj & MASK32;
            let b2 = bj >> 32;

            let off = 4 * (i + j);
            buff[off + 0] += a0 * b0;
            buff[off + 1] += a1 * b0;
            buff[off + 2] += a2 * b0 + a0 * b2;
            buff[off + 3] += a3 * b0 + a1 * b2;
            buff[off + 4] += a2 * b2;
            buff[off + 5] += a3 * b2;
        }
    }

    for i in 1..4 {
        let shift = 16 * i;
        let mut head = 0u64;
        let mut carry = 0u64;

        for j in 0..4 {
            let block = 4 * j;
            let xi = buff[block];
            let yi = (buff[block + i] << shift) + head;
            let zi = xi.wrapping_add(yi).wrapping_add(carry);
            buff[block] = zi;
            carry = (xi & yi | (xi | yi) & !zi) >> 63;
            head = buff[block + i] >> (64 - shift);
        }
    }

    [buff[0], buff[4], buff[8], buff[12]]
}

pub fn gfp_mul(c: &mut GFp, a: &GFp, b: &GFp) {
    let mut t = mul(a.value, b.value);
    let m = half_mul([t[0], t[1], t[2], t[3]], NP);
    let t2 = mul([m[0], m[1], m[2], m[3]], P2);

    let mut carry = 0u64;
    for i in 0..8 {
        let ti = t[i];
        let t2i = t2[i];
        let zi = ti.wrapping_add(t2i).wrapping_add(carry);
        t[i] = zi;
        carry = (ti & t2i | (ti | t2i) & !zi) >> 63;
    }

    c.value = [t[4], t[5], t[6], t[7]];
    gfp_carry(&mut c.value, carry);
}

impl std::fmt::Display for GFp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Montgomery decode before displaying, just like Go implementation
        let mut c = self.clone();
        mont_decode(&mut c, self);
        write!(
            f,
            "{:016x}{:016x}{:016x}{:016x}",
            c.value[3], c.value[2], c.value[1], c.value[0]
        )
    }
}
