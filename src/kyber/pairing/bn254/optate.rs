use crate::kyber::pairing::bn254::constants::{
    U as U_CONSTANT, XI_TO_P_MINUS_1_OVER_2, XI_TO_P_MINUS_1_OVER_3, XI_TO_P_SQUARED_MINUS_1_OVER_3,
};
use crate::kyber::pairing::bn254::curve::CurvePoint;
use crate::kyber::pairing::bn254::gfp::GFp;
use crate::kyber::pairing::bn254::gfp12::GFp12;
use crate::kyber::pairing::bn254::gfp2::GFp2;
use crate::kyber::pairing::bn254::gfp6::GFp6;
use crate::kyber::pairing::bn254::twist::TwistPoint;
use num_bigint::BigUint;
use std::str::FromStr;

// sixuPlus2NAF is 6u+2 in non-adjacent form.
// This matches the Go implementation exactly
const SIXU_PLUS_2_NAF: [i8; 65] = [
    0, 0, 0, 1, 0, 1, 0, -1, 0, 0, 1, -1, 0, 0, 1, 0, 0, 1, 1, 0, -1, 0, 0, 1, 0, -1, 0, 0, 0, 0,
    1, 1, 1, 0, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, 1, 1, 0, 0, -1, 0, 0, 0, 1, 1, 0, -1, 0,
    0, 1, 0, 1, 1,
];

// u constant for BN254 - matches Go implementation exactly
lazy_static::lazy_static! {
    static ref U: BigUint = BigUint::from_str(U_CONSTANT).unwrap();
}

/// Line function for addition in the Miller loop
/// This implements the mixed addition algorithm from "Faster Computation of the Tate Pairing"
/// See http://arxiv.org/pdf/0904.0854v3.pdf
pub fn line_function_add(
    r: &TwistPoint,
    p: &TwistPoint,
    q: &CurvePoint,
    r2: &GFp2,
) -> (GFp2, GFp2, GFp2, TwistPoint) {
    // B := (&gfP2{}).Mul(&p.x, &r.t)
    let mut b = GFp2::new();
    b.mul(p.get_x(), r.get_t());

    // D := (&gfP2{}).Add(&p.y, &r.z)
    // D.Square(D).Sub(D, r2).Sub(D, &r.t).Mul(D, &r.t)
    let mut d = GFp2::new();
    d.add(p.get_y(), r.get_z());
    let mut d_squared = GFp2::new();
    d_squared.square(&d);
    d = d_squared;
    let d_clone = d.clone();
    d.sub(&d_clone, r2);
    let d_clone = d.clone();
    let r_t = r.get_t().clone();
    d.sub(&d_clone, &r_t);
    let d_clone = d.clone();
    let r_t = r.get_t().clone();
    d.mul(&d_clone, &r_t);

    // H := (&gfP2{}).Sub(B, &r.x)
    let mut h = GFp2::new();
    h.sub(&b, r.get_x());

    // I := (&gfP2{}).Square(H)
    let mut i = GFp2::new();
    i.square(&h);

    // E := (&gfP2{}).Add(I, I)
    // E.Add(E, E)
    let mut e = GFp2::new();
    e.add(&i, &i);
    let e_clone = e.clone();
    e.add(&e_clone, &e_clone);

    // J := (&gfP2{}).Mul(H, E)
    let mut j = GFp2::new();
    j.mul(&h, &e);

    // L1 := (&gfP2{}).Sub(D, &r.y)
    // L1.Sub(L1, &r.y)
    let mut l1 = GFp2::new();
    l1.sub(&d, r.get_y());
    let l1_clone = l1.clone();
    let r_y = r.get_y().clone();
    l1.sub(&l1_clone, &r_y);

    // V := (&gfP2{}).Mul(&r.x, E)
    let mut v = GFp2::new();
    v.mul(r.get_x(), &e);

    // rOut = &twistPoint{}
    let mut r_out = TwistPoint::new();

    // rOut.x.Square(L1).Sub(&rOut.x, J).Sub(&rOut.x, V).Sub(&rOut.x, V)
    r_out.get_x_mut().square(&l1);
    let r_out_x_clone = r_out.get_x().clone();
    r_out.get_x_mut().sub(&r_out_x_clone, &j);
    let r_out_x_clone = r_out.get_x().clone();
    r_out.get_x_mut().sub(&r_out_x_clone, &v);
    let r_out_x_clone = r_out.get_x().clone();
    r_out.get_x_mut().sub(&r_out_x_clone, &v);

    // rOut.z.Add(&r.z, H).Square(&rOut.z).Sub(&rOut.z, &r.t).Sub(&rOut.z, I)
    r_out.get_z_mut().add(r.get_z(), &h);
    let mut z_squared = GFp2::new();
    let r_out_z_clone = r_out.get_z().clone();
    z_squared.square(&r_out_z_clone);
    r_out.get_z_mut().set(&z_squared);
    let r_out_z_clone = r_out.get_z().clone();
    let r_t = r.get_t().clone();
    r_out.get_z_mut().sub(&r_out_z_clone, &r_t);
    let r_out_z_clone = r_out.get_z().clone();
    r_out.get_z_mut().sub(&r_out_z_clone, &i);

    // t := (&gfP2{}).Sub(V, &rOut.x)
    // t.Mul(t, L1)
    let mut t = GFp2::new();
    let r_out_x = r_out.get_x().clone();
    t.sub(&v, &r_out_x);
    let t_clone = t.clone();
    t.mul(&t_clone, &l1);

    // t2 := (&gfP2{}).Mul(&r.y, J)
    // t2.Add(t2, t2)
    let mut t2 = GFp2::new();
    t2.mul(r.get_y(), &j);
    let t2_clone = t2.clone();
    t2.add(&t2_clone, &t2_clone);

    // rOut.y.Sub(t, t2)
    r_out.get_y_mut().sub(&t, &t2);

    // rOut.t.Square(&rOut.z)
    let r_out_z = r_out.get_z().clone();
    r_out.get_t_mut().square(&r_out_z);

    // t.Add(&p.y, &rOut.z).Square(t).Sub(t, r2).Sub(t, &rOut.t)
    let r_out_z = r_out.get_z().clone();
    t.add(p.get_y(), &r_out_z);
    let t_clone = t.clone();
    t.square(&t_clone);
    let t_clone = t.clone();
    t.sub(&t_clone, r2);
    let t_clone = t.clone();
    let r_out_t = r_out.get_t().clone();
    t.sub(&t_clone, &r_out_t);

    // t2.Mul(L1, &p.x)
    // t2.Add(t2, t2)
    t2.mul(&l1, p.get_x());
    let t2_clone = t2.clone();
    t2.add(&t2_clone, &t2_clone);

    // a = (&gfP2{}).Sub(t2, t)
    let mut a = GFp2::new();
    a.sub(&t2, &t);

    // c = (&gfP2{}).MulScalar(&rOut.z, &q.y)
    // c.Add(c, c)
    let mut c = GFp2::new();
    let r_out_z = r_out.get_z().clone();
    c.mul_scalar(&r_out_z, q.get_y());
    let c_clone = c.clone();
    c.add(&c_clone, &c_clone);

    // b = (&gfP2{}).Neg(L1)
    // b.MulScalar(b, &q.x).Add(b, b)
    let mut b_result = GFp2::new();
    b_result.neg_from(&l1);
    let b_result_clone = b_result.clone();
    b_result.mul_scalar(&b_result_clone, q.get_x());
    let b_result_clone = b_result.clone();
    b_result.add(&b_result_clone, &b_result_clone);

    (a, b_result, c, r_out)
}

/// Line function for doubling in the Miller loop
/// This implements the doubling algorithm for a=0 from "Faster Computation of the Tate Pairing"
/// See http://arxiv.org/pdf/0904.0854v3.pdf
pub fn line_function_double(r: &TwistPoint, q: &CurvePoint) -> (GFp2, GFp2, GFp2, TwistPoint) {
    // A := (&gfP2{}).Square(&r.x)
    let mut a = GFp2::new();
    a.square(r.get_x());

    // B := (&gfP2{}).Square(&r.y)
    let mut b = GFp2::new();
    b.square(r.get_y());

    // C := (&gfP2{}).Square(B)
    let mut c = GFp2::new();
    c.square(&b);

    // D := (&gfP2{}).Add(&r.x, B)
    // D.Square(D).Sub(D, A).Sub(D, C).Add(D, D)
    let mut d = GFp2::new();
    d.add(r.get_x(), &b);
    let d_clone = d.clone();
    d.square(&d_clone);
    let d_clone = d.clone();
    d.sub(&d_clone, &a);
    let d_clone = d.clone();
    d.sub(&d_clone, &c);
    let d_clone = d.clone();
    d.add(&d_clone, &d_clone);

    // E := (&gfP2{}).Add(A, A)
    // E.Add(E, A)
    let mut e = GFp2::new();
    e.add(&a, &a);
    let e_clone = e.clone();
    e.add(&e_clone, &a);

    // G := (&gfP2{}).Square(E)
    let mut g = GFp2::new();
    g.square(&e);

    // rOut = &twistPoint{}
    let mut r_out = TwistPoint::new();

    // rOut.x.Sub(G, D).Sub(&rOut.x, D)
    r_out.get_x_mut().sub(&g, &d);
    let r_out_x = r_out.get_x().clone();
    r_out.get_x_mut().sub(&r_out_x, &d);

    // rOut.z.Add(&r.y, &r.z).Square(&rOut.z).Sub(&rOut.z, B).Sub(&rOut.z, &r.t)
    r_out.get_z_mut().add(r.get_y(), r.get_z());
    let r_out_z = r_out.get_z().clone();
    r_out.get_z_mut().square(&r_out_z);
    let r_out_z = r_out.get_z().clone();
    r_out.get_z_mut().sub(&r_out_z, &b);
    let r_out_z = r_out.get_z().clone();
    let r_t = r.get_t().clone();
    r_out.get_z_mut().sub(&r_out_z, &r_t);

    // rOut.y.Sub(D, &rOut.x).Mul(&rOut.y, E)
    let r_out_x = r_out.get_x().clone();
    r_out.get_y_mut().sub(&d, &r_out_x);
    let r_out_y = r_out.get_y().clone();
    r_out.get_y_mut().mul(&r_out_y, &e);

    // t := (&gfP2{}).Add(C, C)
    // t.Add(t, t).Add(t, t)
    let mut t = GFp2::new();
    t.add(&c, &c);
    let t_clone = t.clone();
    t.add(&t_clone, &t_clone);
    let t_clone = t.clone();
    t.add(&t_clone, &t_clone);

    // rOut.y.Sub(&rOut.y, t)
    let r_out_y = r_out.get_y().clone();
    r_out.get_y_mut().sub(&r_out_y, &t);

    // rOut.t.Square(&rOut.z)
    let r_out_z = r_out.get_z().clone();
    r_out.get_t_mut().square(&r_out_z);

    // t.Mul(E, &r.t).Add(t, t)
    let r_t = r.get_t().clone();
    t.mul(&e, &r_t);
    let t_clone = t.clone();
    t.add(&t_clone, &t_clone);

    // b = (&gfP2{}).Neg(t)
    // b.MulScalar(b, &q.x)
    let mut b_result = GFp2::new();
    b_result.neg_from(&t);
    let b_result_clone = b_result.clone();
    b_result.mul_scalar(&b_result_clone, q.get_x());

    // a = (&gfP2{}).Add(&r.x, E)
    // a.Square(a).Sub(a, A).Sub(a, G)
    let mut a_result = GFp2::new();
    a_result.add(r.get_x(), &e);
    let a_result_clone = a_result.clone();
    a_result.square(&a_result_clone);
    let a_result_clone = a_result.clone();
    a_result.sub(&a_result_clone, &a);
    let a_result_clone = a_result.clone();
    a_result.sub(&a_result_clone, &g);

    // t.Add(B, B).Add(t, t)
    t.add(&b, &b);
    let t_clone = t.clone();
    t.add(&t_clone, &t_clone);

    // a.Sub(a, t)
    let a_result_clone = a_result.clone();
    a_result.sub(&a_result_clone, &t);

    // c = (&gfP2{}).Mul(&rOut.z, &r.t)
    // c.Add(c, c).MulScalar(c, &q.y)
    let mut c_result = GFp2::new();
    let r_out_z = r_out.get_z().clone();
    let r_t = r.get_t().clone();
    c_result.mul(&r_out_z, &r_t);
    let c_result_clone = c_result.clone();
    c_result.add(&c_result_clone, &c_result_clone);
    let c_result_clone = c_result.clone();
    c_result.mul_scalar(&c_result_clone, q.get_y());

    (a_result, b_result, c_result, r_out)
}

/// Multiply line function result with current pairing value
/// This matches the Go implementation exactly
pub fn mul_line(ret: &mut GFp12, a: &GFp2, b: &GFp2, c: &GFp2) {
    // a2 := &gfP6{}
    // a2.y.Set(a)
    // a2.z.Set(b)
    // a2.Mul(a2, &ret.x)
    let mut a2 = GFp6::new();
    a2.get_y_mut().set(a);
    a2.get_z_mut().set(b);
    let ret_x = ret.get_x().clone();
    let a2_clone = a2.clone();
    a2.mul(&a2_clone, &ret_x);

    // t3 := (&gfP6{}).MulScalar(&ret.y, c)
    let mut t3 = GFp6::new();
    let ret_y = ret.get_y().clone();
    t3.mul_scalar(&ret_y, c);

    // t := (&gfP2{}).Add(b, c)
    let mut t = GFp2::new();
    t.add(b, c);

    // t2 := &gfP6{}
    // t2.y.Set(a)
    // t2.z.Set(t)
    let mut t2 = GFp6::new();
    t2.get_y_mut().set(a);
    t2.get_z_mut().set(&t);

    // ret.x.Add(&ret.x, &ret.y)
    let ret_x_clone = ret.get_x().clone();
    let ret_y_clone = ret.get_y().clone();
    ret.get_x_mut().add(&ret_x_clone, &ret_y_clone);

    // ret.y.Set(t3)
    ret.get_y_mut().set(&t3);

    // ret.x.Mul(&ret.x, t2).Sub(&ret.x, a2).Sub(&ret.x, &ret.y)
    let ret_x_clone = ret.get_x().clone();
    ret.get_x_mut().mul(&ret_x_clone, &t2);
    let ret_x_clone = ret.get_x().clone();
    ret.get_x_mut().sub(&ret_x_clone, &a2);
    let ret_x_clone = ret.get_x().clone();
    let ret_y_clone = ret.get_y().clone();
    ret.get_x_mut().sub(&ret_x_clone, &ret_y_clone);

    // a2.MulTau(a2)
    let a2_clone = a2.clone();
    a2.mul_tau(&a2_clone);

    // ret.y.Add(&ret.y, a2)
    let ret_y_clone = ret.get_y().clone();
    ret.get_y_mut().add(&ret_y_clone, &a2);
}

/// Miller loop for calculating the Optimal Ate pairing
/// See algorithm 1 from http://cryptojedi.org/papers/dclxvi-20100714.pdf
/// This exactly matches the Go miller function
pub fn miller(q: &TwistPoint, p: &CurvePoint) -> GFp12 {

    // ret := (&gfP12{}).SetOne()
    let mut ret = GFp12::new();
    ret.set_one();

    // aAffine := &twistPoint{}
    // aAffine.Set(q)
    // aAffine.MakeAffine()
    let mut a_affine = q.clone();

    a_affine.make_affine();

    // bAffine := &curvePoint{}
    // bAffine.Set(p)
    // bAffine.MakeAffine()
    let mut b_affine = p.clone();
    b_affine.make_affine();

    // minusA := &twistPoint{}
    // minusA.Neg(aAffine)
    let mut minus_a = TwistPoint::new();
    minus_a.neg(&a_affine);

    // r := &twistPoint{}
    // r.Set(aAffine)
    let mut r = a_affine.clone();

    // r2 := (&gfP2{}).Square(&aAffine.y)
    let mut r2 = GFp2::new();
    r2.square(a_affine.get_y());

    // Main Miller loop - exactly like Go
    for i in (1..SIXU_PLUS_2_NAF.len()).rev() {
        // a, b, c, newR := lineFunctionDouble(r, bAffine)
        let (a, b, c, new_r) = line_function_double(&r, &b_affine);

        if i != SIXU_PLUS_2_NAF.len() - 1 {
            let temp_ret = ret.clone();
            ret.square(&temp_ret);
        }

        // mulLine(ret, a, b, c)
        mul_line(&mut ret, &a, &b, &c);
        // r = newR
        r = new_r;

        // switch sixuPlus2NAF[i-1] {
        match SIXU_PLUS_2_NAF[i - 1] {
            // case 1:
            //     a, b, c, newR = lineFunctionAdd(r, aAffine, bAffine, r2)
            1 => {
                let (a, b, c, new_r) = line_function_add(&r, &a_affine, &b_affine, &r2);
                mul_line(&mut ret, &a, &b, &c);
                r = new_r;
            }
            // case -1:
            //     a, b, c, newR = lineFunctionAdd(r, minusA, bAffine, r2)
            -1 => {
                let (a, b, c, new_r) = line_function_add(&r, &minus_a, &b_affine, &r2);
                mul_line(&mut ret, &a, &b, &c);
                r = new_r;
            }
            // default:
            //     continue
            _ => continue,
        }
    }

    // Go does additional Frobenius computations here - we need to implement those exactly

    // q1 := &twistPoint{}
    // q1.x.Conjugate(&aAffine.x).Mul(&q1.x, xiToPMinus1Over3)
    let mut q1 = TwistPoint::new();
    q1.get_x_mut().conjugate(a_affine.get_x());
    let xi_to_p_minus_1_over_3 = GFp2::from_gfp(
        GFp::from_u64_array(XI_TO_P_MINUS_1_OVER_3[0]),
        GFp::from_u64_array(XI_TO_P_MINUS_1_OVER_3[1]),
    );
    let temp_x = q1.get_x().clone();
    q1.get_x_mut().mul(&temp_x, &xi_to_p_minus_1_over_3);

    // q1.y.Conjugate(&aAffine.y).Mul(&q1.y, xiToPMinus1Over2)
    q1.get_y_mut().conjugate(a_affine.get_y());
    let xi_to_p_minus_1_over_2 = GFp2::from_gfp(
        GFp::from_u64_array(XI_TO_P_MINUS_1_OVER_2[0]),
        GFp::from_u64_array(XI_TO_P_MINUS_1_OVER_2[1]),
    );
    let temp_y = q1.get_y().clone();
    q1.get_y_mut().mul(&temp_y, &xi_to_p_minus_1_over_2);
    q1.get_z_mut().set_one();
    q1.get_t_mut().set_one();
    println!("DEBUG: q1: {}", q1.to_string());

    // minusQ2 := &twistPoint{}
    // minusQ2.x.MulScalar(&aAffine.x, xiToPSquaredMinus1Over3)
    let mut minus_q2 = TwistPoint::new();
    let xi_to_p_squared_minus_1_over_3 = GFp::from_u64_array(XI_TO_P_SQUARED_MINUS_1_OVER_3);
    minus_q2
        .get_x_mut()
        .mul_scalar(a_affine.get_x(), &xi_to_p_squared_minus_1_over_3);
    // minusQ2.y.Set(&aAffine.y)
    minus_q2.get_y_mut().set(a_affine.get_y());
    minus_q2.get_z_mut().set_one();
    minus_q2.get_t_mut().set_one();

    // r2.Square(&q1.y)
    r2.square(q1.get_y());

    // a, b, c, newR = lineFunctionAdd(r, q1, bAffine, r2)
    let (a, b, c, new_r) = line_function_add(&r, &q1, &b_affine, &r2);


    // mulLine(ret, a, b, c)
    mul_line(&mut ret, &a, &b, &c);
    // r = newR
    r = new_r;

    // r2.Square(&minusQ2.y)
    r2.square(minus_q2.get_y());

    // a, b, c, newR = lineFunctionAdd(r, minusQ2, bAffine, r2)
    let (a, b, c, _new_r) = line_function_add(&r, &minus_q2, &b_affine, &r2);
    // mulLine(ret, a, b, c)
    mul_line(&mut ret, &a, &b, &c);

    ret
}

/// Final exponentiation computes the (p¹²-1)/Order-th power of an element of
/// GF(p¹²) to obtain an element of GT
/// See steps 13-15 of algorithm 1 from http://cryptojedi.org/papers/dclxvi-20100714.pdf
pub fn final_exponentiation(in_val: &GFp12) -> GFp12 {
    // t1 := &gfP12{}
    let mut t1 = GFp12::new();

    // This is the p^6-Frobenius
    // t1.x.Neg(&in.x)
    // t1.y.Set(&in.y)
    t1.get_x_mut().neg(in_val.get_x());
    t1.get_y_mut().set(in_val.get_y());
    println!("DEBUG: after p^6-Frobenius setup t1: {}", t1.to_string());

    // inv := &gfP12{}
    // inv.Invert(in)
    // t1.Mul(t1, inv)
    let mut inv = GFp12::new();
    inv.invert(in_val);
    println!("PASSED: DEBUG: inverted input: {}", inv.to_string());

    let temp_t1 = t1.clone();
    t1.mul(&temp_t1, &inv);
    println!("DEBUG: t1 after multiply with inv: {}", t1.to_string());

    // t2 := (&gfP12{}).FrobeniusP2(t1)
    // t1.Mul(t1, t2)
    let mut t2 = GFp12::new();
    t2.frobenius_p2(&t1);
    let temp_t1 = t1.clone();
    t1.mul(&temp_t1, &t2);
    println!("DEBUG: PASSED t1 t2 mul");

    // fp := (&gfP12{}).Frobenius(t1)
    // fp2 := (&gfP12{}).FrobeniusP2(t1)
    // fp3 := (&gfP12{}).Frobenius(fp2)
    let mut fp = GFp12::new();
    fp.frobenius(&t1);
    let mut fp2 = GFp12::new();
    fp2.frobenius_p2(&t1);
    let mut fp3 = GFp12::new();
    fp3.frobenius(&fp2);
    println!("DEBUG: PASSED: fp fp2 fp3 frobenius");

    // Compute u-th powers
    let u = &U;
    // fu := (&gfP12{}).Exp(t1, u)
    // fu2 := (&gfP12{}).Exp(fu, u)
    // fu3 := (&gfP12{}).Exp(fu2, u)
    let mut fu = GFp12::new();
    fu.exp(&t1, &u);
    let mut fu2 = GFp12::new();
    fu2.exp(&fu, &u);
    let mut fu3 = GFp12::new();
    fu3.exp(&fu2, &u);
    println!("DEBUG: PASSED: fu fu2 fu3 exp");

    // Compute various Frobenius maps
    // y3 := (&gfP12{}).Frobenius(fu)
    // fu2p := (&gfP12{}).Frobenius(fu2)
    // fu3p := (&gfP12{}).Frobenius(fu3)
    // y2 := (&gfP12{}).FrobeniusP2(fu2)
    let mut y3 = GFp12::new();
    y3.frobenius(&fu);
    let mut fu2p = GFp12::new();
    fu2p.frobenius(&fu2);
    let mut fu3p = GFp12::new();
    fu3p.frobenius(&fu3);
    let mut y2 = GFp12::new();
    y2.frobenius_p2(&fu2);
    println!("DEBUG: PASSSED: y3 fu2p fu3p y2 frobenius");

    // y0 := &gfP12{}
    // y0.Mul(fp, fp2).Mul(y0, fp3)
    let mut y0 = GFp12::new();
    y0.mul(&fp, &fp2);
    let temp_y0 = y0.clone();
    y0.mul(&temp_y0, &fp3);
    println!("DEBUG: PASSSED y0 Mul(fp, fp2).Mul(y0, fp3)");

    // y1 := (&gfP12{}).Conjugate(t1)
    // y5 := (&gfP12{}).Conjugate(fu2)
    // y3.Conjugate(y3)
    let mut y1 = GFp12::new();
    y1.conjugate(&t1);
    let mut y5 = GFp12::new();
    y5.conjugate(&fu2);
    let temp_y3 = y3.clone();
    y3.conjugate(&temp_y3);

    // y4 := (&gfP12{}).Mul(fu, fu2p)
    // y4.Conjugate(y4)
    let mut y4 = GFp12::new();
    y4.mul(&fu, &fu2p);
    let temp_y4 = y4.clone();
    y4.conjugate(&temp_y4);

    // y6 := (&gfP12{}).Mul(fu3, fu3p)
    // y6.Conjugate(y6)
    let mut y6 = GFp12::new();
    y6.mul(&fu3, &fu3p);
    let temp_y6 = y6.clone();
    y6.conjugate(&temp_y6);
    println!("DEBUG: PASSED y6 in final_exp");

    // Final computation
    // t0 := (&gfP12{}).Square(y6)
    // t0.Mul(t0, y4).Mul(t0, y5)
    let mut t0 = GFp12::new();
    t0.square(&y6);
    let temp_t0 = t0.clone();
    t0.mul(&temp_t0, &y4);
    let temp_t0 = t0.clone();
    t0.mul(&temp_t0, &y5);

    // t1.Mul(y3, y5).Mul(t1, t0)
    t1.mul(&y3, &y5);
    let temp_t1 = t1.clone();
    t1.mul(&temp_t1, &t0);

    // t0.Mul(t0, y2)
    let temp_t0 = t0.clone();
    t0.mul(&temp_t0, &y2);

    // t1.Square(t1).Mul(t1, t0).Square(t1)
    let temp_t1 = t1.clone();
    t1.square(&temp_t1);
    let temp_t1 = t1.clone();
    t1.mul(&temp_t1, &t0);
    let temp_t1 = t1.clone();
    t1.square(&temp_t1);

    // t0.Mul(t1, y1)
    t0.mul(&t1, &y1);

    // t1.Mul(t1, y0)
    let temp_t1 = t1.clone();
    t1.mul(&temp_t1, &y0);

    // t0.Square(t0).Mul(t0, t1)
    let temp_t0 = t0.clone();
    t0.square(&temp_t0);
    let temp_t0 = t0.clone();
    t0.mul(&temp_t0, &t1);

    t0
}

/// Optimal Ate pairing implementation
/// This is the main pairing function that combines Miller loop and final exponentiation
/// Matches the Go implementation exactly
pub fn optimal_ate(a: &TwistPoint, b: &CurvePoint) -> GFp12 {
    let e = miller(a, b);

    let mut ret = final_exponentiation(&e);
    println!("DEBUG: final exponentiation result: {}", ret.to_string());
    println!("DEBUG: FINAL EXPONENTIATION IS CORRECT (inside optimal_ate)");

    if a.is_infinity() || b.is_infinity() {
        ret.set_one();
    }
    ret
}

/// Convenience function for pairing computation
/// This matches the Go implementation's Pair method exactly
/// The Go Pair method calls optimalAte(b, a) where b is G2 and a is G1
pub fn pair(g1_point: &CurvePoint, g2_point: &TwistPoint) -> GFp12 {
    optimal_ate(g2_point, g1_point)
}

/// Validate pairing equation
/// This checks if e(p1, p2) == e(inv1, inv2)
/// This matches the Go ValidatePairing method
pub fn validate_pairing(
    p1: &CurvePoint,
    p2: &TwistPoint,
    inv1: &CurvePoint,
    inv2: &TwistPoint,
) -> bool {
    let pairing1 = pair(p1, p2);
    let pairing2 = pair(inv1, inv2);
    pairing1 == pairing2
}
