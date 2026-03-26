use num_bigint::BigUint;
use std::str::FromStr;

// BN254 curve parameters
// u is the BN parameter
pub const U: &str = "4965661367192848881";

// p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
pub const P: &str = "21888242871839275222246405745257275088696311157297823662689037894645226208583";

// Order is the number of elements in both G₁ and G₂: 36u⁴+36u³+18u²+6u+1
pub const ORDER: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

// p2 is p, represented as little-endian 64-bit words
pub const P2: [u64; 4] = [
    0x3c208c16d87cfd47,
    0x97816a916871ca8d,
    0xb85045b68181585d,
    0x30644e72e131a029,
];

// np is the negative inverse of p, mod 2^256
pub const NP: [u64; 4] = [
    0x87d20782e4866389,
    0x9ede7d651eca6ac9,
    0xd8afcbd01833da80,
    0xf57a22b791888c6b,
];

// rN1 is R^-1 where R = 2^256 mod p
pub const RN1: [u64; 4] = [
    0xed84884a014afa37,
    0xeb2022850278edf8,
    0xcf63e9cfb74492d9,
    0x2e67157159e5c639,
];

// r2 is R^2 where R = 2^256 mod p
pub const R2: [u64; 4] = [
    0xf32cfc5b538afa89,
    0xb5e71911d44501fb,
    0x47ab1eff0a417ff6,
    0x06d89f71cab8351f,
];

// r3 is R^3 where R = 2^256 mod p
pub const R3: [u64; 4] = [
    0xb1cd6dafda1530df,
    0x62f210e6a7283db6,
    0xef7f0b0c0ada0afb,
    0x20fd6e902d592544,
];

// r1 is R^-1 where R = 2^256 mod p (Montgomery representation of 1)
pub const R1: [u64; 4] = [
    0xed84884a014afa37,
    0xeb2022850278edf8,
    0xcf63e9cfb74492d9,
    0x2e67157159e5c639,
];

// xiToPMinus1Over6 is ξ^((p-1)/6) where ξ = i+9
pub const XI_TO_P_MINUS_1_OVER_6: [[u64; 4]; 2] = [
    [
        0xa222ae234c492d72,
        0xd00f02a4565de15b,
        0xdc2ff3a253dfc926,
        0x10a75716b3899551,
    ],
    [
        0xaf9ba69633144907,
        0xca6b1d7387afb78a,
        0x11bded5ef08a2087,
        0x02f34d751a1f3a7c,
    ],
];

// xiToPMinus1Over3 is ξ^((p-1)/3) where ξ = i+9
pub const XI_TO_P_MINUS_1_OVER_3: [[u64; 4]; 2] = [
    [
        0x6e849f1ea0aa4757,
        0xaa1c7b6d89f89141,
        0xb6e713cdfae0ca3a,
        0x26694fbb4e82ebc3,
    ],
    [
        0xb5773b104563ab30,
        0x347f91c8a9aa6454,
        0x7a007127242e0991,
        0x1956bcd8118214ec,
    ],
];

// xiToPMinus1Over2 is ξ^((p-1)/2) where ξ = i+9
pub const XI_TO_P_MINUS_1_OVER_2: [[u64; 4]; 2] = [
    [
        0xa1d77ce45ffe77c7,
        0x07affd117826d1db,
        0x6d16bd27bb7edc6b,
        0x2c87200285defecc,
    ],
    [
        0xe4bbdd0c2936b629,
        0xbb30f162e133bacb,
        0x31a9d1b6f9645366,
        0x253570bea500f8dd,
    ],
];

// xiToPSquaredMinus1Over3 is ξ^((p²-1)/3) where ξ = i+9
pub const XI_TO_P_SQUARED_MINUS_1_OVER_3: [u64; 4] = [
    0x3350c88e13e80b9c,
    0x7dce557cdb5e56b9,
    0x6001b4b8b615564a,
    0x2682e617020217e0,
];

// xiTo2PSquaredMinus2Over3 is ξ^((2p²-2)/3) where ξ = i+9 (a cubic root of unity, mod p)
pub const XI_TO_2P_SQUARED_MINUS_2_OVER_3: [u64; 4] = [
    0x71930c11d782e155,
    0xa6bb947cffbe3323,
    0xaa303344d4741444,
    0x2c3b3f0d26594943,
];

// xiToPSquaredMinus1Over6 is ξ^((1p²-1)/6) where ξ = i+9 (a cubic root of -1, mod p)
pub const XI_TO_P_SQUARED_MINUS_1_OVER_6: [u64; 4] = [
    0xca8d800500fa1bf2,
    0xf0c5d61468b39769,
    0x0e201271ad0d4418,
    0x04290f65bad856e6,
];

// xiTo2PMinus2Over3 is ξ^((2p-2)/3) where ξ = i+9
pub const XI_TO_2P_MINUS_2_OVER_3: [[u64; 4]; 2] = [
    [
        0x5dddfd154bd8c949,
        0x62cb29a5a4445b60,
        0x37bc870a0c7dd2b9,
        0x24830a9d3171f0fd,
    ],
    [
        0x7361d77f843abe92,
        0xa5bb2bd3273411fb,
        0x9c941f314b3e2399,
        0x15df9cddbb9fd3ec,
    ],
];

// g(Z)
pub const C1: [u64; 4] = [
    0x115482203dbf392d,
    0x926242126eaa626a,
    0xe16a48076063c052,
    0x07c5909386eddc93,
];

// -Z / 2
pub const C2: [u64; 4] = [
    0xb461a4448976f7d5,
    0xc6843fb439555fa7,
    0x28f0d12384840918,
    0x112ceb58a394e07d,
];

// sqrt(-g(Z) * (3 * Z^2 + 4 * A))
pub const C3: [u64; 4] = [
    0x7c8487078735ab72,
    0x51da7e0048bfb8d4,
    0x945cfd183cbd7bf4,
    0x0b70b1ec48ae62c6,
];

// 4 * -g(Z) / (3 * Z^2 + 4 * A)
pub const C4: [u64; 4] = [
    0xa79a2bdca0800831,
    0x19fd7617e49815a1,
    0xbb8d0c885550c7b1,
    0x05c4aeb6ec7e0f48,
];

pub const P_MINUS_1_OVER_2: [u64; 4] = [
    0x9e10460b6c3e7ea3,
    0xcbc0b548b438e546,
    0xdc2822db40c0ac2e,
    0x183227397098d014,
];

pub const P_PLUS_1_OVER_4: [u64; 4] = [
    0x4f082305b61f3f52,
    0x65e05aa45a1c72a3,
    0x6e14116da0605617,
    0xc19139cb84c680a,
];

// Generator point coordinates for G1
pub const G1_X: &str = "1";
pub const G1_Y: &str = "2";

// Generator point coordinates for G2
pub const G2_X: &str =
    "10857046999023057135944570762232829481370756359578518086990519993285655852781";
pub const G2_Y: &str =
    "11559732032986387107991004021392285783925812861821192530917403151452391805634";

// Twisting parameters
pub const XI: &str = "9";

// Curve parameter b
pub const CURVE_B: &str = "3";

// Helper function to convert string to BigUint (handles negative numbers)
pub fn big_from_base10(s: &str) -> BigUint {
    if s.starts_with('-') {
        // For negative numbers, we'll use the absolute value
        // In the context of BN254, negative numbers are typically handled modulo the field
        let abs_str = &s[1..];
        BigUint::from_str(abs_str).expect("Invalid base10 string")
    } else {
        BigUint::from_str(s).expect("Invalid base10 string")
    }
}

// Montgomery encoding constants (string versions for compatibility)
pub const R_STR: &str =
    "6350874878119819312338956282401532410528162663560392320966563075034087161851";
pub const R2_STR: &str =
    "1593091911132452454343501436159168166101817767994993327299668517868971768566";

// Scalar field parameters
pub const SCALAR_FIELD: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

// Domain separation tags for hash functions
pub const H2_TAG: &[u8] = b"IBE-H2";
pub const H3_TAG: &[u8] = b"IBE-H3";
pub const H4_TAG: &[u8] = b"IBE-H4";

// BLS signature domain tags
pub const BLS_SIG_BN254G1_XMD_KECCAK_256_SVDW_RO_NUL: &[u8] =
    b"BLS_SIG_BN254G1_XMD:KECCAK-256_SVDW_RO_NUL_";
pub const BLS_SIG_BN254G2_XMD_KECCAK_256_SVDW_RO_NUL: &[u8] =
    b"BLS_SIG_BN254G2_XMD:KECCAK-256_SVDW_RO_NUL_";
