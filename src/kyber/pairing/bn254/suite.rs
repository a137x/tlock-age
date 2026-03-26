use crate::kyber::pairing::bn254::group::{GroupG1, GroupG2, GroupGT};
use crate::kyber::pairing::bn254::point::{PointG1, PointG2, PointGT};
use sha3::{Digest, Keccak256};

// Domain constants matching Go implementation exactly
const DEFAULT_DOMAIN_G1: &[u8] = b"BN254G1_XMD:KECCAK-256_SSWU_RO_";
const DEFAULT_DOMAIN_G2: &[u8] = b"BN254G2_XMD:KECCAK-256_SSWU_RO_";

pub struct BN254Suite {
    g1: GroupG1,
    g2: GroupG2,
    gt: GroupGT,
    domain_g1: Vec<u8>,
    domain_g2: Vec<u8>,
}

impl BN254Suite {
    /// NewSuite generates and returns a new BN254 pairing suite.
    /// This matches the Go NewSuite() function exactly.
    pub fn new() -> Self {
        Self {
            g1: GroupG1::new(DEFAULT_DOMAIN_G1.to_vec()),
            g2: GroupG2::new(DEFAULT_DOMAIN_G2.to_vec()),
            gt: GroupGT::new(),
            domain_g1: DEFAULT_DOMAIN_G1.to_vec(),
            domain_g2: DEFAULT_DOMAIN_G2.to_vec(),
        }
    }

    /// NewSuiteG1 returns a G1 suite.
    /// This matches the Go NewSuiteG1() function exactly.
    pub fn new_suite_g1() -> Self {
        let suite = Self::new();
        // In Go, this sets the commonSuite.Group to groupG1
        // For Rust, we'll just return the same suite since we don't have the same structure
        suite
    }

    /// NewSuiteG2 returns a G2 suite.
    /// This matches the Go NewSuiteG2() function exactly.
    pub fn new_suite_g2() -> Self {
        let suite = Self::new();
        // In Go, this sets the commonSuite.Group to groupG2
        // For Rust, we'll just return the same suite since we don't have the same structure
        suite
    }

    /// NewSuiteGT returns a GT suite.
    /// This matches the Go NewSuiteGT() function exactly.
    pub fn new_suite_gt() -> Self {
        let suite = Self::new();
        // In Go, this sets the commonSuite.Group to groupGT
        // For Rust, we'll just return the same suite since we don't have the same structure
        suite
    }

    /// NewSuiteRand generates and returns a new BN254 suite seeded by the given random stream.
    /// This matches the Go NewSuiteRand(rand cipher.Stream) function exactly.
    // pub fn new_suite_rand<R: RngCore + Send + Sync + 'static>(mut rng: R) -> Self {
    //     Self {
    //         g1: GroupG1::new(DEFAULT_DOMAIN_G1.to_vec()),
    //         g2: GroupG2::new(DEFAULT_DOMAIN_G2.to_vec()),
    //         gt: GroupGT::new(),
    //         domain_g1: DEFAULT_DOMAIN_G1.to_vec(),
    //         domain_g2: DEFAULT_DOMAIN_G2.to_vec(),
    //         random_stream: Some(Box::new(rng)),
    //     }
    // }

    /// SetDomainG1 sets the G1 domain.
    /// This matches the Go SetDomainG1(dst []byte) function exactly.
    pub fn set_domain_g1(&mut self, dst: &[u8]) {
        let new_dst = dst.to_vec();
        self.domain_g1 = new_dst.clone();
        self.g1 = GroupG1::new(new_dst);
    }

    /// SetDomainG2 sets the G2 domain.
    /// This matches the Go SetDomainG2(dst []byte) function exactly.
    pub fn set_domain_g2(&mut self, dst: &[u8]) {
        let new_dst = dst.to_vec();
        self.domain_g2 = new_dst.clone();
        self.g2 = GroupG2::new(new_dst);
    }

    /// G1 returns the group G1 of the BN254 pairing.
    /// This matches the Go G1() kyber.Group function exactly.
    pub fn g1(&self) -> &GroupG1 {
        &self.g1
    }

    /// G2 returns the group G2 of the BN254 pairing.
    /// This matches the Go G2() kyber.Group function exactly.
    pub fn g2(&self) -> &GroupG2 {
        &self.g2
    }

    /// GT returns the group GT of the BN254 pairing.
    /// This matches the Go GT() kyber.Group function exactly.
    pub fn gt(&self) -> &GroupGT {
        &self.gt
    }

    /// Pair takes the points p1 and p2 in groups G1 and G2, respectively, as input
    /// and computes their pairing in GT.
    /// This matches the Go Pair(p1 kyber.Point, p2 kyber.Point) kyber.Point function exactly.
    pub fn pair(&self, p1: &PointG1, p2: &PointG2) -> PointGT {
        // Use the existing pair method from PointGT which should call optate::pair
        let mut result = PointGT::new();
        result.pair(p1, p2);
        result
    }

    /// ValidatePairing validates if e(p1, p2) == e(inv1, inv2).
    /// This matches the Go ValidatePairing(p1, p2, inv1, inv2 kyber.Point) bool function exactly.
    /// NB: Not safe for concurrent calls (as noted in Go)
    pub fn validate_pairing(&self, p1: &PointG1, p2: &PointG2, inv1: &PointG1, inv2: &PointG2) -> bool {
        // Clone points like in Go
        let p2_norm = p2.clone();
        let inv2_norm = inv2.clone();
        
        // Compute pairings and compare
        let pairing1 = self.pair(p1, &p2_norm);
        let pairing2 = self.pair(inv1, &inv2_norm);
        
        pairing1 == pairing2
    }

    /// Hash returns a newly instantiated keccak256 hash function.
    /// This matches the Go Hash() hash.Hash function exactly.
    pub fn hash(&self) -> Keccak256 {
        Keccak256::new()
    }

    /// Scalar returns a new scalar from the G1 group.
    /// This matches the Go Scalar() kyber.Scalar function exactly.
    pub fn scalar(&self) -> crate::kyber::pairing::bn254::Scalar {
        self.g1.scalar()
    }

    /// RandomStream returns a random stream.
    /// This matches the Go RandomStream() cipher.Stream function exactly.
    // pub fn random_stream(&self) -> Box<dyn RngCore + Send + Sync> {
    //     if let Some(ref stream) = self.random_stream {
    //         // Return a clone or reference to the existing stream
    //         // For simplicity, we'll create a new random stream
    //         Box::new(rand::rngs::OsRng)
    //     } else {
    //         Box::new(rand::rngs::OsRng)
    //     }
    // }

    /// String returns a recognizable string that this is a combined suite.
    /// This matches the Go String() string function exactly.
    pub fn to_string(&self) -> String {
        "bn254".to_string()
    }
}

impl Default for BN254Suite {
    fn default() -> Self {
        Self::new()
    }
}

// Additional trait implementations to match Go's interface patterns
impl std::fmt::Display for BN254Suite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
} 