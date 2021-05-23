use curve25519_dalek::ristretto::RistrettoPoint;
use sha2::digest::Output;
use sha2::{Digest, Sha256};

pub fn hash_point(point: RistrettoPoint) -> Output<Sha256> {
    Sha256::digest(point.compress().as_bytes())
}
