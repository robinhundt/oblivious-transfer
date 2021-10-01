use crate::Aes256Cbc;
use aes::cipher::generic_array::typenum::Unsigned;
use aes::cipher::generic_array::GenericArray;
use aes::Aes256;
use block_modes::cipher::NewBlockCipher;
use block_modes::BlockMode;
use curve25519_dalek::ristretto::RistrettoPoint;
use digest::FixedOutput;
use hkdf::Hkdf;
use sha2::digest::Output;
use sha2::{Digest, Sha256};

pub fn derive_key_from_point(
    point: RistrettoPoint,
) -> GenericArray<u8, <Aes256 as NewBlockCipher>::KeySize> {
    let hkdf = Hkdf::<Sha256>::new(None, point.compress().as_bytes());
    let mut okm = [0; <Sha256 as FixedOutput>::OutputSize::USIZE];
    hkdf.expand(&[], &mut okm).unwrap();
    okm.into()
}
