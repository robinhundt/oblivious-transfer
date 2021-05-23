use aes::Aes256;
use async_trait::async_trait;
use block_modes::block_padding::Pkcs7;
use block_modes::Cbc;
use futures::{Sink, Stream};
use rand::{CryptoRng, Rng};

mod chou_orlandi;
mod util;

pub(crate) type Aes256Cbc = Cbc<Aes256, Pkcs7>;

#[async_trait]
pub trait OTSender
where
    Self: Sized,
{
    type Msg;

    async fn init<RNG, S, R>(sink: &mut S, stream: &mut R, rng: &mut RNG) -> Result<Self, Error>
    where
        RNG: CryptoRng + Rng + Send,
        S: Sink<Self::Msg> + Unpin + Send,
        R: Stream<Item = Self::Msg> + Send;

    async fn send<RNG, S, R>(
        &mut self,
        inputs: [Self::Msg; 2],
        sink: &mut S,
        stream: &mut R,
        rng: &mut RNG,
    ) -> Result<(), Error>
    where
        RNG: CryptoRng + Rng + Send,
        S: Sink<Self::Msg> + Unpin + Send,
        R: Stream<Item = Self::Msg> + Unpin + Send;
}

#[async_trait]
pub trait OTReceiver
where
    Self: Sized,
{
    type Msg;

    async fn init<RNG, S, R>(sink: &mut S, stream: &mut R, rng: &mut RNG) -> Result<Self, Error>
    where
        RNG: CryptoRng + Rng + Send,
        S: Sink<Self::Msg> + Unpin + Send,
        R: Stream<Item = Self::Msg> + Unpin + Send;

    async fn receive<RNG, S, R>(
        &mut self,
        input: bool,
        sink: &mut S,
        stream: &mut R,
        rng: &mut RNG,
    ) -> Result<Self::Msg, Error>
    where
        RNG: CryptoRng + Rng + Send,
        S: Sink<Self::Msg> + Unpin + Send,
        R: Stream<Item = Self::Msg> + Unpin + Send;
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum Error {
    #[error("No init message received")]
    NoInitReceived,
    #[error("Error sending ciphertexts")]
    SendCiphertexts,
    #[error("Ciphertext missing")]
    CiphertextMissing,
    #[error("Unable to decrypt ciphertext")]
    DecryptionError,
}
