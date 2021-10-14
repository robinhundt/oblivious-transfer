use async_trait::async_trait;
use digest::generic_array::{ArrayLength, GenericArray};
use futures::{Sink, Stream};
use rand::{CryptoRng, Rng};

mod hl17;

#[async_trait]
pub trait BaseOTSender
where
    Self: Sized,
{
    type OutputSize: ArrayLength<u8>;
    type Msg;

    async fn init<RNG, S, R>(sink: &mut S, stream: &mut R, rng: &mut RNG) -> Result<Self, Error>
    where
        RNG: CryptoRng + Rng + Send,
        S: Sink<Self::Msg> + Unpin + Send,
        R: Stream<Item = Self::Msg> + Unpin + Send;

    async fn send<RNG, S, R>(
        &mut self,
        sink: &mut S,
        stream: &mut R,
        rng: &mut RNG,
    ) -> Result<[GenericArray<u8, Self::OutputSize>; 2], Error>
    where
        RNG: CryptoRng + Rng + Send,
        S: Sink<Self::Msg> + Unpin + Send,
        R: Stream<Item = Self::Msg> + Unpin + Send;
}

#[async_trait]
pub trait BaseOTReceiver
where
    Self: Sized,
{
    type OutputSize: ArrayLength<u8>;
    type Msg;

    async fn init<RNG, S, R>(
        choice: bool,
        sink: &mut S,
        stream: &mut R,
        rng: &mut RNG,
    ) -> Result<Self, Error>
    where
        RNG: CryptoRng + Rng + Send,
        S: Sink<Self::Msg> + Unpin + Send,
        R: Stream<Item = Self::Msg> + Unpin + Send;

    async fn receive<RNG, S, R>(
        &mut self,
        sink: &mut S,
        stream: &mut R,
        rng: &mut RNG,
    ) -> Result<GenericArray<u8, Self::OutputSize>, Error>
    where
        RNG: CryptoRng + Rng + Send,
        S: Sink<Self::Msg> + Unpin + Send,
        R: Stream<Item = Self::Msg> + Unpin + Send;
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum Error {
    #[error("No init message received")]
    NoInitReceived,
    #[error("Wrong message")]
    WrongMessage,
    #[error("Error sending init message")]
    SendInit,
    #[error("Ciphertext missing")]
    CiphertextMissing,
    #[error("Unable to decrypt ciphertext")]
    DecryptionError,
}
