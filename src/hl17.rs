use crate::util::derive_key_from_point;
use crate::{Aes256Cbc, Error, OTReceiver, OTSender};
use aes::cipher::generic_array::typenum::Unsigned;
use aes::cipher::generic_array::GenericArray;
use async_trait::async_trait;
use block_modes::BlockMode;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use futures::TryFutureExt;
use futures::{Sink, SinkExt, Stream, StreamExt};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};

pub struct Sender {
    secret: Scalar,
    share: RistrettoPoint,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum OTMessage {
    RistrettoPoint(RistrettoPoint),
    Bytes(Vec<u8>),
}

#[async_trait]
impl OTSender for Sender {
    type Input = Vec<u8>;
    type Msg = OTMessage;

    async fn init<RNG, S, R>(sink: &mut S, _stream: &mut R, rng: &mut RNG) -> Result<Self, Error>
    where
        RNG: CryptoRng + Rng + Send,
        S: Sink<Self::Msg> + Unpin + Send,
        R: Stream + Send,
    {
        todo!()
    }

    async fn send<RNG, S, R>(
        &mut self,
        inputs: [Self::Input; 2],
        sink: &mut S,
        stream: &mut R,
        rng: &mut RNG,
    ) -> Result<(), Error>
    where
        RNG: CryptoRng + Rng + Send,
        S: Sink<Self::Msg> + Unpin + Send,
        R: Stream<Item = Self::Msg> + Unpin + Send,
    {
        todo!()
    }
}

pub struct Receiver {
    share: RistrettoPoint,
}

#[async_trait]
impl OTReceiver for Receiver {
    type Output = <Sender as OTSender>::Input;
    type Msg = <Sender as OTSender>::Msg;

    async fn init<RNG, S, R>(_sink: &mut S, stream: &mut R, _rng: &mut RNG) -> Result<Self, Error>
    where
        RNG: CryptoRng + Rng + Send,
        S: Sink<Self::Msg> + Unpin + Send,
        R: Stream<Item = Self::Msg> + Unpin + Send,
    {
        todo!()
    }

    async fn receive<RNG, S, R>(
        &mut self,
        input: bool,
        sink: &mut S,
        stream: &mut R,
        rng: &mut RNG,
    ) -> Result<Self::Output, Error>
    where
        RNG: CryptoRng + Rng + Send,
        S: Sink<Self::Msg> + Unpin + Send,
        R: Stream<Item = Self::Msg> + Unpin + Send,
    {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::{Receiver, Sender};
    use crate::{OTReceiver, OTSender};
    use futures::executor;
    use futures::{channel::mpsc, future};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn it_works() {
        let (mut s0, mut r0) = mpsc::unbounded();
        let (mut s1, mut r1) = mpsc::unbounded();
        let mut rng_send = StdRng::seed_from_u64(42);
        let mut rng_recv = StdRng::seed_from_u64(42 * 42);
        let sender = Sender::init(&mut s0, &mut r1, &mut rng_send);
        let receiver = Receiver::init(&mut s1, &mut r0, &mut rng_recv);

        let (sender, receiver) = executor::block_on(future::join(sender, receiver));
        let (mut sender, mut receiver) = (sender.unwrap(), receiver.unwrap());
        let send_inputs = [vec![1, 2, 3, 4], vec![42, 42]];
        let send_fut = sender.send(send_inputs, &mut s0, &mut r1, &mut rng_send);
        let recv_fut = receiver.receive(true, &mut s1, &mut r0, &mut rng_recv);
        let (_, res) = executor::block_on(future::join(send_fut, recv_fut));
        assert_eq!(Ok(vec![42, 42]), res)
    }
}
