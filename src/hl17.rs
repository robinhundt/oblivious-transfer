// allow non snake case so identifiers can be same as in the paper
#![allow(non_snake_case)]
///! Adaption of https://github.com/encryptogroup/MOTION/blob/master/src/motioncore/oblivious_transfer/base_ots/ot_hl17.h
/// which itself is based on https://eprint.iacr.org/2017/1011
use crate::Error::{NoInitReceived, SendInit, WrongMessage};
use crate::{BaseOTReceiver, BaseOTSender, Error};
use async_trait::async_trait;
use blake2::{Blake2b, Digest};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use digest::generic_array::GenericArray;
use digest::FixedOutput;

use futures::{Sink, SinkExt, Stream, StreamExt};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};

const COMPRESSED_RISTRETTO_SIZE: usize = 32;

pub struct Sender {
    /// counter for number OTs
    i: usize,
    y: Scalar,
    S: RistrettoPoint,
    T: RistrettoPoint,
    R: RistrettoPoint,
}

pub struct Receiver {
    /// counter for number OTs
    i: usize,
    x: Scalar,
    S: RistrettoPoint,
    R: RistrettoPoint,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum OTMessage {
    RistrettoPoint(RistrettoPoint),
    Bytes(Vec<u8>),
}

#[async_trait]
impl BaseOTSender for Sender {
    type OutputSize = <Blake2b as FixedOutput>::OutputSize;
    type Msg = OTMessage;

    async fn init<RNG, S, R>(sink: &mut S, stream: &mut R, rng: &mut RNG) -> Result<Self, Error>
    where
        RNG: CryptoRng + Rng + Send,
        S: Sink<Self::Msg> + Unpin + Send,
        R: Stream<Item = Self::Msg> + Unpin + Send,
    {
        let y = Scalar::random(rng);
        let S = &RISTRETTO_BASEPOINT_TABLE * &y;
        let T = RistrettoPoint::hash_from_bytes::<Blake2b>(S.compress().as_bytes());
        sink.send(OTMessage::RistrettoPoint(S))
            .await
            .map_err(|_| SendInit)?;
        let R = match stream.next().await {
            None => Err(NoInitReceived)?,
            Some(OTMessage::RistrettoPoint(R)) => R,
            Some(_) => Err(WrongMessage)?,
        };
        Ok(Self { i: 0, y, S, T, R })
    }

    async fn send<RNG, S, R>(
        &mut self,
        _sink: &mut S,
        _stream: &mut R,
        _rng: &mut RNG,
    ) -> Result<[GenericArray<u8, Self::OutputSize>; 2], Error>
    where
        RNG: CryptoRng + Rng + Send,
        S: Sink<Self::Msg> + Unpin + Send,
        R: Stream<Item = Self::Msg> + Unpin + Send,
    {
        let compressed_S_R = {
            // A CompressedRistretto is 32 bytes big, we need to hash 3
            let mut t = Vec::with_capacity(3 * COMPRESSED_RISTRETTO_SIZE);
            t.extend_from_slice(self.S.compress().as_bytes());
            t.extend_from_slice(self.R.compress().as_bytes());
            t
        };
        let mut hasher = Blake2b::new();
        let mut hash_points = |point: RistrettoPoint| {
            hasher.update(&compressed_S_R);
            hasher.update(point.compress().as_bytes());
            hasher.finalize_reset()
        };
        let out0 = hash_points(&self.R * &self.y);
        let out1 = hash_points(&self.y * (&self.R - &self.T));
        Ok([out0, out1])
    }
}

#[async_trait]
impl BaseOTReceiver for Receiver {
    type OutputSize = <Blake2b as FixedOutput>::OutputSize;
    type Msg = <Sender as BaseOTSender>::Msg;

    async fn init<RNG, S, R>(
        choice: bool,
        sink: &mut S,
        stream: &mut R,
        rng: &mut RNG,
    ) -> Result<Self, Error>
    where
        RNG: CryptoRng + Rng + Send,
        S: Sink<Self::Msg> + Unpin + Send,
        R: Stream<Item = Self::Msg> + Unpin + Send,
    {
        let x = Scalar::random(rng);
        let S = match stream.next().await {
            None => Err(NoInitReceived)?,
            Some(OTMessage::RistrettoPoint(S)) => S,
            Some(_) => Err(WrongMessage)?,
        };
        let T = RistrettoPoint::hash_from_bytes::<Blake2b>(S.compress().as_bytes());
        let R = &RISTRETTO_BASEPOINT_TABLE * &x + &T * Scalar::from(u8::from(choice));
        sink.send(OTMessage::RistrettoPoint(R))
            .await
            .map_err(|_| SendInit)?;
        Ok(Self { i: 0, x, S, R })
    }

    async fn receive<RNG, S, R>(
        &mut self,
        _sink: &mut S,
        _stream: &mut R,
        _rng: &mut RNG,
    ) -> Result<GenericArray<u8, Self::OutputSize>, Error>
    where
        RNG: CryptoRng + Rng + Send,
        S: Sink<Self::Msg> + Unpin + Send,
        R: Stream<Item = Self::Msg> + Unpin + Send,
    {
        let mut hasher = Blake2b::new();
        hasher.update(self.S.compress().as_bytes());
        hasher.update(self.R.compress().as_bytes());
        hasher.update((&self.S * &self.x).compress().as_bytes());
        Ok(hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::{Receiver, Sender};
    use crate::{BaseOTReceiver, BaseOTSender};
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
        let receiver = Receiver::init(true, &mut s1, &mut r0, &mut rng_recv);

        let (sender, receiver) = executor::block_on(future::join(sender, receiver));
        let (mut sender, mut receiver) = (sender.unwrap(), receiver.unwrap());
        let send_fut = sender.send(&mut s0, &mut r1, &mut rng_send);
        let recv_fut = receiver.receive(&mut s1, &mut r0, &mut rng_recv);
        let (snd_res, rcv_res) = executor::block_on(future::join(send_fut, recv_fut));
        assert_eq!(snd_res.unwrap()[1], rcv_res.unwrap())
    }
}
