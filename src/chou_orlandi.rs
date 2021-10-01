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
        let secret = Scalar::random(rng);
        let share = RISTRETTO_BASEPOINT_POINT * secret;
        sink.send(OTMessage::RistrettoPoint(share.clone()))
            .map_err(|_| Error::SendCiphertexts)
            .await?;
        Ok(Self { secret, share })
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
        let msg = stream.next().await.ok_or(Error::NoInitReceived)?;
        let share = match msg {
            OTMessage::RistrettoPoint(point) => point,
            OTMessage::Bytes(_) => return Err(Error::WrongMessage),
        };
        let k0 = derive_key_from_point(self.secret * share);
        let k1 = derive_key_from_point((share - self.share) * self.secret);
        let keys = [k0, k1];
        let ivs: [GenericArray<_, _>; 2] = [
            rng.gen::<[u8; <Aes256Cbc as BlockMode<_, _>>::IvSize::USIZE]>()
                .into(),
            rng.gen::<[u8; <Aes256Cbc as BlockMode<_, _>>::IvSize::USIZE]>()
                .into(),
        ];
        for ((k, iv), input) in keys.iter().zip(&ivs).zip(&inputs) {
            let cipher = Aes256Cbc::new_fix(k, iv);
            let mut ciphertext = cipher.encrypt_vec(input.as_slice());
            let mut iv_ciphertext = iv.to_vec();
            iv_ciphertext.append(&mut ciphertext);
            sink.send(OTMessage::Bytes(iv_ciphertext))
                .map_err(|_| Error::SendCiphertexts)
                .await?;
        }
        Ok(())
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
        let msg = stream.next().await.ok_or(Error::NoInitReceived)?;
        let share = match msg {
            OTMessage::RistrettoPoint(point) => point,
            OTMessage::Bytes(_) => return Err(Error::WrongMessage),
        };
        Ok(Self { share })
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
        let scalar = Scalar::random(rng);
        let share = if input {
            scalar * RISTRETTO_BASEPOINT_POINT + self.share
        } else {
            scalar * RISTRETTO_BASEPOINT_POINT
        };
        sink.send(OTMessage::RistrettoPoint(share.clone()))
            .map_err(|_| Error::SendCiphertexts)
            .await?;
        let k = derive_key_from_point(self.share * scalar);
        let skip_amount = if input { 1 } else { 0 };
        let msg = stream
            .skip(skip_amount)
            .next()
            .await
            .ok_or(Error::CiphertextMissing)?;
        let ciphertext = match msg {
            OTMessage::RistrettoPoint(_) => return Err(Error::WrongMessage),
            OTMessage::Bytes(c) => c,
        };
        let (iv, c) = split_iv_ciphertext(&ciphertext);
        let cipher = Aes256Cbc::new_from_slices(&k, iv).unwrap();
        let res = cipher.decrypt_vec(c).map_err(|_| Error::DecryptionError)?;
        Ok(res)
    }
}

fn split_iv_ciphertext(iv_ciphertext: &Vec<u8>) -> (&[u8], &[u8]) {
    iv_ciphertext.split_at(<Aes256Cbc as BlockMode<_, _>>::IvSize::USIZE)
}

#[cfg(test)]
mod tests {
    use crate::chou_orlandi::{Receiver, Sender};
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
