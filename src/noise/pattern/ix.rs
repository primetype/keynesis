use crate::{
    buffer::BufRead,
    key::{ed25519::PublicKey, Key},
    noise::{HandshakeState, HandshakeStateError, TransportState},
};
use rand_core::{CryptoRng, RngCore};
use std::io::Write;

/// Interactive Handshake [**Noise IX**]
///
/// [**Noise IX**]: https://noiseexplorer.com/patterns/IX/
pub struct IX<RNG, S> {
    inner: HandshakeState<RNG>,
    state: S,
}

pub struct A;
pub struct WaitB;
pub struct SendB {
    re: PublicKey,
    rs: PublicKey,
}

impl<RNG> IX<RNG, A> {
    pub const PROTOCOL_NAME: &'static str = "Noise_IX_25519_ChaChaPoly_BLAKE2b";

    pub fn new(rng: RNG, prologue: &[u8]) -> Self {
        Self {
            inner: HandshakeState::new(rng, prologue, Self::PROTOCOL_NAME),
            state: A,
        }
    }
}

impl<RNG> IX<RNG, A>
where
    RNG: RngCore + CryptoRng,
{
    pub fn initiate(
        self,
        s: &PublicKey,
        mut output: impl Write,
    ) -> Result<IX<RNG, WaitB>, HandshakeStateError> {
        let Self {
            mut inner,
            state: A,
        } = self;

        inner.write_e(&mut output)?;
        inner.write_s(s, &mut output)?;

        inner.encrypt_and_hash(&[], &mut output)?;

        Ok(IX {
            inner,
            state: WaitB,
        })
    }
}
impl<RNG> IX<RNG, A> {
    pub fn receive(self, input: &[u8]) -> Result<IX<RNG, SendB>, HandshakeStateError> {
        let Self {
            mut inner,
            state: A,
        } = self;

        let mut input = BufRead::new(input);

        let re = inner.read_e(&mut input)?;
        let rs = inner.read_s(&mut input)?;

        inner.decrypt_and_hash(&mut input, &mut [])?;

        Ok(IX {
            inner,
            state: SendB { re, rs },
        })
    }
}
impl<RNG> IX<RNG, SendB>
where
    RNG: RngCore + CryptoRng,
{
    pub fn reply<K>(
        self,
        s: &K,
        mut output: impl Write,
    ) -> Result<TransportState, HandshakeStateError>
    where
        K: Key,
    {
        let Self {
            mut inner,
            state: SendB { re, rs },
        } = self;

        inner.write_e(&mut output)?;
        inner.dh_ex(&re);
        inner.dh_ex(&rs);
        inner.write_s(&s.public(), &mut output)?;
        inner.dh_sx(s, &re);

        inner.encrypt_and_hash(&[], &mut output)?;

        let (remote, local) = inner.symmetric_state().split();

        Ok(TransportState::new(
            *inner.symmetric_state().get_handshake_hash(),
            local,
            remote,
            rs,
        ))
    }
}
impl<RNG> IX<RNG, WaitB> {
    pub fn receive<K>(self, s: &K, input: &[u8]) -> Result<TransportState, HandshakeStateError>
    where
        K: Key,
    {
        let Self {
            mut inner,
            state: WaitB,
        } = self;

        let mut input = BufRead::new(input);

        let re = inner.read_e(&mut input)?;
        inner.dh_ex(&re);
        inner.dh_sx(s, &re);
        let rs = inner.read_s(&mut input)?;
        inner.dh_ex(&rs);

        inner.decrypt_and_hash(&mut input, &mut [])?;

        let (local, remote) = inner.symmetric_state().split();

        Ok(TransportState::new(
            *inner.symmetric_state().get_handshake_hash(),
            local,
            remote,
            rs,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{key::ed25519::SecretKey, noise::CipherState};

    fn establish_handshake(
        rng1: crate::Seed,
        rng2: crate::Seed,
        initiator_s: SecretKey,
        responder_s: SecretKey,
    ) -> (TransportState, TransportState) {
        let initiator_key = initiator_s.public_key();
        let responder_key = responder_s.public_key();

        let mut rng1 = rng1.into_rand_chacha();
        let mut rng2 = rng2.into_rand_chacha();

        let initiator = IX::new(&mut rng1, &[]);
        let responder = IX::new(&mut rng2, &[]);

        let mut output = Vec::with_capacity(1024);
        let initiator = initiator
            .initiate(&initiator_key, &mut output)
            .expect("initiator sends message A");
        let input = output;
        let responder = responder
            .receive(input.as_slice())
            .expect("responder receives message A");

        let mut output = Vec::with_capacity(1024);
        let responder = responder
            .reply(&responder_s, &mut output)
            .expect("responder sends message B");
        let input = output;
        let initiator = initiator
            .receive(&initiator_s, input.as_slice())
            .expect("initiator receives message B");

        assert_eq!(&initiator_key, responder.remote_public_identity());
        assert_eq!(&responder_key, initiator.remote_public_identity());

        (initiator, responder)
    }

    #[quickcheck]
    fn full_round(
        rng1: crate::Seed,
        rng2: crate::Seed,
        initiator_s: SecretKey,
        responder_s: SecretKey,
        messages_init_to_responder: Vec<Vec<u8>>,
        messages_resp_to_initiator: Vec<Vec<u8>>,
    ) -> bool {
        let (mut initiator, mut responder) =
            establish_handshake(rng1, rng2, initiator_s, responder_s);

        for message in messages_init_to_responder {
            let mut output = vec![0; message.len() + CipherState::TAG_LEN];
            initiator
                .send(&message, &mut output)
                .expect("send encrypted message");

            let input = output;
            let mut output = vec![0; message.len()];
            responder
                .receive(&input, &mut output)
                .expect("receive message");

            assert!(message == output, "decryption of the message failed")
        }

        for message in messages_resp_to_initiator {
            let mut output = vec![0; message.len() + CipherState::TAG_LEN];
            responder
                .send(&message, &mut output)
                .expect("send encrypted message");

            let input = output;
            let mut output = vec![0; message.len()];
            initiator
                .receive(&input, &mut output)
                .expect("receive message");

            assert!(message == output, "decryption of the message failed")
        }

        true
    }
}
