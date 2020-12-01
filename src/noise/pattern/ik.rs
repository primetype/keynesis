use crate::{
    key::{ed25519::PublicKey, Key},
    noise::{HandshakeState, HandshakeStateError, TransportState},
};
use bytes::{Buf, BufMut};
use rand_core::{CryptoRng, RngCore};

/// Interactive Handshake [**Noise IK**]
///
/// [**Noise IK**]: https://noiseexplorer.com/patterns/IK/
pub struct IK<RNG, S> {
    inner: HandshakeState<RNG>,
    state: S,
}

pub struct A;
pub struct WaitB {
    rs: PublicKey,
}
pub struct SendB {
    re: PublicKey,
    rs: PublicKey,
}

impl<RNG> IK<RNG, A> {
    pub const PROTOCOL_NAME: &'static str = "Noise_IK_25519_ChaChaPoly_BLAKE2b";

    pub fn new(rng: RNG, prologue: &[u8]) -> Self {
        Self {
            inner: HandshakeState::new(rng, prologue, &Self::PROTOCOL_NAME),
            state: A,
        }
    }
}

impl<RNG> IK<RNG, A>
where
    RNG: RngCore + CryptoRng,
{
    pub fn initiate<K>(
        self,
        s: &K,
        rs: PublicKey,
        mut output: impl BufMut,
    ) -> Result<IK<RNG, WaitB>, HandshakeStateError>
    where
        K: Key,
    {
        let Self {
            mut inner,
            state: A,
        } = self;

        inner.write_e(&mut output)?;
        inner.dh_ex(&rs);
        inner.write_s(&s.public(), &mut output)?;
        inner.dh_sx(s, &rs);

        inner.encrypt_and_hash(&[], &mut output)?;

        Ok(IK {
            inner,
            state: WaitB { rs },
        })
    }
}
impl<RNG> IK<RNG, A> {
    pub fn receive<K>(
        self,
        s: &K,
        mut input: impl Buf,
    ) -> Result<IK<RNG, SendB>, HandshakeStateError>
    where
        K: Key,
    {
        let Self {
            mut inner,
            state: A,
        } = self;

        let re = inner.read_e(&mut input)?;
        inner.dh_sx(s, &re);
        let rs = inner.read_s(&mut input)?;
        inner.dh_sx(s, &rs);

        inner.decrypt_and_hash(&mut input, &mut [])?;

        Ok(IK {
            inner,
            state: SendB { re, rs },
        })
    }
}
impl<RNG> IK<RNG, SendB>
where
    RNG: RngCore + CryptoRng,
{
    pub fn remote_public_identity(&self) -> &PublicKey {
        &self.state.rs
    }

    pub fn reply(self, mut output: impl BufMut) -> Result<TransportState, HandshakeStateError> {
        let Self {
            mut inner,
            state: SendB { re, rs },
        } = self;

        inner.write_e(&mut output)?;
        inner.dh_ex(&re);
        inner.dh_ex(&rs);

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
impl<RNG> IK<RNG, WaitB> {
    pub fn remote_public_identity(&self) -> &PublicKey {
        &self.state.rs
    }

    pub fn receive<K>(
        self,
        s: &K,
        mut input: impl Buf,
    ) -> Result<TransportState, HandshakeStateError>
    where
        K: Key,
    {
        let Self {
            mut inner,
            state: WaitB { rs },
        } = self;

        let re = inner.read_e(&mut input)?;
        inner.dh_ex(&re);
        inner.dh_sx(s, &re);

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

        let initiator = IK::new(&mut rng1, &[]);
        let responder = IK::new(&mut rng2, &[]);

        let mut output = Vec::with_capacity(1024);
        let initiator = initiator
            .initiate(&initiator_s, responder_key, &mut output)
            .expect("initiator sends message A");
        let input = output;
        let responder = responder
            .receive(&responder_s, input.as_slice())
            .expect("responder receives message A");

        let mut output = Vec::with_capacity(1024);
        let responder = responder
            .reply(&mut output)
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
