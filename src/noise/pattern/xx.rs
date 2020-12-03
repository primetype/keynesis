use std::io::Write;

use crate::{
    buffer::BufRead,
    hash::Hash,
    key::{ed25519::PublicKey, Dh},
    noise::{HandshakeState, HandshakeStateError, TransportState},
};
use rand_core::{CryptoRng, RngCore};

/// Interactive Handshake [**Noise XX**]
///
/// [**Noise XX**]: https://noiseexplorer.com/patterns/XX/
pub struct XX<DH, H, RNG, S>
where
    H: Hash,
{
    inner: HandshakeState<RNG, DH, H>,
    state: S,
}

pub struct A;
pub struct WaitB;
pub struct SendB {
    re: PublicKey,
}
pub struct WaitC;
pub struct SendC {
    re: PublicKey,
    rs: PublicKey,
}

impl<DH, H, RNG> XX<DH, H, RNG, A>
where
    DH: Dh,
    H: Hash,
{
    pub fn new(rng: RNG, prologue: &[u8]) -> Self {
        let protocol_name = format!(
            "Noise_{pattern}_{dh}_{cipher}_{hash}",
            pattern = "XX",
            dh = DH::name(),
            cipher = "ChaChaPoly",
            hash = H::name(),
        );

        Self {
            inner: HandshakeState::new(rng, prologue, &protocol_name),
            state: A,
        }
    }
}

impl<DH, H, RNG> XX<DH, H, RNG, A>
where
    RNG: RngCore + CryptoRng,
    DH: Dh,
    H: Hash,
{
    pub fn initiate(
        self,
        mut output: impl Write,
    ) -> Result<XX<DH, H, RNG, WaitB>, HandshakeStateError> {
        let Self {
            mut inner,
            state: A,
        } = self;

        inner.write_e(&mut output)?;

        inner.encrypt_and_hash(&[], &mut output)?;

        Ok(XX {
            inner,
            state: WaitB,
        })
    }
}

impl<DH, H, RNG> XX<DH, H, RNG, A>
where
    DH: Dh,
    H: Hash,
{
    pub fn receive(self, input: &[u8]) -> Result<XX<DH, H, RNG, SendB>, HandshakeStateError> {
        let Self {
            mut inner,
            state: A,
        } = self;

        let mut input = BufRead::new(input);

        let re = inner.read_e(&mut input)?;

        inner.decrypt_and_hash(&mut input, &mut [])?;

        Ok(XX {
            inner,
            state: SendB { re },
        })
    }
}

impl<DH, H, RNG> XX<DH, H, RNG, SendB>
where
    RNG: RngCore + CryptoRng,
    DH: Dh,
    H: Hash,
{
    pub fn reply(
        self,
        s: &DH,
        mut output: impl Write,
    ) -> Result<XX<DH, H, RNG, WaitC>, HandshakeStateError> {
        let Self {
            mut inner,
            state: SendB { re },
        } = self;

        inner.write_e(&mut output)?;
        inner.dh_ex(&re);
        inner.write_s(&s.public(), &mut output)?;
        inner.dh_sx(s, &re);

        inner.encrypt_and_hash(&[], &mut output)?;

        Ok(XX {
            inner,
            state: WaitC,
        })
    }
}

impl<DH, H, RNG> XX<DH, H, RNG, WaitB>
where
    DH: Dh,
    H: Hash,
{
    pub fn receive(self, input: &[u8]) -> Result<XX<DH, H, RNG, SendC>, HandshakeStateError> {
        let Self {
            mut inner,
            state: WaitB,
        } = self;

        let mut input = BufRead::new(input);

        let re = inner.read_e(&mut input)?;
        inner.dh_ex(&re);
        let rs = inner.read_s(&mut input)?;
        inner.dh_ex(&rs);

        // decode the payload
        inner.decrypt_and_hash(&mut input, &mut [])?;

        let state = SendC { rs, re };

        Ok(XX { inner, state })
    }
}

impl<DH, H, RNG> XX<DH, H, RNG, SendC>
where
    DH: Dh,
    H: Hash,
{
    pub fn reply(
        self,
        s: &DH,
        mut output: impl Write,
    ) -> Result<TransportState<H>, HandshakeStateError> {
        let Self {
            mut inner,
            state: SendC { re, rs },
        } = self;

        inner.write_s(&s.public(), &mut output)?;
        inner.dh_sx(s, &re);

        // encode the payload: put the chain code so the peer can retrieve the public identity
        inner.encrypt_and_hash(&[], &mut output)?;

        let (local, remote) = inner.symmetric_state().split();

        Ok(TransportState::new(
            inner.symmetric_state().get_handshake_hash().clone(),
            local,
            remote,
            rs,
        ))
    }
}

impl<DH, H, RNG> XX<DH, H, RNG, WaitC>
where
    DH: Dh,
    H: Hash,
{
    pub fn receive(self, input: &[u8]) -> Result<TransportState<H>, HandshakeStateError> {
        let Self {
            mut inner,
            state: WaitC,
        } = self;

        let mut input = BufRead::new(input);

        let rs = inner.read_s(&mut input)?;
        inner.dh_ex(&rs);

        inner.decrypt_and_hash(&mut input, &mut [])?;

        let (remote, local) = inner.symmetric_state().split();

        Ok(TransportState::new(
            inner.symmetric_state().get_handshake_hash().clone(),
            local,
            remote,
            rs,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        key::{curve25519, ed25519, ed25519_extended, ed25519_hd},
        noise::transport_state::tests::test_transport,
    };
    use cryptoxide::{blake2b::Blake2b, blake2s::Blake2s};

    fn establish_handshake<H: Hash, K1: Dh, K2: Dh>(
        rng1: crate::Seed,
        rng2: crate::Seed,
        initiator_s: K1,
        responder_s: K2,
    ) -> (TransportState<H>, TransportState<H>) {
        let initiator_key = initiator_s.public();
        let responder_key = responder_s.public();

        let mut rng1 = rng1.into_rand_chacha();
        let mut rng2 = rng2.into_rand_chacha();

        let initiator = XX::new(&mut rng1, &[]);
        let responder = XX::new(&mut rng2, &[]);

        let mut output = Vec::with_capacity(1024);
        let initiator = initiator
            .initiate(&mut output)
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
            .receive(input.as_slice())
            .expect("initiator receives message B");

        let mut output = Vec::with_capacity(1024);
        let initiator = initiator
            .reply(&initiator_s, &mut output)
            .expect("initiator sends message C");
        let input = output;
        let responder = responder
            .receive(input.as_slice())
            .expect("responder receives message C");

        assert_eq!(&initiator_key, responder.remote_public_identity());
        assert_eq!(&responder_key, initiator.remote_public_identity());

        (initiator, responder)
    }

    macro_rules! mk_test {
        ($name:ident, $sk1:ty, $sk2:ty, $hash:ty) => {
            #[quickcheck]
            fn $name(
                rng1: crate::Seed,
                rng2: crate::Seed,
                initiator_s: $sk1,
                responder_s: $sk2,
                messages_init_to_responder: Vec<Vec<u8>>,
                messages_resp_to_initiator: Vec<Vec<u8>>,
            ) -> bool {
                let (initiator, responder) =
                    establish_handshake(rng1, rng2, initiator_s, responder_s);

                test_transport::<$hash>(
                    initiator,
                    responder,
                    messages_init_to_responder,
                    messages_resp_to_initiator,
                )
            }
        };
    }

    mk_test!(
        curve25519_to_curve25519_blake2b,
        curve25519::SecretKey,
        curve25519::SecretKey,
        Blake2b
    );
    mk_test!(
        curve25519_to_curve25519_blake2s,
        curve25519::SecretKey,
        curve25519::SecretKey,
        Blake2s
    );

    mk_test!(
        ed25519_to_ed25519_blake2b,
        ed25519::SecretKey,
        ed25519::SecretKey,
        Blake2b
    );
    mk_test!(
        ed25519_to_ed25519_blake2s,
        ed25519::SecretKey,
        ed25519::SecretKey,
        Blake2s
    );
    mk_test!(
        ed25519_to_ed25519_extended_blake2b,
        ed25519::SecretKey,
        ed25519_extended::SecretKey,
        Blake2b
    );
    mk_test!(
        ed25519_to_ed25519_extended_blake2s,
        ed25519::SecretKey,
        ed25519_extended::SecretKey,
        Blake2s
    );
    mk_test!(
        ed25519_to_ed25519_hd_blake2b,
        ed25519::SecretKey,
        ed25519_hd::SecretKey,
        Blake2b
    );
    mk_test!(
        ed25519_to_ed25519_hd_blake2s,
        ed25519::SecretKey,
        ed25519_hd::SecretKey,
        Blake2s
    );

    mk_test!(
        ed25519_extended_to_ed25519_blake2b,
        ed25519_extended::SecretKey,
        ed25519::SecretKey,
        Blake2b
    );
    mk_test!(
        ed25519_extended_to_ed25519_blake2s,
        ed25519_extended::SecretKey,
        ed25519::SecretKey,
        Blake2s
    );
    mk_test!(
        ed25519_extended_to_ed25519_extended_blake2b,
        ed25519_extended::SecretKey,
        ed25519_extended::SecretKey,
        Blake2b
    );
    mk_test!(
        ed25519_extended_to_ed25519_extended_blake2s,
        ed25519_extended::SecretKey,
        ed25519_extended::SecretKey,
        Blake2s
    );
    mk_test!(
        ed25519_extended_to_ed25519_hd_blake2b,
        ed25519_extended::SecretKey,
        ed25519_hd::SecretKey,
        Blake2b
    );
    mk_test!(
        ed25519_extended_to_ed25519_hd_blake2s,
        ed25519_extended::SecretKey,
        ed25519_hd::SecretKey,
        Blake2s
    );

    mk_test!(
        ed25519_hd_to_ed25519_blake2b,
        ed25519_hd::SecretKey,
        ed25519::SecretKey,
        Blake2b
    );
    mk_test!(
        ed25519_hd_to_ed25519_blake2s,
        ed25519_hd::SecretKey,
        ed25519::SecretKey,
        Blake2s
    );
    mk_test!(
        ed25519_hd_to_ed25519_extended_blake2b,
        ed25519_hd::SecretKey,
        ed25519_extended::SecretKey,
        Blake2b
    );
    mk_test!(
        ed25519_hd_to_ed25519_extended_blake2s,
        ed25519_hd::SecretKey,
        ed25519_extended::SecretKey,
        Blake2s
    );
    mk_test!(
        ed25519_hd_to_ed25519_hd_blake2b,
        ed25519_hd::SecretKey,
        ed25519_hd::SecretKey,
        Blake2b
    );
    mk_test!(
        ed25519_hd_to_ed25519_hd_blake2s,
        ed25519_hd::SecretKey,
        ed25519_hd::SecretKey,
        Blake2s
    );
}
