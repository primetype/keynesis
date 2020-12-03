use std::io::Write;

use crate::{
    buffer::BufRead,
    hash::Hash,
    key::{ed25519::PublicKey, Dh},
    noise::{CipherState, HandshakeState, HandshakeStateError},
};
use rand_core::{CryptoRng, RngCore};

/// One-Way Handshake [**Noise X**]
///
/// [**Noise X**]: https://noiseexplorer.com/patterns/X/
pub struct X<DH, H, RNG>
where
    H: Hash,
{
    inner: HandshakeState<RNG, DH, H>,
}
impl<DH, H, RNG> X<DH, H, RNG>
where
    DH: Dh,
    H: Hash,
{
    pub fn new(rng: RNG, prologue: &[u8]) -> Self {
        let protocol_name = format!(
            "Noise_{pattern}_{dh}_{cipher}_{hash}",
            pattern = "X",
            dh = DH::name(),
            cipher = "ChaChaPoly",
            hash = H::name(),
        );

        Self {
            inner: HandshakeState::new(rng, prologue, &protocol_name),
        }
    }
}

impl<DH, H, RNG> X<DH, H, RNG>
where
    RNG: RngCore + CryptoRng,
    DH: Dh,
    H: Hash,
{
    /// establish a one-way handshake with an already known `PublicIdentity`
    /// and send the given payload too.
    ///
    /// This is not the strongest way to establish a channel with another
    /// peer. However it is strong enough encryption scheme as long as the
    /// peer's `PrivateIdentity` is not compromised. This is why we are not
    /// allowing a TransportState to be built with this function.
    ///
    /// This is an asymmetric encryption scheme. Once the message has been
    /// sent, we won't be able to decode it back.
    pub fn send(
        self,
        s: &DH,
        rs: &PublicKey,
        payload: impl AsRef<[u8]>,
        mut output: impl Write,
    ) -> Result<(), HandshakeStateError> {
        let Self { mut inner } = self;

        inner.mix_hash(&rs);

        inner.write_e(&mut output)?;
        inner.dh_ex(rs);
        inner.write_s(&s.public(), &mut output)?;
        inner.dh_sx(s, rs);

        inner.encrypt_and_hash(payload.as_ref(), &mut output)?;
        Ok(())
    }
}

impl<DH, H, RNG> X<DH, H, RNG>
where
    DH: Dh,
    H: Hash,
{
    /// receive a one-way handshake with an unknown
    pub fn receive(
        self,
        s: &DH,
        input: &[u8],
    ) -> Result<(PublicKey, Box<[u8]>), HandshakeStateError> {
        let Self { mut inner } = self;

        inner.mix_hash(&s.public());

        let mut input = BufRead::new(input);

        let re = inner.read_e(&mut input)?;
        inner.dh_sx(s, &re);
        let rs = inner.read_s(&mut input)?;
        inner.dh_sx(s, &rs);

        let mut bytes = vec![0; input.remaining() - CipherState::TAG_LEN];
        inner.decrypt_and_hash(&mut input, &mut bytes)?;

        Ok((rs, bytes.into_boxed_slice()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::{curve25519, ed25519, ed25519_extended, ed25519_hd};
    use cryptoxide::{blake2b::Blake2b, blake2s::Blake2s};

    fn send_one_way_x<H: Hash, K1: Dh, K2: Dh>(
        rng1: crate::Seed,
        rng2: crate::Seed,
        sender_s: K1,
        receiver_s: K2,
        message: Vec<u8>,
    ) -> bool {
        let sender_key = sender_s.public();
        let receiver_key = receiver_s.public();

        let sender = X::<_, H, _>::new(rng1.into_rand_chacha(), &[]);
        let receiver = X::<_, H, _>::new(rng2.into_rand_chacha(), &[]);

        let mut output = Vec::with_capacity(1024);
        sender
            .send(&sender_s, &receiver_key, &message, &mut output)
            .expect("Send Payload one way handshake X");

        let input = output;
        let (decoded_sender_key, decoded_message) = receiver
            .receive(&receiver_s, input.as_slice())
            .expect("Receive  payload one way handshake X");

        assert_eq!(sender_key, decoded_sender_key);

        message.as_slice() == decoded_message.as_ref()
    }

    macro_rules! mk_test {
        ($name:ident, $sk1:ty, $sk2:ty, $hash:ty) => {
            #[quickcheck]
            fn $name(
                rng1: crate::Seed,
                rng2: crate::Seed,
                initiator_s: $sk1,
                responder_s: $sk2,
                message: Vec<u8>,
            ) -> bool {
                send_one_way_x::<$hash, _, _>(rng1, rng2, initiator_s, responder_s, message)
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
