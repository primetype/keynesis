use std::io::Write;

use crate::{
    buffer::BufRead,
    hash::Hash,
    key::{ed25519::PublicKey, Dh},
    noise::{CipherState, HandshakeState, HandshakeStateError},
    seed::Seed,
};
use rand_core::{CryptoRng, RngCore};

/// One-Way Handshake [**Noise N**]
///
/// [**Noise N**]: https://noiseexplorer.com/patterns/K/
pub struct N<DH, H, RNG>
where
    H: Hash,
{
    inner: HandshakeState<RNG, DH, H>,
}
impl<DH, H, RNG> N<DH, H, RNG>
where
    DH: Dh,
    H: Hash,
{
    pub fn new(rng: RNG, psk: &Option<Seed>, prologue: &[u8]) -> Self {
        let pattern = if psk.is_some() { "Kpsk0" } else { "K" };

        let protocol_name = format!(
            "Noise_{pattern}_{dh}_{cipher}_{hash}",
            pattern = pattern,
            dh = DH::name(),
            cipher = "ChaChaPoly",
            hash = H::name(),
        );

        let mut inner = HandshakeState::new(rng, prologue, &protocol_name);

        if let Some(psk) = psk {
            inner.psk(psk.as_ref());
        }

        Self { inner }
    }
}

impl<DH, H, RNG> N<DH, H, RNG>
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
        rs: &PublicKey,
        payload: impl AsRef<[u8]>,
        mut output: impl Write,
    ) -> Result<(), HandshakeStateError> {
        let Self { mut inner } = self;

        inner.mix_hash(&rs);

        inner.write_e(&mut output)?;
        inner.dh_ex(rs);

        inner.encrypt_and_hash(payload.as_ref(), &mut output)?;
        Ok(())
    }
}

impl<DH, H, RNG> N<DH, H, RNG>
where
    DH: Dh,
    H: Hash,
{
    /// receive a one-way handshake with an unknown
    pub fn receive(self, s: &DH, input: &[u8]) -> Result<Box<[u8]>, HandshakeStateError> {
        let Self { mut inner } = self;

        inner.mix_hash(&s.public());

        let mut input = BufRead::new(input);

        let re = inner.read_e(&mut input)?;
        inner.dh_sx(s, &re);

        let mut bytes = vec![0; input.remaining() - CipherState::TAG_LEN];
        inner.decrypt_and_hash(&mut input, &mut bytes)?;

        Ok(bytes.into_boxed_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::{curve25519, ed25519, ed25519_extended, ed25519_hd};
    use cryptoxide::{blake2b::Blake2b, blake2s::Blake2s};

    fn send_one_way_n<H: Hash, K1: Dh, K2: Dh>(
        rng1: crate::Seed,
        rng2: crate::Seed,
        receiver_s: K2,
        message: Vec<u8>,
    ) -> bool {
        let receiver_key = receiver_s.public();

        let sender = N::<K1, H, _>::new(rng1.into_rand_chacha(), &None, &[]);
        let receiver = N::<_, H, _>::new(rng2.into_rand_chacha(), &None, &[]);

        let mut output = Vec::with_capacity(1024);
        sender
            .send(&receiver_key, &message, &mut output)
            .expect("Send Payload one way handshake N");

        let input = output;
        let decoded_message = receiver
            .receive(&receiver_s, input.as_slice())
            .expect("Receive  payload one way handshake N");

        message.as_slice() == decoded_message.as_ref()
    }

    fn send_one_way_n_psk0<H: Hash, K1: Dh, K2: Dh>(
        rng1: crate::Seed,
        rng2: crate::Seed,
        psk: crate::Seed,
        receiver_s: K2,
        message: Vec<u8>,
    ) -> bool {
        let receiver_key = receiver_s.public();

        let sender = N::<K1, H, _>::new(rng1.into_rand_chacha(), &Some(psk.clone()), &[]);
        let receiver = N::<_, H, _>::new(rng2.into_rand_chacha(), &Some(psk), &[]);

        let mut output = Vec::with_capacity(1024);
        sender
            .send(&receiver_key, &message, &mut output)
            .expect("Send Payload one way handshake N");

        let input = output;
        let decoded_message = receiver
            .receive(&receiver_s, input.as_slice())
            .expect("Receive  payload one way handshake N");

        message.as_slice() == decoded_message.as_ref()
    }

    macro_rules! mk_test {
        ($name:ident, $sk1:ty, $sk2:ty, $hash:ty) => {
            mod $name {
                use super::*;
                #[quickcheck]
                fn n(
                    rng1: crate::Seed,
                    rng2: crate::Seed,
                    responder_s: $sk2,
                    message: Vec<u8>,
                ) -> bool {
                    send_one_way_n::<$hash, $sk1, _>(rng1, rng2, responder_s, message)
                }

                #[quickcheck]
                fn n_psk0(
                    rng1: crate::Seed,
                    rng2: crate::Seed,
                    psk: crate::Seed,
                    responder_s: $sk2,
                    message: Vec<u8>,
                ) -> bool {
                    send_one_way_n_psk0::<$hash, $sk1, _>(rng1, rng2, psk, responder_s, message)
                }
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
