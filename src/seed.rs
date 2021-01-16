use crate::memsec::Scrubbed as _;
use cryptoxide::{hmac::Hmac, pbkdf2::pbkdf2, sha2::Sha512};
use rand_chacha::ChaChaRng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use std::{
    fmt::{self, Debug, Display, Formatter},
    str::FromStr,
};

#[derive(Clone)]
pub struct Seed([u8; Self::SIZE]);

impl Seed {
    pub const SIZE: usize = 32;

    /// Generate a random see with the given Cryptographically secure
    /// Random Number Generator (RNG).
    ///
    /// This is useful to generate one time only `Seed` that does not
    /// need to be remembered or saved.
    pub fn generate<RNG>(rng: &mut RNG) -> Self
    where
        RNG: RngCore + CryptoRng,
    {
        let mut bytes = [0; Self::SIZE];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// it is possible to derive the Seed from a given key
    ///
    /// the key may be given by a secure hardware or simply be
    /// a mnemonic phrase given by a user and a password.
    ///
    /// It is possible, but not recommended, that the password is left
    /// empty. However, the key needs to be large enough to generate
    /// enough entropy for the derived seed.
    pub fn derive_from_key<K, P>(key: K, password: P) -> Self
    where
        K: AsRef<[u8]>,
        P: AsRef<[u8]>,
    {
        debug_assert!(
            key.as_ref().len() >= 32,
            "It is highly unsafe to use key with less than 32bytes"
        );

        let iteration = 1_000_000;
        let mut bytes = [0; Self::SIZE];

        let mut mac = Hmac::new(Sha512::new(), password.as_ref());

        pbkdf2(&mut mac, key.as_ref(), iteration, &mut bytes);

        Self(bytes)
    }

    /// use this to seed a ChaCha RNG
    ///
    /// then you can use the RNG to create new private key. This is an
    /// handy way to derive a private key from a key and a password
    /// (or an HSM and a password?)
    pub fn into_rand_chacha(self) -> ChaChaRng {
        ChaChaRng::from_seed(self.0)
    }
}

impl Drop for Seed {
    fn drop(&mut self) {
        self.0.scrub()
    }
}

impl Display for Seed {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&hex::encode(&self.0), f)
    }
}

impl Debug for Seed {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Seed").field(&hex::encode(&self.0)).finish()
    }
}

impl AsRef<[u8]> for Seed {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl FromStr for Seed {
    type Err = hex::FromHexError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0; Self::SIZE];
        hex::decode_to_slice(s, &mut bytes)?;
        Ok(Self(bytes))
    }
}

impl From<[u8; Self::SIZE]> for Seed {
    fn from(seed: [u8; Self::SIZE]) -> Self {
        Self(seed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::{Arbitrary, Gen};

    impl Arbitrary for Seed {
        fn arbitrary(g: &mut Gen) -> Self {
            let mut bytes = [0; Self::SIZE];
            bytes.iter_mut().for_each(|byte| {
                *byte = u8::arbitrary(g);
            });
            Self(bytes)
        }
    }
}
