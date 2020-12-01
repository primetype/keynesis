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
    ///
    /// This function uses HMAC PBKDF2 SHA512 with up to `100_000_000` iterations
    /// if the key is less than 4 bytes... down to `390_625` iteration
    /// from 32bytes long keys onward.
    ///
    /// the operation is therefor very slow to execute, especially with small sized keys.
    pub fn derive_from_key<K, P>(key: K, password: P) -> Self
    where
        K: AsRef<[u8]>,
        P: AsRef<[u8]>,
    {
        let iteration = iteration(key.as_ref().len() as u32);
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

fn iteration(n: u32) -> u32 {
    let n = std::cmp::min(n, 32);
    100_000_000u32.wrapping_div_euclid(2u32.saturating_pow(n.div_euclid(4)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::{Arbitrary, Gen};

    impl Arbitrary for Seed {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            let mut bytes = [0; Self::SIZE];
            g.fill_bytes(&mut bytes);
            Self(bytes)
        }
    }

    #[test]
    fn iterations() {
        assert_eq!(iteration(0), 100_000_000);
        assert_eq!(iteration(1), 100_000_000);
        assert_eq!(iteration(2), 100_000_000);
        assert_eq!(iteration(3), 100_000_000);
        assert_eq!(iteration(4), 50_000_000);
        assert_eq!(iteration(5), 50_000_000);
        assert_eq!(iteration(6), 50_000_000);
        assert_eq!(iteration(7), 50_000_000);
        assert_eq!(iteration(8), 25_000_000);
        assert_eq!(iteration(9), 25_000_000);
        assert_eq!(iteration(10), 25_000_000);
        assert_eq!(iteration(11), 25_000_000);
        assert_eq!(iteration(12), 12_500_000);
        assert_eq!(iteration(13), 12_500_000);
        assert_eq!(iteration(14), 12_500_000);
        assert_eq!(iteration(15), 12_500_000);
        assert_eq!(iteration(16), 6_250_000);
        assert_eq!(iteration(17), 6_250_000);
        assert_eq!(iteration(18), 6_250_000);
        assert_eq!(iteration(19), 6_250_000);
        assert_eq!(iteration(20), 3_125_000);
        assert_eq!(iteration(21), 3_125_000);
        assert_eq!(iteration(22), 3_125_000);
        assert_eq!(iteration(23), 3_125_000);
        assert_eq!(iteration(24), 1_562_500);
        assert_eq!(iteration(25), 1_562_500);
        assert_eq!(iteration(26), 1_562_500);
        assert_eq!(iteration(27), 1_562_500);
        assert_eq!(iteration(28), 781_250);
        assert_eq!(iteration(29), 781_250);
        assert_eq!(iteration(30), 781_250);
        assert_eq!(iteration(31), 781_250);
        assert_eq!(iteration(32), 390_625);
    }

    #[quickcheck]
    fn iteration_greater_then_32_bytes(i: u32) -> quickcheck::TestResult {
        if i <= 32 {
            quickcheck::TestResult::discard()
        } else {
            quickcheck::TestResult::from_bool(iteration(i) == iteration(32))
        }
    }
}
