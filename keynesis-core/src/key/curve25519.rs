use crate::{
    key::SharedSecret,
    memsec::{self, Scrubbed as _},
};
use cryptoxide::curve25519::curve25519;
use rand_core::{CryptoRng, RngCore};
use std::{
    convert::TryFrom,
    fmt::{self, Debug, Formatter},
    hash::{Hash, Hasher},
    str::FromStr,
};
use thiserror::Error;

#[derive(Clone)]
pub struct SecretKey {
    secret: [u8; Self::SIZE],
    public: [u8; 32],
}

pub use crate::key::ed25519::{PublicKey, PublicKeyError};

impl SecretKey {
    pub const SIZE: usize = 32;

    /// create a dummy instance of the object but filled with zeroes
    #[inline(always)]
    const fn zero() -> Self {
        Self {
            secret: [0; Self::SIZE],
            public: [0; 32],
        }
    }

    /// generate a new `SecretKey` with the given random number generator
    ///
    pub fn new<Rng>(mut rng: Rng) -> Self
    where
        Rng: RngCore + CryptoRng,
    {
        let mut s = Self::zero();
        rng.fill_bytes(&mut s.secret);

        s.secret[0] &= 0b1111_1000;
        s.secret[31] &= 0b0011_1111;
        s.secret[31] |= 0b0100_0000;

        let pk = cryptoxide::curve25519::curve25519_base(&s.secret);
        s.public = pk;

        debug_assert!(
            s.check_structure(),
            "checking we properly set the bit tweaks for the extended Ed25519"
        );

        s
    }

    #[allow(clippy::verbose_bit_mask)]
    fn check_structure(&self) -> bool {
        (self.secret[0] & 0b0000_0111) == 0
            && (self.secret[31] & 0b0100_0000) == 0b0100_0000
            && (self.secret[31] & 0b1000_0000) == 0
    }

    /// get the `PublicKey` associated to this key
    ///
    /// Unlike the `SecretKey`, the `PublicKey` can be safely
    /// publicly shared. The key can then be used to verify any
    /// `Signature` generated with this `SecretKey` and the original
    /// message.
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from(self.public)
    }

    /// generate a shared secret between the owner of the given Curve25519 public key and
    /// ourselves.
    ///
    pub fn exchange(&self, public_key: &PublicKey) -> SharedSecret {
        SharedSecret::new(curve25519(&self.secret, public_key.as_ref()))
    }

    /// get a reference to the inner Seed bytes
    ///
    /// # Security Consideration
    ///
    /// be mindful that leaking the content of the internal signing key
    /// may result in losing the ultimate control of the signing key
    pub fn leak_as_ref(&self) -> &[u8; Self::SIZE] {
        &self.secret
    }
}

/* Format ****************************************************************** */

/// conveniently provide a proper implementation to debug for the
/// SecretKey types when only *testing* the library
#[cfg(test)]
impl Debug for SecretKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SecretKey<Ed25519Extended>")
            .field(&hex::encode(&self.secret[..]))
            .finish()
    }
}

/// conveniently provide an incomplete implementation of Debug for the
/// SecretKey.
#[cfg(not(test))]
impl Debug for SecretKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SecretKey<Ed25519Extended>")
            .field(&"...")
            .finish()
    }
}

/* Conversion ************************************************************** */

#[derive(Debug, Error)]
pub enum SecretKeyError {
    #[error("Invalid size, expecting {}", SecretKey::SIZE)]
    InvalidSize,
    #[error("Invalid structure")]
    InvalidStructure,
}

impl TryFrom<[u8; Self::SIZE]> for SecretKey {
    type Error = SecretKeyError;

    fn try_from(bytes: [u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let public = cryptoxide::curve25519::curve25519_base(&bytes);
        let s = Self {
            secret: bytes,
            public,
        };
        if s.check_structure() {
            Ok(s)
        } else {
            Err(Self::Error::InvalidStructure)
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for SecretKey {
    type Error = SecretKeyError;
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        if value.len() != Self::SIZE {
            Err(Self::Error::InvalidSize)
        } else {
            let mut s = [0; Self::SIZE];
            s.copy_from_slice(value);
            Self::try_from(s)
        }
    }
}

impl FromStr for SecretKey {
    type Err = hex::FromHexError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut r = Self::zero();
        hex::decode_to_slice(s, &mut r.secret)?;
        let public = cryptoxide::curve25519::curve25519_base(&r.secret);
        r.public = public;
        Ok(r)
    }
}

/* Eq ********************************************************************** */

impl PartialEq<Self> for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        unsafe { memsec::memeq(self.secret.as_ptr(), other.secret.as_ptr(), Self::SIZE) }
    }
}

impl Eq for SecretKey {}

/* Hash ******************************************************************** */

impl Hash for SecretKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.secret.as_ref().hash(state)
    }
}

/* Drop ******************************************************************** */

/// custom implementation of Drop so we can have more certainty that
/// the signing key raw data will be scrubbed (zeroed) before releasing
/// the memory
impl Drop for SecretKey {
    fn drop(&mut self) {
        self.secret.scrub()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::{Arbitrary, Gen, TestResult};

    impl Arbitrary for SecretKey {
        fn arbitrary(g: &mut Gen) -> Self {
            let mut s = Self::zero();
            s.secret.iter_mut().for_each(|byte| {
                *byte = u8::arbitrary(g);
            });

            s.secret[0] &= 0b1111_1000;
            s.secret[31] &= 0b0011_1111;
            s.secret[31] |= 0b0100_0000;

            s.public = cryptoxide::curve25519::curve25519_base(&s.secret);

            s
        }
    }

    #[quickcheck]
    fn verify_exchange_works(alice: SecretKey, bob: SecretKey) -> bool {
        let alice_pk = alice.public_key();
        let bob_pk = bob.public_key();

        alice.exchange(&bob_pk) == bob.exchange(&alice_pk)
    }

    #[quickcheck]
    fn secret_key_try_from_correct_size(secret_key: SecretKey) -> TestResult {
        match SecretKey::try_from(secret_key.leak_as_ref().as_ref()) {
            Ok(_) => TestResult::passed(),
            Err(SecretKeyError::InvalidSize) => {
                TestResult::error("was expecting the test to pass, not an invalid size")
            }
            Err(SecretKeyError::InvalidStructure) => {
                TestResult::error("was expecting the test to pass, not an invalid structure")
            }
        }
    }

    #[quickcheck]
    fn secret_key_try_from_incorrect_size(bytes: Vec<u8>) -> TestResult {
        if bytes.len() == SecretKey::SIZE {
            return TestResult::discard();
        }
        match SecretKey::try_from(bytes.as_slice()) {
            Ok(_) => TestResult::error(
                "Expecting to fail with invalid size instead of having a valid value",
            ),
            Err(SecretKeyError::InvalidSize) => TestResult::passed(),
            Err(SecretKeyError::InvalidStructure) => {
                TestResult::error("was expecting an invalid size error, not an invalid structure")
            }
        }
    }
}
