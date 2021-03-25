use crate::{
    key::SharedSecret,
    memsec::{self, Scrubbed as _},
};
use cryptoxide::ed25519;
use rand_core::{CryptoRng, RngCore};
use std::{
    cmp::Ordering,
    convert::TryFrom,
    fmt::{self, Debug, Display, Formatter},
    hash::{Hash, Hasher},
    str::FromStr,
};
use thiserror::Error;

/// Ed25519 Secret Key
///
/// Mind it though, losing this key means losing control over your identity
#[derive(Clone)]
pub struct SecretKey([u8; Self::SIZE]);

/// Ed25519 Public Key
///
/// Can safely be shared publicly, everyone with this key can:
///
/// * verify a signature generated by the associate `SecretKey`;
/// * establish a Diffie-Hellman key exchange (using curve25519)
///
#[derive(Clone, Copy)]
pub struct PublicKey([u8; Self::SIZE]);

/// A signature that can be verified with a Ed25519 `PublicKey`
#[derive(Clone, Copy)]
pub struct Signature([u8; Self::SIZE]);

impl SecretKey {
    /// the size of the Secret key in bytes
    pub const SIZE: usize = ed25519::SEED_LENGTH;

    /// create a dummy instance of the object but filled with zeroes
    #[inline(always)]
    const fn zero() -> Self {
        Self([0; Self::SIZE])
    }

    /// generate a new `SecretKey` with the given random number generator
    ///
    pub fn new<Rng>(mut rng: Rng) -> Self
    where
        Rng: RngCore + CryptoRng,
    {
        let mut s = Self::zero();
        rng.fill_bytes(&mut s.0);
        s
    }

    /// generate a shared secret between the owner of the given public key and
    /// ourselves.
    ///
    pub fn exchange(&self, public_key: &PublicKey) -> SharedSecret {
        SharedSecret::new(ed25519::exchange(public_key.as_ref(), &self.0))
    }

    /// get the `PublicKey` associated to this key
    ///
    /// Unlike the `SecretKey`, the `PublicKey` can be safely
    /// publicly shared. The key can then be used to verify any
    /// `Signature` generated with this `SecretKey` and the original
    /// message.
    pub fn public_key(&self) -> PublicKey {
        let (mut sk, pk) = ed25519::keypair(&self.0);

        // the `sk` is a private component, scrubbing it reduce the
        // risk of an adversary accessing the memory remains of this
        // value
        sk.scrub();

        PublicKey(pk)
    }

    /// create a `Signature` for the given message with this `SecretKey`.
    ///
    /// The `Signature` can then be verified against the associated `PublicKey`
    /// and the original message.
    pub fn sign<T: AsRef<[u8]>>(&self, msg: T) -> Signature {
        let (mut sk, _) = ed25519::keypair(&self.0);

        let signature = ed25519::signature(msg.as_ref(), &sk);

        // we don't need this signature component, make sure to scrub the
        // content before releasing the results
        sk.scrub();

        Signature(signature)
    }

    /// get a reference to the inner Seed bytes
    ///
    /// # Security Consideration
    ///
    /// be mindful that leaking the content of the internal signing key
    /// may result in losing the ultimate control of the signing key
    #[cfg(test)]
    fn leak_as_ref(&self) -> &[u8; Self::SIZE] {
        &self.0
    }
}

impl PublicKey {
    pub const SIZE: usize = ed25519::PUBLIC_KEY_LENGTH;

    #[inline(always)]
    const fn zero() -> Self {
        Self([0; Self::SIZE])
    }

    /// verify the `Signature` with the original message
    ///
    /// this function will verify that only the associated `SecretKey`
    /// generated the `Signature` with the original message (non repudiation).
    pub fn verify<T: AsRef<[u8]>>(&self, msg: T, signature: &Signature) -> bool {
        ed25519::verify(msg.as_ref(), &self.0, &signature.0)
    }
}

impl Signature {
    pub const SIZE: usize = ed25519::SIGNATURE_LENGTH;

    #[inline(always)]
    const fn zero() -> Self {
        Self([0; Self::SIZE])
    }
}

/* Format ****************************************************************** */

impl Display for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&hex::encode(self.as_ref()), f)
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&hex::encode(self.as_ref()), f)
    }
}

impl Debug for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Signature<Ed25519>")
            .field(&hex::encode(self.as_ref()))
            .finish()
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PublicKey<Ed25519>")
            .field(&hex::encode(self.as_ref()))
            .finish()
    }
}

/// conveniently provide a proper implementation to debug for the
/// SecretKey types when only *testing* the library
#[cfg(test)]
impl Debug for SecretKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SecretKey<Ed25519>")
            .field(&hex::encode(&self.0))
            .finish()
    }
}

/// conveniently provide an incomplete implementation of Debug for the
/// SecretKey.
#[cfg(not(test))]
impl Debug for SecretKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SecretKey<Ed25519>").field(&"...").finish()
    }
}

/* Conversion ************************************************************** */

impl<'a> From<&'a Signature> for String {
    fn from(s: &'a Signature) -> Self {
        s.to_string()
    }
}

impl From<Signature> for String {
    fn from(s: Signature) -> Self {
        s.to_string()
    }
}

impl From<[u8; Self::SIZE]> for SecretKey {
    fn from(bytes: [u8; Self::SIZE]) -> Self {
        Self(bytes)
    }
}

impl From<[u8; Self::SIZE]> for PublicKey {
    fn from(bytes: [u8; Self::SIZE]) -> Self {
        Self(bytes)
    }
}

impl From<PublicKey> for [u8; PublicKey::SIZE] {
    fn from(pk: PublicKey) -> Self {
        pk.0
    }
}

impl From<[u8; Self::SIZE]> for Signature {
    fn from(bytes: [u8; Self::SIZE]) -> Self {
        Self(bytes)
    }
}

#[derive(Debug, Error)]
pub enum SecretKeyError {
    #[error("Invalid size, expecting {}", SecretKey::SIZE)]
    InvalidSize,
}

#[derive(Debug, Error)]
pub enum PublicKeyError {
    #[error("Invalid size, expecting {}", PublicKey::SIZE)]
    InvalidSize,
}

#[derive(Debug, Error)]
pub enum SignatureError {
    #[error("Invalid size, expecting {}", PublicKey::SIZE)]
    InvalidSize,
}

impl<'a> TryFrom<&'a [u8]> for SecretKey {
    type Error = SecretKeyError;
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        if value.len() != Self::SIZE {
            Err(Self::Error::InvalidSize)
        } else {
            let mut s = Self::zero();
            s.0.copy_from_slice(value);
            Ok(s)
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for PublicKey {
    type Error = PublicKeyError;
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        if value.len() != Self::SIZE {
            Err(Self::Error::InvalidSize)
        } else {
            let mut s = Self::zero();
            s.0.copy_from_slice(value);
            Ok(s)
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for Signature {
    type Error = SignatureError;
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        if value.len() != Self::SIZE {
            Err(Self::Error::InvalidSize)
        } else {
            let mut s = Self::zero();
            s.0.copy_from_slice(value);
            Ok(s)
        }
    }
}

impl FromStr for SecretKey {
    type Err = hex::FromHexError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut r = Self::zero();
        hex::decode_to_slice(s, &mut r.0)?;
        Ok(r)
    }
}

impl FromStr for PublicKey {
    type Err = hex::FromHexError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut r = Self::zero();
        hex::decode_to_slice(s, &mut r.0)?;
        Ok(r)
    }
}

impl FromStr for Signature {
    type Err = hex::FromHexError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut r = Self::zero();
        hex::decode_to_slice(s, &mut r.0)?;
        Ok(r)
    }
}

impl<'a> TryFrom<&'a str> for Signature {
    type Error = <Self as FromStr>::Err;
    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

/* Eq ********************************************************************** */

impl PartialEq<Self> for Signature {
    fn eq(&self, other: &Self) -> bool {
        unsafe { memsec::memeq(self.0.as_ptr(), other.0.as_ptr(), Self::SIZE) }
    }
}

impl PartialEq<Self> for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        unsafe { memsec::memeq(self.0.as_ptr(), other.0.as_ptr(), Self::SIZE) }
    }
}

impl PartialEq<Self> for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        unsafe { memsec::memeq(self.0.as_ptr(), other.0.as_ptr(), Self::SIZE) }
    }
}

impl Eq for Signature {}
impl Eq for PublicKey {}
impl Eq for SecretKey {}

/* Ord ********************************************************************* */

impl PartialOrd<Self> for Signature {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl PartialOrd<Self> for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Signature {
    fn cmp(&self, other: &Self) -> Ordering {
        unsafe { memsec::memcmp(self.0.as_ptr(), other.0.as_ptr(), Self::SIZE) }
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        unsafe { memsec::memcmp(self.0.as_ptr(), other.0.as_ptr(), Self::SIZE) }
    }
}

/* Hash ******************************************************************** */

impl Hash for Signature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state)
    }
}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state)
    }
}

impl Hash for SecretKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.as_ref().hash(state)
    }
}

/* AsRef ******************************************************************* */

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/* Drop ******************************************************************** */

/// custom implementation of Drop so we can have more certainty that
/// the secret key raw data will be scrubbed (zeroed) before releasing
/// the memory
impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.scrub()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::{Arbitrary, Gen, TestResult};

    impl Arbitrary for SecretKey {
        fn arbitrary(g: &mut Gen) -> Self {
            let mut s = Self::zero();
            s.0.iter_mut().for_each(|byte| {
                *byte = u8::arbitrary(g);
            });
            s
        }
    }

    impl Arbitrary for PublicKey {
        fn arbitrary(g: &mut Gen) -> Self {
            let mut s = Self::zero();
            s.0.iter_mut().for_each(|byte| {
                *byte = u8::arbitrary(g);
            });
            s
        }
    }

    impl Arbitrary for Signature {
        fn arbitrary(g: &mut Gen) -> Self {
            let mut s = Self::zero();
            s.0.iter_mut().for_each(|byte| {
                *byte = u8::arbitrary(g);
            });
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
    fn signing_verify_works(signing_key: SecretKey, message: Vec<u8>) -> bool {
        let public_key = signing_key.public_key();
        let signature = signing_key.sign(&message);

        public_key.verify(message, &signature)
    }

    #[quickcheck]
    fn verify_random_signature_does_not_work(
        public_key: PublicKey,
        signature: Signature,
        message: Vec<u8>,
    ) -> bool {
        // NOTE: this test may fail but it is impossible to see this happening at all
        //       we are generating 32 random bytes of verify key and 64 random bytes
        //       of signature with an randomly generated message of a random number
        //       of bytes in, if the message were empty, the probability to have
        //       a signature that matches the verify key would still be 1 out of 2^96.
        //       if this test fails and it is not a bug, go buy a lottery ticket.
        !public_key.verify(message, &signature)
    }

    #[quickcheck]
    fn signing_key_try_from_correct_size(signing_key: SecretKey) -> TestResult {
        match SecretKey::try_from(signing_key.leak_as_ref().as_ref()) {
            Ok(_) => TestResult::passed(),
            Err(SecretKeyError::InvalidSize) => TestResult::error("was expecting the test to pass"),
        }
    }

    #[quickcheck]
    fn signing_key_try_from_incorrect_size(bytes: Vec<u8>) -> TestResult {
        if bytes.len() == SecretKey::SIZE {
            return TestResult::discard();
        }
        match SecretKey::try_from(bytes.as_slice()) {
            Ok(_) => TestResult::error(
                "Expecting to fail with invalid size instead of having a valid value",
            ),
            Err(SecretKeyError::InvalidSize) => TestResult::passed(),
        }
    }

    #[quickcheck]
    fn public_key_try_from_correct_size(public_key: PublicKey) -> TestResult {
        match PublicKey::try_from(public_key.as_ref()) {
            Ok(_) => TestResult::passed(),
            Err(PublicKeyError::InvalidSize) => TestResult::error("was expecting the test to pass"),
        }
    }

    #[quickcheck]
    fn public_key_try_from_incorrect_size(bytes: Vec<u8>) -> TestResult {
        if bytes.len() == PublicKey::SIZE {
            return TestResult::discard();
        }
        match PublicKey::try_from(bytes.as_slice()) {
            Ok(_) => TestResult::error(
                "Expecting to fail with invalid size instead of having a valid value",
            ),
            Err(PublicKeyError::InvalidSize) => TestResult::passed(),
        }
    }

    #[quickcheck]
    fn signature_try_from_correct_size(signature: Signature) -> TestResult {
        match Signature::try_from(signature.as_ref()) {
            Ok(_) => TestResult::passed(),
            Err(SignatureError::InvalidSize) => TestResult::error("was expecting the test to pass"),
        }
    }

    #[quickcheck]
    fn signature_try_from_incorrect_size(bytes: Vec<u8>) -> TestResult {
        if bytes.len() == Signature::SIZE {
            return TestResult::discard();
        }
        match Signature::try_from(bytes.as_slice()) {
            Ok(_) => TestResult::error(
                "Expecting to fail with invalid size instead of having a valid value",
            ),
            Err(SignatureError::InvalidSize) => TestResult::passed(),
        }
    }

    #[quickcheck]
    fn public_key_from_str(public_key: PublicKey) -> TestResult {
        let s = public_key.to_string();

        match s.parse::<PublicKey>() {
            Ok(decoded) => {
                if decoded == public_key {
                    TestResult::passed()
                } else {
                    TestResult::error("the decoded key is not equal")
                }
            }
            Err(error) => TestResult::error(error.to_string()),
        }
    }

    #[quickcheck]
    fn signature_from_str(signature: Signature) -> TestResult {
        let s = signature.to_string();

        match s.parse::<Signature>() {
            Ok(decoded) => {
                if decoded == signature {
                    TestResult::passed()
                } else {
                    TestResult::error("the decoded signature is not equal")
                }
            }
            Err(error) => TestResult::error(error.to_string()),
        }
    }
}
