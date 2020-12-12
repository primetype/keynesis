use crate::{
    key::{
        curve25519,
        ed25519::{PublicKey, SecretKey},
    },
    noise::{HandshakeStateError, N},
    passport::block::Time,
    Seed,
};
use cryptoxide::blake2b::Blake2b;
use rand_core::{CryptoRng, RngCore};
use std::{
    convert::{TryFrom, TryInto as _},
    fmt::{self, Formatter},
};
use thiserror::Error;

const COUNT_INDEX: usize = 0;
const COUNT_END: usize = COUNT_INDEX + std::mem::size_of::<u8>();
const KEY_INDEX: usize = COUNT_END;
const KEY_END: usize = KEY_INDEX + PublicKey::SIZE;
const CREATED_AT_INDEX: usize = KEY_END;
const CREATED_AT_END: usize = CREATED_AT_INDEX + Time::SIZE;

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct SetSharedKey(Box<[u8]>);

pub struct SetSharedKeyMut<'a>(&'a mut Vec<u8>, usize);

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct SetSharedKeySlice<'a>(&'a [u8]);

#[derive(Debug, Error)]
pub enum SetSharedKeyError {
    #[error("not valid length for a MasterKey registration entry")]
    InvalidLength,

    #[error("Set shared key entries need to have at least one entry")]
    AtLeastOneSharedKey,

    #[error("Set shared key entries can have at most {} entries", u8::MAX)]
    AtMost255SharedKey,

    #[error("Cannot encrypt key to the recipient")]
    Noise(
        #[source]
        #[from]
        HandshakeStateError,
    ),
}

impl SetSharedKey {
    pub const MIN_SIZE: usize = CREATED_AT_END;
    pub const MSG_SIZE: usize = PublicKey::SIZE + SecretKey::SIZE + 16;
    pub const ID_SIZE: usize = 8;

    pub fn size(slice: &[u8]) -> usize {
        let count = *slice
            .get(0)
            .expect("expect non empty slice to get the size") as usize;

        Self::MIN_SIZE + count * (Self::ID_SIZE + Self::MSG_SIZE)
    }

    #[inline(always)]
    pub fn as_slice(&self) -> SetSharedKeySlice<'_> {
        SetSharedKeySlice(&self.0)
    }

    #[inline(always)]
    pub fn key(&self) -> PublicKey {
        self.as_slice().key()
    }

    #[inline(always)]
    pub fn created_at(&self) -> Time {
        self.as_slice().created_at()
    }

    pub fn messages(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.as_slice().messages()
    }
}

impl<'a> SetSharedKeyMut<'a> {
    pub fn new(bytes: &'a mut Vec<u8>, key: &curve25519::PublicKey) -> Self {
        let start_index = bytes.len();
        bytes.push(0);
        bytes.extend_from_slice(key.as_ref());
        bytes.extend_from_slice(&Time::now().to_be_bytes());

        Self(bytes, start_index)
    }

    pub fn share_with<RNG>(
        &mut self,
        rng: &mut RNG,
        key: &curve25519::SecretKey,
        to: &PublicKey,
        passphrase: &Option<Seed>,
    ) -> Result<(), SetSharedKeyError>
    where
        RNG: RngCore + CryptoRng,
    {
        let mut bytes = [0; SetSharedKey::MSG_SIZE];
        N::<SecretKey, Blake2b, _>::new(rng, passphrase, &[]).send(
            to,
            key.leak_as_ref(),
            &mut bytes.as_mut(),
        )?;
        self.0
            .extend_from_slice(&to.as_ref()[..SetSharedKey::ID_SIZE]);
        self.0.extend_from_slice(&bytes);
        self.count_incr()?;

        Ok(())
    }

    #[inline(always)]
    fn count_incr(&mut self) -> Result<(), SetSharedKeyError> {
        if let Some(count) = self.0[self.1].checked_add(1) {
            self.0[self.1] = count;
            Ok(())
        } else {
            Err(SetSharedKeyError::AtMost255SharedKey)
        }
    }

    pub fn finalize(self) -> Result<&'a mut Vec<u8>, SetSharedKeyError> {
        if self.0[self.1] == 0 {
            Err(SetSharedKeyError::AtLeastOneSharedKey)
        } else {
            Ok(self.0)
        }
    }
}

impl<'a> SetSharedKeySlice<'a> {
    /// if you need to own the `Header`, you can convert the slice into
    /// a `Header`. This will allocate the memory on the heap.
    pub fn to_set_shared_key(&self) -> SetSharedKey {
        SetSharedKey(
            self.0
                .try_into()
                .expect("slice should have the appropriate size"),
        )
    }

    /// Create a SetSharedKeySlice from the given slice
    ///
    /// This function will check the lengths, the version
    /// is a valid version (not a forbidden one), the signature
    /// matches the header's signed data and the author
    pub fn try_from_slice(slice: &'a [u8]) -> Result<Self, SetSharedKeyError> {
        if slice.len() < SetSharedKey::MIN_SIZE {
            return Err(SetSharedKeyError::InvalidLength);
        }

        let entry = Self::from_slice_unchecked(slice);

        let count = entry.count();
        let len = SetSharedKey::MIN_SIZE + count * (SetSharedKey::MSG_SIZE + SetSharedKey::ID_SIZE);

        if len != slice.len() {
            return Err(SetSharedKeyError::InvalidLength);
        }

        Ok(entry)
    }

    /// function to make of the given slice the SetSharedKeySlice
    ///
    /// this function does not check the content is valid for a given
    /// Header. However in debug mode, this function will throw an error
    /// if the slice if not at least of the appropriate size.
    ///
    /// use this function only if you are confident the given slice is
    /// a valid header. Otherwise, use `try_from_slice` function.
    #[inline(always)]
    pub fn from_slice_unchecked(slice: &'a [u8]) -> Self {
        debug_assert!(
            slice.len() >= SetSharedKey::MIN_SIZE,
            "the slice should have the appropriate min length"
        );
        Self(slice)
    }

    pub fn key(&self) -> PublicKey {
        self.0[KEY_INDEX..KEY_END].try_into().expect("key")
    }

    #[inline(always)]
    pub fn count(&self) -> usize {
        self.0[0] as usize
    }

    pub fn messages(&self) -> impl Iterator<Item = (&'a [u8], &'a [u8])> {
        self.0[SetSharedKey::MIN_SIZE..]
            .chunks_exact(SetSharedKey::ID_SIZE + SetSharedKey::MSG_SIZE)
            .map(|slice| slice.split_at(SetSharedKey::ID_SIZE))
    }

    pub fn created_at(&self) -> Time {
        u32::from_be_bytes(
            self.0[CREATED_AT_INDEX..CREATED_AT_END]
                .try_into()
                .expect("created_at"),
        )
        .into()
    }
}

impl<'a> TryFrom<&'a [u8]> for SetSharedKeySlice<'a> {
    type Error = SetSharedKeyError;
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        Self::try_from_slice(value)
    }
}

impl TryFrom<Box<[u8]>> for SetSharedKey {
    type Error = SetSharedKeyError;
    fn try_from(value: Box<[u8]>) -> Result<Self, Self::Error> {
        let _ = SetSharedKeySlice::try_from_slice(&value)?;
        Ok(Self(value))
    }
}

impl<'a> fmt::Debug for SetSharedKeySlice<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let msg = self
            .messages()
            .map(|(k, v)| (hex::encode(k), hex::encode(v)))
            .collect::<Vec<_>>();
        f.debug_struct("SetSharedKeySlice")
            .field("key", &self.key())
            .field("created_at", &self.created_at())
            .field("messages", &msg)
            .finish()
    }
}

impl fmt::Debug for SetSharedKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let msg = self
            .messages()
            .map(|(k, v)| (hex::encode(k), hex::encode(v)))
            .collect::<Vec<_>>();
        f.debug_struct("SetSharedKey")
            .field("key", &self.key())
            .field("created_at", &self.created_at())
            .field("messages", &msg)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::{Arbitrary, Gen};

    impl Arbitrary for SetSharedKey {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            let mut bytes = Vec::with_capacity(1024);
            let key = curve25519::SecretKey::arbitrary(g);
            let mut builder = SetSharedKeyMut::new(&mut bytes, &key.public_key());
            let mut rng = Seed::arbitrary(g).into_rand_chacha();
            let passphrase = Arbitrary::arbitrary(g);

            let count = u8::arbitrary(g).wrapping_add(1);
            for _ in 0..count {
                builder
                    .share_with(&mut rng, &key, &PublicKey::arbitrary(g), &passphrase)
                    .expect("Valid share to the key");
            }

            builder.finalize().expect("Valid entry");

            Self(bytes.into_boxed_slice())
        }
    }

    #[test]
    fn finalize_not_enough() {
        let mut g = quickcheck::StdThreadGen::new(1024);
        let g = &mut g;

        let mut bytes = Vec::with_capacity(1024);
        let key = SecretKey::arbitrary(g);
        let builder = SetSharedKeyMut::new(&mut bytes, &key.public_key());

        matches!(
            builder.finalize(),
            Err(SetSharedKeyError::AtLeastOneSharedKey)
        );
    }

    #[test]
    fn share_with_too_many() {
        let mut g = quickcheck::StdThreadGen::new(1024);
        let g = &mut g;

        let mut bytes = Vec::with_capacity(1024);
        let key = curve25519::SecretKey::arbitrary(g);
        let mut builder = SetSharedKeyMut::new(&mut bytes, &key.public_key());
        let passphrase = Arbitrary::arbitrary(g);
        let mut rng = Seed::arbitrary(g).into_rand_chacha();

        for _ in 0..u8::MAX {
            builder
                .share_with(&mut rng, &key, &PublicKey::arbitrary(g), &passphrase)
                .expect("Valid share to the key");
        }

        matches!(
            builder.share_with(&mut rng, &key, &PublicKey::arbitrary(g), &passphrase),
            Err(SetSharedKeyError::AtMost255SharedKey)
        );
    }

    #[test]
    fn register_master_key_size() {
        assert_eq!(
            SetSharedKey::MIN_SIZE,
            37,
            "expecting a constant size for the SetSharedKey and that it should be documented"
        );
    }

    #[quickcheck]
    fn decode_slice(entry: SetSharedKey) -> bool {
        SetSharedKeySlice::try_from_slice(&entry.0).is_ok()
    }
}
