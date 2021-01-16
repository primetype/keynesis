use crate::{key::ed25519::PublicKey, passport::block::Time};
use std::{
    convert::{TryFrom, TryInto as _},
    fmt::{self, Formatter},
};
use thiserror::Error;

const KEY_INDEX: usize = 0;
const KEY_END: usize = KEY_INDEX + PublicKey::SIZE;
const CREATED_AT_INDEX: usize = KEY_END;
const CREATED_AT_END: usize = CREATED_AT_INDEX + Time::SIZE;

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct DeregisterMasterKey([u8; Self::SIZE]);

pub struct DeregisterMasterKeyMut<'a>(&'a mut [u8]);

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct DeregisterMasterKeySlice<'a>(&'a [u8]);

#[derive(Debug, Error, Eq, PartialEq)]
pub enum DeregisterMasterKeyError {
    #[error("not valid length for a MasterKey deregistration entry")]
    InvalidLength,

    #[error("The signature does verify against the entry")]
    InvalidSignature,
}

impl DeregisterMasterKey {
    pub const SIZE: usize = CREATED_AT_END;

    #[inline(always)]
    pub fn as_slice(&self) -> DeregisterMasterKeySlice<'_> {
        DeregisterMasterKeySlice(&self.0)
    }

    #[inline(always)]
    pub fn key(&self) -> PublicKey {
        self.as_slice().key()
    }

    #[inline(always)]
    pub fn created_at(&self) -> Time {
        self.as_slice().created_at()
    }
}

impl<'a> DeregisterMasterKeyMut<'a> {
    pub fn new(slice: &'a mut [u8], key: &PublicKey) -> Self {
        let mut s = Self(slice);

        let created_at = Time::now();

        s.created_at(created_at);
        s.key(key);

        s
    }

    fn created_at(&mut self, time: Time) {
        self.0[CREATED_AT_INDEX..CREATED_AT_END].copy_from_slice(&time.to_be_bytes())
    }

    fn key(&mut self, key: &PublicKey) {
        self.0[KEY_INDEX..KEY_END].copy_from_slice(key.as_ref())
    }

    pub fn finalize(self) -> DeregisterMasterKeySlice<'a> {
        let slice = self.0;

        DeregisterMasterKeySlice::from_slice_unchecked(slice)
    }
}

impl<'a> DeregisterMasterKeySlice<'a> {
    /// if you need to own the `Header`, you can convert the slice into
    /// a `Header`. This will allocate the memory on the heap.
    pub fn to_register_master_key(&self) -> DeregisterMasterKey {
        DeregisterMasterKey(
            self.0
                .try_into()
                .expect("slice should have the appropriate size"),
        )
    }

    /// Create a DeregisterMasterKeySlice from the given slice
    ///
    pub fn try_from_slice(slice: &'a [u8]) -> Result<Self, DeregisterMasterKeyError> {
        if slice.len() != DeregisterMasterKey::SIZE {
            return Err(DeregisterMasterKeyError::InvalidLength);
        }

        let register_master_key = Self::from_slice_unchecked(slice);

        Ok(register_master_key)
    }

    /// function to make of the given slice the DeregisterMasterKey
    ///
    /// this function does not check the content is valid for a given
    /// Header. However in debug mode, this function will throw an error
    /// if the slice if not at least of the appropriate size.
    ///
    /// use this function only if you are confident the given slice is
    /// a valid header. Otherwise, use `try_from_slice` function.
    #[inline(always)]
    pub fn from_slice_unchecked(slice: &'a [u8]) -> Self {
        debug_assert_eq!(
            slice.len(),
            DeregisterMasterKey::SIZE,
            "the slice should have the appropriate length"
        );
        Self(slice)
    }

    pub fn key(&self) -> PublicKey {
        self.0[KEY_INDEX..KEY_END].try_into().expect("key")
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

impl<'a> TryFrom<&'a [u8]> for DeregisterMasterKeySlice<'a> {
    type Error = DeregisterMasterKeyError;
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        Self::try_from_slice(value)
    }
}

impl TryFrom<[u8; Self::SIZE]> for DeregisterMasterKey {
    type Error = DeregisterMasterKeyError;
    fn try_from(value: [u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let _ = DeregisterMasterKeySlice::try_from_slice(&value)?;
        Ok(Self(value))
    }
}

impl<'a> fmt::Debug for DeregisterMasterKeySlice<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeregisterMasterKeySlice")
            .field("key", &self.key())
            .field("created_at", &self.created_at())
            .finish()
    }
}

impl fmt::Debug for DeregisterMasterKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeregisterMasterKey")
            .field("key", &self.key())
            .field("created_at", &self.created_at())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::{Arbitrary, Gen};

    impl Arbitrary for DeregisterMasterKey {
        fn arbitrary(g: &mut Gen) -> Self {
            let key = PublicKey::arbitrary(g);

            let mut bytes = [0; Self::SIZE];
            let builder = DeregisterMasterKeyMut::new(&mut bytes, &key);

            let _ = builder.finalize();

            Self::try_from(bytes).expect("valid header")
        }
    }

    #[test]
    fn register_master_key_size() {
        assert_eq!(
            DeregisterMasterKey::SIZE,
            36,
            "expecting a constant size for the DeregisterMasterKey and that it should be documented"
        );
    }

    #[quickcheck]
    fn decode_slice(register_master_key: DeregisterMasterKey) -> bool {
        DeregisterMasterKeySlice::try_from_slice(&register_master_key.0).is_ok()
    }
}
