use crate::{
    key::ed25519::{PublicKey, SecretKey, Signature},
    passport::block::{Hash, Time},
};
use std::{
    borrow::Cow,
    convert::{TryFrom, TryInto as _},
    fmt::{self, Formatter},
};
use thiserror::Error;

const MAX_ALIAS_LEN: usize = 32;

const KEY_INDEX: usize = 0;
const KEY_END: usize = KEY_INDEX + PublicKey::SIZE;
const ALIAS_INDEX: usize = KEY_END;
const ALIAS_END: usize = ALIAS_INDEX + MAX_ALIAS_LEN;
const PASSPORT_ID_INDEX: usize = ALIAS_END;
const PASSPORT_ID_END: usize = PASSPORT_ID_INDEX + Hash::SIZE;
const CREATED_AT_INDEX: usize = PASSPORT_ID_END;
const CREATED_AT_END: usize = CREATED_AT_INDEX + Time::SIZE;
const REGISTRATION_TIMEOUT_INDEX: usize = CREATED_AT_END;
const REGISTRATION_TIMEOUT_END: usize = REGISTRATION_TIMEOUT_INDEX + Time::SIZE;
const SIGNATURE_INDEX: usize = REGISTRATION_TIMEOUT_END;
const SIGNATURE_END: usize = SIGNATURE_INDEX + Signature::SIZE;

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct RegisterMasterKey([u8; Self::SIZE]);

pub struct RegisterMasterKeyMut<'a>(&'a mut [u8]);

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct RegisterMasterKeySlice<'a>(&'a [u8]);

#[derive(Debug, Error, Eq, PartialEq)]
pub enum RegisterMasterKeyError {
    #[error("not valid length for a MasterKey registration entry")]
    InvalidLength,

    #[error("The signature does verify against the entry")]
    InvalidSignature,

    #[error("Invalid alias")]
    InvalidAlias,

    #[error("The registration timeout ({registration_timeout}) and creation time ({created_at}) are not consistent")]
    InvalidRegistrationTime {
        created_at: Time,
        registration_timeout: Time,
    },
}

impl RegisterMasterKey {
    pub const SIZE: usize = SIGNATURE_END;
    /// number of seconds to do the registration
    pub const REGISTRATION_TIMEOUT: u32 = 3600;

    #[inline(always)]
    pub fn as_slice(&self) -> RegisterMasterKeySlice<'_> {
        RegisterMasterKeySlice(&self.0)
    }

    #[inline(always)]
    pub fn key(&self) -> PublicKey {
        self.as_slice().key()
    }

    pub fn alias(&self) -> Cow<'_, str> {
        self.as_slice().alias()
    }

    #[inline(always)]
    pub fn created_at(&self) -> Time {
        self.as_slice().created_at()
    }

    #[inline(always)]
    pub fn passport(&self) -> Hash {
        self.as_slice().passport()
    }

    #[inline(always)]
    pub fn registration_timeout(&self) -> Time {
        self.as_slice().registration_timeout()
    }

    #[inline(always)]
    pub fn signature(&self) -> Signature {
        self.as_slice().signature()
    }
}

impl<'a> RegisterMasterKeyMut<'a> {
    pub fn new(
        slice: &'a mut [u8],
        alias: &str,
        passport_id: Hash,
    ) -> Result<Self, RegisterMasterKeyError> {
        let mut s = Self(slice);

        if !check_alias(alias) {
            return Err(RegisterMasterKeyError::InvalidAlias);
        }

        s.alias(alias);
        let created_at = Time::now();
        s.created_at(created_at);
        let registration_timeout = created_at
            .wrapping_add(RegisterMasterKey::REGISTRATION_TIMEOUT)
            .into();
        s.passport(passport_id);
        s.registration_timeout(registration_timeout);

        Ok(s)
    }

    fn alias(&mut self, alias: &str) {
        self.0[ALIAS_INDEX..(ALIAS_INDEX + alias.len())].copy_from_slice(alias.as_bytes());
    }

    fn passport(&mut self, passport_id: Hash) {
        self.0[PASSPORT_ID_INDEX..PASSPORT_ID_END].copy_from_slice(passport_id.as_ref())
    }

    fn created_at(&mut self, time: Time) {
        self.0[CREATED_AT_INDEX..CREATED_AT_END].copy_from_slice(&time.to_be_bytes())
    }

    fn registration_timeout(&mut self, time: Time) {
        self.0[REGISTRATION_TIMEOUT_INDEX..REGISTRATION_TIMEOUT_END]
            .copy_from_slice(&time.to_be_bytes())
    }

    pub fn finalize(self, author: &SecretKey) -> RegisterMasterKeySlice<'a> {
        let slice = self.0;
        let pk = author.public_key();

        slice[KEY_INDEX..KEY_END].copy_from_slice(pk.as_ref());
        let signature = author.sign(&slice[KEY_INDEX..SIGNATURE_INDEX]);

        slice[SIGNATURE_INDEX..SIGNATURE_END].copy_from_slice(signature.as_ref());

        RegisterMasterKeySlice::from_slice_unchecked(slice)
    }
}

impl<'a> RegisterMasterKeySlice<'a> {
    /// if you need to own the `Header`, you can convert the slice into
    /// a `Header`. This will allocate the memory on the heap.
    pub fn to_register_master_key(&self) -> RegisterMasterKey {
        RegisterMasterKey(
            self.0
                .try_into()
                .expect("slice should have the appropriate size"),
        )
    }

    /// Create a RegisterMasterKeySlice from the given slice
    ///
    /// This function will check the lengths, the version
    /// is a valid version (not a forbidden one), the signature
    /// matches the header's signed data and the author
    pub fn try_from_slice(slice: &'a [u8]) -> Result<Self, RegisterMasterKeyError> {
        if slice.len() != RegisterMasterKey::SIZE {
            return Err(RegisterMasterKeyError::InvalidLength);
        }

        let register_master_key = Self::from_slice_unchecked(slice);

        if register_master_key.created_at() >= register_master_key.registration_timeout() {
            return Err(RegisterMasterKeyError::InvalidRegistrationTime {
                created_at: register_master_key.created_at(),
                registration_timeout: register_master_key.registration_timeout(),
            });
        }
        debug_assert_eq!(
            register_master_key
                .registration_timeout()
                .checked_sub(*register_master_key.created_at()),
            Some(RegisterMasterKey::REGISTRATION_TIMEOUT),
            "for now we are expecting this value to always be the same"
        );

        let signature = register_master_key.signature();
        let author = register_master_key.key();
        let signed_data = register_master_key.proof_data();

        if !author.verify(signed_data, &signature) {
            return Err(RegisterMasterKeyError::InvalidSignature);
        }

        Ok(register_master_key)
    }

    /// function to make of the given slice the RegisterMasterKey
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
            RegisterMasterKey::SIZE,
            "the slice should have the appropriate length"
        );
        Self(slice)
    }

    pub fn key(&self) -> PublicKey {
        self.0[KEY_INDEX..KEY_END].try_into().expect("key")
    }

    pub fn passport(&self) -> Hash {
        self.0[PASSPORT_ID_INDEX..PASSPORT_ID_END]
            .try_into()
            .expect("Passport ID")
    }

    pub fn alias(&self) -> Cow<'a, str> {
        let slice = &self.0[ALIAS_INDEX..ALIAS_END];
        let mut split = slice.split(|x| x == &0x00);
        if let Some(slice) = split.next() {
            String::from_utf8_lossy(slice)
        } else {
            Cow::Owned(String::new())
        }
    }

    pub fn created_at(&self) -> Time {
        u32::from_be_bytes(
            self.0[CREATED_AT_INDEX..CREATED_AT_END]
                .try_into()
                .expect("created_at"),
        )
        .into()
    }

    pub fn registration_timeout(&self) -> Time {
        u32::from_be_bytes(
            self.0[REGISTRATION_TIMEOUT_INDEX..REGISTRATION_TIMEOUT_END]
                .try_into()
                .expect("registration_timeout"),
        )
        .into()
    }

    /// data to use to sign/verify
    #[inline(always)]
    pub fn proof_data(&self) -> &[u8] {
        &self.0[KEY_INDEX..SIGNATURE_INDEX]
    }

    pub fn signature(&self) -> Signature {
        self.0[SIGNATURE_INDEX..SIGNATURE_END]
            .try_into()
            .expect("signature")
    }
}

fn check_alias(alias: &str) -> bool {
    alias.len() <= (ALIAS_END - ALIAS_INDEX) && alias.is_ascii()
}

impl<'a> TryFrom<&'a [u8]> for RegisterMasterKeySlice<'a> {
    type Error = RegisterMasterKeyError;
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        Self::try_from_slice(value)
    }
}

impl TryFrom<[u8; Self::SIZE]> for RegisterMasterKey {
    type Error = RegisterMasterKeyError;
    fn try_from(value: [u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let _ = RegisterMasterKeySlice::try_from_slice(&value)?;
        Ok(Self(value))
    }
}

impl<'a> fmt::Debug for RegisterMasterKeySlice<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegisterMasterKeySlice")
            .field("key", &self.key())
            .field("alias", &self.alias())
            .field("created_at", &self.created_at())
            .field("passport", &self.passport())
            .field("registration_timeout", &self.registration_timeout())
            .field("signature", &self.signature())
            .finish()
    }
}

impl fmt::Debug for RegisterMasterKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegisterMasterKey")
            .field("key", &self.key())
            .field("alias", &self.alias())
            .field("created_at", &self.created_at())
            .field("passport", &self.passport())
            .field("registration_timeout", &self.registration_timeout())
            .field("signature", &self.signature())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::{Arbitrary, Gen};

    const ALIASES: &[&str] = &["", "alias", "01234567890123456789012345678901"];

    impl Arbitrary for RegisterMasterKey {
        fn arbitrary(g: &mut Gen) -> Self {
            let sk = SecretKey::arbitrary(g);
            let alias = ALIASES[usize::arbitrary(g) % ALIASES.len()];
            let passport_id = Hash::arbitrary(g);

            let mut bytes = [0; Self::SIZE];
            let builder =
                RegisterMasterKeyMut::new(&mut bytes, alias, passport_id).expect("valid entry");

            let _ = builder.finalize(&sk);

            Self::try_from(bytes).expect("valid header")
        }
    }

    #[test]
    fn register_master_key_size() {
        assert_eq!(
            RegisterMasterKey::SIZE,
            152,
            "expecting a constant size for the RegisterMasterKey and that it should be documented"
        );
    }

    #[quickcheck]
    fn decode_slice(register_master_key: RegisterMasterKey) -> bool {
        RegisterMasterKeySlice::try_from_slice(&register_master_key.0).is_ok()
    }
}
