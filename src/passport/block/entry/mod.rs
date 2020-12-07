mod register_master_key;

pub use self::register_master_key::{
    RegisterMasterKey, RegisterMasterKeyError, RegisterMasterKeyMut, RegisterMasterKeySlice,
};
use crate::key::ed25519::SecretKey;
use std::{
    convert::{TryFrom, TryInto as _},
    fmt::{self, Formatter},
    ops::{Deref, DerefMut},
};
use thiserror::Error;

const ENTRY_TYPE_INDEX: usize = 0;
const ENTRY_TYPE_END: usize = ENTRY_TYPE_INDEX + std::mem::size_of::<u16>();

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum EntryType {
    RegisterMasterKey,
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct Entry(Box<[u8]>);

pub struct EntryMut<T> {
    slice_ptr: *mut u8,
    slice_size: usize,
    t: T,
}

pub struct EntrySlice<'a>(&'a [u8]);

#[derive(Debug, Error, Eq, PartialEq)]
pub enum EntryError {
    #[error("not valid length for a header")]
    InvalidLength,

    #[error("Unknown entry type {value}")]
    UnknownEntryType { value: u16 },

    #[error("Expecting a valid Master Key registration entry")]
    RegisterMasterKey(
        #[from]
        #[source]
        RegisterMasterKeyError,
    ),
}

impl EntryType {
    pub fn to_u16(self) -> u16 {
        match self {
            Self::RegisterMasterKey => 0x0001,
        }
    }

    pub fn try_from_u16(value: u16) -> Result<Self, EntryError> {
        match value {
            1 => Ok(Self::RegisterMasterKey),
            0 | 2..=u16::MAX => Err(EntryError::UnknownEntryType { value }),
        }
    }

    /// get the *total* size of the entry
    ///
    /// this means all size of the actual data of the entry as well
    /// as the 2 extra bytes of the `EntryType`
    pub fn size(self) -> usize {
        let size = match self {
            Self::RegisterMasterKey => RegisterMasterKey::SIZE,
        };

        size + std::mem::size_of::<u16>()
    }
}

impl Entry {
    #[inline(always)]
    pub fn as_slice(&self) -> EntrySlice<'_> {
        EntrySlice(&self.0)
    }

    #[inline(always)]
    pub fn entry_type(&self) -> EntryType {
        self.as_slice().entry_type()
    }

    #[inline(always)]
    pub fn register_master_key(&self) -> Option<RegisterMasterKeySlice<'_>> {
        self.as_slice().register_master_key()
    }
}

impl<'a> EntryMut<RegisterMasterKeyMut<'a>> {
    pub fn new_register_master_key(slice: &'a mut [u8]) -> Self {
        assert!(slice.len() == EntryType::RegisterMasterKey.size());

        slice[ENTRY_TYPE_INDEX..ENTRY_TYPE_END]
            .copy_from_slice(&EntryType::RegisterMasterKey.to_u16().to_be_bytes());

        let slice_ptr = slice.as_mut_ptr();
        let slice_size = slice.len();
        let t = RegisterMasterKeyMut::new(&mut slice[ENTRY_TYPE_END..]);

        Self {
            slice_ptr,
            slice_size,
            t,
        }
    }

    pub fn finalize(self, author: &SecretKey) -> EntrySlice<'a> {
        let _ = self.t.finalize(author);

        let slice = unsafe { std::slice::from_raw_parts(self.slice_ptr, self.slice_size) };

        EntrySlice::from_slice_unchecked(slice)
    }
}

impl<'a> EntrySlice<'a> {
    /// get a owned version of the entry
    pub fn to_entry(&self) -> Entry {
        Entry(Vec::from(self.0).into_boxed_slice())
    }

    /// create an entry slice from the given slice
    ///
    /// checks that the data is fully consistent and contains
    /// the necessary length for the entry type (2 bytes) and
    /// for all the remaining data.
    pub fn try_from_slice(slice: &'a [u8]) -> Result<Self, EntryError> {
        if slice.len() < 2 {
            return Err(EntryError::InvalidLength);
        }

        let entry = Self(slice);

        match entry.entry_type() {
            EntryType::RegisterMasterKey => {
                // make sure the underlying entry is valid too
                RegisterMasterKeySlice::try_from_slice(&slice[ENTRY_TYPE_END..])?;
            }
        }

        Ok(entry)
    }

    /// create an entry slice, does not check the consistency of the data.
    ///
    /// # panic
    ///
    /// however on debug mode, this function will throw a panic message
    /// if the size does not match.
    pub fn from_slice_unchecked(slice: &'a [u8]) -> Self {
        let entry = Self(slice);

        debug_assert!(slice.len() > 2, "needs at least 2 bytes for the EntryType");
        debug_assert_eq!(slice.len(), entry.entry_type().size());

        entry
    }

    pub fn entry_type(&self) -> EntryType {
        EntryType::try_from_u16(u16::from_be_bytes(
            self.0[ENTRY_TYPE_INDEX..ENTRY_TYPE_END]
                .try_into()
                .expect("entry_type"),
        ))
        .expect("valid entry_type")
    }

    /// access the entry's data itself
    ///
    /// returns None if this is an different EntryType
    /// This function does not check if the entry data is valid
    /// (`RegisterMasterKeySlice::from_slice_unchecked` is used).
    pub fn register_master_key(&self) -> Option<RegisterMasterKeySlice<'a>> {
        if EntryType::RegisterMasterKey == self.entry_type() {
            let slice = &self.0[ENTRY_TYPE_END..];

            Some(RegisterMasterKeySlice::from_slice_unchecked(slice))
        } else {
            None
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for EntrySlice<'a> {
    type Error = EntryError;
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        Self::try_from_slice(value)
    }
}

impl TryFrom<Box<[u8]>> for Entry {
    type Error = EntryError;
    fn try_from(value: Box<[u8]>) -> Result<Self, Self::Error> {
        let _ = EntrySlice::try_from_slice(&value)?;
        Ok(Self(value))
    }
}

impl TryFrom<Vec<u8>> for Entry {
    type Error = EntryError;
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let _ = EntrySlice::try_from_slice(&value)?;
        Ok(Self(value.into_boxed_slice()))
    }
}

impl<'a> fmt::Debug for EntrySlice<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut dbg = f.debug_tuple("EntrySlice");
        if let Some(entry) = self.register_master_key() {
            dbg.field(&entry);
        }
        dbg.finish()
    }
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut dbg = f.debug_tuple("Entry");
        if let Some(entry) = self.register_master_key() {
            dbg.field(&entry);
        }
        dbg.finish()
    }
}

impl<T> Deref for EntryMut<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.t
    }
}

impl<T> DerefMut for EntryMut<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.t
    }
}

impl<'a> AsRef<[u8]> for EntrySlice<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::{Arbitrary, Gen};

    impl Arbitrary for EntryType {
        fn arbitrary<G: Gen>(_g: &mut G) -> Self {
            // let t = u16::arbitrary(g) % 1 + 1;
            let t = 1;
            Self::try_from_u16(t).expect("value should be correct entry type")
        }
    }

    impl Arbitrary for Entry {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            let t = EntryType::arbitrary(g);
            let mut bytes = vec![0; t.size()];

            match t {
                EntryType::RegisterMasterKey => {
                    let sk = SecretKey::arbitrary(g);
                    let _ = EntryMut::new_register_master_key(&mut bytes).finalize(&sk);
                }
            }

            bytes.try_into().expect("We are building a valid Entry")
        }
    }

    #[quickcheck]
    fn decode_slice(entry: Entry) -> bool {
        EntrySlice::try_from_slice(&entry.0).is_ok()
    }
}
