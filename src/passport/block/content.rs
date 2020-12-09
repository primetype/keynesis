use crate::passport::block::{EntryError, EntrySlice, EntryType, Hash, Hasher};
use std::{
    convert::TryInto as _,
    fmt::{self, Formatter},
    iter::FusedIterator,
    ops::Deref,
};
use thiserror::Error;

#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Hash)]
pub struct Content(Box<[u8]>);

#[derive(Ord, PartialOrd, Eq, PartialEq)]
pub(crate) struct ContentMut<'a>(&'a mut Vec<u8>);

#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Hash)]
pub struct ContentSlice<'a>(&'a [u8]);

#[derive(Debug, Error)]
pub enum ContentError {
    #[error("Content's max size has been reached, cannot add the entry")]
    MaxSizeReached,

    #[error("The content has {extra} bytes we do not know what they are for, it could the buffer was truncated")]
    InvalidLength { extra: usize },

    #[error("Invalid entry")]
    Entry(
        #[from]
        #[source]
        EntryError,
    ),
}

pub struct ContentSliceIter<'a>(&'a [u8]);

impl Content {
    pub const MAX_SIZE: usize = u16::MAX as usize;

    pub fn as_slice(&self) -> ContentSlice<'_> {
        ContentSlice(&self.0)
    }

    pub fn iter(&self) -> ContentSliceIter<'_> {
        self.as_slice().iter()
    }

    pub fn hash(&self) -> Hash {
        self.as_slice().hash()
    }
}

impl<'a> ContentMut<'a> {
    pub(crate) fn new(bytes: &'a mut Vec<u8>) -> Self {
        Self(bytes)
    }

    #[cfg(test)]
    fn into_content(self) -> Content {
        Content(self.0.to_owned().into_boxed_slice())
    }

    pub(crate) fn push(&mut self, entry: &EntrySlice<'_>) -> Result<(), ContentError> {
        let current_size = self.0.len();
        let needed_size = current_size + entry.as_ref().len();
        if needed_size > Content::MAX_SIZE {
            return Err(ContentError::MaxSizeReached);
        }
        self.0.extend_from_slice(entry.as_ref());
        Ok(())
    }
}

impl<'a> ContentSlice<'a> {
    pub fn iter(&self) -> ContentSliceIter<'a> {
        ContentSliceIter(self.0)
    }

    pub fn to_content(&self) -> Content {
        Content(self.0.to_vec().into_boxed_slice())
    }

    pub fn from_slice_unchecked(slice: &'a [u8]) -> Self {
        Self(slice)
    }

    pub fn try_from_slice(slice: &'a [u8]) -> Result<Self, ContentError> {
        if slice.len() > Content::MAX_SIZE {
            return Err(ContentError::MaxSizeReached);
        }

        let content = Self(slice);

        let mut slice = content.0;

        while slice.len() >= 2 {
            let entry_type =
                EntryType::try_from_u16(u16::from_be_bytes(slice[..2].try_into().unwrap()))?;
            let size = entry_type.size(&slice[2..]);

            let _ = EntrySlice::try_from_slice(&slice[..size])?;
            slice = &slice[size..];
        }

        if slice.is_empty() {
            Ok(content)
        } else {
            Err(ContentError::InvalidLength { extra: slice.len() })
        }
    }

    pub fn hash(&self) -> Hash {
        Hasher::hash(self.0)
    }
}

impl<'a> IntoIterator for ContentSlice<'a> {
    type IntoIter = ContentSliceIter<'a>;
    type Item = EntrySlice<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> Iterator for ContentSliceIter<'a> {
    type Item = EntrySlice<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() {
            None
        } else {
            let entry_type =
                EntryType::try_from_u16(u16::from_be_bytes(self.0[..2].try_into().unwrap()))
                    .unwrap();
            let size = entry_type.size(&self.0[2..]);

            let entry = EntrySlice::from_slice_unchecked(&self.0[..size]);
            self.0 = &self.0[size..];

            Some(entry)
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.0.is_empty() {
            (0, Some(0))
        } else {
            (1, None)
        }
    }
}

impl<'a> FusedIterator for ContentSliceIter<'a> {}

impl<'a> fmt::Debug for ContentSlice<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl fmt::Debug for Content {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl<'a> AsRef<[u8]> for ContentSlice<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> Deref for ContentMut<'a> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> Deref for ContentSlice<'a> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for Content {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        key::ed25519::{PublicKey, SecretKey},
        passport::block::{Entry, EntryMut},
        Seed,
    };
    use quickcheck::{Arbitrary, Gen};

    impl Arbitrary for Content {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            let max = usize::arbitrary(g) % 12;
            let mut bytes = Vec::with_capacity(1024);
            let mut content = ContentMut::new(&mut bytes);

            for _ in 0..max {
                let entry = Entry::arbitrary(g);
                match content.push(&entry.as_slice()) {
                    Ok(()) => (),
                    Err(ContentError::MaxSizeReached) => break,
                    Err(error) => {
                        // another error occurred, it should not happen but
                        // better ready than sorry
                        unreachable!(&error)
                    }
                }
            }

            content.into_content()
        }
    }

    /// test to make sure we detect the limit of the Content
    /// when using `push`
    #[test]
    fn too_long_fail() {
        let content = [0; Content::MAX_SIZE + 1];

        match ContentSlice::try_from_slice(&content) {
            Err(ContentError::MaxSizeReached) => (),
            Err(error) => panic!("Didn't expect this error: {:?}", error),
            Ok(_) => panic!("Content should have failed with too long error"),
        }
    }

    #[test]
    fn test_shared_entry_only() {
        let mut rng = quickcheck::StdThreadGen::new(1024);

        let max = 1;
        let mut bytes = Vec::with_capacity(1024);
        let mut content = ContentMut::new(&mut bytes);

        for _ in 0..max {
            let mut entry_bytes = Vec::with_capacity(1024);
            let key = SecretKey::arbitrary(&mut rng);
            let mut builder = EntryMut::new_set_shared_key(&mut entry_bytes, &key.public_key());
            let passphrase = Option::<Seed>::arbitrary(&mut rng);
            let mut entry_rng = Seed::arbitrary(&mut rng).into_rand_chacha();

            let count = u8::arbitrary(&mut rng) % 12 + 1;
            for _ in 0..count {
                builder
                    .share_with(
                        &mut entry_rng,
                        &key,
                        &PublicKey::arbitrary(&mut rng),
                        &passphrase,
                    )
                    .expect("valid share to this key");
            }

            let entry = builder.finalize().expect("valid key sharing entry");
            match content.push(&entry) {
                Ok(()) => (),
                Err(ContentError::MaxSizeReached) => break,
                Err(error) => {
                    // another error occurred, it should not happen but
                    // better ready than sorry
                    unreachable!(&error)
                }
            }
        }

        let _ = content.into_content();
    }

    #[quickcheck]
    fn decode_slice(content: Content) -> bool {
        ContentSlice::try_from_slice(&content.0).unwrap();
        true
    }
}
