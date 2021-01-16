mod content;
pub mod entry;
mod hash;
mod header;
mod previous;
mod time;
mod version;

use crate::key::ed25519::SecretKey;

use self::{content::ContentMut, header::HeaderMut};
pub use self::{
    content::{Content, ContentError, ContentSlice},
    entry::{Entry, EntryError, EntryMut, EntrySlice, EntryType},
    hash::{Hash, Hasher},
    header::{Header, HeaderError, HeaderSlice},
    previous::Previous,
    time::Time,
    version::Version,
};
use std::{
    convert::TryFrom,
    fmt::{self, Formatter},
};
use thiserror::Error;

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct Block(Box<[u8]>);

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct BlockSlice<'a>(&'a [u8]);

pub struct BlockMut(Vec<u8>);

#[derive(Debug, Error)]
pub enum BlockError {
    #[error("Invalid block length, expecting at least {} bytes", Header::SIZE)]
    InvalidLength,

    #[error("Content's size ({received}bytes) does not match the expected size ({expected}bytes)")]
    IncompatibleContentSize { expected: u16, received: usize },

    #[error("Incompatible content hash, does not match the hash in the header")]
    IncompatibleContentHash,

    #[error("invalid block header")]
    Header(
        #[source]
        #[from]
        HeaderError,
    ),

    #[error("invalid block content")]
    Content(
        #[from]
        #[source]
        ContentError,
    ),
}

impl Block {
    #[inline(always)]
    pub fn as_slice(&self) -> BlockSlice<'_> {
        BlockSlice(&self.0)
    }

    #[inline(always)]
    pub fn header(&self) -> HeaderSlice<'_> {
        self.as_slice().header()
    }

    #[inline(always)]
    pub fn content(&self) -> ContentSlice<'_> {
        self.as_slice().content()
    }
}

impl BlockMut {
    pub fn new() -> Self {
        let mut bytes = vec![0; Header::SIZE];
        bytes.reserve(1024);
        Self(bytes)
    }

    fn header_mut(&mut self) -> HeaderMut<'_> {
        HeaderMut::new(&mut self.0[..Header::SIZE])
    }

    fn content_mut(&mut self) -> ContentMut<'_> {
        ContentMut::new(&mut self.0)
    }

    pub fn push(&mut self, entry: EntrySlice<'_>) -> Result<(), BlockError> {
        Ok(self.content_mut().push(entry)?)
    }

    pub fn version(&mut self, version: Version) {
        self.header_mut().version(version)
    }

    pub fn time(&mut self, time: Time) {
        self.header_mut().time(time)
    }

    pub fn previous(&mut self, previous: &Previous) {
        self.header_mut().previous(previous)
    }

    pub fn finalize(mut self, author: &SecretKey) -> Block {
        let content_size = self.0[Header::SIZE..].len();
        let content_hash = Hasher::hash(&self.0[Header::SIZE..]);

        self.header_mut().content_hash(&content_hash);
        self.header_mut().content_size(content_size as u16);

        let _ = self.header_mut().finalize(author);

        Block(self.0.into_boxed_slice())
    }
}

impl<'a> BlockSlice<'a> {
    pub fn to_block(&self) -> Block {
        Block(self.0.to_vec().into_boxed_slice())
    }

    pub fn header(&self) -> HeaderSlice<'a> {
        HeaderSlice::from_slice_unchecked(&self.0[..Header::SIZE])
    }

    pub fn content(&self) -> ContentSlice<'a> {
        ContentSlice::from_slice_unchecked(&self.0[Header::SIZE..])
    }

    pub fn from_slice_unchecked(slice: &'a [u8]) -> Self {
        debug_assert!(
            slice.len() >= Header::SIZE,
            "there should be at least enough space in the header"
        );

        Self(slice)
    }

    pub fn try_from_slice(slice: &'a [u8]) -> Result<Self, BlockError> {
        if slice.len() < Header::SIZE {
            return Err(BlockError::InvalidLength);
        }
        let (header, content) = slice.split_at(Header::SIZE);

        let header = HeaderSlice::try_from_slice(header)?;

        if header.content_size() as usize != content.len() {
            return Err(BlockError::IncompatibleContentSize {
                expected: header.content_size(),
                received: content.len(),
            });
        }
        if header.content_hash() != Hasher::hash(content) {
            return Err(BlockError::IncompatibleContentHash);
        }

        let _ = ContentSlice::try_from_slice(content)?;

        Ok(Self(slice))
    }
}

impl<'a> TryFrom<&'a [u8]> for BlockSlice<'a> {
    type Error = BlockError;
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        Self::try_from_slice(value)
    }
}

impl fmt::Debug for Block {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Block")
            .field("header", &self.header())
            .field("content", &self.content())
            .finish()
    }
}

impl<'a> fmt::Debug for BlockSlice<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlockSlice")
            .field("header", &self.header())
            .field("content", &self.content())
            .finish()
    }
}

impl Default for BlockMut {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> AsRef<[u8]> for BlockSlice<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for Block {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::ed25519::SecretKey;
    use quickcheck::{Arbitrary, Gen};

    impl Arbitrary for Block {
        fn arbitrary(g: &mut Gen) -> Self {
            let author = SecretKey::arbitrary(g);
            let mut block = BlockMut::new();

            let max = usize::arbitrary(g) % 12;
            for _ in 0..max {
                let entry = Entry::arbitrary(g);
                match block.push(entry.as_slice()) {
                    Ok(()) => (),
                    Err(BlockError::Content(ContentError::MaxSizeReached)) => break,
                    Err(error) => {
                        // another error occurred, it should not happen but
                        // better ready than sorry
                        unreachable!(&error)
                    }
                }
            }

            block.version(Version::arbitrary(g));
            block.previous(&Previous::arbitrary(g));
            block.time(Time::arbitrary(g));

            block.finalize(&author)
        }
    }

    #[quickcheck]
    fn decode_slice(block: Block) -> bool {
        BlockSlice::try_from_slice(&block.0).is_ok()
    }
}
