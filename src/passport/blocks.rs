use crate::passport::block::{Block, BlockError, BlockSlice};
use std::{array::TryFromSliceError, convert::TryInto, iter::FromIterator};
use thiserror::Error;

#[derive(Clone)]
pub struct PassportBlocks<P>(P);
#[derive(Copy, Clone)]
pub struct PassportBlocksSlice<'a>(&'a [u8]);
#[derive(Copy, Clone)]
pub struct BlockIter<'a>(&'a [u8]);

#[derive(Debug, Error)]
pub enum BlocksError {
    #[error("Invalid block")]
    InvalidBlock(
        #[source]
        #[from]
        BlockError,
    ),
    #[error("Invalid Index")]
    InvalidIndex(
        #[source]
        #[from]
        TryFromSliceError,
    ),
}

impl PassportBlocks<Vec<u8>> {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn try_from(bytes: Vec<u8>) -> Result<Self, BlocksError> {
        let _ = PassportBlocksSlice::try_from_slice(bytes.as_slice())?;
        Ok(Self(bytes))
    }

    pub fn push(&mut self, block: BlockSlice) {
        let size = block.as_ref().len() as u32;

        self.0.extend_from_slice(&size.to_be_bytes());
        self.0.extend_from_slice(block.as_ref());
    }
}

impl<P> PassportBlocks<P>
where
    P: AsRef<[u8]>,
{
    pub fn as_slice(&self) -> PassportBlocksSlice<'_> {
        PassportBlocksSlice(self.0.as_ref())
    }

    pub fn iter(&self) -> BlockIter {
        self.as_slice().iter()
    }
}

impl<'a> PassportBlocksSlice<'a> {
    pub fn try_from_slice(slice: &'a [u8]) -> Result<Self, BlocksError> {
        let pbs = Self(slice);

        let mut blocks = pbs.iter();
        while let Some(block) = blocks.move_next()? {
            let _block = BlockSlice::try_from_slice(block)?;
        }

        Ok(Self(slice))
    }

    pub fn is_empty(self) -> bool {
        self.0.is_empty()
    }

    /// number of bytes in the passport block export
    pub fn len(self) -> usize {
        self.0.len()
    }

    pub fn to_blocks(self) -> PassportBlocks<Vec<u8>> {
        PassportBlocks(self.0.to_vec())
    }

    pub fn iter(self) -> BlockIter<'a> {
        BlockIter(self.0)
    }

    pub fn get(self, index: usize) -> Option<BlockSlice<'a>> {
        self.iter().nth(index)
    }
}

impl<'a> BlockIter<'a> {
    fn move_next(&mut self) -> Result<Option<&'a [u8]>, TryFromSliceError> {
        if self.0.is_empty() {
            return Ok(None);
        }

        let size = {
            let bytes = self.0[..4].try_into()?;
            u32::from_be_bytes(bytes) as usize
        };
        let current = &self.0[4..4 + size];
        self.0 = &self.0[4 + size..];
        Ok(Some(current))
    }
}

impl<P> AsRef<[u8]> for PassportBlocks<P>
where
    P: AsRef<[u8]>,
{
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<'a> AsRef<[u8]> for PassportBlocksSlice<'a> {
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}

impl<'a> Iterator for BlockIter<'a> {
    type Item = BlockSlice<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        self.move_next()
            .expect("State should be valid")
            .map(BlockSlice::from_slice_unchecked)
    }
}

impl<'a> IntoIterator for PassportBlocksSlice<'a> {
    type IntoIter = BlockIter<'a>;
    type Item = BlockSlice<'a>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl FromIterator<Block> for PassportBlocks<Vec<u8>> {
    fn from_iter<T: IntoIterator<Item = Block>>(iter: T) -> Self {
        let mut pb = Self::new();

        for block in iter {
            pb.push(block.as_slice());
        }

        pb
    }
}

impl<'a> FromIterator<BlockSlice<'a>> for PassportBlocks<Vec<u8>> {
    fn from_iter<T: IntoIterator<Item = BlockSlice<'a>>>(iter: T) -> Self {
        let mut pb = Self::new();

        for block in iter {
            pb.push(block);
        }

        pb
    }
}

impl Default for PassportBlocks<Vec<u8>> {
    fn default() -> Self {
        Self::new()
    }
}
