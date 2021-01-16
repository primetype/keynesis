use crate::{
    key::ed25519::{PublicKey, SecretKey, Signature},
    passport::block::{Hash, Hasher, Previous, Time, Version},
};
use std::{
    convert::{TryFrom, TryInto},
    fmt::{self, Formatter},
};
use thiserror::Error;

const VERSION_INDEX: usize = 0;
const VERSION_END: usize = VERSION_INDEX + Version::SIZE;
const CONTENT_SIZE_INDEX: usize = VERSION_END;
const CONTENT_SIZE_END: usize = CONTENT_SIZE_INDEX + std::mem::size_of::<u16>();
const TIME_INDEX: usize = CONTENT_SIZE_END;
const TIME_END: usize = TIME_INDEX + Time::SIZE;
const CONTENT_HASH_INDEX: usize = TIME_END;
const CONTENT_HASH_END: usize = CONTENT_HASH_INDEX + Hash::SIZE;
const PREVIOUS_INDEX: usize = CONTENT_HASH_END;
const PREVIOUS_END: usize = PREVIOUS_INDEX + Hash::SIZE;
const PROOF_AUTHOR_INDEX: usize = PREVIOUS_END;
const PROOF_AUTHOR_END: usize = PROOF_AUTHOR_INDEX + PublicKey::SIZE;
const PROOF_SIGNATURE_INDEX: usize = PROOF_AUTHOR_END;
const PROOF_SIGNATURE_END: usize = PROOF_SIGNATURE_INDEX + Signature::SIZE;

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct Header([u8; Self::SIZE]);

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct HeaderSlice<'a>(&'a [u8]);

pub struct HeaderMut<'a>(&'a mut [u8]);

#[derive(Debug, Error)]
pub enum HeaderError {
    #[error("not valid length for a header")]
    InvalidLength,

    #[error("The header's version has been marked as forbidden {0}")]
    ForbiddenVersion(Version),

    #[error("The signature does verify against the author")]
    InvalidSignature,
}

impl Header {
    /// constant size of the header
    ///
    /// having a deterministically and small header size we can fairly
    /// easily mitigate slowloris with expecting the first `Header::SIZE`
    /// bytes. One can read all of these bytes and then verify the consistency
    /// (the signature for example).
    ///
    /// Also, another constant is that the first 2 bytes are the `Version`
    /// number, so it is also handy to detect unexpected version early.
    ///
    /// ```
    /// # use keynesis::passport::block::Header;
    /// assert_eq!(Header::SIZE, 136);
    /// ```
    pub const SIZE: usize = PROOF_SIGNATURE_END;

    #[inline(always)]
    pub fn as_slice(&self) -> HeaderSlice<'_> {
        HeaderSlice::from_slice_unchecked(self.0.as_ref())
    }

    #[inline(always)]
    pub fn version(&self) -> Version {
        self.as_slice().version()
    }

    #[inline(always)]
    pub fn content_size(&self) -> u16 {
        self.as_slice().content_size()
    }

    #[inline(always)]
    pub fn time(&self) -> Time {
        self.as_slice().time()
    }

    #[inline(always)]
    pub fn content_hash(&self) -> Hash {
        self.as_slice().content_hash()
    }

    #[inline(always)]
    pub fn previous(&self) -> Previous {
        self.as_slice().previous()
    }

    /// data to use to sign/verify the header
    #[inline(always)]
    pub fn header_proof_data(&self) -> &[u8] {
        self.as_slice().proof_data()
    }

    #[inline(always)]
    pub fn author(&self) -> PublicKey {
        self.as_slice().author()
    }

    #[inline(always)]
    pub fn signature(&self) -> Signature {
        self.as_slice().signature()
    }
}

impl<'a> HeaderMut<'a> {
    pub fn new(slice: &'a mut [u8]) -> Self {
        Self(slice)
    }

    pub fn version(&mut self, version: Version) {
        self.0[VERSION_INDEX..VERSION_END].copy_from_slice(&version.to_be_bytes())
    }

    pub fn content_size(&mut self, size: u16) {
        self.0[CONTENT_SIZE_INDEX..CONTENT_SIZE_END].copy_from_slice(&size.to_be_bytes());
    }

    pub fn time(&mut self, time: Time) {
        self.0[TIME_INDEX..TIME_END].copy_from_slice(&time.to_be_bytes())
    }

    pub fn content_hash(&mut self, hash: &Hash) {
        self.0[CONTENT_HASH_INDEX..CONTENT_HASH_END].copy_from_slice(hash.as_ref())
    }

    pub fn previous(&mut self, previous: &Previous) {
        let hash = match previous {
            Previous::None => &Hash::ZERO,
            Previous::Previous(hash) => hash,
        };
        self.0[PREVIOUS_INDEX..PREVIOUS_END].copy_from_slice(hash.as_ref());
    }

    pub fn finalize(self, author: &SecretKey) -> HeaderSlice<'a> {
        let slice = self.0;
        let pk = author.public_key();

        slice[PROOF_AUTHOR_INDEX..PROOF_AUTHOR_END].copy_from_slice(pk.as_ref());
        let signature = author.sign(&slice[VERSION_INDEX..PROOF_AUTHOR_END]);

        slice[PROOF_SIGNATURE_INDEX..PROOF_SIGNATURE_END].copy_from_slice(signature.as_ref());

        HeaderSlice::from_slice_unchecked(slice)
    }
}

impl<'a> HeaderSlice<'a> {
    /// if you need to own the `Header`, you can convert the slice into
    /// a `Header`. This will allocate the memory on the heap.
    pub fn to_header(&self) -> Header {
        Header(
            self.0
                .try_into()
                .expect("Header slice should have the appropriate size"),
        )
    }

    /// Create a HeaderSlice from the given slice
    ///
    /// This function will check the lengths, the version
    /// is a valid version (not a forbidden one), the signature
    /// matches the header's signed data and the author
    pub fn try_from_slice(slice: &'a [u8]) -> Result<Self, HeaderError> {
        if slice.len() != Header::SIZE {
            return Err(HeaderError::InvalidLength);
        }

        let header = Self::from_slice_unchecked(slice);

        if header.version().is_forbidden() {
            return Err(HeaderError::ForbiddenVersion(header.version()));
        }

        let signature = header.signature();
        let author = header.author();
        let signed_data = header.proof_data();

        if !author.verify(signed_data, &signature) {
            return Err(HeaderError::InvalidSignature);
        }

        Ok(header)
    }

    /// function to make of the given slice the header
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
            Header::SIZE,
            "the slice should have the appropriate length"
        );
        Self(slice)
    }

    pub fn hash(&self) -> Hash {
        Hasher::hash(self.0)
    }

    pub fn version(&self) -> Version {
        u16::from_be_bytes(
            self.0[VERSION_INDEX..VERSION_END]
                .try_into()
                .expect("version"),
        )
        .into()
    }

    pub fn content_size(&self) -> u16 {
        u16::from_be_bytes(
            self.0[CONTENT_SIZE_INDEX..CONTENT_SIZE_END]
                .try_into()
                .expect("content_size"),
        )
    }

    pub fn time(&self) -> Time {
        u32::from_be_bytes(self.0[TIME_INDEX..TIME_END].try_into().expect("time")).into()
    }

    pub fn content_hash(&self) -> Hash {
        self.0[CONTENT_HASH_INDEX..CONTENT_HASH_END]
            .try_into()
            .expect("content_hash")
    }

    pub fn previous(&self) -> Previous {
        let hash = self.0[PREVIOUS_INDEX..PREVIOUS_END]
            .try_into()
            .expect("previous");

        if hash == Hash::ZERO {
            Previous::None
        } else {
            Previous::Previous(hash)
        }
    }

    /// data to use to sign/verify the header
    #[inline(always)]
    pub fn proof_data(&self) -> &'a [u8] {
        &self.0[VERSION_INDEX..PROOF_SIGNATURE_INDEX]
    }

    pub fn author(&self) -> PublicKey {
        self.0[PROOF_AUTHOR_INDEX..PROOF_AUTHOR_END]
            .try_into()
            .expect("author")
    }

    pub fn signature(&self) -> Signature {
        self.0[PROOF_SIGNATURE_INDEX..PROOF_SIGNATURE_END]
            .try_into()
            .expect("signature")
    }
}

impl<'a> TryFrom<&'a [u8]> for HeaderSlice<'a> {
    type Error = HeaderError;
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        Self::try_from_slice(value)
    }
}

impl TryFrom<[u8; Self::SIZE]> for Header {
    type Error = HeaderError;
    fn try_from(value: [u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let _ = HeaderSlice::try_from_slice(&value)?;
        Ok(Self(value))
    }
}

impl<'a> fmt::Debug for HeaderSlice<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("HeaderSlice")
            .field("version", &self.version())
            .field("time", &self.time())
            .field("previous", &self.previous())
            .field("content_size", &self.content_size())
            .field("content_hash", &self.content_hash())
            .field("author", &self.author())
            .field("signature", &self.signature())
            .finish()
    }
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Header")
            .field("version", &self.version())
            .field("time", &self.time())
            .field("previous", &self.previous())
            .field("content_size", &self.content_size())
            .field("content_hash", &self.content_hash())
            .field("author", &self.author())
            .field("signature", &self.signature())
            .finish()
    }
}

impl AsRef<[u8]> for Header {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> AsRef<[u8]> for HeaderSlice<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::{Arbitrary, Gen};

    impl Arbitrary for Header {
        fn arbitrary(g: &mut Gen) -> Self {
            let sk = SecretKey::arbitrary(g);

            let mut bytes = [0; Self::SIZE];
            let mut builder = HeaderMut::new(&mut bytes);

            builder.version(Version::arbitrary(g));
            builder.content_size(u16::arbitrary(g));
            builder.content_hash(&Hash::arbitrary(g));
            builder.time(Time::arbitrary(g));
            builder.previous(&Previous::arbitrary(g));

            let _ = builder.finalize(&sk);

            Header::try_from(bytes).expect("valid header")
        }
    }

    #[test]
    fn header_size() {
        assert_eq!(
            Header::SIZE,
            136,
            "expecting a constant size for the header and that it should be documented"
        );
    }

    #[quickcheck]
    fn decode_slice(header: Header) -> bool {
        HeaderSlice::try_from_slice(&header.0).is_ok()
    }
}
