use cryptoxide::blake2b::Blake2b;
use std::{
    array::TryFromSliceError,
    convert::{TryFrom, TryInto as _},
    fmt::{self, Formatter},
    str::FromStr,
};

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct Hash([u8; Self::SIZE]);

pub struct Hasher(Blake2b);

impl Hash {
    pub const SIZE: usize = 16;

    pub const ZERO: Self = Self([0; Self::SIZE]);
}

impl Hasher {
    pub fn new() -> Self {
        Self(Blake2b::new(Hash::SIZE))
    }

    pub fn update(&mut self, input: impl AsRef<[u8]>) {
        use cryptoxide::digest::Digest as _;
        self.0.input(input.as_ref());
    }

    pub fn result(&mut self) -> Hash {
        use cryptoxide::digest::Digest as _;

        let mut output = Hash::ZERO;
        self.0.result(&mut output.0);
        output
    }

    pub fn reset(&mut self) {
        self.0.reset()
    }

    pub fn hash(input: impl AsRef<[u8]>) -> Hash {
        let mut output = Hash::ZERO;
        Blake2b::blake2b(&mut output.0, input.as_ref(), &[]);
        output
    }
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

/* Format ****************************************************************** */

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Hash")
            .field(&hex::encode(self.as_ref()))
            .finish()
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.as_ref()))
    }
}

impl FromStr for Hash {
    type Err = hex::FromHexError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut hash = Self::ZERO;

        hex::decode_to_slice(s, &mut hash.0)?;

        Ok(hash)
    }
}

/* Conversion ************************************************************** */

impl From<[u8; Self::SIZE]> for Hash {
    fn from(hash: [u8; Self::SIZE]) -> Self {
        Self(hash)
    }
}

impl Into<[u8; Self::SIZE]> for Hash {
    fn into(self) -> [u8; Self::SIZE] {
        self.0
    }
}

impl<'a> TryFrom<&'a [u8]> for Hash {
    type Error = TryFromSliceError;
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        value.try_into().map(Self)
    }
}

/* AsRef ******************************************************************* */

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::{Arbitrary, Gen};

    impl Arbitrary for Hash {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            let mut hash = Self::ZERO;
            g.fill_bytes(&mut hash.0);
            hash
        }
    }

    #[quickcheck]
    fn hasher_new_hash(bytes1: Vec<u8>, bytes2: Vec<u8>) -> bool {
        let mut bytes = Vec::with_capacity(bytes1.len() + bytes2.len());
        bytes.extend_from_slice(bytes1.as_slice());
        bytes.extend_from_slice(bytes2.as_slice());

        let mut hasher = Hasher::new();
        hasher.update(bytes1);
        hasher.update(bytes2);

        Hasher::hash(bytes) == hasher.result()
    }

    #[quickcheck]
    fn to_string_from_str(hash: Hash) -> bool {
        let s = hash.to_string();
        let h = s.parse().unwrap();

        hash == h
    }
}
