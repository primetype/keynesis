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
    pub fn hash(input: impl AsRef<[u8]>) -> Hash {
        let mut output = Hash::ZERO;
        Blake2b::blake2b(&mut output.0, input.as_ref(), &[]);
        output
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
    fn to_string_from_str(hash: Hash) -> bool {
        let s = hash.to_string();
        let h = s.parse().unwrap();

        hash == h
    }
}
