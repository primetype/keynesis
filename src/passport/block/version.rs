use std::{
    fmt::{self, Formatter},
    ops::Deref,
    str::FromStr,
};

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct Version(u16);

/// list of versions that are known to have a flow or to
/// be incompatible. Hopefully we can keep this list empty.
///
pub const FORBIDDEN_VERSION: &[Version] = &[];

impl Version {
    /// the size of an encoded version in bytes
    pub const SIZE: usize = std::mem::size_of::<u16>();

    /// denote version that are being used for testing
    pub const TESTING: Self = Version(0x0000);

    /// the minimal supported version but the current version of the software
    pub const MIN: Self = Self(0x0000);

    /// the current version of the protocol implemented by the software
    pub const CURRENT: Self = Self::TESTING;

    /// the maximum version supported by the implementation of the software
    ///
    /// This value will likely always be CURRENT.
    pub const MAX: Self = Self::CURRENT;

    /// get the current version of the library
    #[inline(always)]
    pub const fn current() -> Self {
        Self::CURRENT
    }

    /// check if the given version is `TESTING`
    #[inline(always)]
    pub fn is_testing(self) -> bool {
        self == Self::TESTING
    }

    /// check if the given version is one of the supported versions
    #[inline(always)]
    pub fn is_supported(self) -> bool {
        Self::MIN <= self && self <= Self::MAX
    }

    /// check if the given version is one fo the known forbidden
    /// versions. This may happen that a given version is supported
    /// but is now in the list of forbidden versions due to a
    /// critical error that may have happen during the development.
    ///
    /// Can be seen as a yanked versions from the system.
    #[inline(always)]
    pub fn is_forbidden(self) -> bool {
        FORBIDDEN_VERSION.contains(&self)
    }
}

impl Default for Version {
    fn default() -> Self {
        Self::CURRENT
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for Version {
    type Err = std::num::ParseIntError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let version = s.parse().map(Self)?;

        Ok(version)
    }
}

impl From<u16> for Version {
    fn from(version: u16) -> Self {
        Self(version)
    }
}

impl From<Version> for u16 {
    fn from(v: Version) -> Self {
        v.0
    }
}

impl Deref for Version {
    type Target = u16;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::{Arbitrary, Gen};

    impl Arbitrary for Version {
        fn arbitrary(g: &mut Gen) -> Self {
            Self(u16::arbitrary(g))
        }
    }

    #[test]
    fn current_is_supported() {
        assert!(Version::current().is_supported());
    }

    #[test]
    fn current_is_default() {
        assert_eq!(Version::default(), Version::current());
    }

    #[test]
    fn current_is_not_forbidden() {
        assert!(!Version::current().is_forbidden());
    }
}
