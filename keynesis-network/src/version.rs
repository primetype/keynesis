use std::{
    convert::TryFrom,
    fmt::{self, Formatter},
    num::ParseIntError,
    str::FromStr,
};

/// protocol version number
///
/// technically this is limited to 8 bytes. However it is easy to imagine
/// than more than 256 version numbers are a bit overkill.
///
///
/// Versions will be listed here overtime. However when performing the
/// handshake, this function will use [`Version::CURRENT`] and will check
/// how the remote's version match the [`Version::MIN`] and [`Version::MAX`].
/// See [`is_supported`].
///
/// [`is_supported`]: Version::is_supported
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Version(u8);

impl Version {
    /// the encoded size of the [`Version`].
    ///
    /// ```
    /// # use keynesis_network::Version;
    /// assert_eq!(Version::SIZE, 1)
    /// ```
    pub const SIZE: usize = std::mem::size_of::<u8>();

    /// version 1:
    ///
    /// Support syncing passports between the nodes
    pub const V1: Self = Self(0x01);

    /// get the minimal supported version supported by this implementation
    pub const MIN: Self = Self::V1;

    /// get the current version implemented by this implementation
    pub const CURRENT: Self = Self::V1;

    /// get the maximal supported version supported by this implementation
    pub const MAX: Self = Self::CURRENT;

    /// returns if the version is currently supported or not
    ///
    /// This is similar as to testing the given version against
    /// the increasing order:
    ///
    /// ```
    /// # use keynesis_network::Version;
    /// assert!(
    ///   Version::CURRENT.is_supported() ==
    ///   (Version::CURRENT >= Version::MIN && Version::CURRENT <= Version::MAX)
    /// );
    /// ```
    #[inline]
    pub fn is_supported(self) -> bool {
        Self::MIN <= self && self <= Self::MAX
    }

    #[inline]
    pub(crate) const fn from_u8(version: u8) -> Self {
        Self(version)
    }

    #[inline]
    pub(crate) const fn to_u8(self) -> u8 {
        self.0
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

impl From<Version> for String {
    fn from(version: Version) -> Self {
        version.to_string()
    }
}

impl FromStr for Version {
    type Err = ParseIntError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        u8::from_str(s).map(Self)
    }
}

impl<'a> TryFrom<&'a str> for Version {
    type Error = ParseIntError;
    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl TryFrom<String> for Version {
    type Error = ParseIntError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// simple test to check the current version is marked _supported_
    #[test]
    fn current_version_is_supported() {
        assert!(Version::CURRENT.is_supported())
    }

    #[test]
    fn parse_current_version() {
        let current = Version::CURRENT.0.to_string();

        let version = Version::try_from(current.as_str()).unwrap();

        assert_eq!(version, Version::CURRENT)
    }
}
