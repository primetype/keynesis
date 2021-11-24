use crate::Version;
use keynesis_core::key::ed25519;

/// initial handshake message
///
/// composed of the [`Version`] and the noise initiator handshake [`IK`]
///
/// [`IK`]: keynesis::noise::IK
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug, Hash)]
pub struct HandshakeInitialize([u8; Self::SIZE]);

/// handshake reply
///
/// composed of the [`Version`] and the noise response handshake [`IK`]
///
/// [`IK`]: keynesis::noise::IK
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug, Hash)]
pub struct HandshakeResponse([u8; Self::SIZE]);

impl HandshakeInitialize {
    pub const SIZE: usize =
        Version::SIZE + ed25519::PublicKey::SIZE + (ed25519::PublicKey::SIZE + 16) + 16;
    pub const DEFAULT: Self = Self::new(Version::CURRENT);

    const fn new(version: Version) -> Self {
        Self::from_bytes([version.to_u8(); Self::SIZE])
    }

    pub const fn from_bytes(bytes: [u8; Self::SIZE]) -> Self {
        Self(bytes)
    }

    pub fn version(&self) -> Version {
        Version::from_u8(self.0[0])
    }

    pub fn message(&self) -> &[u8] {
        &self.0[1..]
    }

    pub fn message_mut(&mut self) -> &mut [u8] {
        &mut self.0[1..]
    }
}

impl HandshakeResponse {
    pub const SIZE: usize = Version::SIZE + ed25519::PublicKey::SIZE + 16;
    pub const DEFAULT: Self = Self::new(Version::CURRENT);

    const fn new(version: Version) -> Self {
        Self::from_bytes([version.to_u8(); Self::SIZE])
    }

    pub const fn from_bytes(bytes: [u8; Self::SIZE]) -> Self {
        Self(bytes)
    }

    pub fn version(&self) -> Version {
        Version::from_u8(self.0[0])
    }

    pub fn message(&self) -> &[u8] {
        &self.0[1..]
    }

    pub fn message_mut(&mut self) -> &mut [u8] {
        &mut self.0[1..]
    }
}

impl AsRef<[u8]> for HandshakeInitialize {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsRef<[u8]> for HandshakeResponse {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
