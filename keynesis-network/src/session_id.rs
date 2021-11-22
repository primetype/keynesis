use std::{fmt, str::FromStr};

/// unique identifier of a session established between 2 peers
///
/// this session identifier is generated with the handshake and
/// is unique to the connection (reconnecting to the same peer
/// will generate a new [`SessionId`])
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub struct SessionId([u8; 64]);

impl SessionId {
    pub const SIZE: usize = 64;

    pub(crate) const fn new(session: [u8; Self::SIZE]) -> Self {
        Self(session)
    }
}

impl AsRef<[u8]> for SessionId {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(&self.0))
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SessionId")
            .field(&hex::encode(&self.0))
            .finish()
    }
}

impl FromStr for SessionId {
    type Err = hex::FromHexError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut session_id = SessionId([0; 64]);
        hex::decode_to_slice(s, &mut session_id.0)?;
        Ok(session_id)
    }
}
