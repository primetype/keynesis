use crate::{
    key::ed25519::PublicKey,
    noise::{CipherState, CipherStateError, SymmetricState},
};
use std::{convert::TryFrom, fmt, str::FromStr};

/// Unique identifier of a Noise Session (a `TransportState`) between 2 peers.
///
/// This is derived from the Handshake when it has been finalized.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct SessionId([u8; SymmetricState::HASH_LEN]);

/// Noise transport session between 2 participant. Communication is
/// Asymmetric. So it is possible to send messages independently from
/// the messages to receive. This allows to continue sending our current
/// messages without having to make sure we are in sync with the remote
/// messages.
///
/// All messages are authenticated and because we are rekeying after
/// each messages we have strong forward secrecy.
pub struct TransportState {
    handshake_hash: SessionId,
    local: CipherState,
    remote: CipherState,
    remote_id: PublicKey,
}

impl TransportState {
    pub(crate) fn new(
        handshake_hash: [u8; SymmetricState::HASH_LEN],
        local: CipherState,
        remote: CipherState,
        remote_id: PublicKey,
    ) -> Self {
        TransportState {
            handshake_hash: SessionId(handshake_hash),
            local,
            remote,
            remote_id,
        }
    }

    /// unique identifier of the noise session
    pub fn noise_session(&self) -> &SessionId {
        &self.handshake_hash
    }

    /// get the remote's public identity
    pub fn remote_public_identity(&self) -> &PublicKey {
        &self.remote_id
    }

    /// get the number of message received from the remote peer
    ///
    /// this function will be a little tainted by the handshake state
    /// it also account for the number of times either encrypt or
    /// decrypt has been used during the handshake. This is because
    /// during the handshake the exchange is symmetrical while in the
    /// transport era the exchanges are asymmetrical.
    pub fn count_received(&self) -> u64 {
        self.remote.nonce().into_u64()
    }

    /// get the number of message sent to the remote peer
    ///
    /// this function will be a little tainted by the handshake state
    /// it also account for the number of times either encrypt or
    /// decrypt has been used during the handshake. This is because
    /// during the handshake the exchange is symmetrical while in the
    /// transport era the exchanges are asymmetrical.
    pub fn count_sent(&self) -> u64 {
        self.local.nonce().into_u64()
    }

    /// send message to the remote peer
    pub fn send(
        &mut self,
        input: impl AsRef<[u8]>,
        output: &mut [u8],
    ) -> Result<(), CipherStateError> {
        self.local.encrypt_with_ad(&[], input, output)?;
        self.local.rekey();

        Ok(())
    }

    /// receive message from the remote peer
    pub fn receive(
        &mut self,
        input: impl AsRef<[u8]>,
        output: &mut [u8],
    ) -> Result<(), CipherStateError> {
        self.remote.decrypt_with_ad(&[], input, output)?;
        self.remote.rekey();

        Ok(())
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
        let mut bytes = [0; SymmetricState::HASH_LEN];
        hex::decode_to_slice(s, &mut bytes)?;
        Ok(Self(bytes))
    }
}

impl Into<String> for SessionId {
    fn into(self) -> String {
        self.to_string()
    }
}

impl TryFrom<String> for SessionId {
    type Error = <Self as FromStr>::Err;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}
