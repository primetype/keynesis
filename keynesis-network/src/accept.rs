use crate::{
    codec::handshake::{HandshakeInitialize, HandshakeResponse},
    Handle,
};
use anyhow::{bail, Context as _, Result};
use keynesis_core::{
    hash::Blake2b,
    key::{
        ed25519::{self, PublicKey},
        Dh,
    },
    noise::{ik::A, IK},
};
use rand_core::{CryptoRng, RngCore};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

/// accept incoming handshake
///
/// upon opening an ASMTP session with our node, the initiator will send
/// the initial handshake to authenticate themselves and the responser is required
/// to respond accordingly.
///
/// This object offers the necessary tooling to identify the initiator so it is
/// possible to deny the connection early enough (see [Accepting::accept])
pub struct Accepting<I, O, RNG, K = ed25519::SecretKey> {
    reader: I,
    writer: O,
    state: IK<K, Blake2b, RNG, A>,
}

impl<I, O, K, RNG> Accepting<I, O, RNG, K>
where
    K: Dh,
    RNG: CryptoRng + RngCore,
{
    pub(crate) fn new(rng: RNG, reader: I, writer: O) -> Self {
        Self {
            reader,
            writer,
            state: IK::new(rng, &[]),
        }
    }
}

impl<I, O, K, RNG> Accepting<I, O, RNG, K>
where
    I: AsyncRead + Unpin,
    O: AsyncWrite + Unpin,
    K: Dh,
    RNG: CryptoRng + RngCore,
{
    /// perform the initial handshake with the peer
    ///
    /// Upon receiving the initial handshake message, the function `check_id` will
    /// verify the public key of the user. For example the user can maintain a list
    /// of unwelcome public keys.
    ///
    /// If the peer is accepted and is using a supported version of the protocol
    /// then the functions replies the response handshake.
    ///
    /// # Errors
    ///
    /// This function may fail for IO operations as well as for processing the
    /// noise handshake.
    ///
    pub async fn accept<F>(self, k: &K, check_id: F) -> Result<Handle<I, O>>
    where
        F: Fn(&PublicKey) -> bool,
    {
        let Self {
            mut reader,
            mut writer,
            state,
        } = self;

        let mut bytes = [0; HandshakeInitialize::SIZE];

        reader
            .read_exact(&mut bytes)
            .await
            .context("Cannot receive the Noise IK initiate Handshake")?;

        let message = HandshakeInitialize::from_bytes(bytes);

        if !message.version().is_supported() {
            bail!("Unsupported version {:?}", message.version());
        }

        let state = state
            .receive(k, message.message())
            .context("Noise IK Handshake Initiate failed")?;

        if !check_id(state.remote_public_identity()) {
            bail!(
                "Rejecting connection with {}",
                state.remote_public_identity()
            )
        }

        let mut message = HandshakeResponse::DEFAULT;

        let state = state
            .reply(&mut message.message_mut())
            .context("Cannot prep the Noise's Handshake Response message")?;

        writer
            .write_all(message.as_ref())
            .await
            .context("Cannot send the Noise IK response Handshake")?;

        Ok(Handle::new(reader, writer, state))
    }
}
