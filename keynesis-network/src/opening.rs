use crate::{
    codec::handshake::{HandshakeInitialize, HandshakeResponse},
    Handle,
};
use anyhow::{bail, Context as _, Result};
use keynesis::{
    hash::Blake2b,
    key::{
        ed25519::{self, PublicKey},
        Dh,
    },
    noise::{ik::WaitB, IK},
};
use rand_core::{CryptoRng, RngCore};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

pub struct Opening<I, O, RNG, K = ed25519::SecretKey> {
    reader: I,
    writer: O,
    state: IK<K, Blake2b, RNG, WaitB>,
}

impl<I, O, RNG, K> Opening<I, O, RNG, K>
where
    O: AsyncWrite + Unpin,
    K: Dh,
    RNG: CryptoRng + RngCore,
{
    pub(crate) async fn new(
        rng: RNG,
        k: &K,
        rs: PublicKey,
        reader: I,
        mut writer: O,
    ) -> Result<Self> {
        let mut message = HandshakeInitialize::DEFAULT;
        let ik = IK::new(rng, &[]);

        let state = ik
            .initiate(k, rs, message.message_mut())
            .context("Cannot initiate Noise IK handshake")?;

        writer
            .write_all(message.as_ref())
            .await
            .context("Cannot send the Noise IK initial Handshake")?;

        Ok(Self {
            reader,
            writer,
            state,
        })
    }
}

impl<I, O, RNG, K> Opening<I, O, RNG, K>
where
    I: AsyncRead + Unpin,
    O: AsyncWrite + Unpin,
    K: Dh,
    RNG: CryptoRng + RngCore,
{
    pub(crate) async fn wait(self, k: &K) -> Result<Handle<I, O>> {
        let Self {
            mut reader,
            writer,
            state,
        } = self;

        let mut bytes = [0; HandshakeResponse::SIZE];

        reader
            .read_exact(&mut bytes)
            .await
            .context("Cannot receive the Noise IK response Handshake")?;

        let message = HandshakeResponse::from_bytes(bytes);

        if !message.version().is_supported() {
            bail!("Unsupported version {:?}", message.version());
        }

        let state = state
            .receive(k, message.message())
            .context("Noise IK Handshake response failed")?;

        Ok(Handle::new(reader, writer, state))
    }
}
