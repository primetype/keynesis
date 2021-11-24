use crate::SessionId;
use bytes::{Buf as _, BufMut as _, Bytes, BytesMut};
use keynesis_core::{
    hash::Blake2b,
    key::ed25519::PublicKey,
    noise::{TransportReceiveHalf, TransportSendHalf},
};
use std::io;
use tokio_util::codec::{Decoder, Encoder};

const MIN_FRAME_LENGTH: usize = 16; // the length and the 16 bytes of mac
pub const MAX_FRAME_LENGTH: usize = u16::MAX as usize - HEAD_LENGTH;
const HEAD_LENGTH: usize = std::mem::size_of::<u16>();

/**
# Decoder for encrypted connections

this is the [tokio codec] object to decode encrypted data. See [`NoiseEncryptedDecoder::new`]
for more information on how to create this half object.

In addition to encrypting the data, this decoder make sure the length of the frame is within
boundaries of the allowed messages.

[tokio codec]: tokio_util::codec
*/
pub struct NoiseEncryptedDecoder {
    noise: TransportReceiveHalf<Blake2b>,
    session: SessionId,
    decode_state: State,
}

/**
# Encoder for encrypted connections

this is the [tokio codec] object to encode encrypted data. See [`NoiseEncryptedEncoder::new`]
for more information on how to create this half object.

In addition to encrypting the data, this encoder make sure the length of the frame is within
boundaries of the allowed messages.

[tokio codec]: tokio_util::codec
*/
pub struct NoiseEncryptedEncoder {
    noise: TransportSendHalf<Blake2b>,
    session: SessionId,
}

/// state of the data being read
///
/// initially we expect the [`State::Head`] which is a pre-determined
/// size and contains the size of the data to read. Once the
enum State {
    Data(usize),
    Head,
}

impl NoiseEncryptedEncoder {
    /// create the encoded with the given [`TransportSendHalf`].
    ///
    /// [`TransportSendHalf`]: keynesis::noise::TransportSendHalf
    pub fn new(noise: TransportSendHalf<Blake2b>) -> Self {
        let session = SessionId::new(*noise.noise_session());
        Self { noise, session }
    }

    /// retrieve the unique noise [`SessionId`].
    pub fn session_id(&self) -> &SessionId {
        &self.session
    }

    /// retrieve the remote's public key. When performing the handshake
    /// the two peers are going to securely share their public keys in
    /// order to authenticate to each others.
    ///
    pub fn remote_public_identity(&self) -> &PublicKey {
        self.noise.remote_public_identity()
    }
}

impl NoiseEncryptedDecoder {
    pub fn new(noise: TransportReceiveHalf<Blake2b>) -> Self {
        let decode_state = State::Head;
        let session = SessionId::new(*noise.noise_session());
        Self {
            noise,
            session,
            decode_state,
        }
    }

    /// retrieve the unique noise [`SessionId`].
    pub fn session_id(&self) -> &SessionId {
        &self.session
    }

    /// retrieve the remote's public key. When performing the handshake
    /// the two peers are going to securely share their public keys in
    /// order to authenticate to each others.
    ///
    pub fn remote_public_identity(&self) -> &PublicKey {
        self.noise.remote_public_identity()
    }

    fn decode_head(&mut self, src: &mut BytesMut) -> io::Result<Option<usize>> {
        if src.len() < HEAD_LENGTH {
            return Ok(None);
        }

        let n = src.get_u16() as usize;

        if n < MIN_FRAME_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame is too short",
            ));
        }

        if n > MAX_FRAME_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame is too long",
            ));
        }

        src.reserve(n);

        Ok(Some(n))
    }

    fn decode_data(&mut self, n: usize, src: &mut BytesMut) -> io::Result<Option<BytesMut>> {
        if src.len() < n {
            return Ok(None);
        }

        let bytes = src.split_to(n);
        let mut output = vec![0; n.wrapping_sub(16)];

        if let Err(error) = self.noise.receive(bytes.as_ref(), &mut output) {
            Err(io::Error::new(io::ErrorKind::InvalidData, error))
        } else {
            Ok(Some(BytesMut::from(output.as_slice())))
        }
    }
}

impl Decoder for NoiseEncryptedDecoder {
    type Item = BytesMut;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let n = match self.decode_state {
            State::Head => match self.decode_head(src)? {
                Some(n) => {
                    self.decode_state = State::Data(n);
                    n
                }
                None => return Ok(None),
            },
            State::Data(n) => n,
        };

        match self.decode_data(n, src)? {
            Some(data) => {
                self.decode_state = State::Head;
                src.reserve(HEAD_LENGTH);
                Ok(Some(data))
            }
            None => Ok(None),
        }
    }
}

impl Encoder<Bytes> for NoiseEncryptedEncoder {
    type Error = io::Error;
    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let n = item.len();

        if n > (MAX_FRAME_LENGTH - 16) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "frame is too long",
            ));
        }

        let n = n.wrapping_add(16);

        dst.reserve(HEAD_LENGTH + n);

        dst.put_u16(n as u16);

        let mut output = vec![0; n];
        if let Err(error) = self.noise.send(item.as_ref(), &mut output) {
            Err(io::Error::new(io::ErrorKind::InvalidInput, error))
        } else {
            dst.extend_from_slice(output.as_ref());
            Ok(())
        }
    }
}
