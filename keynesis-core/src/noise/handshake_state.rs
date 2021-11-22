use crate::{
    buffer::BufRead,
    hash::Hash,
    key::{ed25519_extended::PublicKey, Dh},
    noise::{CipherState, CipherStateError, SymmetricState},
};
use rand_core::{CryptoRng, RngCore};
use std::io::Write;
use thiserror::Error;

pub(crate) struct HandshakeState<RNG, DH, H>
where
    H: Hash,
{
    symmetric_state: SymmetricState<H>,

    rng: RNG,
    is_psk: bool,
    e: Option<DH>,
}

#[derive(Debug, Error)]
pub enum HandshakeStateError {
    #[error("Not enough bytes, expecting to read a public key")]
    ExpectingPublicKey,

    #[error("Error while encrypting payload")]
    Cipher(#[from] CipherStateError),

    #[error("Not enough space in the output")]
    NotEnoughOutput,

    #[error("Not enough input")]
    NotEnoughInput,

    #[error("Cannot write message")]
    Write(#[from] std::io::Error),
}

impl<RNG, DH, H> HandshakeState<RNG, DH, H>
where
    RNG: RngCore + CryptoRng,
    DH: Dh,
    H: Hash,
{
    pub(crate) fn write_e(&mut self, mut output: impl Write) -> Result<(), HandshakeStateError> {
        if self.e.is_none() {
            self.e = Some(DH::generate(&mut self.rng));
        }
        if let Some(e) = &self.e {
            let public = e.public();
            output.write_all(public.as_ref())?;
            self.symmetric_state.mix_hash(public.as_ref());
            if self.is_psk {
                self.symmetric_state.mix_key(public.as_ref());
            }
        } else {
            unsafe { std::hint::unreachable_unchecked() }
        }
        Ok(())
    }
}

impl<RNG, DH, H> HandshakeState<RNG, DH, H>
where
    DH: Dh,
    H: Hash,
{
    pub(crate) fn new(rng: RNG, prologue: &[u8], protocol_name: &str) -> Self {
        let mut symmetric_state = SymmetricState::initialize_symmetric(protocol_name);
        symmetric_state.mix_hash(prologue);

        Self {
            symmetric_state,
            rng,
            is_psk: false,
            e: None,
        }
    }

    pub(crate) fn psk(&mut self, psk: &[u8]) {
        self.is_psk = true;
        self.symmetric_state.mix_key_and_hash(psk);
    }

    pub(crate) fn mix_hash(&mut self, pk: &PublicKey) {
        self.symmetric_state.mix_hash(pk.as_ref());
    }

    pub(crate) fn symmetric_state(&mut self) -> &mut SymmetricState<H> {
        &mut self.symmetric_state
    }

    fn encrypted_len(&self, len: usize) -> usize {
        if self.symmetric_state.has_key() {
            len + CipherState::TAG_LEN
        } else {
            len
        }
    }

    pub(crate) fn read_e(
        &mut self,
        input: &mut BufRead<'_>,
    ) -> Result<PublicKey, HandshakeStateError> {
        if input.remaining() < PublicKey::SIZE {
            Err(HandshakeStateError::ExpectingPublicKey)
        } else {
            let mut pk = [0; PublicKey::SIZE];
            input.read(&mut pk);
            self.symmetric_state.mix_hash(&pk);
            if self.is_psk {
                self.symmetric_state.mix_key(&pk);
            }
            Ok(PublicKey::from(pk))
        }
    }

    pub(crate) fn write_s(
        &mut self,
        s: &PublicKey,
        mut output: impl Write,
    ) -> Result<(), HandshakeStateError> {
        let len = self.encrypted_len(PublicKey::SIZE);
        let mut pk = [0; PublicKey::SIZE + CipherState::TAG_LEN];
        self.symmetric_state
            .encrypt_and_hash(s.as_ref(), &mut pk[..len])?;
        output.write_all(&pk[..len])?;
        Ok(())
    }

    pub(crate) fn read_s(
        &mut self,
        input: &mut BufRead<'_>,
    ) -> Result<PublicKey, HandshakeStateError> {
        let len = self.encrypted_len(PublicKey::SIZE);
        if input.remaining() < len {
            Err(HandshakeStateError::NotEnoughInput)
        } else {
            let mut pk = [0; PublicKey::SIZE];
            self.symmetric_state
                .decrypt_and_hash(&input.slice(len), &mut pk)?;
            input.advance(len);
            Ok(PublicKey::from(pk))
        }
    }

    pub(crate) fn encrypt_and_hash(
        &mut self,
        plaintext: &[u8],
        mut output: impl Write,
    ) -> Result<(), HandshakeStateError> {
        let mut buffer = [0; u16::MAX as usize];
        let len = self.encrypted_len(plaintext.len());
        let mut tag = &mut buffer[..len];
        let len = self.symmetric_state.encrypt_and_hash(plaintext, &mut tag)?;
        output.write_all(&buffer[..len])?;
        Ok(())
    }

    pub(crate) fn decrypt_and_hash(
        &mut self,
        input: &mut BufRead,
        output: &mut [u8],
    ) -> Result<(), HandshakeStateError> {
        let len = input.remaining();
        self.symmetric_state
            .decrypt_and_hash(input.slice(len), output)?;
        input.advance(len);

        Ok(())
    }

    pub(crate) fn dh_ex(&mut self, re: &PublicKey) {
        if let Some(e) = &self.e {
            let dh = e.dh(re);
            self.symmetric_state.mix_key(dh);
        } else {
            // this error can only happen if we do a `ee` or an `es`
            // before doing an `e`
            panic!(
                "we are trying to Diffie-Hellman our ephemeral key but it has not been generated"
            )
        }
    }

    pub(crate) fn dh_sx<K: Dh>(&mut self, s: &K, e: &PublicKey) {
        let dh = s.dh(e);
        self.symmetric_state.mix_key(dh.as_ref());
    }
}
