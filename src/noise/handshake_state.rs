use crate::{
    key::{
        ed25519::{PublicKey, SecretKey},
        Key,
    },
    noise::{CipherState, CipherStateError, SymmetricState},
};
use bytes::{Buf, BufMut};
use rand_core::{CryptoRng, RngCore};
use thiserror::Error;

pub(crate) struct HandshakeState<RNG> {
    symmetric_state: SymmetricState,

    rng: RNG,
    e: Option<SecretKey>,
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
}

impl<RNG> HandshakeState<RNG>
where
    RNG: RngCore + CryptoRng,
{
    pub(crate) fn write_e(&mut self, mut output: impl BufMut) -> Result<(), HandshakeStateError> {
        if output.remaining_mut() < PublicKey::SIZE {
            Err(HandshakeStateError::NotEnoughOutput)
        } else {
            if self.e.is_none() {
                self.e = Some(SecretKey::new(&mut self.rng));
            }
            if let Some(e) = &self.e {
                let public = e.public_key();
                output.put_slice(public.as_ref());
                self.symmetric_state.mix_hash(public.as_ref());
            } else {
                unsafe { std::hint::unreachable_unchecked() }
            }
            Ok(())
        }
    }
}

impl<RNG> HandshakeState<RNG> {
    pub(crate) fn new(rng: RNG, prologue: &[u8], protocol_name: &str) -> Self {
        let mut symmetric_state = SymmetricState::initialize_symmetric(protocol_name);
        symmetric_state.mix_hash(prologue);

        Self {
            symmetric_state,
            rng,
            e: None,
        }
    }

    pub(crate) fn symmetric_state(&self) -> &SymmetricState {
        &self.symmetric_state
    }

    pub(crate) fn read_e(&mut self, mut input: impl Buf) -> Result<PublicKey, HandshakeStateError> {
        if input.remaining() < PublicKey::SIZE {
            Err(HandshakeStateError::ExpectingPublicKey)
        } else {
            let mut pk = [0; PublicKey::SIZE];
            input.copy_to_slice(&mut pk);
            self.symmetric_state.mix_hash(&pk);
            Ok(PublicKey::from(pk))
        }
    }

    pub(crate) fn write_s(
        &mut self,
        s: &PublicKey,
        mut output: impl BufMut,
    ) -> Result<(), HandshakeStateError> {
        if output.remaining_mut() < PublicKey::SIZE + CipherState::TAG_LEN {
            Err(HandshakeStateError::NotEnoughOutput)
        } else {
            let mut pk = [0; PublicKey::SIZE + CipherState::TAG_LEN];
            self.symmetric_state.encrypt_and_hash(s.as_ref(), &mut pk)?;
            output.put_slice(&pk);
            Ok(())
        }
    }

    pub(crate) fn read_s(&mut self, mut input: impl Buf) -> Result<PublicKey, HandshakeStateError> {
        if input.remaining() < PublicKey::SIZE + CipherState::TAG_LEN {
            Err(HandshakeStateError::NotEnoughInput)
        } else {
            let mut temp = [0; PublicKey::SIZE + CipherState::TAG_LEN];
            input.copy_to_slice(&mut temp);
            let mut pk = [0; PublicKey::SIZE];
            self.symmetric_state.decrypt_and_hash(&temp, &mut pk)?;
            Ok(PublicKey::from(pk))
        }
    }

    pub(crate) fn encrypt_and_hash(
        &mut self,
        plaintext: &[u8],
        mut output: impl BufMut,
    ) -> Result<(), HandshakeStateError> {
        if output.remaining_mut() < plaintext.len() + CipherState::TAG_LEN {
            Err(HandshakeStateError::NotEnoughOutput)
        } else {
            let mut tag = vec![0; plaintext.len() + CipherState::TAG_LEN];
            self.symmetric_state.encrypt_and_hash(plaintext, &mut tag)?;
            output.put_slice(&tag);
            Ok(())
        }
    }

    pub(crate) fn decrypt_and_hash(
        &mut self,
        mut input: impl Buf,
        output: &mut [u8],
    ) -> Result<(), HandshakeStateError> {
        if input.remaining() < output.len() + CipherState::TAG_LEN {
            Err(HandshakeStateError::NotEnoughInput)
        } else {
            let mut cipher_text = vec![0; output.len() + CipherState::TAG_LEN];
            input.copy_to_slice(&mut cipher_text);
            self.symmetric_state.decrypt_and_hash(cipher_text, output)?;

            Ok(())
        }
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

    pub(crate) fn dh_sx<K: Key>(&mut self, s: &K, e: &PublicKey) {
        let dh = s.dh(e);
        self.symmetric_state.mix_key(dh.as_ref());
    }
}
