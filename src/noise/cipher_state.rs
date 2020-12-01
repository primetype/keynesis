use cryptoxide::chacha20poly1305::ChaCha20Poly1305;
use std::fmt;
use thiserror::Error;

#[derive(Debug, Default, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct Nonce(u64);

pub struct CipherState {
    k: [u8; Self::KEY_LEN],
    n: Nonce,
}

#[derive(Debug, Error)]
pub enum CipherStateError {
    #[error("The nonce has reached 2^64-1 operations already")]
    Nonce,

    #[error("Not enough bytes allocated in the output's")]
    NotEnoughOutput,

    #[error("Not enough inputs, cannot process the data")]
    NotEnoughInput,

    #[error("Authenticated decryption failed, invalid final tag")]
    InvalidTag,
}

impl Nonce {
    const fn zero() -> Self {
        Self(0)
    }

    const fn max() -> Self {
        Self(u64::MAX)
    }

    pub(crate) fn into_u64(self) -> u64 {
        self.0
    }

    fn to_bytes(self) -> [u8; 12] {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&self.0.to_le_bytes());
        nonce_bytes
    }

    fn increment(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }
}

impl fmt::Debug for CipherState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CipherState")
            .field("k", &hex::encode(&self.k))
            .field("n", &hex::encode(&self.n.to_bytes()))
            .finish()
    }
}

impl CipherState {
    pub const KEY_LEN: usize = 32;
    pub const TAG_LEN: usize = 16;

    pub fn new() -> Self {
        Self::initialize_key([0; Self::KEY_LEN])
    }

    pub fn initialize_key(k: [u8; Self::KEY_LEN]) -> Self {
        Self {
            k,
            n: Nonce::zero(),
        }
    }

    pub fn has_key(&self) -> bool {
        self.k != [0; 32]
    }

    pub fn set_nonce(&mut self, nonce: Nonce) {
        self.n = nonce;
    }

    pub(crate) fn nonce(&self) -> &Nonce {
        &self.n
    }

    pub fn encrypt_with_ad(
        &mut self,
        ad: impl AsRef<[u8]>,
        plaintext: impl AsRef<[u8]>,
        output: &mut [u8],
    ) -> Result<usize, CipherStateError> {
        let tag_index = plaintext.as_ref().len();
        if tag_index + Self::TAG_LEN > output.len() {
            return Err(CipherStateError::NotEnoughOutput);
        }

        let len = if self.has_key() {
            let mut ctx = ChaCha20Poly1305::new(&self.k, &self.n.to_bytes(), ad.as_ref());

            let mut tag = [0; Self::TAG_LEN];
            ctx.encrypt(plaintext.as_ref(), &mut output[..tag_index], &mut tag);
            output[tag_index..tag_index + tag.len()].copy_from_slice(&tag);
            self.n = self.n.increment().ok_or(CipherStateError::Nonce)?;
            tag_index + Self::TAG_LEN
        } else {
            output[..tag_index].copy_from_slice(plaintext.as_ref());
            tag_index
        };

        Ok(len)
    }

    pub fn decrypt_with_ad(
        &mut self,
        ad: impl AsRef<[u8]>,
        cipher_text: impl AsRef<[u8]>,
        output: &mut [u8],
    ) -> Result<(), CipherStateError> {
        let cipher_text = cipher_text.as_ref();
        if cipher_text.len() < Self::TAG_LEN {
            return Err(CipherStateError::NotEnoughInput);
        }

        let tag_index = cipher_text.len() - Self::TAG_LEN;
        if tag_index > output.len() {
            return Err(CipherStateError::NotEnoughOutput);
        }

        let tag = &cipher_text[tag_index..tag_index + Self::TAG_LEN];
        let cipher_text = &cipher_text[..tag_index];

        self.decrypt_with_ad_(ad, cipher_text, tag, output)
    }

    fn decrypt_with_ad_(
        &mut self,
        ad: impl AsRef<[u8]>,
        cipher_text: impl AsRef<[u8]>,
        tag: &[u8],
        output: &mut [u8],
    ) -> Result<(), CipherStateError> {
        if tag.len() != Self::TAG_LEN {
            return Err(CipherStateError::NotEnoughInput);
        }

        if self.has_key() {
            let mut ctx = ChaCha20Poly1305::new(&self.k, &self.n.to_bytes(), ad.as_ref());

            if !ctx.decrypt(cipher_text.as_ref(), output, tag) {
                return Err(CipherStateError::InvalidTag);
            }

            self.n = self.n.increment().ok_or(CipherStateError::Nonce)?;
        } else {
            output.copy_from_slice(cipher_text.as_ref());
        }

        Ok(())
    }

    /// one way function to derive a new cipher key from the previous key
    ///
    /// this prevents compromised keys to decrypt older messages. Periodically
    /// or continuous rekey is recommended
    pub fn rekey(&mut self) {
        let mut new_key = [0; Self::KEY_LEN];
        let mut _tag = [0; Self::TAG_LEN];

        let mut ctx = ChaCha20Poly1305::new(&self.k, &Nonce::max().to_bytes(), &[]);
        ctx.encrypt(&[0; Self::KEY_LEN], &mut new_key, &mut _tag);

        self.k = new_key;
    }
}

impl Default for CipherState {
    fn default() -> Self {
        Self::new()
    }
}
