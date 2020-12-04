use cryptoxide::chacha20poly1305::ChaCha20Poly1305;
use std::fmt;
use thiserror::Error;

#[derive(Debug, Default, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct Nonce(u64);

#[derive(Clone)]
pub struct CipherState {
    k: [u8; Self::KEY_LEN],
    n: Nonce,
    has_key: bool,
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
        Self {
            k: [0; Self::KEY_LEN],
            n: Nonce::zero(),
            has_key: false,
        }
    }

    pub fn initialize_key(k: [u8; Self::KEY_LEN]) -> Self {
        Self {
            k,
            n: Nonce::zero(),
            has_key: true,
        }
    }

    #[inline(always)]
    pub fn has_key(&self) -> bool {
        self.has_key
    }

    #[inline(always)]
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
        let len = if self.has_key() {
            if tag_index + Self::TAG_LEN > output.len() {
                return Err(CipherStateError::NotEnoughOutput);
            }

            let mut ctx = ChaCha20Poly1305::new(&self.k, &self.n.to_bytes(), ad.as_ref());

            let (output, tag) = output.split_at_mut(tag_index);
            ctx.encrypt(plaintext.as_ref(), output, &mut tag[..Self::TAG_LEN]);
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
        if self.has_key() {
            let cipher_text = cipher_text.as_ref();
            if cipher_text.len() < Self::TAG_LEN {
                return Err(CipherStateError::NotEnoughInput);
            }

            let tag_index = cipher_text.len() - Self::TAG_LEN;
            if tag_index > output.len() {
                return Err(CipherStateError::NotEnoughOutput);
            }

            let (cipher_text, tag) = cipher_text.split_at(tag_index);

            let mut ctx = ChaCha20Poly1305::new(&self.k, &self.n.to_bytes(), ad.as_ref());

            if !ctx.decrypt(cipher_text.as_ref(), output, &tag[..Self::TAG_LEN]) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use noiseexplorer_ik::state::CipherState as CipherStateRef;

    #[test]
    fn ref_empty() {
        let mut ours = CipherState::new();
        let mut theirs = CipherStateRef::new();

        assert_eq!(
            ours.n.0,
            theirs.n.get_value().unwrap(),
            "nonce should be initialised to 0"
        );
        assert_eq!(
            ours.k,
            theirs.k.as_bytes(),
            "key should be initialised to 0"
        );

        const PLAINTEXT: &[u8] = b"plain text";
        let mut our_output = [0u8; 1024];
        ours.encrypt_with_ad(&[], PLAINTEXT, &mut our_output)
            .unwrap();

        let mut their_output = [0; 10];
        let mut their_mac = [0; 16];
        their_output.copy_from_slice(PLAINTEXT);
        let err = theirs
            .encrypt_with_ad(&[], &mut their_output, &mut their_mac)
            .unwrap_err();
        assert_eq!(noiseexplorer_ik::error::NoiseError::EmptyKeyError, err);

        assert_eq!(
            &our_output[..PLAINTEXT.len()],
            &their_output[..PLAINTEXT.len()],
            "encrypted data should be the same"
        );
        assert_eq!(
            &our_output[PLAINTEXT.len()..PLAINTEXT.len() + CipherState::TAG_LEN],
            &their_mac,
            "encrypted data MAC should be the same"
        );
        assert_eq!(
            &our_output[..PLAINTEXT.len()],
            &PLAINTEXT[..],
            "no key, so input should be the same as output"
        )
    }

    #[test]
    fn ref_something() {
        const KEY: [u8; CipherState::KEY_LEN] = [0x1b; CipherState::KEY_LEN];

        let mut ours = CipherState::initialize_key(KEY);
        let mut theirs = CipherStateRef::from_key(noiseexplorer_ik::types::Key::from_bytes(KEY));

        let mut decrypt_ours = ours.clone();
        let mut decrypt_theirs = theirs.clone();

        assert_eq!(
            ours.n.0,
            theirs.n.get_value().unwrap(),
            "nonce should be initialised to 0"
        );
        assert_eq!(
            ours.k,
            theirs.k.as_bytes(),
            "key should be initialised to 0"
        );
        assert_eq!(ours.n.0, 0, "nonce should be initialised to 0");

        const PLAINTEXT: &[u8] = b"plain text";
        let mut our_output = [0u8; 1024];
        ours.encrypt_with_ad(&[], PLAINTEXT, &mut our_output)
            .unwrap();

        let mut their_output = [0; 10];
        let mut their_mac = [0; 16];
        their_output.copy_from_slice(PLAINTEXT);
        theirs
            .encrypt_with_ad(&[], &mut their_output, &mut their_mac)
            .unwrap();

        assert_eq!(
            &our_output[..PLAINTEXT.len()],
            &their_output[..PLAINTEXT.len()],
            "encrypted data should be the same"
        );
        assert_eq!(
            &our_output[PLAINTEXT.len()..PLAINTEXT.len() + CipherState::TAG_LEN],
            &their_mac,
            "encrypted data MAC should be the same"
        );

        decrypt_theirs
            .decrypt_with_ad(&[], &mut their_output, &mut their_mac)
            .unwrap();
        assert_eq!(their_output, PLAINTEXT);

        let mut our_decrypted = [0u8; 10];
        decrypt_ours
            .decrypt_with_ad(
                &[],
                &our_output[..PLAINTEXT.len() + CipherState::TAG_LEN],
                &mut our_decrypted,
            )
            .unwrap();
        assert_eq!(our_decrypted, PLAINTEXT);

        assert_eq!(
            ours.n.0,
            theirs.n.get_value().unwrap(),
            "nonce should be incremented to 1"
        );
        assert_eq!(
            ours.k,
            theirs.k.as_bytes(),
            "key should be incremented to 1"
        );
        assert_eq!(ours.n.0, 1, "nonce should be incremented to 1");
    }
}
