use crate::{
    hash::Hash,
    noise::{CipherState, CipherStateError},
};
use std::fmt;

#[derive(Clone)]
pub struct SymmetricState<H: Hash> {
    cipher_state: CipherState,
    ck: H::HASH,
    h: H::HASH,
    hasher: H,
}

impl<H> fmt::Debug for SymmetricState<H>
where
    H: Hash,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct(&format!("SymmetricState<{}>", H::name()))
            .field("ck", &hex::encode(&self.ck))
            .field("h", &hex::encode(&self.h))
            .field("cipher_state", &self.cipher_state)
            .finish()
    }
}

impl<H> SymmetricState<H>
where
    H: Hash,
{
    pub fn has_key(&self) -> bool {
        self.cipher_state.has_key()
    }

    pub fn initialize_symmetric(protocol_name: impl AsRef<[u8]>) -> Self {
        let protocol_name = protocol_name.as_ref();
        let mut h = H::zero_hash();
        let mut ck = H::zero_hash();
        let cipher_state = CipherState::new();
        let mut hasher = H::hasher();

        if protocol_name.len() > H::HASH_LEN {
            hasher.input(protocol_name);
            hasher.result(&mut h);
        } else {
            h.as_mut()[..protocol_name.len()].copy_from_slice(protocol_name);
        }

        ck.as_mut().copy_from_slice(h.as_ref());

        Self {
            h,
            ck,
            cipher_state,
            hasher,
        }
    }

    pub fn mix_key(&mut self, input_key_material: impl AsRef<[u8]>) {
        let mut temp_k = H::zero_hash();

        hkdf(
            &mut self.hasher,
            self.ck.clone().as_ref(),
            input_key_material.as_ref(),
            Output::Output2,
            &mut self.ck,
            &mut temp_k,
            &mut H::zero_hash(),
        );

        let mut k = [0; CipherState::KEY_LEN];
        k.copy_from_slice(&temp_k.as_ref()[..CipherState::KEY_LEN]);
        self.cipher_state = CipherState::initialize_key(k);
    }

    pub fn mix_hash(&mut self, data: impl AsRef<[u8]>) {
        self.hasher.reset();
        self.hasher.input(self.h.as_ref());
        self.hasher.input(data.as_ref());
        self.hasher.result(&mut self.h);
    }

    // allow the function to be unused, it is meant to be as we don't have
    // any pre-shared key
    pub fn mix_key_and_hash(&mut self, input_key_material: impl AsRef<[u8]>) {
        let mut temp_h = H::zero_hash();
        let mut temp_k = H::zero_hash();

        hkdf(
            &mut self.hasher,
            self.ck.clone().as_ref(),
            input_key_material.as_ref(),
            Output::Output3,
            &mut self.ck,
            &mut temp_h,
            &mut temp_k,
        );

        self.mix_hash(&temp_h);

        let mut k = [0; CipherState::KEY_LEN];
        k.copy_from_slice(&temp_k.as_ref()[..CipherState::KEY_LEN]);
        self.cipher_state = CipherState::initialize_key(k);
    }

    pub fn get_handshake_hash(&self) -> &H::HASH {
        &self.h
    }

    pub fn encrypt_and_hash(
        &mut self,
        plaintext: impl AsRef<[u8]>,
        output: &mut [u8],
    ) -> Result<usize, CipherStateError> {
        let size = self
            .cipher_state
            .encrypt_with_ad(&self.h, plaintext, output)?;
        self.mix_hash(&output[..size]);
        Ok(size)
    }

    pub fn decrypt_and_hash(
        &mut self,
        cipher_text: impl AsRef<[u8]>,
        output: &mut [u8],
    ) -> Result<(), CipherStateError> {
        self.cipher_state
            .decrypt_with_ad(&self.h, &cipher_text, output)?;
        self.mix_hash(cipher_text.as_ref());
        Ok(())
    }

    pub fn split(&mut self) -> (CipherState, CipherState) {
        let mut temp_k1 = H::zero_hash();
        let mut temp_k2 = H::zero_hash();

        hkdf(
            &mut self.hasher,
            self.ck.as_ref(),
            &[],
            Output::Output2,
            &mut temp_k1,
            &mut temp_k2,
            &mut H::zero_hash(),
        );

        let mut k1 = [0; CipherState::KEY_LEN];
        k1.copy_from_slice(&temp_k1.as_ref()[..CipherState::KEY_LEN]);

        let mut k2 = [0; CipherState::KEY_LEN];
        k2.copy_from_slice(&temp_k2.as_ref()[..CipherState::KEY_LEN]);

        (
            CipherState::initialize_key(k1),
            CipherState::initialize_key(k2),
        )
    }
}

fn hmac<H: Hash>(hasher: &mut H, key: &[u8], data: &[u8], extra: Option<&[u8]>, out: &mut H::HASH) {
    let mut inner = H::zero_hash();
    let mut inner_pad = H::zero_block();
    let mut out_pad = H::zero_block();

    unsafe {
        std::ptr::write_bytes(
            inner_pad.as_mut().as_mut_ptr(),
            0x36,
            inner_pad.as_ref().len(),
        );
        std::ptr::write_bytes(out_pad.as_mut().as_mut_ptr(), 0x5c, out_pad.as_ref().len());
    }

    for (i, e) in key.iter().copied().enumerate() {
        inner_pad.as_mut()[i] ^= e;
        out_pad.as_mut()[i] ^= e;
    }

    hasher.reset();
    hasher.input(&inner_pad);
    hasher.input(data);
    if let Some(extra) = extra {
        hasher.input(extra);
    }
    hasher.result(&mut inner);

    hasher.reset();
    hasher.input(&out_pad);
    hasher.input(&inner);
    hasher.result(out);
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
enum Output {
    Output1,
    Output2,
    Output3,
}

fn hkdf<H: Hash>(
    hasher: &mut H,
    chaining_key: &[u8],
    input_key_material: &[u8],
    output: Output,
    output1: &mut H::HASH,
    output2: &mut H::HASH,
    output3: &mut H::HASH,
) {
    use Output::*;

    let mut tmp_key = H::zero_hash();
    hmac(hasher, chaining_key, input_key_material, None, &mut tmp_key);

    hmac(hasher, tmp_key.as_ref(), &[1u8], None, output1);
    if output == Output1 {
        return;
    }

    hmac(
        hasher,
        tmp_key.as_ref(),
        output1.as_ref(),
        Some(&[0x02]),
        output2,
    );
    if output == Output2 {
        return;
    }

    hmac(
        hasher,
        tmp_key.as_ref(),
        output2.as_ref(),
        Some(&[0x03]),
        output3,
    );
    debug_assert_eq!(output, Output3);
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptoxide::blake2s::Blake2s;
    use noiseexplorer_ik::state::SymmetricState as SymmetricStateRef;

    #[test]
    fn ref_empty() {
        const PROTOCOL_NAME: &str = "";

        let mut ours = SymmetricState::initialize_symmetric(PROTOCOL_NAME);
        let mut theirs = SymmetricStateRef::initialize_symmetric(PROTOCOL_NAME.as_bytes());
        assert_eq!(ours.ck, theirs.ck.as_bytes(),);
        assert_eq!(ours.h, theirs.h.as_bytes(),);

        test_mix_with(&mut ours, &mut theirs);
        test_encrypt_with(ours, theirs);
    }

    #[test]
    fn ref_32() {
        const PROTOCOL_NAME: [u8; 32] = [0xca; 32];

        let mut ours = SymmetricState::initialize_symmetric(PROTOCOL_NAME);
        let mut theirs = SymmetricStateRef::initialize_symmetric(&PROTOCOL_NAME);
        assert_eq!(ours.ck, theirs.ck.as_bytes(),);
        assert_eq!(ours.h, theirs.h.as_bytes(),);

        test_mix_with(&mut ours, &mut theirs);
        test_encrypt_with(ours, theirs);
    }

    #[test]
    fn ref_long() {
        const PROTOCOL_NAME: [u8; 64] = [0xca; 64];

        let mut ours = SymmetricState::initialize_symmetric(PROTOCOL_NAME);
        let mut theirs = SymmetricStateRef::initialize_symmetric(&PROTOCOL_NAME);
        assert_eq!(ours.ck, theirs.ck.as_bytes(),);
        assert_eq!(ours.h, theirs.h.as_bytes(),);

        test_mix_with(&mut ours, &mut theirs);
        test_encrypt_with(ours, theirs);
    }

    fn test_mix_with(ours: &mut SymmetricState<Blake2s>, theirs: &mut SymmetricStateRef) {
        const DATA: &[u8] = b"MIX HASH DATA";
        ours.mix_hash(DATA);
        theirs.mix_hash(DATA);
        assert_eq!(ours.ck, theirs.ck.as_bytes(),);
        assert_eq!(ours.h, theirs.h.as_bytes(),);

        const INPUT_KEY_MATERIAL: &[u8] = b"INPUT KEY MATERIAL";
        ours.mix_key(INPUT_KEY_MATERIAL);
        theirs.mix_key(INPUT_KEY_MATERIAL);
        assert_eq!(ours.ck, theirs.ck.as_bytes(),);
        assert_eq!(ours.h, theirs.h.as_bytes(),);
    }

    fn test_encrypt_with(mut ours: SymmetricState<Blake2s>, mut theirs: SymmetricStateRef) {
        const DATA: &[u8] = b"MIX HASH DATA";
        ours.mix_hash(DATA);
        theirs.mix_hash(DATA);
        assert_eq!(ours.ck, theirs.ck.as_bytes(),);
        assert_eq!(ours.h, theirs.h.as_bytes(),);

        const INPUT_KEY_MATERIAL: &[u8] = b"INPUT KEY MATERIAL";
        ours.mix_key(INPUT_KEY_MATERIAL);
        theirs.mix_key(INPUT_KEY_MATERIAL);
        assert_eq!(ours.ck, theirs.ck.as_bytes(),);
        assert_eq!(ours.h, theirs.h.as_bytes(),);

        // TESTING ENCRYPT/DECRYPT

        let mut decrypt_ours = ours.clone();
        let mut decrypt_theirs = theirs.clone();

        const PLAINTEXT: &[u8] = b"plain text";
        let mut our_output = [0u8; 26];
        ours.encrypt_and_hash(PLAINTEXT, &mut our_output).unwrap();

        let mut their_output = [0; 26];
        their_output[..PLAINTEXT.len()].copy_from_slice(PLAINTEXT);
        theirs.encrypt_and_hash(&mut their_output).unwrap();

        assert_eq!(ours.h, theirs.h.as_bytes(),);
        assert_eq!(ours.ck, theirs.ck.as_bytes(),);
        assert_eq!(
            &our_output[..PLAINTEXT.len() + CipherState::TAG_LEN],
            &their_output[..PLAINTEXT.len() + CipherState::TAG_LEN],
            "encrypted data should be the same"
        );

        decrypt_theirs.decrypt_and_hash(&mut their_output).unwrap();
        assert_eq!(decrypt_theirs.h.as_bytes(), theirs.h.as_bytes(),);
        assert_eq!(decrypt_theirs.ck.as_bytes(), theirs.ck.as_bytes(),);
        assert_eq!(&their_output[..PLAINTEXT.len()], PLAINTEXT);

        let mut plaintext = [0; 10];
        decrypt_ours
            .decrypt_and_hash(&our_output, &mut plaintext)
            .unwrap();
        assert_eq!(decrypt_ours.h, decrypt_theirs.h.as_bytes(),);
        assert_eq!(decrypt_ours.ck, decrypt_theirs.ck.as_bytes(),);
        assert_eq!(&plaintext[..PLAINTEXT.len()], PLAINTEXT);
    }
}
