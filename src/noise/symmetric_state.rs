use crate::noise::{CipherState, CipherStateError};
use cryptoxide::blake2b::Blake2b;
use std::fmt;

pub struct SymmetricState {
    cipher_state: CipherState,
    ck: [u8; Self::HASH_LEN],
    h: [u8; Self::HASH_LEN],
}

impl fmt::Debug for SymmetricState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SymmetricState")
            .field("ck", &hex::encode(&self.ck))
            .field("h", &hex::encode(&self.h))
            .field("cipher_state", &self.cipher_state)
            .finish()
    }
}

impl SymmetricState {
    pub const HASH_LEN: usize = 64;
    pub const BLOCK_LEN: usize = 128;

    pub fn initialize_symmetric(protocol_name: impl AsRef<[u8]>) -> Self {
        let protocol_name = protocol_name.as_ref();
        let mut h = [0; Self::HASH_LEN];
        let mut ck = [0; Self::HASH_LEN];
        let cipher_state = CipherState::new();

        if protocol_name.len() > Self::HASH_LEN {
            Blake2b::blake2b(&mut h, protocol_name, &[]);
        } else {
            h[..protocol_name.len()].copy_from_slice(protocol_name);
        }

        ck.copy_from_slice(&h);

        Self {
            h,
            ck,
            cipher_state,
        }
    }

    pub fn mix_key(&mut self, input_key_material: impl AsRef<[u8]>) {
        let mut temp_k = [0; Self::HASH_LEN];

        hkdf(
            &self.ck.clone(),
            input_key_material.as_ref(),
            Output::Output2,
            &mut self.ck,
            &mut temp_k,
            &mut [],
        );

        let mut k = [0; CipherState::KEY_LEN];
        k.copy_from_slice(&temp_k[..CipherState::KEY_LEN]);
        self.cipher_state = CipherState::initialize_key(k);
    }

    pub fn mix_hash(&mut self, data: impl AsRef<[u8]>) {
        use cryptoxide::digest::Digest as _;
        let mut blake2b = Blake2b::new(SymmetricState::HASH_LEN);
        blake2b.input(&self.h);
        blake2b.input(data.as_ref());
        blake2b.result(&mut self.h);
    }

    // allow the function to be unused, it is meant to be as we don't have
    // any pre-shared key
    #[allow(dead_code)]
    pub fn mix_key_and_hash(&mut self, input_key_material: impl AsRef<[u8]>) {
        let mut temp_h = [0; Self::HASH_LEN];
        let mut temp_k = [0; Self::HASH_LEN];

        hkdf(
            &self.ck.clone(),
            input_key_material.as_ref(),
            Output::Output3,
            &mut self.ck,
            &mut temp_h,
            &mut temp_k,
        );

        self.mix_hash(&temp_h);

        let mut k = [0; CipherState::KEY_LEN];
        k.copy_from_slice(&temp_k[..CipherState::KEY_LEN]);
        self.cipher_state = CipherState::initialize_key(k);
    }

    pub fn get_handshake_hash(&self) -> &[u8; Self::HASH_LEN] {
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
        self.mix_hash(&output[..]);
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

    pub fn split(&self) -> (CipherState, CipherState) {
        let mut temp_k1 = [0; Self::HASH_LEN];
        let mut temp_k2 = [0; Self::HASH_LEN];

        hkdf(
            &self.ck,
            &[],
            Output::Output2,
            &mut temp_k1,
            &mut temp_k2,
            &mut [],
        );

        let mut k1 = [0; CipherState::KEY_LEN];
        k1.copy_from_slice(&temp_k1[..CipherState::KEY_LEN]);

        let mut k2 = [0; CipherState::KEY_LEN];
        k2.copy_from_slice(&temp_k2[..CipherState::KEY_LEN]);

        (
            CipherState::initialize_key(k1),
            CipherState::initialize_key(k2),
        )
    }
}

fn hmac(key: &[u8], data: &[u8], out: &mut [u8]) {
    use cryptoxide::digest::Digest as _;
    let mut inner = [0; SymmetricState::HASH_LEN];
    let mut inner_pad = [0x36u8; SymmetricState::BLOCK_LEN];
    let mut out_pad = [0x5cu8; SymmetricState::BLOCK_LEN];
    for count in 0..key.len() {
        inner_pad[count] ^= key[count];
        out_pad[count] ^= key[count];
    }

    let mut blake2b = Blake2b::new(SymmetricState::HASH_LEN);
    blake2b.input(&inner_pad);
    blake2b.input(data);
    blake2b.result(&mut inner);

    let mut blake2b = Blake2b::new(SymmetricState::HASH_LEN);
    blake2b.input(&out_pad);
    blake2b.input(&inner);
    blake2b.result(out);
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
enum Output {
    Output1,
    Output2,
    Output3,
}

fn hkdf(
    chaining_key: &[u8],
    input_key_material: &[u8],
    output: Output,
    output1: &mut [u8],
    output2: &mut [u8],
    output3: &mut [u8],
) {
    use Output::*;

    let mut tmp_key = [0; SymmetricState::HASH_LEN];
    hmac(chaining_key, input_key_material, &mut tmp_key);

    hmac(&tmp_key, &[1u8], output1);
    if output == Output1 {
        return;
    }

    let mut in2 = [0; SymmetricState::HASH_LEN + 1];
    in2[..SymmetricState::HASH_LEN].copy_from_slice(output1);
    in2[SymmetricState::HASH_LEN] = 0x02;
    hmac(&tmp_key, &in2, output2);
    if output == Output2 {
        return;
    }

    let mut in3 = [0; SymmetricState::HASH_LEN + 1];
    in3[..SymmetricState::HASH_LEN].copy_from_slice(output2);
    in3[SymmetricState::HASH_LEN] = 0x03;
    hmac(&tmp_key, &in3, output3);
    debug_assert_eq!(output, Output3);
}
