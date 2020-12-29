pub use cryptoxide::digest::Digest;
pub use cryptoxide::{blake2b::Blake2b, blake2s::Blake2s};

pub trait Hash {
    const HASH_LEN: usize;
    const BLOCK_LEN: usize;

    type HASH: AsRef<[u8]> + AsMut<[u8]> + Clone;
    type BLOCK: AsRef<[u8]> + AsMut<[u8]> + Clone;

    fn name() -> &'static str;

    fn zero_hash() -> Self::HASH;

    fn zero_block() -> Self::BLOCK;

    fn hasher() -> Self;

    fn reset(&mut self);

    fn input(&mut self, data: impl AsRef<[u8]>);

    fn result(&mut self, output: &mut Self::HASH);
}

impl Hash for Blake2b {
    const HASH_LEN: usize = 64;
    const BLOCK_LEN: usize = 128;

    type HASH = [u8; 64];
    type BLOCK = [u8; 128];

    fn name() -> &'static str {
        "BLAKE2b"
    }

    fn zero_hash() -> Self::HASH {
        [0; Self::HASH_LEN]
    }

    fn zero_block() -> Self::BLOCK {
        [0; Self::BLOCK_LEN]
    }

    fn hasher() -> Self {
        Blake2b::new(Self::HASH_LEN)
    }

    fn reset(&mut self) {
        Digest::reset(self)
    }

    fn input(&mut self, data: impl AsRef<[u8]>) {
        Digest::input(self, data.as_ref())
    }

    fn result(&mut self, output: &mut Self::HASH) {
        Digest::result(self, output.as_mut());
    }
}

impl Hash for Blake2s {
    const HASH_LEN: usize = 32;
    const BLOCK_LEN: usize = 64;

    type HASH = [u8; 32];
    type BLOCK = [u8; 64];

    fn name() -> &'static str {
        "BLAKE2s"
    }

    fn zero_hash() -> Self::HASH {
        [0; Self::HASH_LEN]
    }

    fn zero_block() -> Self::BLOCK {
        [0; Self::BLOCK_LEN]
    }

    fn hasher() -> Self {
        Blake2s::new(Self::HASH_LEN)
    }

    fn reset(&mut self) {
        Digest::reset(self)
    }

    fn input(&mut self, data: impl AsRef<[u8]>) {
        Digest::input(self, data.as_ref())
    }

    fn result(&mut self, output: &mut Self::HASH) {
        Digest::result(self, output.as_mut());
    }
}
