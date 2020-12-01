/*!
# Keynesis: key management for signing and e2e communication

Keynesis leverage the curve25519 and ed25519 to provide some keys
and APIs to use for different purpose

[`ChaCha20`]: https://docs.rs/cryptoxide/0.2.1/cryptoxide/chacha20/index.html
*/

#[cfg(test)]
#[macro_use(quickcheck)]
extern crate quickcheck_macros;

pub mod key;
pub mod memsec;
pub mod noise;
mod seed;

pub use self::{
    key::{ed25519::Signature, SharedSecret},
    seed::Seed,
};
