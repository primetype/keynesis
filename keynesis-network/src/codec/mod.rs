/*!
# ASMTP encryption protocol encoder/decoder

beside the handshake, all the information in the protocol are expected
to be encrypted.
*/

pub(crate) mod encryption;
pub(crate) mod handshake;

pub use self::encryption::{NoiseEncryptedDecoder, NoiseEncryptedEncoder};
