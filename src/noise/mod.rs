/*!
# Noise Protocol

This module provides some of the noise's patterns and configuration.
Currently we only support `Ed25519` for the key exchange, ChaChaPoly
for the cipher and BLAKE2b for the hash function.

We also limit to a few patterns so far (X, IX, XX, IK). There are pros and
cons to use one over the other.

See [Noise Specification] for more details about the noise protocol. And have
a look at [Noise Explorer] for the details regarding the different patterns
available here.

[Noise Specification]: http://noiseprotocol.org/noise.html
[Noise Explorer]: https://noiseexplorer.com/patterns/
*/
mod cipher_state;
mod handshake_state;
mod pattern;
mod symmetric_state;
mod transport_state;

pub(crate) use self::{
    cipher_state::CipherState, handshake_state::HandshakeState, symmetric_state::SymmetricState,
};
pub use self::{
    cipher_state::CipherStateError,
    handshake_state::HandshakeStateError,
    pattern::*,
    transport_state::{SessionId, TransportState},
};
