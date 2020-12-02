/*!
# Noise Handshake patterns

Here are implemented a few of the handshakes available from the noise protocol.
The naming convention of these patterns matches the one defined in the
[Noise Specification].

all of these handshakes expect the participants to authenticate. This means that
We should always be able to authenticate messages between the participants.

Each of these handshakes comes with pros and cons. Before using any of these you
should look at the [Noise Explorer] to understand the signification of the handshakes
how you can leverage that.

[Noise Specification]: http://noiseprotocol.org/noise.html
[Noise Explorer]: https://noiseexplorer.com/patterns/
*/
pub mod ik;
pub mod ix;
pub mod x;
pub mod xx;

pub use self::{ik::IK, ix::IX, x::X, xx::XX};
