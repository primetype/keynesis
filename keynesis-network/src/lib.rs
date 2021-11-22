/*!
# ASMTP network protocol

this crate implements the Anonymous and Secure Mail Transfer Protocol (ASMTP).
The protocol is rather simple:

1. 2 peers perform a handshake including the version and a [Noise Protocol IK] handshake
   allowing to authenticate each other and to establish a secure communication between
   the 2 nodes.
2. Once the connection is established, all messages are encrypted and authenticated.
   After each messages the key is being rotated (see Noise's transport state _rekey_
   function).
3. Only 2 types of messages are allowed to transport between the nodes:
   a. [`Gossip`] which are information about other peers in the network and their
      subscriptions (see [`poldercast`])
   b. [`Topic`] based message: messages that are associated with a 32bytes topic
      code.

This crates only implements the network part of ASMTP.

## ASMTP and Poldercast

[`poldercast`] is a Pub/Sub protocol that allows to build a topology of peers
based on their topic preferences (their subscriptions).

ASMTP will use the [`Topic`] to relay messages to the appropriate peers.

[Noise Protocol IK]: https://noiseexplorer.com/patterns/IK/
[`Gossip`]: poldercast::Gossip
[`Topic`]: poldercast::Topic
[`poldercast`]: poldercast

*/

mod accept;
mod codec;
mod handle;
pub mod net;
mod opening;
mod session_id;
mod version;

pub use self::{accept::Accepting, handle::Handle, session_id::SessionId, version::Version};
