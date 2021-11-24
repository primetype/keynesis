# KEYNESIS-NETWORK

This crate implements the network part of the Anonymous Secure Mail Transfer
Protocol (**ASMTP**). See siblings libraries for the other part of the protocol
as well as [`keynesis`].

This crates does not contain material to keep and manage multiple connections,
see `asmtpd`'s code for that. Instead here we are focusing on the low level part
of the protocol. Providing the core features such as the protocol for the
establishing handshakes (establishing a secure bidirectional connection with
forward secrecy enabled: `noise`).

## Handshake

the handshake is pretty simple, it consist of one byte of protocol version
and followed by the [IK] noise pattern handshake messages. This allows for
the initiator to open their identity only to the expected peer.

## Messages

Once the connection is established all messages in or out are encrypted with
forward secrecy. We have guarantee that the remote peer is the expected peer
and they also have means to authenticate our node.

Now we can send messages.

## Lack of multiplexing

as you can see there is no Request/Response to the messages. While it is possible to
request a peer to do something for us there is no way of knowing if the node is going
to respond to that specific request or not. If after sometimes there is no response
you might want to try again. But for now there is no multiplexing of the queries
in order to simplify the implementation of the network protocol.

There is exactly 7 message types (8 with the handshake) that goes through the network
and while there is room for up to 255 it is likely not to grow much.

## License

This project is licensed under the [MIT] **OR** [Apache-2.0] dual license.

[MIT]: https://github.com/primetype/keynesis/blob/master/keynesis-network/LICENSE-MIT
[Apache-2.0]: https://github.com/primetype/keynesis/blob/master/keynesis-network/LICENSE-APACHE

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in ASMTP by you, shall be licensed as `MIT OR Apache-2.0` dual
license, without any additional terms or conditions.

[`keynesis`]: https://github.com/primetype/keynesis