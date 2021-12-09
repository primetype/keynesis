/*!
Wrapper/helpers of the ASMTP protocol on top of TCP

While it still possible to use the low level [`Handle`] for the implementation
of the protocol. The `net` module provides the necessary toolbox for an efficient
and simple to use network implementation
*/

use crate::SessionId;
use crate::{
    accept,
    handle::{Handle, HandleReadHalf, HandleWriteHalf},
};
use anyhow::{bail, Context as _, Result};
use bytes::Bytes;
use futures::prelude::*;
use keynesis_core::key::{
    ed25519::{self, PublicKey},
    Dh,
};
use rand_core::{CryptoRng, RngCore};
use std::{
    fmt::{self, Display},
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::net::{
    lookup_host,
    tcp::{OwnedReadHalf, OwnedWriteHalf},
    TcpListener, TcpStream, ToSocketAddrs,
};

/// object that will listen to inbound connections and handle incoming connections
/// accordingly.
///
/// The process of handling the data received from the peers (handling the handshake)
/// is done asynchronously so we can start a new thread to process the new peer and
/// accept new connections straight away.
///
pub struct Listener {
    listener: TcpListener,
}

/// A bidirectional, encrypted and authenticated connection with a peer
///
/// the connection can be conveniently split into its halves ([`ConnectionWriter`]
/// and [`ConnectionReader`]) for more convenient handling of that the protocol
/// may be available to write data and receive data at different time.
///
pub struct Connection {
    writer: ConnectionWriter,
    reader: ConnectionReader,
}

/// writer halve of the authenticated encrypted connection with the peer
pub struct ConnectionWriter {
    writer: HandleWriteHalf<OwnedWriteHalf>,
    peer_addr: SocketAddr,
}

/// reader halve of the authenticated encrypted connection with the peer
pub struct ConnectionReader {
    reader: HandleReadHalf<OwnedReadHalf>,
    peer_addr: SocketAddr,
}

/// object to accept incoming connection
///
/// this is split from the [`Listener`]'s [`accept`](Listener::accept) function
/// so that we can process the handshake in a separate thread/task and not block
/// other incoming connections.
///
pub struct Accepting<RNG, K = ed25519::SecretKey> {
    handle: accept::Accepting<OwnedReadHalf, OwnedWriteHalf, RNG, K>,
    peer_addr: SocketAddr,
}

impl Listener {
    /// create a new listener object
    ///
    /// will listen for incoming connection at the given [`ToSocketAddrs`] address.
    ///
    pub async fn new<A>(addr: A) -> Result<Self>
    where
        A: ToSocketAddrs + Display,
    {
        let listener = TcpListener::bind(&addr)
            .await
            .with_context(|| format!("Cannot listen to {}", addr))?;

        Ok(Self { listener })
    }

    /// start accepting a new incoming connection
    ///
    /// this function _blocks_ until a new inbound connection happens. This function
    /// does not perform any handshake verification of any sort. This will is better
    /// to run it in an different task so you can start accepting new inbound
    /// connections
    pub async fn accept<RNG, K>(&self, rng: RNG) -> Result<Accepting<RNG, K>>
    where
        RNG: CryptoRng + RngCore,
        K: Dh,
    {
        let (stream, peer_addr) = self
            .listener
            .accept()
            .await
            .context("Cannot accept new peer from the listener")?;

        let (reader, writer) = stream.into_split();

        let handle = Handle::accept(rng, reader, writer);

        Ok(Accepting { handle, peer_addr })
    }
}

impl<RNG, K> Accepting<RNG, K>
where
    RNG: CryptoRng + RngCore,
    K: Dh,
{
    /// the inbound new connection's remote address
    ///
    /// beware that this may not reflect the peer's actual address as they may be
    /// behind routers. Also this is not the same as the address that may be
    /// advertised by the peer in the gossip as they might use a different port
    /// number or a different routes for inbounds or outbound connections
    /// depending on their IT configuration.
    ///
    /// This is however available so that server implementation may decides
    /// to blacklist inbound connections coming from certain area or known
    /// IP addresses that are known to be not welcomed.
    ///
    pub fn remote_address(&self) -> SocketAddr {
        self.peer_addr
    }

    /// perform the handshake check with the inbound peer
    ///
    /// except to receive the first message of the [Noise **IK**] handshake.
    /// The [`Dh`] implemented by the remote peer must be the same as the
    /// one implemented here.
    ///
    /// [Noise **IK**]: https://noiseexplorer.com/patterns/IK/
    #[tracing::instrument(skip(k, check_id), level = "debug")]
    pub async fn handshake<F>(self, k: &K, check_id: F) -> Result<Connection>
    where
        F: Fn(&PublicKey) -> bool,
    {
        let Self { handle, peer_addr } = self;

        tracing::debug!("processing remote's handshake");

        let handle = handle
            .accept(k, check_id)
            .await
            .with_context(|| format!("Failed to handshake with {}", peer_addr))?;

        tracing::debug!(
            session_id = %handle.session_id(),
            id = %handle.remote_public_identity(),
            "handshake succeed",
        );

        let (reader, writer) = handle.split();
        let reader = ConnectionReader { reader, peer_addr };
        let writer = ConnectionWriter { writer, peer_addr };

        Ok(Connection { reader, writer })
    }
}

impl ConnectionReader {
    /// retrieve the public identity of the peer
    ///
    pub fn remote_public_identity(&self) -> &PublicKey {
        self.reader.remote_public_identity()
    }

    /// the remote peer address we are receiving messages from
    ///
    /// beware that this may not reflect the peer's actual address as they may be
    /// behind routers. Also this is not the same as the address that may be
    /// advertised by the peer in the gossip as they might use a different port
    /// number or a different routes for inbounds or outbound connections
    /// depending on their IT configuration.
    pub fn remote_address(&self) -> SocketAddr {
        self.peer_addr
    }

    /// retrieve the unique identifier of the established session
    ///
    /// this is derived from the NOISE handshake and is the same
    /// on both sides of the stream (here and for the remote).
    pub fn session_id(&self) -> &SessionId {
        self.reader.session_id()
    }
}

impl ConnectionWriter {
    /// retrieve the public identity of the peer
    ///
    pub fn remote_public_identity(&self) -> &PublicKey {
        self.writer.remote_public_identity()
    }

    /// the remote address we are sending messages to
    ///
    /// beware that this may not reflect the peer's actual address as they may be
    /// behind routers. Also this is not the same as the address that may be
    /// advertised by the peer in the gossip as they might use a different port
    /// number or a different routes for inbounds or outbound connections
    /// depending on their IT configuration.
    ///
    pub fn remote_address(&self) -> SocketAddr {
        self.peer_addr
    }

    /// retrieve the unique identifier of the established session
    ///
    /// this is derived from the NOISE handshake and is the same
    /// on both sides of the stream (here and for the remote).
    pub fn session_id(&self) -> &SessionId {
        self.writer.session_id()
    }
}

impl Connection {
    /// retrieve the public identity of the peer
    ///
    pub fn remote_public_identity(&self) -> &PublicKey {
        self.writer.remote_public_identity()
    }

    /// the remote address we are sending/receiving messages to/from
    ///
    /// beware that this may not reflect the peer's actual address as they may be
    /// behind routers. Also this is not the same as the address that may be
    /// advertised by the peer in the gossip as they might use a different port
    /// number or a different routes for inbounds or outbound connections
    /// depending on their IT configuration.
    ///
    pub fn remote_address(&self) -> SocketAddr {
        self.writer.remote_address()
    }

    /// retrieve the unique identifier of the established session
    ///
    /// this is derived from the NOISE handshake and is the same
    /// on both sides of the stream (here and for the remote).
    pub fn session_id(&self) -> &SessionId {
        self.writer.session_id()
    }

    /// connect to the given socket address, expecting the remote to identify
    /// with the [`PublicKey`] `rs`.
    ///
    /// The function will use the given `RNG` to generate an ephemeral private keys
    /// that will be used only for this connection and the given key `k` to authenticate
    /// ourself to the remote.
    ///
    #[tracing::instrument(skip(k, rng), level = "info")]
    pub async fn connect_to<RNG, K>(
        rng: RNG,
        k: &K,
        peer_addr: SocketAddr,
        rs: PublicKey,
    ) -> Result<Self>
    where
        RNG: CryptoRng + RngCore,
        K: Dh,
    {
        let stream = TcpStream::connect(peer_addr)
            .await
            .with_context(|| format!("Cannot connect to peer {}", peer_addr))?;

        let (reader, writer) = stream.into_split();

        let handle = Handle::open(rng, k, rs, reader, writer)
            .await
            .with_context(|| format!("Failed to handshake with peer {}", peer_addr))?;

        tracing::debug!(
            session_id = %handle.session_id(),
            id = %handle.remote_public_identity(),
            "handshake succeed",
        );

        let (reader, writer) = handle.split();

        let reader = ConnectionReader { reader, peer_addr };
        let writer = ConnectionWriter { writer, peer_addr };
        Ok(Self { reader, writer })
    }

    /// attempt to connect to any resolved [`lookup_host`] result of the given [`ToSocketAddrs`].
    ///
    /// The function will returns at the first successful attempt or once all the possible options
    /// have been tried and failed.
    ///
    #[tracing::instrument(skip(k, rng), level = "info")]
    pub async fn connect<RNG, K, A>(
        mut rng: RNG,
        k: &K,
        peer_addr: A,
        rs: PublicKey,
    ) -> Result<Self>
    where
        RNG: RngCore + CryptoRng,
        A: ToSocketAddrs + Display + fmt::Debug,
        K: Dh,
    {
        let peer_addrs = lookup_host(&peer_addr)
            .await
            .context("Cannot connect to remote peer address")?;

        for socket_addr in peer_addrs {
            match Self::connect_to(&mut rng, k, socket_addr, rs).await {
                Ok(connection) => return Ok(connection),
                Err(error) => {
                    tracing::info!(reason = ?error, "Failed to connect to {} with {}", peer_addr, socket_addr);
                    continue;
                }
            }
        }

        bail!("Cannot connect to {}", peer_addr)
    }

    /// split the connections into 2 parts
    ///
    /// this allows to have 2 different independent objects to read or write to/from
    /// the remote peer.
    pub fn into_parts(self) -> (ConnectionReader, ConnectionWriter) {
        let Self { reader, writer } = self;

        (reader, writer)
    }
}

impl Stream for Connection {
    type Item = Result<Bytes>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let connection = self.get_mut();
        Pin::new(&mut connection.reader).poll_next(cx)
    }
}

impl Stream for ConnectionReader {
    type Item = Result<Bytes>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let connection = self.get_mut();
        match Pin::new(&mut connection.reader).poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Err(error))) => Poll::Ready(Some(
                Err(error).context("Cannot receive message from connection"),
            )),
            Poll::Ready(Some(Ok(bytes))) => {
                let r = bytes.freeze();

                Poll::Ready(Some(Ok(r)))
            }
        }
    }
}

impl stream::FusedStream for ConnectionReader {
    fn is_terminated(&self) -> bool {
        self.reader.is_terminated()
    }
}

impl stream::FusedStream for Connection {
    fn is_terminated(&self) -> bool {
        self.reader.is_terminated()
    }
}

impl Sink<Bytes> for Connection {
    type Error = anyhow::Error;

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        let connection = self.get_mut();
        Pin::new(&mut connection.writer).start_send(item)
    }

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let connection = self.get_mut();
        Pin::new(&mut connection.writer).poll_ready(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let connection = self.get_mut();
        Pin::new(&mut connection.writer).poll_close(cx)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let connection = self.get_mut();
        Pin::new(&mut connection.writer).poll_flush(cx)
    }
}

impl Sink<Bytes> for ConnectionWriter {
    type Error = anyhow::Error;

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        let connection = self.get_mut();
        Pin::new(&mut connection.writer).start_send(item)
    }

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let connection = self.get_mut();
        Pin::new(&mut connection.writer).poll_ready(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let connection = self.get_mut();
        Pin::new(&mut connection.writer).poll_close(cx)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let connection = self.get_mut();
        Pin::new(&mut connection.writer).poll_flush(cx)
    }
}

impl<RNG, K> fmt::Debug for Accepting<RNG, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Accepting")
            .field("remote_address", &self.peer_addr)
            .finish()
    }
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("remote_address", &self.remote_address())
            .field("session", &self.session_id())
            .field("id", self.remote_public_identity())
            .finish()
    }
}
