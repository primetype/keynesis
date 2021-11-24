use crate::{
    codec::{NoiseEncryptedDecoder, NoiseEncryptedEncoder},
    opening::Opening,
    Accepting, SessionId,
};
use anyhow::{Context as _, Result};
use bytes::{Bytes, BytesMut};
use futures::{prelude::*, stream::FusedStream as _};
use keynesis_core::{
    hash::Blake2b,
    key::{ed25519::PublicKey, Dh},
    noise::{TransportReceiveHalf, TransportSendHalf, TransportState},
};
use rand_core::{CryptoRng, RngCore};
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{FramedRead, FramedWrite};

/// bidirectional handle of an encrypted connection
///
/// The [`Handle`] is composed of 2 halves that can be split for more convenient
/// management of the ins and outs of the connections.
///
/// see [`Handle::split`] for more information
pub struct Handle<I, O> {
    stream: HandleReadHalf<I>,
    sink: HandleWriteHalf<O>,
}

/// the reading half of the encrypted connection
///
/// see [`Handle::split`] for more information
pub struct HandleReadHalf<I> {
    none: bool,
    stream: FramedRead<I, NoiseEncryptedDecoder>,
}

/// the writing half of the encrypted connection
///
/// see [`Handle::split`] for more information
pub struct HandleWriteHalf<O> {
    sink: FramedWrite<O, NoiseEncryptedEncoder>,
}

impl<I> HandleReadHalf<I>
where
    I: AsyncRead,
{
    fn new(stream: I, state: TransportReceiveHalf<Blake2b>) -> Self {
        let stream = FramedRead::new(stream, NoiseEncryptedDecoder::new(state));
        let none = false;

        Self { stream, none }
    }

    /// retrieve the public identity of the peer
    ///
    pub fn remote_public_identity(&self) -> &PublicKey {
        self.stream.decoder().remote_public_identity()
    }

    /// retrieve the unique identifier of the established session
    ///
    /// this is derived from the NOISE handshake and is the same
    /// on both sides of the stream (here and for the remote).
    pub fn session_id(&self) -> &SessionId {
        self.stream.decoder().session_id()
    }
}

impl<O> HandleWriteHalf<O>
where
    O: AsyncWrite,
{
    fn new(stream: O, state: TransportSendHalf<Blake2b>) -> Self {
        let sink = FramedWrite::new(stream, NoiseEncryptedEncoder::new(state));

        Self { sink }
    }

    /// retrieve the public identity of the peer
    ///
    pub fn remote_public_identity(&self) -> &PublicKey {
        self.sink.encoder().remote_public_identity()
    }

    /// retrieve the unique identifier of the established session
    ///
    /// this is derived from the NOISE handshake and is the same
    /// on both sides of the stream (here and for the remote).
    pub fn session_id(&self) -> &SessionId {
        self.sink.encoder().session_id()
    }
}

impl<I, O> Handle<I, O>
where
    I: AsyncRead + Unpin,
    O: AsyncWrite + Unpin,
{
    pub(crate) fn new(stream: I, sink: O, state: TransportState<Blake2b>) -> Self {
        let (tsh, trh) = state.split();

        let stream = HandleReadHalf::new(stream, trh);
        let sink = HandleWriteHalf::new(sink, tsh);

        Self { stream, sink }
    }

    /// split the handle into 2 parts into 2 separate half
    ///
    /// One will contains the writing half and the other one the reading half. This is
    /// because the connection is bidirectional/duplex so it is more convenient to handle
    /// the protocol if the 2 halves are split. However, if you are only using the
    /// synchronous you can keep the [`Handle`] as it is.
    pub fn split(self) -> (HandleReadHalf<I>, HandleWriteHalf<O>) {
        (self.stream, self.sink)
    }

    /// prepare accepting the new request from the given stream
    ///
    pub fn accept<K, RNG>(rng: RNG, reader: I, writer: O) -> Accepting<I, O, RNG, K>
    where
        K: Dh,
        RNG: RngCore + CryptoRng,
    {
        Accepting::new(rng, reader, writer)
    }

    /// open a new stream with the remote peer connected to the `stream` and
    /// expecting the remote's public identity `rs`.
    ///
    /// In order to open the connection, the remote peer will need to
    /// verify our identity, so we needs the private key associated
    /// to our identity (`K`).
    ///
    /// We will generate an ephemeral key, the `rng` will do that at the appropriate
    /// time.
    ///
    pub async fn open<K, RNG>(rng: RNG, k: &K, rs: PublicKey, reader: I, writer: O) -> Result<Self>
    where
        K: Dh,
        RNG: RngCore + CryptoRng,
    {
        let opening = Opening::new(rng, k, rs, reader, writer).await?;
        opening.wait(k).await
    }

    /// retrieve the public identity of the peer
    ///
    #[allow(dead_code)]
    pub fn remote_public_identity(&self) -> &PublicKey {
        self.stream.remote_public_identity()
    }

    /// retrieve the unique identifier of the established session
    ///
    /// this is derived from the NOISE handshake and is the same
    /// on both sides of the stream (here and for the remote).
    pub fn session_id(&self) -> &SessionId {
        self.stream.session_id()
    }
}

impl<I, O> Stream for Handle<I, O>
where
    I: AsyncRead + Unpin,
    O: Unpin,
{
    type Item = Result<BytesMut>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let handle = self.get_mut();
        let stream = Pin::new(&mut handle.stream);
        stream.poll_next(cx)
    }
}

impl<I> Stream for HandleReadHalf<I>
where
    I: AsyncRead + Unpin,
{
    type Item = Result<BytesMut>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.is_terminated() {
            return Poll::Ready(None);
        }

        let handle = self.get_mut();
        let stream = Pin::new(&mut handle.stream);

        match futures::ready!(stream.poll_next(cx)) {
            None => {
                handle.none = true;
                Poll::Ready(None)
            }
            Some(result) => Poll::Ready(Some(result.context("Invalid frame received from peer"))),
        }
    }
}

impl<I> stream::FusedStream for HandleReadHalf<I>
where
    I: AsyncRead + Unpin,
{
    fn is_terminated(&self) -> bool {
        self.none
    }
}

impl<I, O> stream::FusedStream for Handle<I, O>
where
    I: AsyncRead + Unpin,
    O: Unpin,
{
    fn is_terminated(&self) -> bool {
        self.stream.is_terminated()
    }
}

impl<I, O> Sink<Bytes> for Handle<I, O>
where
    I: Unpin,
    O: AsyncWrite + Unpin,
{
    type Error = anyhow::Error;

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        let handle = self.get_mut();
        Pin::new(&mut handle.sink).start_send(item)
    }

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let handle = self.get_mut();
        Pin::new(&mut handle.sink).poll_ready(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let handle = self.get_mut();
        Pin::new(&mut handle.sink).poll_close(cx)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let handle = self.get_mut();
        Pin::new(&mut handle.sink).poll_flush(cx)
    }
}

impl<O> Sink<Bytes> for HandleWriteHalf<O>
where
    O: AsyncWrite + Unpin,
{
    type Error = anyhow::Error;

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        let handle = self.get_mut();

        Pin::new(&mut handle.sink)
            .start_send(item)
            .context("Cannot send the encrypted data to the handle")?;

        Ok(())
    }

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let handle = self.get_mut();
        match Pin::new(&mut handle.sink).poll_ready(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => Poll::Ready(result.context("Cannot poll_ready the handle")),
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let handle = self.get_mut();
        match Pin::new(&mut handle.sink).poll_close(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => Poll::Ready(result.context("Cannot poll_close the handle")),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let handle = self.get_mut();
        match Pin::new(&mut handle.sink).poll_flush(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => Poll::Ready(result.context("Cannot poll_flush the handle")),
        }
    }
}
