use std::io;
use std::mem::MaybeUninit;
use std::pin::Pin;
use std::task::{self, Poll};

use crate::protocol;
use futures_util::ready;
use protocol::codec::{PacketHeader, PacketStatus, PacketType};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{self, debug_span, event, trace_span, Level};

pub trait TlsStream: AsyncRead + AsyncWrite + Unpin {
    type Ret: AsyncRead + AsyncWrite + Unpin;
    #[cfg(feature = "tls")]
    fn take_inner(&mut self) -> Self::Ret;
}

#[cfg(not(feature = "tls"))]
impl<X: AsyncRead + AsyncWrite + Unpin> TlsStream for X {
    type Ret = X;
}

#[cfg(feature = "tls")]
impl<S: AsyncRead + AsyncWrite + Unpin> TlsStream for tokio_tls::TlsStream<TlsPreloginWrapper<S>> {
    type Ret = S;

    fn take_inner(&mut self) -> S {
        self.get_mut().stream.take().unwrap()
    }
}

// TODO: AsyncWrite/Reads buf methods
pub enum MaybeTlsStream<T: TlsStream> {
    Raw(T::Ret),
    Tls(T),
}

impl<T: TlsStream> AsyncRead for MaybeTlsStream<T> {
    unsafe fn prepare_uninitialized_buffer(&self, buf: &mut [MaybeUninit<u8>]) -> bool {
        match self {
            MaybeTlsStream::Raw(s) => s.prepare_uninitialized_buffer(buf),
            MaybeTlsStream::Tls(s) => s.prepare_uninitialized_buffer(buf),
        }
    }

    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            MaybeTlsStream::Raw(s) => Pin::new(s).poll_read(cx, buf),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl<T: TlsStream> AsyncWrite for MaybeTlsStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut task::Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            MaybeTlsStream::Raw(s) => Pin::new(s).poll_write(cx, buf),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Raw(s) => Pin::new(s).poll_flush(cx),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Raw(s) => Pin::new(s).poll_shutdown(cx),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

pub struct TlsPreloginWrapper<S> {
    stream: Option<S>,
    pub(crate) pending_handshake: bool,

    header_buf: [u8; protocol::HEADER_BYTES],
    header_pos: usize,
    read_remaining: usize,

    wr_buf: Vec<u8>,
    header_written: bool,
}

impl<S> TlsPreloginWrapper<S> {
    pub fn new(stream: S) -> Self {
        TlsPreloginWrapper {
            stream: Some(stream),
            pending_handshake: true,

            header_buf: [0u8; protocol::HEADER_BYTES],
            header_pos: 0,
            read_remaining: 0,
            wr_buf: vec![0u8; protocol::HEADER_BYTES],
            header_written: false,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for TlsPreloginWrapper<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if !self.pending_handshake {
            return Pin::new(&mut self.stream.as_mut().unwrap()).poll_read(cx, buf);
        }

        let span = trace_span!("TlsNeg::poll_read");
        let _enter = span.enter();

        let inner = self.get_mut();
        if !inner.header_buf[inner.header_pos..].is_empty() {
            event!(Level::TRACE, "read_header");
            while !inner.header_buf[inner.header_pos..].is_empty() {
                let read = ready!(Pin::new(&mut inner.stream.as_mut().unwrap())
                    .poll_read(cx, &mut inner.header_buf[inner.header_pos..]))?;
                event!(Level::TRACE, read_header_bytes = read);
                if read == 0 {
                    return Poll::Ready(Ok(0));
                }
                inner.header_pos += read;
            }

            let header = PacketHeader::unserialize(&inner.header_buf)
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;

            assert_eq!(header.ty, PacketType::PreLogin);
            assert_eq!(header.status, PacketStatus::EndOfMessage);
            inner.read_remaining = header.length as usize - protocol::HEADER_BYTES;
            event!(Level::TRACE, packet_bytes = inner.read_remaining);
        }

        let max_read = ::std::cmp::min(inner.read_remaining, buf.len());
        let read = ready!(
            Pin::new(&mut inner.stream.as_mut().unwrap()).poll_read(cx, &mut buf[..max_read])
        )?;
        inner.read_remaining -= read;
        if inner.read_remaining == 0 {
            inner.header_pos = 0;
        }
        Poll::Ready(Ok(read))
    }
    unsafe fn prepare_uninitialized_buffer(&self, buf: &mut [MaybeUninit<u8>]) -> bool {
        for x in buf {
            *x.as_mut_ptr() = 0;
        }

        true
    }
    fn poll_read_buf<B: bytes::BufMut>(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut B,
    ) -> Poll<io::Result<usize>>
    where
        Self: Sized,
    {
        if !buf.has_remaining_mut() {
            return Poll::Ready(Ok(0));
        }

        unsafe {
            let n = {
                let b = buf.bytes_mut();

                self.prepare_uninitialized_buffer(b);

                // Convert to `&mut [u8]`
                let b = &mut *(b as *mut [MaybeUninit<u8>] as *mut [u8]);

                let n = ready!(self.poll_read(cx, b))?;
                assert!(n <= b.len(), "Bad AsyncRead implementation, more bytes were reported as read than the buffer can hold");
                n
            };

            buf.advance_mut(n);
            Poll::Ready(Ok(n))
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TlsPreloginWrapper<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if !self.pending_handshake {
            return Pin::new(&mut self.stream.as_mut().unwrap()).poll_write(cx, buf);
        }

        let span = trace_span!("TlsNeg::poll_write");
        let _enter = span.enter();
        event!(Level::TRACE, amount = buf.len());

        self.wr_buf.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context) -> Poll<io::Result<()>> {
        let inner = self.get_mut();

        if inner.pending_handshake {
            let span = trace_span!("TlsNeg::poll_flush");
            let _enter = span.enter();

            if !inner.header_written {
                event!(Level::TRACE, "prepending header to buf");
                let mut header = PacketHeader::new(inner.wr_buf.len(), 0);
                header.ty = PacketType::PreLogin;
                header.status = PacketStatus::EndOfMessage;
                header.serialize(&mut inner.wr_buf)?;
                inner.header_written = true;
            }

            while !inner.wr_buf.is_empty() {
                let written =
                    ready!(Pin::new(&mut inner.stream.as_mut().unwrap())
                        .poll_write(cx, &mut inner.wr_buf))?;
                event!(Level::TRACE, written = written);
                inner.wr_buf.drain(..written);
            }
            inner.wr_buf.resize(protocol::HEADER_BYTES, 0);
            inner.header_written = false;
            event!(Level::TRACE, "flushing underlying stream");
        }
        Pin::new(&mut inner.stream.as_mut().unwrap()).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut task::Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream.as_mut().unwrap()).poll_shutdown(cx)
    }
}
