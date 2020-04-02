use super::{codec::RedmondCodec, Context, PacketHeader, PacketStatus};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::sink::{Sink, SinkExt};
use std::sync::atomic::Ordering;
use tokio_util::codec::Encoder;

const HEADER_BYTES: usize = 8;
const ALL_HEADERS_LEN_TX: usize = 22;

pub struct PacketWriter<'a, S> {
    sink: &'a mut S,
    codec: RedmondCodec<'a>,
    header_template: PacketHeader,
    buf: BytesMut,
    packet_size: usize,
}

impl<'a, S> PacketWriter<'a, S>
where
    S: Sink<Bytes, Error = crate::Error> + Unpin,
{
    pub fn new(sink: &'a mut S, context: &'a Context, header_template: PacketHeader) -> Self {
        let packet_size = context.packet_size.load(Ordering::SeqCst) as usize;
        let codec = RedmondCodec::new(context);

        let mut buf = BytesMut::with_capacity(packet_size);
        buf.extend_from_slice(&[0u8; HEADER_BYTES]);

        Self {
            sink,
            codec,
            header_template,
            buf,
            packet_size,
        }
    }

    pub async fn write_bytes(&mut self, mut buf: &[u8]) -> crate::Result<()> {
        while !buf.is_empty() {
            let free_buf_space = self.packet_size - self.buf.len();
            let writable = std::cmp::min(buf.len(), free_buf_space);
            self.buf.extend_from_slice(&buf[..writable]);

            buf = &buf[writable..];

            // If we overlap into a next packet, flush it out
            if !buf.is_empty() {
                self.flush_packet().await?;
            }
        }

        Ok(())
    }

    pub async fn flush_packet(&mut self) -> crate::Result<()> {
        self.header_template.length = self.buf.len() as u16;

        self.codec
            .write_header(self.header_template, &mut self.buf[..HEADER_BYTES]);

        self.sink.send(self.buf.to_bytes()).await?;
        self.buf.truncate(HEADER_BYTES);

        Ok(())
    }

    pub async fn finish(mut self) -> crate::Result<()> {
        self.header_template.status = PacketStatus::EndOfMessage;
        self.flush_packet().await?;
        self.sink.flush().await?;

        Ok(())
    }
}
