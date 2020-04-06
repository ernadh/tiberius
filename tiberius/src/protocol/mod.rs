pub mod codec;
mod login;
mod tokenstream;
mod types;
mod writer;

pub use login::{LoginMessage, PreloginMessage};
pub use tokenstream::*;
pub mod rpc;

use bitflags::bitflags;
use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use codec::*;
use std::{
    borrow::Cow,
    convert::TryFrom,
    io::{self, Cursor, Write},
    sync::atomic::{AtomicU32, AtomicU8, Ordering},
    sync::Arc,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::Mutex,
};
use tracing::{event, Level};

use crate::{
    plp::{ReadTyMode, ReadTyState},
    Error, Result,
};

macro_rules! uint_enum {
    ($( #[$gattr:meta] )* pub enum $ty:ident { $( $( #[$attr:meta] )* $variant:ident = $val:expr,)* }) => {
        uint_enum!($( #[$gattr ])* (pub) enum $ty { $( $( #[$attr] )* $variant = $val, )* });
    };
    ($( #[$gattr:meta] )* enum $ty:ident { $( $( #[$attr:meta] )* $variant:ident = $val:expr,)* }) => {
        uint_enum!($( #[$gattr ])* () enum $ty { $( $( #[$attr] )* $variant = $val, )* });
    };

    ($( #[$gattr:meta] )* ( $($vis:tt)* ) enum $ty:ident { $( $( #[$attr:meta] )* $variant:ident = $val:expr,)* }) => {
        #[derive(Debug, Copy, Clone, PartialEq)]
        $( #[$gattr] )*
        $( $vis )* enum $ty {
            $( $( #[$attr ])* $variant = $val, )*
        }

        impl ::std::convert::TryFrom<u8> for $ty {
            type Error = ();
            fn try_from(n: u8) -> ::std::result::Result<$ty, ()> {
                match n {
                    $( x if x == $ty::$variant as u8 => Ok($ty::$variant), )*
                    _ => Err(()),
                }
            }
        }

        impl ::std::convert::TryFrom<u32> for $ty {
            type Error = ();
            fn try_from(n: u32) -> ::std::result::Result<$ty, ()> {
                match n {
                    $( x if x == $ty::$variant as u32 => Ok($ty::$variant), )*
                    _ => Err(()),
                }
            }
        }
    }
}

uint_enum! {
    #[repr(u32)]
    #[derive(PartialOrd)]
    pub enum FeatureLevel {
        SqlServerV7 = 0x70000000,
        SqlServer2000 = 0x71000000,
        SqlServer2000Sp1 = 0x71000001,
        SqlServer2005 = 0x72090002,
        SqlServer2008 = 0x730A0003,
        SqlServer2008R2 = 0x730B0003,
        /// 2012, 2014, 2016
        SqlServerN = 0x74000004,
    }
}

impl FeatureLevel {
    pub fn done_row_count_bytes(self) -> u8 {
        if self as u8 >= FeatureLevel::SqlServer2005 as u8 {
            8
        } else {
            4
        }
    }
}

uint_enum! {
    /// The configured encryption level specifying if encryption is required
    #[repr(u8)]
    pub enum EncryptionLevel {
        /// Only use encryption for the login procedure
        Off = 0,
        /// Encrypt everything if possible
        On = 1,
        /// Do not encrypt anything
        NotSupported = 2,
        /// Encrypt everything and fail if not possible
        Required = 3,
    }
}

/// Context, that might be required to make sure we understand and are understood by the server
pub struct Context {
    pub version: FeatureLevel,
    pub packet_size: AtomicU32,
    pub packet_id: AtomicU8,
    pub last_meta: parking_lot::Mutex<Option<Arc<TokenColMetaData>>>,
}

impl Context {
    pub fn new() -> Context {
        Context {
            version: FeatureLevel::SqlServerN,
            packet_size: AtomicU32::new(4096),
            packet_id: AtomicU8::new(0),
            last_meta: parking_lot::Mutex::new(None),
        }
    }

    pub fn new_header(&self, length: usize) -> PacketHeader {
        PacketHeader::new(length, self.packet_id.fetch_add(1, Ordering::SeqCst))
    }

    pub fn set_last_meta(&self, meta: Arc<TokenColMetaData>) {
        *self.last_meta.lock() = Some(meta);
    }
}

/// The amount of bytes a packet header consists of
pub const HEADER_BYTES: usize = 8;
pub const ALL_HEADERS_LEN_TX: usize = 22;

uint_enum! {
    /// the type of the packet [2.2.3.1.1]#[repr(u32)]
    #[repr(u8)]
    pub enum PacketType {
        SQLBatch = 1,
        /// unused
        PreTDSv7Login = 2,
        RPC = 3,
        TabularResult = 4,
        AttentionSignal = 6,
        BulkLoad = 7,
        /// Federated Authentication Token
        Fat = 8,
        TransactionManagerReq = 14,
        TDSv7Login = 16,
        SSPI = 17,
        PreLogin = 18,
    }
}

uint_enum! {
    /// the message state [2.2.3.1.2]
    #[repr(u8)]
    pub enum PacketStatus {
        NormalMessage = 0,
        EndOfMessage = 1,
        /// [client to server ONLY] (EndOfMessage also required)
        IgnoreEvent = 3,
        /// [client to server ONLY] [>= TDSv7.1]
        ResetConnection = 0x08,
        /// [client to server ONLY] [>= TDSv7.3]
        ResetConnectionSkipTran = 0x10,
    }
}

/// packet header consisting of 8 bytes [2.2.3.1]
#[derive(Debug, Clone, Copy)]
pub struct PacketHeader {
    pub ty: PacketType,
    pub status: PacketStatus,
    /// [BE] the length of the packet (including the 8 header bytes)
    /// must match the negotiated size sending from client to server [since TDSv7.3] after login
    /// (only if not EndOfMessage)
    pub length: u16,
    /// [BE] the process ID on the server, for debugging purposes only
    pub spid: u16,
    /// packet id
    pub id: u8,
    /// currently unused
    pub window: u8,
}

impl PacketHeader {
    pub fn new(length: usize, id: u8) -> PacketHeader {
        assert!(length <= u16::max_value() as usize);
        PacketHeader {
            ty: PacketType::TDSv7Login,
            status: PacketStatus::ResetConnection,
            length: length as u16,
            spid: 0,
            id: id,
            window: 0,
        }
    }

    pub fn serialize(&self, target: &mut [u8]) -> io::Result<()> {
        let mut writer = Cursor::new(target);
        writer.write_u8(self.ty as u8)?;
        writer.write_u8(self.status as u8)?;
        writer.write_u16::<BigEndian>(self.length)?;
        writer.write_u16::<BigEndian>(self.spid)?;
        writer.write_u8(self.id)?;
        writer.write_u8(self.window)
    }

    pub fn unserialize(buf: &[u8]) -> Result<PacketHeader> {
        let mut cursor = Cursor::new(buf);

        let raw_ty = cursor.read_u8()?;
        let ty = PacketType::try_from(raw_ty).map_err(|_| {
            Error::Protocol(format!("header: invalid packet type: {}", raw_ty).into())
        })?;

        let status = PacketStatus::try_from(cursor.read_u8()?)
            .map_err(|_| Error::Protocol("header: invalid packet status".into()))?;

        let header = PacketHeader {
            ty,
            status,
            length: cursor.read_u16::<BigEndian>()?,
            spid: cursor.read_u16::<BigEndian>()?,
            id: cursor.read_u8()?,
            window: cursor.read_u8()?,
        };

        Ok(header)
    }
}

#[derive(Debug)]
pub enum ReadState {
    Generic(TokenType, Option<usize>),
    Row(TokenType, Vec<ColumnData<'static>>, Option<ReadTyState>),
    Type(ReadTyState),
}

pub struct PacketReader<'a, C: AsyncRead> {
    conn: &'a mut C,
    /// packet contents (without headers)
    buf: Vec<u8>,
    pos: usize,
    done: bool,
    state_tracked: bool,
}

impl<'a, C: AsyncRead + Unpin> PacketReader<'a, C> {
    pub fn new(conn: &'a mut C) -> Self {
        PacketReader {
            conn,
            buf: vec![],
            pos: 0,
            done: false,
            state_tracked: false,
        }
    }

    pub(crate) fn remaining_buf(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    pub async fn read_header(&mut self) -> Result<PacketHeader> {
        use tokio::io::AsyncReadExt;

        // tokens can only span across packets within the same stream (no EndOfMessage in between)
        // so we are done with all tokens that came before if this is the case
        if self.done {
            self.done = false;
            self.buf.clear();
            self.pos = 0;
        }
        let mut header_buf = vec![0u8; HEADER_BYTES];
        let read_bytes = self.conn.read_exact(&mut header_buf).await?;
        event!(Level::TRACE, read_bytes);
        let header = PacketHeader::unserialize(&header_buf)?;
        Ok(header)
    }

    pub async fn read_packet(&mut self) -> Result<PacketHeader> {
        let header = self.read_header().await?;
        self.read_packet_with_header(&header).await?;
        Ok(header)
    }

    pub async fn read_packet_with_header(&mut self, header: &PacketHeader) -> Result<()> {
        use tokio::io::AsyncReadExt;

        let pos = self.buf.len();
        self.buf
            .resize(pos + header.length as usize - HEADER_BYTES, 0);
        let read_bytes = self.conn.read_exact(&mut self.buf[pos..]).await?;
        event!(Level::TRACE, read_bytes);
        if header.status == PacketStatus::EndOfMessage {
            self.done = true;
        }
        Ok(())
    }

    pub async fn read_bytes(&mut self, n: usize) -> Result<&[u8]> {
        // TODO: optimize allocations?
        while self.buf[self.pos..].len() < n {
            self.read_packet().await?;
        }
        let ret = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(ret)
    }

    pub async fn read_u8(&mut self) -> Result<u8> {
        Ok(self.read_bytes(1).await?[0])
    }

    pub async fn read_i8(&mut self) -> Result<i8> {
        Ok(self.read_u8().await? as i8)
    }

    /// read byte string with or without PLP
    pub async fn read_plp_type(&mut self, mode: ReadTyMode) -> crate::Result<Option<Vec<u8>>> {
        let mut read_state = ReadTyState::new(mode);

        // If we did not read anything yet, initialize the reader.
        if read_state.data.is_none() {
            let size = match read_state.mode {
                ReadTyMode::FixedSize(_) => self.read_u16::<LittleEndian>().await? as u64,
                ReadTyMode::Plp => self.read_u64::<LittleEndian>().await?,
            };

            read_state.data = match (size, read_state.mode) {
                (0xffff, ReadTyMode::FixedSize(_)) => None, // NULL value
                (0xffffffffffffffff, ReadTyMode::Plp) => None, // NULL value
                (0xfffffffffffffffe, ReadTyMode::Plp) => Some(Vec::new()), // unknown size
                (len, _) => Some(Vec::with_capacity(len as usize)), // given size
            };

            // If this is not PLP, treat everything as a single chunk.
            if let ReadTyMode::FixedSize(_) = read_state.mode {
                read_state.chunk_data_left = size as usize;
            }
        }

        // If there is a buffer, we have something to read.
        if let Some(ref mut buf) = read_state.data {
            loop {
                if read_state.chunk_data_left == 0 {
                    // We have no chunk. Start a new one.
                    let chunk_size = match read_state.mode {
                        ReadTyMode::FixedSize(_) => 0,
                        ReadTyMode::Plp => self.read_u32::<LittleEndian>().await? as usize,
                    };

                    if chunk_size == 0 {
                        break; // found a sentinel, we're done
                    } else {
                        read_state.chunk_data_left = chunk_size
                    }
                } else {
                    // Just read a byte
                    let byte = self.read_u8().await?;
                    read_state.chunk_data_left -= 1;

                    buf.push(byte);
                }
            }
        }

        Ok(read_state.data.take())
    }
}

macro_rules! read_byteorder_impl {
    ( $( $name:ident, $ty:ty ),* ) => {
        impl<'a, C: AsyncRead + Unpin> PacketReader<'a, C> {
            $(
                pub async fn $name<B: byteorder::ByteOrder>(&mut self) -> Result<$ty> {
                    Ok(self.read_bytes(::std::mem::size_of::<$ty>()).await?.$name::<B>()?)
                }
            )*
        }
    }
}
read_byteorder_impl!(
    read_u32, u32, read_i32, i32, read_u16, u16, read_i16, i16, read_f32, f32, read_f64, f64,
    read_i64, i64, read_u64, u64
);

pub struct PacketWriter<'a, C: AsyncWrite> {
    pub(crate) conn: &'a mut C,
    header_template: PacketHeader,
    buf: Vec<u8>,
}

impl<'a, C: AsyncWrite + Unpin> PacketWriter<'a, C> {
    pub fn new(conn: &'a mut C, header_template: PacketHeader) -> Self {
        PacketWriter {
            conn,
            header_template,
            buf: vec![0u8; HEADER_BYTES],
        }
    }

    pub async fn write_bytes(&mut self, ctx: &Context, mut buf: &[u8]) -> Result<()> {
        let packet_size = ctx.packet_size.load(Ordering::SeqCst) as usize;

        while !buf.is_empty() {
            let free_buf_space = packet_size - self.buf.len();
            let writable = std::cmp::min(buf.len(), free_buf_space);
            self.buf.extend_from_slice(&buf[..writable]);

            buf = &buf[writable..];

            // If we overlap into a next packet, flush it out
            if !buf.is_empty() {
                self.flush_packet(ctx).await?;
            }
        }

        Ok(())
    }

    pub async fn flush_packet(&mut self, _ctx: &Context) -> Result<()> {
        use tokio::io::AsyncWriteExt;

        self.header_template.length = self.buf.len() as u16;
        self.header_template
            .serialize(&mut self.buf[..HEADER_BYTES])?;
        event!(Level::TRACE, write_bytes = self.buf.len());
        self.conn.write_all(&self.buf).await?;
        self.buf.truncate(HEADER_BYTES);
        Ok(())
    }

    pub async fn finish(mut self, ctx: &Context) -> Result<()> {
        use tokio::io::AsyncWriteExt;

        self.header_template.status = PacketStatus::EndOfMessage;
        self.flush_packet(ctx).await?;
        event!(Level::TRACE, "flush");
        self.conn.flush().await?;
        Ok(())
    }
}

#[derive(Debug)]
#[repr(u16)]
enum AllHeaderTy {
    QueryDescriptor = 1,
    TransactionDescriptor = 2,
    TraceActivity = 3,
}

pub async fn write_trans_descriptor<C: AsyncWrite + Unpin>(
    w: &mut PacketWriter<'_, C>,
    ctx: &Context,
    id: u64, // TODO: move into context
) -> Result<()> {
    let mut buf = [0u8; 22];
    let mut cursor = Cursor::new(&mut buf[..]);
    cursor.write_u32::<LittleEndian>(ALL_HEADERS_LEN_TX as u32)?;
    cursor.write_u32::<LittleEndian>(ALL_HEADERS_LEN_TX as u32 - 4)?;
    cursor.write_u16::<LittleEndian>(AllHeaderTy::TransactionDescriptor as u16)?;
    // transaction descriptor
    cursor.write_u64::<LittleEndian>(id)?;
    // outstanding requests (TransactionDescrHeader)
    cursor.write_u32::<LittleEndian>(1)?;

    w.write_bytes(ctx, &buf).await?;
    Ok(())
}
