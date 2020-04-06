mod column_data;
mod decode;
mod encode;
mod macros;
mod rpc_request;
mod token_col_metadata;
mod token_done;
mod token_row;
mod token_type;
mod type_info;

pub use column_data::*;
pub use decode::*;
pub use encode::*;
pub use rpc_request::*;
pub use token_col_metadata::*;
pub use token_done::*;
pub use token_row::*;
pub use token_type::*;
pub use type_info::*;

use super::{
    types::{Collation, Guid, Numeric},
    FeatureLevel, PacketHeader, PacketStatus, PacketType, TokenReturnValue,
};
use crate::{
    plp::{ReadTyMode, ReadTyState},
    uint_enum, Error, ReceivedToken,
};
use bitflags::bitflags;
use byteorder::{ByteOrder, LittleEndian};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use encoding::DecoderTrap;
use std::{borrow::Cow, convert::TryFrom, sync::Arc};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio_util::codec::{Decoder, Encoder};

const HEADER_BYTES: usize = 8;
const ALL_HEADERS_LEN_TX: usize = 22;

#[derive(Debug)]
#[repr(u16)]
enum AllHeaderTy {
    QueryDescriptor = 1,
    TransactionDescriptor = 2,
    TraceActivity = 3,
}

pub struct BytesData<'a, C> {
    src: &'a mut BytesMut,
    context: &'a C,
}

impl<'a, C> BytesData<'a, C> {
    pub fn new(src: &'a mut BytesMut, context: &'a C) -> Self {
        Self { src, context }
    }

    pub fn inner(&mut self) -> &mut BytesMut {
        self.src
    }

    pub fn context(&self) -> &'a C {
        self.context
    }
}

pub(crate) fn read_varchar<B: Buf>(src: &mut B, len: impl Into<usize>) -> crate::Result<String> {
    let len = len.into();
    let mut buf = vec![0u16; len / 2];

    for i in 0..len {
        buf[i] = src.get_u16_le();
    }

    Ok(String::from_utf16(&buf[..])?)
}

pub struct RedmondCodec<'a> {
    context: &'a crate::protocol::Context,
}

impl<'a> RedmondCodec<'a> {
    pub fn new(context: &'a crate::protocol::Context) -> Self {
        Self { context }
    }

    pub fn write_header(&self, item: PacketHeader, mut dst: &mut [u8]) {
        dst.put_u8(item.ty as u8);
        dst.put_u8(item.status as u8);
        dst.put_u16(item.length);
        dst.put_u16(item.spid);
        dst.put_u8(item.id);
        dst.put_u8(item.window);
    }

    fn write_trans_descriptor(&self, dst: &mut BytesMut, id: u64) -> crate::Result<()> {
        dst.reserve(22);
        dst.put_u32_le(ALL_HEADERS_LEN_TX as u32);
        dst.put_u32_le(ALL_HEADERS_LEN_TX as u32 - 4);
        dst.put_u16_le(AllHeaderTy::TransactionDescriptor as u16);

        // transaction descriptor
        dst.put_u64_le(id);

        // outstanding requests
        dst.put_u32_le(1);

        Ok(())
    }
}

impl<'a> Decoder for RedmondCodec<'a> {
    type Item = ReceivedToken;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let _recv_token = match TokenType::decode(src)? {
            TokenType::ColMetaData => {
                let meta = Arc::new(TokenColMetaData::decode(src)?);
                self.context.set_last_meta(meta.clone());

                ReceivedToken::NewResultset(meta)
            }
            TokenType::Row => {
                let mut src = BytesData::new(src, self.context);
                ReceivedToken::Row(TokenRow::decode(&mut src)?)
            }
            TokenType::Done | TokenType::DoneInProc => {
                let mut src = BytesData::new(src, self.context);
                ReceivedToken::Done(TokenDone::decode(&mut src)?)
            }
            _ => todo!(),
        };

        todo!()
    }
}

impl<'a> Encoder<Bytes> for RedmondCodec<'a> {
    type Error = Error;

    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> crate::Result<()> {
        dst.extend_from_slice(&item);
        Ok(())
    }
}
