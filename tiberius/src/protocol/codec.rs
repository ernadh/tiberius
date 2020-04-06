mod column_data;
mod decode;
mod macros;
mod token_col_metadata;
mod token_done;
mod token_row;
mod token_type;
mod type_info;

pub use column_data::*;
pub use decode::*;
pub use token_col_metadata::*;
pub use token_done::*;
pub use token_row::*;
pub use token_type::*;
pub use type_info::*;

use super::{
    rpc::{RpcParam, RpcProcIdValue, TokenRpcRequest},
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

bitflags! {
    struct RpcOptionFlags: u16 {
        const WITH_RECOMP   = 0x01;
        const NO_META       = 0x02;
        const REUSE_META    = 0x04;
        // <- 13 reserved bits
    }
}

pub(crate) fn read_varchar(src: &mut BytesMut, len: impl Into<usize>) -> crate::Result<String> {
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

impl<'a> Encoder<TokenRpcRequest<'a>> for RedmondCodec<'a> {
    type Error = Error;

    fn encode(&mut self, item: TokenRpcRequest<'a>, _dst: &mut BytesMut) -> crate::Result<()> {
        let mut buf = BytesMut::new();

        // build the general header for the packet
        let mut _header = PacketHeader {
            ty: PacketType::RPC,
            status: PacketStatus::NormalMessage,
            ..self.context.new_header(0)
        };

        self.write_trans_descriptor(&mut buf, 0)?;

        match item.proc_id {
            RpcProcIdValue::Id(ref id) => {
                let val = (0xffff as u32) | ((*id as u16) as u32) << 16;
                buf.put_u32_le(val);
            }
            RpcProcIdValue::Name(ref _name) => {
                //let (left_bytes, _) = try!(write_varchar::<u16>(&mut cursor, name, 0));
                //assert_eq!(left_bytes, 0);
                todo!()
            }
        }

        buf.put_u16_le(item.flags.bits() as u16);

        for param in item.params.into_iter() {
            self.encode(param, &mut buf)?;
        }

        todo!()
    }
}

impl<'a> Encoder<RpcParam<'a>> for RedmondCodec<'a> {
    type Error = Error;

    fn encode(&mut self, item: RpcParam<'a>, dst: &mut BytesMut) -> crate::Result<()> {
        dst.put_u8(item.name.len() as u8);

        for codepoint in item.name.encode_utf16() {
            dst.put_u16_le(codepoint);
        }

        dst.put_u8(item.flags.bits());
        self.encode(item.value, dst)?;

        Ok(())
    }
}

impl<'a> Encoder<ColumnData<'a>> for RedmondCodec<'a> {
    type Error = Error;

    fn encode(&mut self, item: ColumnData<'a>, dst: &mut BytesMut) -> crate::Result<()> {
        match item {
            ColumnData::Bit(val) => {
                let header = [&[VarLenType::Bitn as u8, 1, 1][..]].concat();

                dst.extend_from_slice(&header);
                dst.put_u8(val as u8);
            }
            ColumnData::I8(val) => {
                let header = [&[VarLenType::Intn as u8, 1, 1][..]].concat();

                dst.extend_from_slice(&header);
                dst.put_i8(val);
            }
            ColumnData::I16(val) => {
                let header = [&[VarLenType::Intn as u8, 2, 2][..]].concat();

                dst.extend_from_slice(&header);
                dst.put_i16_le(val);
            }
            ColumnData::I32(val) => {
                let header = [&[VarLenType::Intn as u8, 4, 4][..]].concat();

                dst.extend_from_slice(&header);
                dst.put_i32_le(val);
            }
            ColumnData::I64(val) => {
                let header = [&[VarLenType::Intn as u8, 8, 8][..]].concat();

                dst.extend_from_slice(&header);
                dst.put_i64_le(val);
            }
            ColumnData::F32(val) => {
                let header = [&[VarLenType::Floatn as u8, 4, 4][..]].concat();

                dst.extend_from_slice(&header);
                dst.put_f32_le(val);
            }
            ColumnData::F64(val) => {
                let header = [&[VarLenType::Floatn as u8, 8, 8][..]].concat();

                dst.extend_from_slice(&header);
                dst.put_f64_le(val);
            }
            ColumnData::String(ref s) if s.len() <= 4000 => {
                dst.put_u8(VarLenType::NVarchar as u8);
                dst.put_u16_le(8000);
                dst.extend_from_slice(&[0u8; 5][..]);
                dst.put_u16_le(2 * s.len() as u16);

                for chr in s.encode_utf16() {
                    dst.put_u16_le(chr);
                }
            }
            ColumnData::String(ref str_) => {
                // length: 0xffff and raw collation
                dst.put_u8(VarLenType::NVarchar as u8);
                dst.extend_from_slice(&[0xff as u8; 2][..]);
                dst.extend_from_slice(&[0u8; 5][..]);

                // we cannot cheaply predetermine the length of the UCS2 string beforehand
                // (2 * bytes(UTF8) is not always right) - so just let the SQL server handle it
                dst.put_u64_le(0xfffffffffffffffe as u64);

                // Write the varchar length
                let ary: Vec<_> = str_.encode_utf16().collect();
                dst.put_u32_le((ary.len() * 2) as u32);

                // And the PLP data
                for chr in ary {
                    dst.put_u16_le(chr);
                }

                // PLP_TERMINATOR
                dst.put_u32_le(0);
            }
            // TODO
            ColumnData::None => {}
            ColumnData::Guid(_) => {}
            ColumnData::Binary(_) => {}
            ColumnData::Numeric(_) => {}
        }

        Ok(())
    }
}
