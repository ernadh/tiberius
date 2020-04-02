mod macros;

use super::{
    rpc::{RpcParam, RpcProcIdValue, TokenRpcRequest},
    types::{Collation, FixedLenType, Guid, Numeric, TypeInfo, VarLenType},
    BaseMetaDataColumn, ColmetaDataFlags, ColumnData, MetaDataColumn, PacketHeader, PacketStatus,
    PacketType, TokenColMetaData, TokenDone, TokenReturnValue, TokenRow, TokenType,
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

    fn read_token(&self, src: &mut BytesMut) -> crate::Result<TokenType> {
        let ty_byte = src.get_u8();

        let ty = TokenType::try_from(ty_byte)
            .map_err(|_| Error::Protocol(format!("invalid token type {:x}", ty_byte).into()))?;

        Ok(ty)
    }

    fn read_varchar(&self, src: &mut BytesMut, len: impl Into<usize>) -> crate::Result<String> {
        let len = len.into();
        let mut buf = vec![0u16; len / 2];

        for i in 0..len {
            buf[i] = src.get_u16_le();
        }

        Ok(String::from_utf16(&buf[..])?)
    }

    fn read_colmetadata_token(&self, src: &mut BytesMut) -> crate::Result<TokenColMetaData> {
        let column_count = src.get_u16_le();
        let mut columns = Vec::with_capacity(column_count as usize);

        if column_count > 0 && column_count < 0xffff {
            /*// CekTable (Column Encryption Keys)
            let cek_count = try!(self.read_u16::<LittleEndian>());
            // TODO: Cek/encryption stuff not implemented yet
            assert_eq!(cek_count, 0);*/

            // read all metadata for each column
            for _ in 0..column_count {
                let len = src.get_u8();

                let meta = MetaDataColumn {
                    base: self.read_basemetadata_column(src)?,
                    col_name: self.read_varchar(src, len)?,
                };
                columns.push(meta);
            }
        }

        Ok(TokenColMetaData { columns })
    }

    fn read_basemetadata_column(&self, src: &mut BytesMut) -> crate::Result<BaseMetaDataColumn> {
        let _user_ty = src.get_u32_le();
        let raw_flags = src.get_u16_le();
        let flags = ColmetaDataFlags::from_bits(raw_flags).unwrap();
        let ty = self.read_type_info(src)?;

        // TODO: for type={text, ntext, and image} TABLENAME

        /*// CryptoMetaData
        let cmd_ordinal = try!(self.read_u16::<LittleEndian>());
        let cmd_user_ty = try!(self.read_u32::<LittleEndian>());
        let cmd_ty_info: TypeInfo = try!(self.unserialize(ctx));
        let cmd_encryption_algo = try!(self.read_u8());
        // TODO:
        assert_eq!(cmd_encryption_algo, 0);
        let cmd_algo_name = try!(self.read_varchar::<u8>());
        let cmd_algo_type = try!(self.read_u8());
        let cmd_norm_version = try!(self.read_u8());*/

        Ok(BaseMetaDataColumn { flags, ty })
    }

    fn read_type_info(&self, src: &mut BytesMut) -> crate::Result<TypeInfo> {
        let ty = src.get_u8();

        if let Ok(ty) = FixedLenType::try_from(ty) {
            return Ok(TypeInfo::FixedLen(ty));
        }

        match VarLenType::try_from(ty) {
            Err(()) => {
                return Err(Error::Protocol(
                    format!("invalid or unsupported column type: {:?}", ty).into(),
                ))
            }
            Ok(ty) => {
                let len = match ty {
                    VarLenType::Bitn
                    | VarLenType::Intn
                    | VarLenType::Floatn
                    | VarLenType::Decimaln
                    | VarLenType::Numericn
                    | VarLenType::Guid
                    | VarLenType::Money
                    | VarLenType::Datetimen
                    | VarLenType::Timen
                    | VarLenType::Datetime2 => src.get_u8() as usize,
                    VarLenType::NChar
                    | VarLenType::NVarchar
                    | VarLenType::BigVarChar
                    | VarLenType::BigBinary => src.get_u16_le() as usize,
                    VarLenType::Daten => 3,
                    _ => unimplemented!(),
                };

                let collation = match ty {
                    VarLenType::NChar | VarLenType::NVarchar | VarLenType::BigVarChar => {
                        Some(Collation::new(src.get_u32_le(), src.get_u8()))
                    }
                    _ => None,
                };

                let vty = match ty {
                    VarLenType::Decimaln | VarLenType::Numericn => TypeInfo::VarLenSizedPrecision {
                        ty,
                        size: len,
                        precision: src.get_u8(),
                        scale: src.get_u8(),
                    },
                    _ => TypeInfo::VarLenSized(ty, len, collation),
                };

                Ok(vty)
            }
        }
    }

    fn read_row_token(&self, src: &mut BytesMut) -> crate::Result<TokenRow> {
        let col_meta = self
            .context
            .last_meta
            .lock()
            .clone()
            .ok_or(Error::Protocol("missing colmeta data".into()))?;

        let mut row = TokenRow {
            meta: col_meta.clone(),
            columns: Vec::with_capacity(col_meta.columns.len()),
        };

        for column in col_meta.columns.iter() {
            let data = self.read_column_data(&column.base, src)?;
            row.columns.push(data);
        }

        Ok(row)
    }

    fn read_column_data(
        &self,
        meta: &BaseMetaDataColumn,
        src: &mut BytesMut,
    ) -> crate::Result<ColumnData<'static>> {
        let ret = match meta.ty {
            TypeInfo::FixedLen(fixed_ty) => self.read_fixed_len_type(fixed_ty, src)?,
            TypeInfo::VarLenSized(ty, len, collation) => {
                self.read_var_len_sized(ty, len, collation, src)?
            }
            TypeInfo::VarLenSizedPrecision { ty, scale, .. } => {
                match ty {
                    // Our representation causes loss of information and is only a very approximate representation
                    // while decimal on the side of MSSQL is an exact representation
                    // TODO: better representation
                    VarLenType::Decimaln | VarLenType::Numericn => {
                        self.read_var_len_sized_precision(scale, src)?
                    }
                    _ => todo!(),
                }
            }
        };
        Ok(ret)
    }

    fn read_var_len_sized_precision(
        &self,
        scale: u8,
        src: &mut BytesMut,
    ) -> crate::Result<ColumnData<'static>> {
        fn read_d128(buf: &[u8]) -> u128 {
            let low_part = LittleEndian::read_u64(&buf[0..]) as u128;

            if !buf[8..].iter().any(|x| *x != 0) {
                return low_part;
            }

            let high_part = match buf.len() {
                12 => LittleEndian::read_u32(&buf[8..]) as u128,
                16 => LittleEndian::read_u64(&buf[8..]) as u128,
                _ => unreachable!(),
            };

            // swap high&low for big endian
            #[cfg(target_endian = "big")]
            let (low_part, high_part) = (high_part, low_part);

            let high_part = high_part * (u64::max_value() as u128 + 1);
            low_part + high_part
        }

        let len = src.get_u8();

        if len == 0 {
            Ok(ColumnData::None)
        } else {
            let sign = match src.get_u8() {
                0 => -1i128,
                1 => 1i128,
                _ => return Err(Error::Protocol("decimal: invalid sign".into())),
            };

            let value = match len {
                5 => src.get_u32_le() as i128 * sign,
                9 => src.get_u64_le() as i128 * sign,
                13 => {
                    let mut bytes = [0u8; 12]; //u96
                    for i in 0..12 {
                        bytes[i] = src.get_u8();
                    }
                    read_d128(&bytes) as i128 * sign
                }
                17 => {
                    let mut bytes = [0u8; 16]; //u96
                    for i in 0..16 {
                        bytes[i] = src.get_u8();
                    }
                    read_d128(&bytes) as i128 * sign
                }
                x => {
                    return Err(Error::Protocol(
                        format!("decimal/numeric: invalid length of {} received", x).into(),
                    ))
                }
            };

            Ok(ColumnData::Numeric(Numeric::new_with_scale(value, scale)))
        }
    }

    fn read_fixed_len_type(
        &self,
        ty: FixedLenType,
        src: &mut BytesMut,
    ) -> crate::Result<ColumnData<'static>> {
        let ret = match ty {
            FixedLenType::Null => ColumnData::None,
            FixedLenType::Bit => ColumnData::Bit(src.get_u8() != 0),
            FixedLenType::Int1 => ColumnData::I8(src.get_i8()),
            FixedLenType::Int2 => ColumnData::I16(src.get_i16_le()),
            FixedLenType::Int4 => ColumnData::I32(src.get_i32_le()),
            FixedLenType::Int8 => ColumnData::I64(src.get_i64_le()),
            FixedLenType::Float4 => ColumnData::F32(src.get_f32_le()),
            FixedLenType::Float8 => ColumnData::F64(src.get_f64_le()),
            // FixedLenType::Datetime => parse_datetimen(trans, 8)?,
            // FixedLenType::Datetime4 => parse_datetimen(trans, 4)?,
            _ => {
                return Err(Error::Protocol(
                    format!("unsupported fixed type decoding: {:?}", ty).into(),
                ))
            }
        };

        Ok(ret)
    }

    fn read_var_len_sized(
        &self,
        ty: VarLenType,
        len: usize,
        collation: Option<Collation>,
        src: &mut BytesMut,
    ) -> crate::Result<ColumnData<'static>> {
        let res = match ty {
            VarLenType::Bitn => self.read_bit(src)?,
            VarLenType::Intn => self.read_int(src)?,
            // 2.2.5.5.1.5 IEEE754
            VarLenType::Floatn => self.read_float(src)?,
            VarLenType::Guid => self.read_guid(src)?,
            VarLenType::NChar | VarLenType::NVarchar => self.read_variable_string(ty, len, src)?,
            VarLenType::BigVarChar => self.read_big_varchar(len, collation, src)?,
            VarLenType::Money => self.read_money(src)?,
            VarLenType::Datetimen => {
                /*
                let len = self.read_u8().await?;
                parse_datetimen(trans, len)?
                 */
                todo!()
            }
            VarLenType::Daten => {
                /*
                    let len = trans.inner.read_u8()?;
                    match len {
                    0 => ColumnData::None,
                    3 => {
                    let mut bytes = [0u8; 4];
                    try_ready!(trans.inner.read_bytes_to(&mut bytes[..3]));
                    ColumnData::Date(time::Date::new(LittleEndian::read_u32(&bytes)))
                }
                    _ => {
                    return Err(Error::Protocol(
                    format!("daten: length of {} is invalid", len).into(),
                ))
                }
                }
                     */
                todo!()
            }
            VarLenType::Timen => {
                /*
                let rlen = trans.inner.read_u8()?;
                ColumnData::Time(time::Time::decode(&mut *trans.inner, *len, rlen)?)
                 */
                todo!()
            }
            VarLenType::Datetime2 => {
                /*
                let rlen = trans.inner.read_u8()? - 3;
                let time = time::Time::decode(&mut *trans.inner, *len, rlen)?;
                let mut bytes = [0u8; 4];
                try_ready!(trans.inner.read_bytes_to(&mut bytes[..3]));
                let date = time::Date::new(LittleEndian::read_u32(&bytes));
                ColumnData::DateTime2(time::DateTime2(date, time))
                 */
                todo!()
            }
            VarLenType::BigBinary => self.read_binary(len, src)?,

            _ => unimplemented!(),
        };

        Ok(res)
    }

    fn read_bit(&self, src: &mut BytesMut) -> crate::Result<ColumnData<'static>> {
        let recv_len = src.get_u8() as usize;

        let res = match recv_len {
            0 => ColumnData::None,
            1 => ColumnData::Bit(src.get_u8() > 0),
            v => {
                return Err(Error::Protocol(
                    format!("bitn: length of {} is invalid", v).into(),
                ))
            }
        };

        Ok(res)
    }

    fn read_int(&self, src: &mut BytesMut) -> crate::Result<ColumnData<'static>> {
        let recv_len = src.get_u8() as usize;

        let res = match recv_len {
            0 => ColumnData::None,
            1 => ColumnData::I8(src.get_i8()),
            2 => ColumnData::I16(src.get_i16_le()),
            4 => ColumnData::I32(src.get_i32_le()),
            8 => ColumnData::I64(src.get_i64_le()),
            _ => unimplemented!(),
        };

        Ok(res)
    }

    fn read_float(&self, src: &mut BytesMut) -> crate::Result<ColumnData<'static>> {
        let len = src.get_u8() as usize;

        let res = match len {
            0 => ColumnData::None,
            4 => ColumnData::F32(src.get_f32_le()),
            8 => ColumnData::F64(src.get_f64_le()),
            _ => {
                return Err(Error::Protocol(
                    format!("floatn: length of {} is invalid", len).into(),
                ))
            }
        };

        Ok(res)
    }

    fn read_guid(&self, src: &mut BytesMut) -> crate::Result<ColumnData<'static>> {
        let len = src.get_u8() as usize;

        let res = match len {
            0 => ColumnData::None,
            16 => {
                let mut data = [0u8; 16];

                for i in 0..16 {
                    data[i] = src.get_u8();
                }

                ColumnData::Guid(Cow::Owned(Guid(data)))
            }
            _ => {
                return Err(Error::Protocol(
                    format!("guid: length of {} is invalid", len).into(),
                ))
            }
        };

        Ok(res)
    }

    fn read_variable_string(
        &self,
        ty: VarLenType,
        len: usize,
        src: &mut BytesMut,
    ) -> crate::Result<ColumnData<'static>> {
        let mode = if ty == VarLenType::NChar {
            ReadTyMode::FixedSize(len)
        } else {
            ReadTyMode::auto(len)
        };

        let data = self.read_plp_type(mode, src)?;

        let res = if let Some(buf) = data {
            if buf.len() % 2 != 0 {
                return Err(Error::Protocol("nvarchar: invalid plp length".into()));
            }

            let buf: Vec<_> = buf.chunks(2).map(LittleEndian::read_u16).collect();
            let s = String::from_utf16(&buf)?;

            ColumnData::String(s.into())
        } else {
            ColumnData::None
        };

        Ok(res)
    }

    fn read_big_varchar(
        &self,
        len: usize,
        collation: Option<Collation>,
        src: &mut BytesMut,
    ) -> crate::Result<ColumnData<'static>> {
        let mode = ReadTyMode::auto(len);
        let data = self.read_plp_type(mode, src)?;

        let res = if let Some(bytes) = data {
            let encoder = collation
                .as_ref()
                .unwrap()
                .encoding()
                .ok_or(Error::Encoding("encoding: unspported encoding".into()))?;

            let s: String = encoder
                .decode(bytes.as_ref(), DecoderTrap::Strict)
                .map_err(Error::Encoding)?;

            ColumnData::String(s.into())
        } else {
            ColumnData::None
        };

        Ok(res)
    }

    fn read_money(&self, src: &mut BytesMut) -> crate::Result<ColumnData<'static>> {
        let len = src.get_u8();

        let res = match len {
            0 => ColumnData::None,
            4 => ColumnData::F64(src.get_i32_le() as f64 / 1e4),
            8 => ColumnData::F64({
                let high = src.get_i32_le() as i64;
                let low = src.get_u32_le() as f64;
                ((high << 32) as f64 + low) / 1e4
            }),
            _ => {
                return Err(Error::Protocol(
                    format!("money: length of {} is invalid", len).into(),
                ))
            }
        };

        Ok(res)
    }

    fn read_binary(&self, len: usize, src: &mut BytesMut) -> crate::Result<ColumnData<'static>> {
        let mode = ReadTyMode::auto(len);
        let data = self.read_plp_type(mode, src)?;

        let res = if let Some(buf) = data {
            ColumnData::Binary(buf.into())
        } else {
            ColumnData::None
        };

        Ok(res)
    }

    /// read byte string with or without PLP
    pub fn read_plp_type(
        &self,
        mode: ReadTyMode,
        src: &mut BytesMut,
    ) -> crate::Result<Option<Vec<u8>>> {
        let mut read_state = ReadTyState::new(mode);

        // If we did not read anything yet, initialize the reader.
        if read_state.data.is_none() {
            let size = match read_state.mode {
                ReadTyMode::FixedSize(_) => src.get_u16_le() as u64,
                ReadTyMode::Plp => src.get_u64_le(),
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
                        ReadTyMode::Plp => src.get_u32_le() as usize,
                    };

                    if chunk_size == 0 {
                        break; // found a sentinel, we're done
                    } else {
                        read_state.chunk_data_left = chunk_size
                    }
                } else {
                    // Just read a byte
                    let byte = src.get_u8();
                    read_state.chunk_data_left -= 1;

                    buf.push(byte);
                }
            }
        }

        Ok(read_state.data.take())
    }
}

impl<'a> Decoder for RedmondCodec<'a> {
    type Item = ReceivedToken;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let _recv_token = match self.read_token(src)? {
            TokenType::ColMetaData => {
                let meta = Arc::new(self.read_colmetadata_token(src)?);
                self.context.set_last_meta(meta.clone());
                ReceivedToken::NewResultset(meta)
            }
            TokenType::Row => {
                let row = self.read_row_token(src)?;
                ReceivedToken::Row(row)
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
