mod numeric;

pub use numeric::Numeric;

use crate::{collation, plp::ReadTyMode, protocol, uint_enum, Error, Result};
use byteorder::{ByteOrder, LittleEndian, ReadBytesExt};
use encoding::{DecoderTrap, Encoding};
use protocol::codec::*;
use std::{borrow::Cow, convert::TryFrom};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufWriter};

#[derive(Debug, Clone, Copy)]
pub struct Collation {
    /// LCID ColFlags Version
    info: u32,
    /// Sortid
    sort_id: u8,
}

impl Collation {
    pub fn new(info: u32, sort_id: u8) -> Self {
        Self { info, sort_id }
    }

    /// return the locale id part of the LCID (the specification here uses ambiguous terms)
    pub fn lcid(&self) -> u16 {
        (self.info & 0xffff) as u16
    }

    /// return an encoding for a given collation
    pub fn encoding(&self) -> Option<&'static dyn Encoding> {
        if self.sort_id == 0 {
            collation::lcid_to_encoding(self.lcid())
        } else {
            collation::sortid_to_encoding(self.sort_id)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Guid(pub(crate) [u8; 16]);

impl Guid {
    pub fn from_bytes(input_bytes: &[u8]) -> Guid {
        assert_eq!(input_bytes.len(), 16);
        let mut bytes = [0u8; 16];
        bytes.clone_from_slice(input_bytes);
        Guid(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl<'a, C: AsyncRead + Unpin> protocol::PacketReader<'a, C> {
    pub async fn read_type_info(&mut self, _ctx: &protocol::Context) -> Result<TypeInfo> {
        let ty = self.read_u8().await?;

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
                    | VarLenType::Datetime2 => self.read_u8().await? as usize,
                    VarLenType::NChar
                    | VarLenType::NVarchar
                    | VarLenType::BigVarChar
                    | VarLenType::BigBinary => self.read_u16::<LittleEndian>().await? as usize,
                    VarLenType::Daten => 3,
                    _ => unimplemented!(),
                };

                let collation = match ty {
                    VarLenType::NChar | VarLenType::NVarchar | VarLenType::BigVarChar => {
                        Some(Collation {
                            info: self.read_u32::<LittleEndian>().await?,
                            sort_id: self.read_u8().await?,
                        })
                    }
                    _ => None,
                };

                let vty = match ty {
                    VarLenType::Decimaln | VarLenType::Numericn => TypeInfo::VarLenSizedPrecision {
                        ty,
                        size: len,
                        precision: self.read_u8().await?,
                        scale: self.read_u8().await?,
                    },
                    _ => TypeInfo::VarLenSized(ty, len, collation),
                };

                Ok(vty)
            }
        }
    }

    pub async fn read_column_data(
        &mut self,
        ctx: &protocol::Context,
        meta: &BaseMetaDataColumn,
    ) -> Result<ColumnData<'static>> {
        let ret = match meta.ty {
            TypeInfo::FixedLen(ref fixed_ty) => self.read_fixed_len_type(&ctx, *fixed_ty).await?,
            TypeInfo::VarLenSized(ty, len, collation) => {
                self.read_var_len_sized(&ctx, ty, len, collation).await?
            }
            TypeInfo::VarLenSizedPrecision {
                ref ty, ref scale, ..
            } => {
                match *ty {
                    // Our representation causes loss of information and is only a very approximate representation
                    // while decimal on the side of MSSQL is an exact representation
                    // TODO: better representation
                    VarLenType::Decimaln | VarLenType::Numericn => {
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

                        let len = self.read_u8().await?;

                        if len == 0 {
                            ColumnData::None
                        } else {
                            let sign = match self.read_u8().await? {
                                0 => -1i128,
                                1 => 1i128,
                                _ => return Err(Error::Protocol("decimal: invalid sign".into())),
                            };

                            let value = match len {
                                5 => self.read_u32::<LittleEndian>().await? as i128 * sign,
                                9 => self.read_u64::<LittleEndian>().await? as i128 * sign,
                                13 => {
                                    let mut bytes = [0u8; 12]; //u96
                                    bytes.clone_from_slice(self.read_bytes(12).await?);
                                    read_d128(&bytes) as i128 * sign
                                }
                                17 => {
                                    let mut bytes = [0u8; 16]; //u96
                                    bytes.clone_from_slice(self.read_bytes(16).await?);
                                    read_d128(&bytes) as i128 * sign
                                }
                                x => {
                                    return Err(Error::Protocol(
                                        format!(
                                            "decimal/numeric: invalid length of {} received",
                                            x
                                        )
                                        .into(),
                                    ))
                                }
                            };

                            ColumnData::Numeric(Numeric::new_with_scale(value, *scale))
                        }
                    }
                    _ => unimplemented!(),
                }
            }
        };
        Ok(ret)
    }

    async fn read_fixed_len_type(
        &mut self,
        _ctx: &protocol::Context,
        ty: FixedLenType,
    ) -> Result<ColumnData<'static>> {
        let ret = match ty {
            FixedLenType::Null => ColumnData::None,
            FixedLenType::Bit => ColumnData::Bit(self.read_u8().await? != 0),
            FixedLenType::Int1 => ColumnData::I8(self.read_i8().await?),
            FixedLenType::Int2 => ColumnData::I16(self.read_i16::<LittleEndian>().await?),
            FixedLenType::Int4 => ColumnData::I32(self.read_i32::<LittleEndian>().await?),
            FixedLenType::Int8 => ColumnData::I64(self.read_i64::<LittleEndian>().await?),
            FixedLenType::Float4 => ColumnData::F32(self.read_f32::<LittleEndian>().await?),
            FixedLenType::Float8 => ColumnData::F64(self.read_f64::<LittleEndian>().await?),
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

    async fn read_var_len_sized(
        &mut self,
        _ctx: &protocol::Context,
        ty: VarLenType,
        len: usize,
        collation: Option<Collation>,
    ) -> Result<ColumnData<'static>> {
        let res = match ty {
            VarLenType::Bitn => self.read_bit().await?,
            VarLenType::Intn => self.read_int().await?,
            // 2.2.5.5.1.5 IEEE754
            VarLenType::Floatn => self.read_float().await?,
            VarLenType::Guid => self.read_guid().await?,
            VarLenType::NChar | VarLenType::NVarchar => {
                self.state_tracked = true;
                let res = self.read_varchar(ty, len).await?;
                self.state_tracked = false;

                res
            }
            VarLenType::BigVarChar => {
                self.state_tracked = true;
                let res = self.read_big_varchar(len, collation).await?;
                self.state_tracked = false;

                res
            }
            VarLenType::Money => self.read_money().await?,
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
            VarLenType::BigBinary => {
                self.state_tracked = true;
                let res = self.read_binary(len).await?;
                self.state_tracked = false;

                res
            }
            _ => unimplemented!(),
        };

        Ok(res)
    }

    async fn read_bit(&mut self) -> Result<ColumnData<'static>> {
        let recv_len = self.read_u8().await? as usize;

        let res = match recv_len {
            0 => ColumnData::None,
            1 => ColumnData::Bit(self.read_u8().await? > 0),
            v => {
                return Err(Error::Protocol(
                    format!("bitn: length of {} is invalid", v).into(),
                ))
            }
        };

        Ok(res)
    }

    async fn read_int(&mut self) -> Result<ColumnData<'static>> {
        let recv_len = self.read_u8().await? as usize;

        let res = match recv_len {
            0 => ColumnData::None,
            1 => ColumnData::I8(self.read_i8().await?),
            2 => ColumnData::I16(self.read_i16::<LittleEndian>().await?),
            4 => ColumnData::I32(self.read_i32::<LittleEndian>().await?),
            8 => ColumnData::I64(self.read_i64::<LittleEndian>().await?),
            _ => unimplemented!(),
        };

        Ok(res)
    }

    async fn read_float(&mut self) -> Result<ColumnData<'static>> {
        let len = self.read_u8().await?;

        let res = match len {
            0 => ColumnData::None,
            4 => ColumnData::F32(self.read_f32::<LittleEndian>().await?),
            8 => ColumnData::F64(self.read_f64::<LittleEndian>().await?),
            _ => {
                return Err(Error::Protocol(
                    format!("floatn: length of {} is invalid", len).into(),
                ))
            }
        };

        Ok(res)
    }

    async fn read_guid(&mut self) -> Result<ColumnData<'static>> {
        let len = self.read_u8().await?;

        let res = match len {
            0 => ColumnData::None,
            16 => {
                let mut data = [0u8; 16];
                data.clone_from_slice(self.read_bytes(16).await?);
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

    async fn read_varchar(&mut self, ty: VarLenType, len: usize) -> Result<ColumnData<'static>> {
        let mode = if ty == VarLenType::NChar {
            ReadTyMode::FixedSize(len)
        } else {
            ReadTyMode::auto(len)
        };

        let data = self.read_plp_type(mode).await?;

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

    async fn read_big_varchar(
        &mut self,
        len: usize,
        collation: Option<Collation>,
    ) -> Result<ColumnData<'static>> {
        let mode = ReadTyMode::auto(len);
        let data = self.read_plp_type(mode).await?;

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

    async fn read_money(&mut self) -> Result<ColumnData<'static>> {
        let len = self.read_u8().await?;

        let res = match len {
            0 => ColumnData::None,
            4 => ColumnData::F64(self.read_i32::<LittleEndian>().await? as f64 / 1e4),
            8 => ColumnData::F64({
                let high = self.read_i32::<LittleEndian>().await? as i64;
                let low = self.read_u32::<LittleEndian>().await? as f64;
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

    async fn read_binary(&mut self, len: usize) -> Result<ColumnData<'static>> {
        let mode = ReadTyMode::auto(len);
        let data = self.read_plp_type(mode).await?;

        let res = if let Some(buf) = data {
            ColumnData::Binary(buf.into())
        } else {
            ColumnData::None
        };

        Ok(res)
    }
}

/*
fn parse_datetimen<'a, I: Io>(trans: &mut TdsTransport<I>, len: u8) -> Result<ColumnData<'a>> {
    let datetime = match len {
        0 => ColumnData::None,
        4 => ColumnData::SmallDateTime(time::SmallDateTime {
            days: trans.inner.read_u16::<LittleEndian>()?,
            seconds_fragments: trans.inner.read_u16::<LittleEndian>()?,
        }),
        8 => ColumnData::DateTime(time::DateTime {
            days: trans.inner.read_i32::<LittleEndian>()?,
            seconds_fragments: trans.inner.read_u32::<LittleEndian>()?,
        }),
        _ => {
            return Err(Error::Protocol(
                format!("datetimen: length of {} is invalid", len).into(),
            ))
        }
    };
    Ok(datetime)
}
*/
