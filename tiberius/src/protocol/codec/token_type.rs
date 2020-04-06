use super::{BytesData, Decode};
use crate::{uint_enum, Error};
use bytes::{Buf, BytesMut};
use std::convert::TryFrom;
use tokio_util::codec::Decoder;

uint_enum! {
    pub enum TokenType {
        ReturnStatus = 0x79,
        ColMetaData = 0x81,
        Error = 0xAA,
        Info = 0xAB,
        Order = 0xA9,
        ColInfo = 0xA5,
        ReturnValue = 0xAC,
        LoginAck = 0xAD,
        Row = 0xD1,
        NbcRow = 0xD2,
        SSPI = 0xED,
        EnvChange = 0xE3,
        Done = 0xFD,
        /// stored procedure completed
        DoneProc = 0xFE,
        /// sql within stored procedure completed
        DoneInProc = 0xFF,
    }
}

impl<'a> Decode<'a, BytesMut> for TokenType {
    fn decode(src: &mut BytesMut) -> crate::Result<Self>
    where
        Self: Sized,
    {
        let ty_byte = src.get_u8();

        let ty = TokenType::try_from(ty_byte)
            .map_err(|_| Error::Protocol(format!("invalid token type {:x}", ty_byte).into()))?;

        Ok(ty)
    }
}
