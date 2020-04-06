use super::{BytesData, Decode};
use crate::{protocol::Context, Error};
use bitflags::bitflags;
use bytes::Buf;

#[derive(Debug)]
pub struct TokenDone {
    pub status: DoneStatus,
    pub cur_cmd: u16,
    pub done_rows: u64,
}

bitflags! {
    pub struct DoneStatus: u16 {
        const MORE = 0x1;
        const ERROR = 0x2;
        const INEXACT = 0x4;
        const COUNT = 0x10;
        const ATTENTION = 0x20;
        const RPC_IN_BATCH  = 0x80;
        const SRVERROR = 0x100;
    }
}

impl<'a> Decode<'a, BytesData<'a, Context>> for TokenDone {
    fn decode(src: &mut BytesData<'a, Context>) -> crate::Result<Self>
    where
        Self: Sized,
    {
        let cur_cmd = src.get_u16_le();
        let done_row_count_bytes = src.context().version.done_row_count_bytes();

        let status = DoneStatus::from_bits(src.get_u16_le())
            .ok_or(Error::Protocol("done(variant): invalid status".into()))?;

        let done_rows = match done_row_count_bytes {
            8 => src.get_u64_le(),
            4 => src.get_u32_le() as u64,
            _ => unreachable!(),
        };

        Ok(TokenDone {
            status,
            cur_cmd,
            done_rows,
        })
    }
}
