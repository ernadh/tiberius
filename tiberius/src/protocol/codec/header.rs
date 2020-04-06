use crate::{uint_enum, Error};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::{
    convert::TryFrom,
    io::{self, Cursor},
};

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
            id,
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

    pub fn unserialize(buf: &[u8]) -> crate::Result<PacketHeader> {
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
