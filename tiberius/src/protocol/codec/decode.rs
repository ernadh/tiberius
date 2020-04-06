use super::BytesData;
use bytes::{Buf, BytesMut};

impl<'a, C> Buf for BytesData<'a, C> {
    fn remaining(&self) -> usize {
        self.src.remaining()
    }

    fn bytes(&self) -> &[u8] {
        self.src.bytes()
    }

    fn advance(&mut self, cnt: usize) {
        self.src.advance(cnt)
    }
}

pub trait Decode<'a, B: Buf> {
    fn decode(src: &mut B) -> crate::Result<Self>
    where
        Self: Sized;
}
