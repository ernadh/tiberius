use bytes::{Buf, BytesMut};

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
