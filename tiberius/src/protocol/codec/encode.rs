use super::BytesData;
use bytes::BufMut;

pub trait Encode<'a, B: BufMut> {
    fn encode(self, dst: &mut B) -> crate::Result<()>;
}

impl<'a, C> BufMut for BytesData<'a, C> {
    fn remaining_mut(&self) -> usize {
        self.src.remaining_mut()
    }

    unsafe fn advance_mut(&mut self, cnt: usize) {
        self.src.advance_mut(cnt)
    }

    fn bytes_mut(&mut self) -> &mut [std::mem::MaybeUninit<u8>] {
        self.src.bytes_mut()
    }
}
