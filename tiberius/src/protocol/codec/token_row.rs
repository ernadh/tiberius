use super::{BaseMetaDataColumn, BytesData, ColumnData, Decode, TokenColMetaData};
use crate::{protocol, Error};
use bytes::BytesMut;
use protocol::Context;
use std::sync::Arc;

#[derive(Debug)]
pub struct TokenRow {
    pub meta: Arc<TokenColMetaData>,
    pub columns: Vec<ColumnData<'static>>,
}

impl TokenRow {
    pub fn new(meta: Arc<TokenColMetaData>) -> Self {
        let columns = Vec::with_capacity(meta.columns.len());

        Self { meta, columns }
    }
}

impl<'a> Decode<'a, BytesData<'a, Context>> for TokenRow {
    fn decode(src: &mut BytesData<'a, Context>) -> crate::Result<Self>
    where
        Self: Sized,
    {
        let col_meta = src
            .context()
            .last_meta
            .lock()
            .clone()
            .ok_or(Error::Protocol("missing colmeta data".into()))?;

        let mut row = TokenRow {
            meta: col_meta.clone(),
            columns: Vec::with_capacity(col_meta.columns.len()),
        };

        for column in col_meta.columns.iter() {
            let mut src: BytesData<BaseMetaDataColumn> = BytesData::new(src.inner(), &column.base);
            let data = ColumnData::decode(&mut src)?;

            row.columns.push(data);
        }

        Ok(row)
    }
}
