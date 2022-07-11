// Copyright (c) Aptos
// SPDX-License-Identifier: Apache-2.0

use super::{ensure_slice_len_eq, SINGLE_ENTRY_CF_NAME};
use crate::{
    consensusdb::schema::{
        block::BlockSchema,
        quorum_certificate::QCSchema,
        single_entry::{SingleEntryKey, SingleEntrySchema},
    },
    error::DbError,
};
use anyhow::{format_err, Result};
use aptos_crypto::HashValue;
use aptos_logger::prelude::*;
use byteorder::ReadBytesExt;
use consensus_types::{block::Block, quorum_cert::QuorumCert};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use schema::{BLOCK_CF_NAME, QC_CF_NAME, SINGLE_ENTRY_CF_NAME};
use schemadb::{
    define_schema,
    schema::{KeyCodec, ValueCodec},
    Options, ReadOptions, SchemaBatch, DB, DEFAULT_COLUMN_FAMILY_NAME,
};
use std::{collections::HashMap, iter::Iterator, mem::size_of, path::Path, time::Instant};
use move_deps::move_prover::cli::Options;

/// The name of the state sync db file
pub const STATE_SYNC_DB_NAME: &str = "state_sync_db";

/// This struct offers a simple interface to persist state sync metadata
/// across node crashes and restarts. This is required to handle failures
/// and reboots during critical parts of the synchronization process.
pub struct PersistentStorage {
    database: DB,
}

impl PersistentStorage {
    pub fn new<P: AsRef<Path> + Clone>(db_root_path: P) -> Self {
        // Set the options to create the database if it's missing
        let mut options = Options::default();
        options.create_if_missing(true);
        options.create_missing_column_families(true);

        // Open the database
        let state_sync_db_path = db_root_path.as_ref().join(STATE_SYNC_DB_NAME);
        let instant = Instant::now();
        let database = DB::open(state_sync_db_path.clone(), "state_sync", vec![SINGLE_ENTRY_CF_NAME], &options)
            .expect("Failed to open/create the state sync database at: {:?}", state_sync_db_path);
        info!(
            "Opened the state sync database at: {:?}, in {:?} ms",
            state_sync_db_path,
            instant.elapsed().as_millis()
        );

        Self { database }
    }

    pub fn get_data(
        &self,
    ) -> Result<(
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Vec<Block>,
        Vec<QuorumCert>,
    )> {
        let last_vote = self.get_last_vote()?;
        let highest_2chain_timeout_certificate = self.get_highest_2chain_timeout_certificate()?;
        let consensus_blocks = self
            .get_blocks()?
            .into_iter()
            .map(|(_block_hash, block_content)| block_content)
            .collect::<Vec<_>>();
        let consensus_qcs = self
            .get_quorum_certificates()?
            .into_iter()
            .map(|(_block_hash, qc)| qc)
            .collect::<Vec<_>>();
        Ok((
            last_vote,
            highest_2chain_timeout_certificate,
            consensus_blocks,
            consensus_qcs,
        ))
    }

    pub fn save_highest_2chain_timeout_certificate(&self, tc: Vec<u8>) -> Result<(), DbError> {
        let mut batch = SchemaBatch::new();
        batch.put::<SingleEntrySchema>(&SingleEntryKey::Highest2ChainTimeoutCert, &tc)?;
        self.commit(batch)?;
        Ok(())
    }

    pub fn save_vote(&self, last_vote: Vec<u8>) -> Result<(), DbError> {
        let mut batch = SchemaBatch::new();
        batch.put::<SingleEntrySchema>(&SingleEntryKey::LastVote, &last_vote)?;
        self.commit(batch)
    }

    pub fn save_blocks_and_quorum_certificates(
        &self,
        block_data: Vec<Block>,
        qc_data: Vec<QuorumCert>,
    ) -> Result<(), DbError> {
        if block_data.is_empty() && qc_data.is_empty() {
            return Err(anyhow::anyhow!("Consensus block and qc data is empty!").into());
        }
        let mut batch = SchemaBatch::new();
        block_data
            .iter()
            .try_for_each(|block| batch.put::<BlockSchema>(&block.id(), block))?;
        qc_data
            .iter()
            .try_for_each(|qc| batch.put::<QCSchema>(&qc.certified_block().id(), qc))?;
        self.commit(batch)
    }

    pub fn delete_blocks_and_quorum_certificates(
        &self,
        block_ids: Vec<HashValue>,
    ) -> Result<(), DbError> {
        if block_ids.is_empty() {
            return Err(anyhow::anyhow!("Consensus block ids is empty!").into());
        }
        let mut batch = SchemaBatch::new();
        block_ids.iter().try_for_each(|hash| {
            batch.delete::<BlockSchema>(hash)?;
            batch.delete::<QCSchema>(hash)
        })?;
        self.commit(batch)
    }

    /// Write the whole schema batch including all data necessary to mutate the ledger
    /// state of some transaction by leveraging rocksdb atomicity support.
    fn commit(&self, batch: SchemaBatch) -> Result<(), DbError> {
        self.db.write_schemas(batch)?;
        Ok(())
    }

    /// Get latest timeout certificates (we only store the latest highest timeout certificates).
    fn get_highest_2chain_timeout_certificate(&self) -> Result<Option<Vec<u8>>, DbError> {
        Ok(self
            .db
            .get::<SingleEntrySchema>(&SingleEntryKey::Highest2ChainTimeoutCert)?)
    }

    pub fn delete_highest_2chain_timeout_certificate(&self) -> Result<(), DbError> {
        let mut batch = SchemaBatch::new();
        batch.delete::<SingleEntrySchema>(&SingleEntryKey::Highest2ChainTimeoutCert)?;
        self.commit(batch)
    }
    /// Get serialized latest vote (if available)
    fn get_last_vote(&self) -> Result<Option<Vec<u8>>, DbError> {
        Ok(self
            .db
            .get::<SingleEntrySchema>(&SingleEntryKey::LastVote)?)
    }

    pub fn delete_last_vote_msg(&self) -> Result<(), DbError> {
        let mut batch = SchemaBatch::new();
        batch.delete::<SingleEntrySchema>(&SingleEntryKey::LastVote)?;
        self.commit(batch)?;
        Ok(())
    }

    /// Get all consensus blocks.
    fn get_blocks(&self) -> Result<HashMap<HashValue, Block>, DbError> {
        let mut iter = self.db.iter::<BlockSchema>(ReadOptions::default())?;
        iter.seek_to_first();
        Ok(iter.collect::<Result<HashMap<HashValue, Block>>>()?)
    }

    /// Get all consensus QCs.
    fn get_quorum_certificates(&self) -> Result<HashMap<HashValue, QuorumCert>, DbError> {
        let mut iter = self.db.iter::<QCSchema>(ReadOptions::default())?;
        iter.seek_to_first();
        Ok(iter.collect::<Result<HashMap<HashValue, QuorumCert>>>()?)
    }
}

/// The raw schema format used by the database
mod database_schema {
    //! This defines a physical storage schema for any single-entry data.
    //!
    //! There will only be one row in this column family for each type of data.
    //! The key will be a serialized enum type designating the data type.
    //!
    //! ```text
    //! |<-------key------->|<-----value----->|
    //! | single entry key  | raw value bytes |
    //! ```
    define_schema!(
        SingleEntrySchema,
        SingleEntryKey,
        Vec<u8>,
        SINGLE_ENTRY_CF_NAME
    );

    #[derive(Debug, Eq, PartialEq, FromPrimitive, ToPrimitive)]
    #[repr(u8)]
    pub enum SingleEntryKey {
        // Used to store the last vote
        LastVote = 0,
        // Two chain timeout cert
        Highest2ChainTimeoutCert = 1,
    }

    impl KeyCodec<SingleEntrySchema> for SingleEntryKey {
        fn encode_key(&self) -> Result<Vec<u8>> {
            Ok(vec![self
                .to_u8()
                .ok_or_else(|| format_err!("ToPrimitive failed."))?])
        }

        fn decode_key(mut data: &[u8]) -> Result<Self> {
            ensure_slice_len_eq(data, size_of::<u8>())?;
            let key = data.read_u8()?;
            SingleEntryKey::from_u8(key).ok_or_else(|| format_err!("FromPrimitive failed."))
        }
    }

    impl ValueCodec<SingleEntrySchema> for Vec<u8> {
        fn encode_value(&self) -> Result<Vec<u8>> {
            Ok(self.clone())
        }

        fn decode_value(data: &[u8]) -> Result<Self> {
            Ok(data.to_vec())
        }
    }
}

#[cfg(test)]
mod test {
    // Tests that the DB can encode / decode data
    #[test]
    fn test_single_entry_schema() {
        assert_encode_decode::<SingleEntrySchema>(&SingleEntryKey::LastVote, &vec![1u8, 2u8, 3u8]);
    }

    test_no_panic_decoding!(SingleEntrySchema);
}
