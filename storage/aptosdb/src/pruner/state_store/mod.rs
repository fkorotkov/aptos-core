// Copyright (c) Aptos
// SPDX-License-Identifier: Apache-2.0

use crate::{
    jellyfish_merkle_node::JellyfishMerkleNodeSchema, metrics::PRUNER_LEAST_READABLE_VERSION,
    pruner::db_pruner::DBPruner, stale_node_index::StaleNodeIndexSchema, OTHER_TIMERS_SECONDS,
};
use anyhow::Result;
use aptos_infallible::Mutex;
use aptos_jellyfish_merkle::StaleNodeIndex;
use aptos_logger::{error, warn};
use aptos_types::transaction::{AtomicVersion, Version};
use schemadb::{ReadOptions, SchemaBatch, SchemaIterator, DB};
use std::{
    iter::Peekable,
    sync::{atomic::Ordering, Arc},
    time::{Duration, Instant},
};

#[cfg(test)]
mod test;

pub const STATE_STORE_PRUNER_NAME: &str = "state store pruner";

pub struct StateStorePruner {
    db: Arc<DB>,
    max_index_purged_version: AtomicVersion,
    index_purged_at: Mutex<Instant>,
    /// Keeps track of the target version that the pruner needs to achieve.
    target_version: AtomicVersion,
    min_readable_version: AtomicVersion,
}

impl DBPruner for StateStorePruner {
    fn name(&self) -> &'static str {
        STATE_STORE_PRUNER_NAME
    }

    fn prune(&self, _ledger_db_batch: &mut SchemaBatch, _max_versions: u64) -> Result<Version> {
        if !self.is_pruning_pending() {
            return Ok(self.min_readable_version());
        }
        let min_readable_version = self.min_readable_version.load(Ordering::Relaxed);
        //let target_version = self.target_version();
        return match prune_state_store(&self.db, min_readable_version, 0) {
            Ok((new_min_readable_version, next_item_stale_since_version)) => {
                self.record_progress(new_min_readable_version);
                // Try to purge the log.
                if let Err(e) = self.maybe_purge_index(next_item_stale_since_version) {
                    warn!(
                        error = ?e,
                        "Failed purging state node index, ignored.",
                    );
                }
                Ok(new_min_readable_version)
            }
            Err(e) => {
                error!(
                    error = ?e,
                    "Error pruning stale state nodes.",
                );
                Err(e)
                // On error, stop retrying vigorously by making next recv() blocking.
            }
        };
    }

    fn initialize_min_readable_version(&self) -> Result<Version> {
        let mut iter = self
            .db
            .iter::<StaleNodeIndexSchema>(ReadOptions::default())?;
        iter.seek_to_first();
        Ok(iter.next().transpose()?.map_or(0, |(index, _)| {
            index
                .stale_since_version
                .checked_sub(1)
                .expect("Nothing is stale since version 0.")
        }))
    }

    fn min_readable_version(&self) -> Version {
        self.min_readable_version.load(Ordering::Relaxed)
    }

    fn set_target_version(&self, target_version: Version) {
        self.target_version.store(target_version, Ordering::Relaxed);
    }

    fn target_version(&self) -> Version {
        self.target_version.load(Ordering::Relaxed)
    }

    fn record_progress(&self, min_readable_version: Version) {
        self.min_readable_version
            .store(min_readable_version, Ordering::Relaxed);
        PRUNER_LEAST_READABLE_VERSION
            .with_label_values(&["state_store"])
            .set(min_readable_version as i64);
    }
}

impl StateStorePruner {
    pub fn new(db: Arc<DB>, max_index_purged_version: Version, index_purged_at: Instant) -> Self {
        let pruner = StateStorePruner {
            db,
            max_index_purged_version: AtomicVersion::new(max_index_purged_version),
            index_purged_at: Mutex::new(index_purged_at),
            target_version: AtomicVersion::new(0),
            min_readable_version: AtomicVersion::new(0),
        };
        pruner.initialize();
        pruner
    }

    /// Purge the stale node index so that after restart not too much already pruned stuff is dealt
    /// with again (although no harm is done deleting those then non-existent things.)
    ///
    /// We issue (range) deletes on the index only periodically instead of after every pruning batch
    /// to avoid sending too many deletions to the DB, which takes disk space and slows it down.
    fn maybe_purge_index(
        &self,
        next_item_stale_since_version_option: Option<Version>,
    ) -> Result<()> {
        const MIN_INTERVAL: Duration = Duration::from_secs(10);
        const MIN_VERSIONS: u64 = 60000;

        let min_readable_version = self.min_readable_version.load(Ordering::Relaxed);

        // Check if the next item in the index has the same `stale_since_version` as the
        // `current min_readable version`. If yes, the index at `min_readable_version` cannot
        // be pruned. If the `next_item_stale_since_version_option` is none. The index does not have
        // more items so we can prune the index at `min_readable_version`.
        if let Some(next_item_stale_since_version) = next_item_stale_since_version_option {
            if next_item_stale_since_version == min_readable_version {
                return Ok(());
            }
        }
        let max_index_purged_version = self.max_index_purged_version.load(Ordering::Relaxed);

        // A deletion is issued at most once in one minute and when the pruner has progressed by at
        // least 60000 versions (assuming the pruner deletes as slow as 1000 versions per second,
        // this imposes at most one minute of work in vain after restarting.)
        let now = Instant::now();
        if now - *self.index_purged_at.lock() > MIN_INTERVAL
            && min_readable_version - max_index_purged_version > MIN_VERSIONS
        {
            self.db.range_delete::<StaleNodeIndexSchema, Version>(
                &(max_index_purged_version + 1), // begin is inclusive
                &(min_readable_version + 1),     // end is exclusive
            )?;
            // The index items at min_readable_version has been consumed already because they
            // indicate nodes that became stale at that version, keeping that version readable,
            // hence is purged above.
            self.max_index_purged_version
                .store(min_readable_version, Ordering::Relaxed);
            *self.index_purged_at.lock() = now;
        }
        Ok(())
    }
}

pub fn prune_state_store(
    db: &DB,
    min_readable_version: Version,
    _max_versions: usize,
) -> anyhow::Result<(Version, Option<Version>)> {
    let batch_size = 1;
    let indices_iter =
        StaleNodeIndicesByNumberOfItemsIterator::new(db, min_readable_version, batch_size)?;
    let next_item_stale_since_version = indices_iter.next_item_stale_since_version;
    let indices = indices_iter.collect::<anyhow::Result<Vec<_>>>()?;

    if indices.is_empty() {
        Ok((min_readable_version, next_item_stale_since_version))
    } else {
        let _timer = OTHER_TIMERS_SECONDS
            .with_label_values(&["pruner_commit"])
            .start_timer();
        let new_min_readable_version = indices.last().expect("Should exist.").stale_since_version;
        let mut batch = SchemaBatch::new();
        indices
            .into_iter()
            .try_for_each(|index| batch.delete::<JellyfishMerkleNodeSchema>(&index.node_key))?;
        db.write_schemas(batch)?;
        Ok((new_min_readable_version, next_item_stale_since_version))
    }
}

struct StaleNodeIndicesByNumberOfItemsIterator<'a> {
    inner: Peekable<SchemaIterator<'a, StaleNodeIndexSchema>>,
    num_items: usize,
    next_item_stale_since_version: Option<Version>,
    start_pruning_version: Version,
}

impl<'a> StaleNodeIndicesByNumberOfItemsIterator<'a> {
    fn new(db: &'a DB, start_pruning_version: Version, num_items: usize) -> anyhow::Result<Self> {
        let mut iter = db.iter::<StaleNodeIndexSchema>(ReadOptions::default())?;
        iter.seek(&start_pruning_version)?;

        Ok(Self {
            inner: iter.peekable(),
            num_items,
            next_item_stale_since_version: None,
            start_pruning_version,
        })
    }

    fn next_result(&mut self) -> Result<Option<StaleNodeIndex>> {
        if self.num_items == 0 {
            return Ok(None);
        }
        match self.inner.next().transpose()? {
            None => Ok(None),
            Some((index, _)) => {
                self.num_items -= 1;
                // Check the next item to determine the `next_item_stale_since_version`
                if let Some(res) = self.inner.peek() {
                    if let Ok((next_index_ref, _)) = res {
                        self.next_item_stale_since_version = Some(next_index_ref.stale_since_version);
                    }
                }
                return Ok(Some(index));
            }
        }
    }
}

impl<'a> Iterator for StaleNodeIndicesByNumberOfItemsIterator<'a> {
    type Item = anyhow::Result<StaleNodeIndex>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_result().transpose()
    }
}
