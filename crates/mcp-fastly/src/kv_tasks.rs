//! KV-backed [`TaskStore`] (wasm-only).
//!
//! Stores each task as JSON under its CSPRNG id in a KV Store. Updates use
//! compare-and-swap via `current_generation()` / `if_generation_match` so a
//! stale write is rejected rather than clobbering a concurrent transition.
//! Native `time_to_live` is set only as an eventual GC backstop — authoritative
//! expiry is the `expires_at` field checked at read time in the core.

use std::time::Duration;

use fastly::kv_store::KVStore;

use mcp_core::tasks::{StoredTask, Task, TaskError, TaskStore};

const STORE: &str = "task_store";
/// Extra GC margin on top of the task's own TTL.
const GC_MARGIN_SECS: u64 = 3600;

pub struct KvTaskStore;

impl KvTaskStore {
    pub fn new() -> Self {
        KvTaskStore
    }

    fn open() -> Result<KVStore, TaskError> {
        match KVStore::open(STORE) {
            Ok(Some(store)) => Ok(store),
            Ok(None) => Err(TaskError(format!("kv store '{STORE}' not found"))),
            Err(e) => Err(TaskError(format!("open kv store: {e}"))),
        }
    }

    fn ttl(task: &Task) -> Duration {
        Duration::from_secs(task.ttl_ms / 1000 + GC_MARGIN_SECS)
    }
}

impl Default for KvTaskStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TaskStore for KvTaskStore {
    fn create(&self, task: &Task) -> Result<(), TaskError> {
        let store = Self::open()?;
        let value = serde_json::to_vec(task).map_err(|e| TaskError(format!("encode task: {e}")))?;
        store
            .build_insert()
            .time_to_live(Self::ttl(task))
            .execute(&task.id, value)
            .map_err(|e| TaskError(format!("create task: {e}")))
    }

    fn load(&self, id: &str) -> Result<Option<StoredTask>, TaskError> {
        let store = Self::open()?;
        // A missing key surfaces as a lookup error; treat it as `None`.
        let mut lookup = match store.lookup(id) {
            Ok(l) => l,
            Err(_) => return Ok(None),
        };
        let generation = lookup.current_generation();
        let bytes = lookup.take_body().into_bytes();
        if bytes.is_empty() {
            return Ok(None);
        }
        let task: Task =
            serde_json::from_slice(&bytes).map_err(|e| TaskError(format!("decode task: {e}")))?;
        Ok(Some(StoredTask { task, generation }))
    }

    fn update(&self, task: &Task, expected_generation: u64) -> Result<(), TaskError> {
        let store = Self::open()?;
        let value = serde_json::to_vec(task).map_err(|e| TaskError(format!("encode task: {e}")))?;
        store
            .build_insert()
            .time_to_live(Self::ttl(task))
            .if_generation_match(expected_generation)
            .execute(&task.id, value)
            .map_err(|e| TaskError(format!("update task (cas): {e}")))
    }
}
