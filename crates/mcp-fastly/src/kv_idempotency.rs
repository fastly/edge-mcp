//! KV-backed [`IdempotencyStore`](mcp_core::IdempotencyStore) (wasm-only).
//!
//! Best-effort duplicate suppression for client `idempotencyKey`s (see the
//! `mcp_core::idempotency` module docs for the exactly-once caveat). The
//! reservation is an atomic insert-if-absent (`if_generation_match(0)`) so only
//! one concurrent caller wins; the loser observes either a pending marker (in
//! progress) or the stored result (replay). Records are short-lived (TTL) —
//! suppression holds for a bounded retention window, not permanently, so a
//! retry after expiry can re-execute the effect.

use std::time::Duration;

use fastly::kv_store::KVStore;
use serde_json::Value;

use mcp_core::{IdempotencyError, IdempotencyStore, Reservation};

const STORE: &str = "idempotency";
/// How long an idempotency record is retained. Covers realistic client retry
/// windows without unbounded growth.
const TTL_SECS: u64 = 600;

pub struct KvIdempotencyStore;

impl KvIdempotencyStore {
    pub fn new() -> Self {
        KvIdempotencyStore
    }

    fn open() -> Result<KVStore, IdempotencyError> {
        match KVStore::open(STORE) {
            Ok(Some(store)) => Ok(store),
            Ok(None) => Err(IdempotencyError(format!("kv store '{STORE}' not found"))),
            Err(e) => Err(IdempotencyError(format!("open kv store: {e}"))),
        }
    }
}

impl Default for KvIdempotencyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl IdempotencyStore for KvIdempotencyStore {
    fn reserve(&self, key: &str) -> Result<Reservation, IdempotencyError> {
        let store = Self::open()?;
        // Atomic insert-if-absent: generation 0 means "no existing entry".
        let pending = b"{\"pending\":true}".to_vec();
        match store
            .build_insert()
            .time_to_live(Duration::from_secs(TTL_SECS))
            .if_generation_match(0)
            .execute(key, pending)
        {
            Ok(()) => Ok(Reservation::Won),
            Err(_) => {
                // Someone already reserved it. Distinguish pending vs complete.
                let mut lookup = store
                    .lookup(key)
                    .map_err(|e| IdempotencyError(format!("lookup: {e}")))?;
                let bytes = lookup.take_body().into_bytes();
                let record: Value = serde_json::from_slice(&bytes)
                    .map_err(|e| IdempotencyError(format!("decode record: {e}")))?;
                match record.get("result") {
                    Some(result) => Ok(Reservation::Cached(result.clone())),
                    None => Ok(Reservation::InProgress),
                }
            }
        }
    }

    fn complete(&self, key: &str, result: &Value) -> Result<(), IdempotencyError> {
        let store = Self::open()?;
        let record = serde_json::to_vec(&serde_json::json!({ "result": result }))
            .map_err(|e| IdempotencyError(format!("encode record: {e}")))?;
        // We own the reservation; overwrite the pending marker with the result.
        store
            .build_insert()
            .time_to_live(Duration::from_secs(TTL_SECS))
            .execute(key, record)
            .map_err(|e| IdempotencyError(format!("complete: {e}")))
    }

    fn release(&self, key: &str) -> Result<(), IdempotencyError> {
        let store = Self::open()?;
        store
            .delete(key)
            .map_err(|e| IdempotencyError(format!("release: {e}")))
    }
}
