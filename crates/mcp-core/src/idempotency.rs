//! Client idempotency keys for side-effecting tool calls (CMCP-006).
//!
//! MRTR continuation tokens are principal-, tool-, and expiry-bound and
//! AEAD-sealed, but they are **replayable** within their validity window — a
//! captured retry (or an honest network retry) could execute a side effect more
//! than once. When a client supplies an `idempotencyKey` on a `tools/call`,
//! the framework provides **best-effort duplicate suppression**: the first
//! caller reserves the key, executes, and stores the result; concurrent or
//! later duplicates replay the stored result (or are rejected while the first
//! is in flight) instead of re-running the side effect.
//!
//! This is **not** general exactly-once execution. The side effect runs before
//! the result is durably recorded, and a store cannot atomically commit an
//! arbitrary external effect together with the KV record. So a crash or KV
//! write-failure after the effect but before `complete`, followed by a retry
//! after the record's retention window expires, can re-execute the effect. For
//! true exactly-once, a tool handler must couple its effect with an idempotency
//! record in the same transactional system. This middleware suppresses
//! duplicates for *completed* calls within the retention window.
//!
//! The store is supplied by the host binding (KV-backed on Fastly). The
//! reservation MUST be atomic (insert-if-absent) so exactly one concurrent
//! caller wins.

use serde_json::Value;

/// An opaque idempotency-store failure.
#[derive(Debug, Clone)]
pub struct IdempotencyError(pub String);

impl std::fmt::Display for IdempotencyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The outcome of reserving an idempotency key before executing a side effect.
pub enum Reservation {
    /// This caller won the reservation and must execute, then call
    /// [`IdempotencyStore::complete`] (or [`IdempotencyStore::release`] if the
    /// call did not produce a cacheable terminal result).
    Won,
    /// A completed result already exists for this key — replay it without
    /// re-executing.
    Cached(Value),
    /// Another in-flight request currently holds the reservation.
    InProgress,
}

/// Makes client-supplied idempotency keys safe. Implementations MUST make
/// [`reserve`](IdempotencyStore::reserve) atomic so exactly one concurrent
/// caller receives [`Reservation::Won`].
pub trait IdempotencyStore {
    fn reserve(&self, key: &str) -> Result<Reservation, IdempotencyError>;
    fn complete(&self, key: &str, result: &Value) -> Result<(), IdempotencyError>;
    fn release(&self, key: &str) -> Result<(), IdempotencyError>;
}

/// Scope a client-supplied key to the principal and tool so keys cannot collide
/// or be replayed across principals/tools. Each component is length-prefixed
/// (`<byte-len>:<value>`) so a separator byte inside any component (a JWT claim
/// or client key may contain arbitrary Unicode) cannot forge a different
/// component boundary — the encoding is injective. `issuer`/`subject` are empty
/// in anonymous demo mode.
pub fn scope_key(issuer: &str, subject: &str, tool: &str, client_key: &str) -> String {
    fn part(s: &str) -> String {
        format!("{}:{}", s.len(), s)
    }
    format!(
        "{}{}{}{}",
        part(issuer),
        part(subject),
        part(tool),
        part(client_key)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_key_is_collision_resistant_across_component_boundaries() {
        // Without length-prefixing these two distinct principals would collide.
        let a = scope_key("a", "b\u{1f}c", "d", "e");
        let b = scope_key("a\u{1f}b", "c", "d", "e");
        assert_ne!(a, b, "component boundaries must be unforgeable");
    }

    #[test]
    fn scope_key_distinguishes_principals_tools_and_keys() {
        let base = scope_key("iss", "sub", "tool", "k");
        assert_ne!(base, scope_key("iss", "other", "tool", "k"));
        assert_ne!(base, scope_key("iss", "sub", "other", "k"));
        assert_ne!(base, scope_key("iss", "sub", "tool", "other"));
    }
}
