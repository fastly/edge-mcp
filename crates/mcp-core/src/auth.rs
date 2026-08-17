//! Authenticated-principal data type (shared across core and host bindings).
//!
//! The *verification* of a credential is a host concern (it needs network and
//! key material) and lives in the binding layer. But the resulting identity is
//! consumed by the core — for the cache-leakage taint (see
//! [`crate::router::RequestCtx`]) and for `(iss, sub)` binding of MRTR and Task
//! continuation tokens — so the data type lives here.

use serde_json::{Map, Value};

/// An authenticated principal derived from a verified bearer token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub issuer: String,
    pub subject: String,
    pub scopes: Vec<String>,
    pub claims: Map<String, Value>,
}

impl Principal {
    /// The composite identity used for continuation-token binding. Two
    /// principals are the "same" only when both issuer and subject match — a
    /// refreshed token under a different issuer or a pairwise `sub` is a
    /// different principal (see [`crate::mrtr`]).
    pub fn id(&self) -> (&str, &str) {
        (self.issuer.as_str(), self.subject.as_str())
    }

    /// A stable, non-secret identifier suitable for a principal-scoped cache
    /// key: `"<issuer>\u{1f}<subject>"`. Never contains the raw token.
    pub fn cache_scope_id(&self) -> String {
        let (issuer, subject) = self.id();
        format!("{issuer}\u{1f}{subject}")
    }
}
