//! `mcp-core` — a transport-agnostic implementation of the Model Context
//! Protocol, spec version `2026-07-28` (the stateless revision).
//!
//! This crate has no dependency on any host platform. It models the JSON-RPC
//! wire envelope, the MCP `_meta` request context, the result/error types, a
//! method dispatcher with a pluggable handler registry, the Multi Round-Trip
//! Request (MRTR) continuation mechanism, and the Tasks extension state
//! machine. A host binding (e.g. `mcp-fastly`) supplies the transport, the
//! key material for the [`Signer`](crate::mrtr::Signer), and the
//! [`TaskStore`](crate::tasks::TaskStore) backing store.
//!
//! The protocol is stateless: every request carries its own identity and
//! capabilities in `_meta`, and continuation state rides in signed,
//! self-contained tokens or an externalized store — never in per-instance
//! session memory.

/// The protocol version this crate implements.
pub const PROTOCOL_VERSION: &str = "2026-07-28";

/// A short random identifier for correlating a client-visible error with the
/// detailed server-side log entry. Not security-sensitive (best-effort RNG).
pub fn correlation_id() -> String {
    let mut b = [0u8; 8];
    let _ = getrandom::getrandom(&mut b);
    use std::fmt::Write;
    let mut s = String::with_capacity(16);
    for byte in b {
        let _ = write!(s, "{byte:02x}");
    }
    s
}

#[cfg(feature = "aead")]
pub mod aead;
pub mod auth;
pub mod dispatch;
pub mod idempotency;
pub mod jsonrpc;
pub mod meta;
pub mod methods;
pub mod mrtr;
pub mod result;
pub mod router;
pub mod schema;
pub mod tasks;

#[cfg(feature = "aead")]
pub use aead::{AeadKey, AeadSigner};
pub use auth::Principal;
pub use dispatch::dispatch;
pub use idempotency::{IdempotencyError, IdempotencyStore, Reservation};
pub use jsonrpc::{ErrorCode, RpcError, RpcId, RpcRequest, RpcResponse};
pub use meta::Meta;
pub use mrtr::{Continuation, InputRequired, Signer, SignerError};
pub use result::{CallResult, CallResultExt, Content, ResultType};
pub use tasks::{Task, TaskCreation, TaskStatus, TaskStore};
pub use router::{
    PromptHandler, RequestCtx, ResourceHandler, Router, RoutingHeaders, ToolDef, ToolHandler,
    ToolOutcome,
};
