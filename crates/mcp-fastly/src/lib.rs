//! Fastly Compute bindings for [`mcp_core`].
//!
//! This crate adapts the transport-agnostic protocol core to Fastly Compute:
//! the request/response adapter, an ES256 JWT/JWKS [`TokenVerifier`], the
//! Secret-Store-backed AEAD signer, fail-closed edge caching, and a KV-backed
//! task store.
//!
//! The verification and configuration logic ([`auth`], [`config`]) is
//! platform-neutral and unit-tested on the host. Everything that makes Fastly
//! host calls lives in the `wasm32`-gated modules ([`adapter`], `stores`), which
//! only compile for the `wasm32-wasip1` target.

pub mod auth;
pub mod cache;
pub mod config;

#[cfg(target_arch = "wasm32")]
pub mod adapter;
#[cfg(target_arch = "wasm32")]
pub mod kv_idempotency;
#[cfg(target_arch = "wasm32")]
pub mod kv_tasks;
#[cfg(target_arch = "wasm32")]
pub mod stores;

pub use auth::{www_authenticate, AuthError, JwkSet, JwtVerifier, TokenVerifier};
pub use config::{ConfigError, VerifierConfig};
