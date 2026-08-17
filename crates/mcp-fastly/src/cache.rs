//! Fail-closed cache-directive derivation (platform-neutral, host-testable).
//!
//! Maps a result's `cacheScope`/`ttlMs` plus the request's fail-closed
//! cacheability flag ([`RequestCtx::is_cacheable`](mcp_core::RequestCtx::is_cacheable))
//! to concrete cache directives. The safety invariant lives here in one place:
//! a response is eligible for the **shared** edge cache only when
//! `cacheScope == "public"` AND the request stayed principal-independent AND a
//! positive TTL was declared. Anything else is `private, no-store`.
//!
//! This module decides the directives; the wasm adapter applies them to the
//! `fastly::Response`. Actually serving cached POST transactions from the edge
//! (Core Cache API with an explicit principal-free key + surrogate-key purge)
//! requires a real Compute service to validate — see the plan's Risks. The
//! directives here are the correct, tested contract downstream of that.

use serde_json::Value;

/// Stale-while-revalidate window applied to shared-cacheable responses.
pub const STALE_WHILE_REVALIDATE_SECS: u64 = 60;

/// The cache directives to apply to a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheDecision {
    /// The `Cache-Control` header value.
    pub cache_control: String,
    /// Surrogate key for targeted purge, when shared-cacheable.
    pub surrogate_key: Option<String>,
    /// Whether the response is eligible for the shared edge cache.
    pub shared: bool,
}

impl CacheDecision {
    fn private() -> Self {
        CacheDecision {
            cache_control: "private, no-store".to_string(),
            surrogate_key: None,
            shared: false,
        }
    }
}

/// The surrogate-key family for a method's list/read response.
fn surrogate_family(method: &str) -> Option<&'static str> {
    match method {
        "tools/list" => Some("mcp-tools-list"),
        "prompts/list" => Some("mcp-prompts-list"),
        "resources/list" => Some("mcp-resources-list"),
        "resources/read" => Some("mcp-resources-read"),
        "server/discover" => Some("mcp-server-discover"),
        _ => None,
    }
}

/// Decide the cache directives for a response.
///
/// `result` is the JSON-RPC `result` object (or `None` for errors / no result).
/// `ctx_cacheable` is the request's fail-closed cacheability flag.
pub fn decide(method: &str, result: Option<&Value>, ctx_cacheable: bool) -> CacheDecision {
    let Some(result) = result else {
        return CacheDecision::private();
    };

    let scope = result.get("cacheScope").and_then(Value::as_str).unwrap_or("private");
    let ttl_ms = result.get("ttlMs").and_then(Value::as_u64).unwrap_or(0);

    // Fail-closed: only methods with a known, purgeable surrogate family may be
    // shared-cached. This excludes tools/call — a tool that returns
    // `cacheScope: public` must never land in the shared edge cache (it has no
    // surrogate key for invalidation and its output may be caller-specific).
    let Some(family) = surrogate_family(method) else {
        return CacheDecision::private();
    };

    let shared = scope == "public" && ctx_cacheable && ttl_ms > 0;
    if !shared {
        return CacheDecision::private();
    }

    let ttl_secs = ttl_ms / 1000;
    CacheDecision {
        cache_control: format!(
            "public, max-age={ttl_secs}, stale-while-revalidate={STALE_WHILE_REVALIDATE_SECS}"
        ),
        surrogate_key: Some(family.to_owned()),
        shared: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn public_cacheable_list_is_shared_with_surrogate_key() {
        let result = json!({ "cacheScope": "public", "ttlMs": 300_000, "tools": [] });
        let d = decide("tools/list", Some(&result), true);
        assert!(d.shared);
        assert_eq!(d.surrogate_key.as_deref(), Some("mcp-tools-list"));
        assert!(d.cache_control.contains("public"));
        assert!(d.cache_control.contains("max-age=300"));
    }

    #[test]
    fn private_scope_is_never_shared() {
        let result = json!({ "cacheScope": "private", "ttlMs": 300_000 });
        let d = decide("resources/read", Some(&result), true);
        assert!(!d.shared);
        assert_eq!(d.cache_control, "private, no-store");
        assert!(d.surrogate_key.is_none());
    }

    #[test]
    fn leakage_guard_public_but_tainted_is_not_shared() {
        // cacheScope public but the request read the principal (ctx_cacheable=false).
        let result = json!({ "cacheScope": "public", "ttlMs": 300_000 });
        let d = decide("resources/read", Some(&result), false);
        assert!(!d.shared, "tainted request must not be shared-cached even if public");
        assert!(d.surrogate_key.is_none());
    }

    #[test]
    fn zero_ttl_is_not_shared() {
        let result = json!({ "cacheScope": "public", "ttlMs": 0 });
        assert!(!decide("tools/list", Some(&result), true).shared);
    }

    #[test]
    fn error_or_no_result_is_private() {
        assert_eq!(decide("tools/call", None, true), CacheDecision::private());
    }

    #[test]
    fn tools_call_result_without_cache_meta_is_private() {
        let result = json!({ "resultType": "complete", "content": [] });
        assert!(!decide("tools/call", Some(&result), true).shared);
    }

    #[test]
    fn tools_call_public_result_is_never_shared() {
        // A tool that returns cacheScope:public must NOT enter the shared cache:
        // tools/call has no purgeable surrogate family and its output can be
        // caller-specific.
        let result = json!({ "resultType": "complete", "content": [], "cacheScope": "public", "ttlMs": 300000 });
        let d = decide("tools/call", Some(&result), true);
        assert!(!d.shared, "tools/call output must never be shared-cached");
        assert_eq!(d.cache_control, "private, no-store");
        assert!(d.surrogate_key.is_none());
    }
}
