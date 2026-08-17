//! The MCP `_meta` request context — sourced from the official SDK (`rmcp::model`).
//!
//! In the stateless `2026-07-28` protocol, per-request identity and
//! capabilities travel in `params._meta` rather than a handshake. [`Meta`] is a
//! thin newtype over rmcp's spec-tracked [`RequestMetaObject`], which models the
//! reserved keys (`protocolVersion`, `clientCapabilities`, `clientInfo`, …) and
//! transitively dereferences to the underlying JSON map — so unknown,
//! extension-namespaced keys still deserialize and survive round-trips
//! untouched. No wire struct in this crate uses `deny_unknown_fields`.
//!
//! We keep our own [`keys`] constants (rmcp's identical ones are private to its
//! meta module) and our own accessor surface so the dispatch middleware's
//! `-32602`/`-32022`/`-32021` behavior is preserved exactly; the values those
//! accessors return are now the SDK's typed views ([`ProtocolVersion`],
//! [`ClientCapabilities`], [`Implementation`]).

use rmcp::model::{ClientCapabilities, Implementation, ProtocolVersion, RequestMetaObject};
use serde_json::Value;

/// Reserved `_meta` keys defined by the spec. (rmcp models the same constants
/// but keeps them private to its meta module, so we retain our own copies for
/// raw access and test construction.)
pub mod keys {
    pub const PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
    pub const CLIENT_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";
    pub const CLIENT_INFO: &str = "io.modelcontextprotocol/clientInfo";
    pub const SERVER_INFO: &str = "io.modelcontextprotocol/serverInfo";
    pub const LOG_LEVEL: &str = "io.modelcontextprotocol/logLevel";
}

/// A parsed view over a request's `_meta` object, backed by rmcp's
/// [`RequestMetaObject`].
#[derive(Debug, Clone, Default)]
pub struct Meta(RequestMetaObject);

impl Meta {
    /// Extract `_meta` from a `params` value. Missing or non-object `_meta`
    /// yields an empty context (the version/capability middleware then reports
    /// the appropriate `-32602`).
    pub fn from_params(params: &Value) -> Self {
        let map = params
            .get("_meta")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        Meta(RequestMetaObject::from(map))
    }

    /// Raw access to any `_meta` key (including unknown, extension-namespaced
    /// keys the server passes through untouched). Reaches the underlying map via
    /// rmcp's deref chain (`RequestMetaObject` → `MetaObject` → JSON object).
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.0.get(key)
    }

    /// The required `io.modelcontextprotocol/protocolVersion`, as rmcp's
    /// spec-tracked [`ProtocolVersion`] (any well-formed string is accepted;
    /// [`crate::router::Router::supports_version`] remains the authoritative gate).
    pub fn protocol_version(&self) -> Option<ProtocolVersion> {
        self.0.protocol_version()
    }

    /// The required `io.modelcontextprotocol/clientCapabilities`, as rmcp's
    /// typed [`ClientCapabilities`].
    pub fn client_capabilities(&self) -> Option<ClientCapabilities> {
        self.0.client_capabilities()
    }

    /// The optional `io.modelcontextprotocol/clientInfo`, as rmcp's typed
    /// [`Implementation`].
    pub fn client_info(&self) -> Option<Implementation> {
        self.0.client_info()
    }

    /// Whether the client negotiated a given extension capability, i.e.
    /// `clientCapabilities.extensions[<id>]` is present (SEP-1724, modeled by
    /// rmcp's [`ClientCapabilities::extensions`]).
    pub fn has_extension_capability(&self, extension_id: &str) -> bool {
        self.client_capabilities()
            .and_then(|c| c.extensions)
            .is_some_and(|exts| exts.contains_key(extension_id))
    }

    /// True when `_meta` carries no keys at all — a cheap signal that it was
    /// omitted entirely.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn params_with_meta(meta: Value) -> Value {
        json!({ "name": "x", "_meta": meta })
    }

    #[test]
    fn reads_reserved_keys() {
        let params = params_with_meta(json!({
            keys::PROTOCOL_VERSION: "2026-07-28",
            keys::CLIENT_CAPABILITIES: { "extensions": { "io.modelcontextprotocol/tasks": {} } },
            keys::CLIENT_INFO: { "name": "demo", "version": "1.0" },
        }));
        let m = Meta::from_params(&params);
        assert_eq!(
            m.protocol_version().as_ref().map(ProtocolVersion::as_str),
            Some("2026-07-28")
        );
        assert!(m.client_info().is_some());
        assert!(m.has_extension_capability("io.modelcontextprotocol/tasks"));
        assert!(!m.has_extension_capability("io.modelcontextprotocol/apps"));
    }

    #[test]
    fn unknown_extension_keys_pass_through() {
        let params = params_with_meta(json!({
            keys::PROTOCOL_VERSION: "2026-07-28",
            "com.example/customTrace": { "id": "abc" },
        }));
        let m = Meta::from_params(&params);
        // A key the server has no typed accessor for is still readable verbatim.
        assert_eq!(m.get("com.example/customTrace").unwrap()["id"], "abc");
    }

    #[test]
    fn missing_meta_is_empty() {
        let m = Meta::from_params(&json!({ "name": "x" }));
        assert!(m.is_empty());
        assert!(m.protocol_version().is_none());
    }
}
