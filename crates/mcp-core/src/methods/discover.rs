//! `server/discover` — the optional upfront capability-discovery RPC that
//! replaces the retired handshake.
//!
//! The result is the SDK's spec-tracked [`rmcp::model::DiscoverResult`]: the
//! `supportedVersions` array, the typed capability set (which method families
//! are registered) with any negotiated extensions under
//! `capabilities.extensions`, the `ttlMs`/`cacheScope` freshness hints
//! (SEP-2549), and `serverInfo` carried in `_meta`
//! (`io.modelcontextprotocol/serverInfo`). It is principal-independent and
//! cacheable.

use rmcp::model::{
    CacheScope, DiscoverResult, ExtensionCapabilities, Implementation, JsonObject,
    ProtocolVersion, PromptsCapability, ResourcesCapability, ServerCapabilities, ToolsCapability,
};
use serde_json::Value;

use crate::jsonrpc::RpcError;
use crate::methods::DEFAULT_LIST_TTL_MS;
use crate::router::{RequestCtx, Router};

pub fn handle(router: &Router, ctx: &RequestCtx, _params: &Value) -> Result<Value, RpcError> {
    ctx.mark_principal_independent();

    let mut capabilities = ServerCapabilities::default();
    if router.has_tools() {
        capabilities.tools = Some(ToolsCapability::default());
    }
    if router.has_prompts() {
        capabilities.prompts = Some(PromptsCapability::default());
    }
    if router.has_resources() {
        capabilities.resources = Some(ResourcesCapability::default());
    }
    if !router.extensions().is_empty() {
        let mut exts = ExtensionCapabilities::new();
        for id in router.extensions() {
            exts.insert(id.clone(), JsonObject::new());
        }
        capabilities.extensions = Some(exts);
    }

    let mut result = DiscoverResult::new(vec![ProtocolVersion::V_2026_07_28], capabilities)
        .with_ttl_ms(DEFAULT_LIST_TTL_MS)
        .with_cache_scope(CacheScope::Public);
    // serverInfo travels in `_meta` (io.modelcontextprotocol/serverInfo) per the
    // 2026-07-28 spec. Skip it if the configured value is not a well-formed
    // Implementation rather than emitting a malformed field.
    if let Some(info) = router.server_info() {
        if let Ok(implementation) = serde_json::from_value::<Implementation>(info.clone()) {
            result = result.with_server_info(implementation);
        }
    }

    Ok(serde_json::to_value(result).unwrap_or(Value::Null))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meta::{keys, Meta};
    use crate::result::{CallResult, CallResultExt};
    use crate::router::{RequestCtx, RoutingHeaders, ToolDef, ToolHandler, ToolOutcome};
    use crate::PROTOCOL_VERSION;
    use serde_json::json;

    struct T;
    impl ToolHandler for T {
        fn definition(&self) -> ToolDef {
            ToolDef {
                name: "t".into(),
                title: None,
                description: "t".into(),
                input_schema: json!({"type":"object"}),
                output_schema: None,
            }
        }
        fn call(&self, _: &RequestCtx, _: &Value) -> Result<ToolOutcome, RpcError> {
            Ok(ToolOutcome::Complete(CallResult::text("x")))
        }
    }

    fn ctx() -> RequestCtx {
        let meta = Meta::from_params(&json!({"_meta":{
            keys::PROTOCOL_VERSION: PROTOCOL_VERSION, keys::CLIENT_CAPABILITIES: {}
        }}));
        RequestCtx::new(meta, None, RoutingHeaders::default())
    }

    #[test]
    fn advertises_extensions_when_registered() {
        let mut r = Router::new();
        r.register_tool(T);
        r.register_extension("io.modelcontextprotocol/tasks");
        let out = handle(&r, &ctx(), &json!({})).unwrap();
        assert_eq!(out["resultType"], "complete");
        // supportedVersions is an array of protocol versions (rmcp DiscoverResult),
        // not the old singular `protocolVersion` string.
        assert_eq!(out["supportedVersions"][0], PROTOCOL_VERSION);
        assert_eq!(out["capabilities"]["tools"], json!({}));
        assert_eq!(
            out["capabilities"]["extensions"]["io.modelcontextprotocol/tasks"],
            json!({})
        );
        assert_eq!(out["cacheScope"], "public");
        assert_eq!(out["ttlMs"], DEFAULT_LIST_TTL_MS);
    }

    #[test]
    fn omits_extensions_when_none() {
        let r = Router::new();
        let out = handle(&r, &ctx(), &json!({})).unwrap();
        assert!(out["capabilities"].get("extensions").is_none());
    }

    #[test]
    fn server_info_travels_in_meta() {
        let mut r = Router::new();
        r.register_tool(T);
        r.with_server_info(json!({ "name": "demo", "version": "1.2.3" }));
        let out = handle(&r, &ctx(), &json!({})).unwrap();
        // Not at the top level anymore — carried under _meta per the spec.
        assert!(out.get("serverInfo").is_none());
        assert_eq!(out["_meta"]["io.modelcontextprotocol/serverInfo"]["name"], "demo");
        assert_eq!(out["_meta"]["io.modelcontextprotocol/serverInfo"]["version"], "1.2.3");
    }
}
