//! `tools/list`, `prompts/list`, `resources/list`, and `resources/read`.
//!
//! These are generated from the [`Router`] registry, so their cache metadata
//! (`ttlMs` / `cacheScope`) and pagination stay consistent. The registry-derived
//! listings are principal-independent, so they mark the request cacheable and
//! advertise `cacheScope: "public"`. A `resources/read` handler that consults
//! the principal taints cacheability (see [`crate::router::RequestCtx`]), and
//! this code downgrades its `cacheScope` to `"private"` accordingly.

use serde_json::{json, Value};

use crate::jsonrpc::RpcError;
use crate::methods::{paginate, CACHE_SCOPE_PRIVATE, CACHE_SCOPE_PUBLIC, DEFAULT_LIST_TTL_MS};
use crate::router::{RequestCtx, Router};

fn cursor_of(params: &Value) -> Option<&str> {
    params.get("cursor").and_then(Value::as_str)
}

/// Choose the `cacheScope` for a response based on whether the request stayed
/// principal-independent.
fn scope_for(ctx: &RequestCtx) -> &'static str {
    if ctx.is_cacheable() {
        CACHE_SCOPE_PUBLIC
    } else {
        CACHE_SCOPE_PRIVATE
    }
}

fn list_result(items: Vec<Value>, key: &str, next: Option<String>, ctx: &RequestCtx) -> Value {
    let mut obj = serde_json::Map::new();
    obj.insert("resultType".into(), json!("complete"));
    obj.insert(key.into(), Value::Array(items));
    if let Some(cursor) = next {
        obj.insert("nextCursor".into(), json!(cursor));
    }
    obj.insert("ttlMs".into(), json!(DEFAULT_LIST_TTL_MS));
    obj.insert("cacheScope".into(), json!(scope_for(ctx)));
    Value::Object(obj)
}

/// Shared body for the three `*/list` methods: registry-derived listings are
/// principal-independent (cacheable, `public`), paginated, and keyed by `key`.
fn list_defs<T: serde::Serialize>(
    defs: Vec<T>,
    key: &str,
    ctx: &RequestCtx,
    params: &Value,
    page_size: usize,
) -> Result<Value, RpcError> {
    ctx.mark_principal_independent();
    let (page, next) = paginate(defs, cursor_of(params), page_size)?;
    let items = page
        .into_iter()
        .map(|d| serde_json::to_value(d).unwrap())
        .collect();
    Ok(list_result(items, key, next, ctx))
}

pub fn tools(router: &Router, ctx: &RequestCtx, params: &Value) -> Result<Value, RpcError> {
    list_defs(router.tool_defs(), "tools", ctx, params, router.list_page_size())
}

pub fn prompts(router: &Router, ctx: &RequestCtx, params: &Value) -> Result<Value, RpcError> {
    list_defs(router.prompt_defs(), "prompts", ctx, params, router.list_page_size())
}

pub fn resources(router: &Router, ctx: &RequestCtx, params: &Value) -> Result<Value, RpcError> {
    list_defs(router.resource_defs(), "resources", ctx, params, router.list_page_size())
}

/// `resources/read` — dispatch into the resource handler by `params.uri`.
pub fn read(router: &Router, ctx: &RequestCtx, params: &Value) -> Result<Value, RpcError> {
    let uri = params
        .get("uri")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params("resources/read requires a string params.uri"))?;
    let handler = router
        .resource(uri)
        .ok_or_else(|| RpcError::invalid_params(format!("unknown resource: {uri}")))?;

    // Registry-derived read is principal-independent unless the handler reads the
    // principal (which taints and flips the scope below).
    ctx.mark_principal_independent();
    let contents = handler.read(ctx)?;

    Ok(json!({
        "resultType": "complete",
        "contents": contents,
        "ttlMs": DEFAULT_LIST_TTL_MS,
        "cacheScope": scope_for(ctx),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Principal;
    use crate::meta::{keys, Meta};
    use crate::router::{
        RequestCtx, ResourceDef, ResourceHandler, RoutingHeaders, ToolDef, ToolHandler, ToolOutcome,
    };
    use crate::result::{CallResult, CallResultExt};
    use crate::PROTOCOL_VERSION;

    struct T(&'static str);
    impl ToolHandler for T {
        fn definition(&self) -> ToolDef {
            ToolDef {
                name: self.0.into(),
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

    struct PublicRes;
    impl ResourceHandler for PublicRes {
        fn definition(&self) -> ResourceDef {
            ResourceDef {
                uri: "mcp://public".into(),
                name: "public".into(),
                description: None,
                mime_type: Some("text/plain".into()),
            }
        }
        fn read(&self, _ctx: &RequestCtx) -> Result<Value, RpcError> {
            Ok(json!([{ "uri": "mcp://public", "text": "hello" }]))
        }
    }

    struct PrivateRes;
    impl ResourceHandler for PrivateRes {
        fn definition(&self) -> ResourceDef {
            ResourceDef {
                uri: "mcp://me".into(),
                name: "me".into(),
                description: None,
                mime_type: None,
            }
        }
        fn read(&self, ctx: &RequestCtx) -> Result<Value, RpcError> {
            // Reading the principal taints cacheability -> cacheScope private.
            let sub = ctx.principal().map(|p| p.subject.clone()).unwrap_or_default();
            Ok(json!([{ "uri": "mcp://me", "text": format!("hi {sub}") }]))
        }
    }

    fn ctx(principal: Option<Principal>) -> RequestCtx {
        let meta = Meta::from_params(&json!({"_meta":{
            keys::PROTOCOL_VERSION: PROTOCOL_VERSION, keys::CLIENT_CAPABILITIES: {}
        }}));
        RequestCtx::new(meta, principal, RoutingHeaders::default())
    }

    fn a_principal() -> Principal {
        Principal {
            issuer: "iss".into(),
            subject: "sub-1".into(),
            scopes: vec![],
            claims: Default::default(),
        }
    }

    #[test]
    fn tools_list_shape_with_cache_metadata() {
        let mut r = Router::new();
        r.register_tool(T("a")).register_tool(T("b"));
        let out = tools(&r, &ctx(None), &json!({})).unwrap();
        assert_eq!(out["resultType"], "complete");
        assert_eq!(out["cacheScope"], "public");
        assert_eq!(out["ttlMs"], DEFAULT_LIST_TTL_MS);
        assert_eq!(out["tools"].as_array().unwrap().len(), 2);
        assert!(out.get("nextCursor").is_none());
    }

    #[test]
    fn tools_list_paginates() {
        let mut r = Router::new();
        r.register_tool(T("a")).register_tool(T("b")).register_tool(T("c"));
        r.with_list_page_size(2);
        let p1 = tools(&r, &ctx(None), &json!({})).unwrap();
        assert_eq!(p1["tools"].as_array().unwrap().len(), 2);
        let cursor = p1["nextCursor"].as_str().unwrap().to_string();
        let p2 = tools(&r, &ctx(None), &json!({ "cursor": cursor })).unwrap();
        assert_eq!(p2["tools"].as_array().unwrap().len(), 1);
        assert!(p2.get("nextCursor").is_none(), "exhausted cursor omits nextCursor");
    }

    #[test]
    fn resources_read_public_is_public_scope() {
        let mut r = Router::new();
        r.register_resource(PublicRes);
        let out = read(&r, &ctx(None), &json!({ "uri": "mcp://public" })).unwrap();
        assert_eq!(out["cacheScope"], "public");
        assert_eq!(out["contents"][0]["text"], "hello");
    }

    #[test]
    fn resources_read_principal_scoped_is_private() {
        let mut r = Router::new();
        r.register_resource(PrivateRes);
        let out = read(&r, &ctx(Some(a_principal())), &json!({ "uri": "mcp://me" })).unwrap();
        assert_eq!(out["cacheScope"], "private", "reading principal must downgrade scope");
        assert_eq!(out["contents"][0]["text"], "hi sub-1");
    }

    #[test]
    fn read_unknown_resource_is_invalid_params() {
        let r = Router::new();
        let err = read(&r, &ctx(None), &json!({ "uri": "mcp://nope" })).unwrap_err();
        assert_eq!(err.code, -32602);
    }

    /// Drift tripwire: our `tools/list` envelope (and its tool items) must be a
    /// valid `rmcp::model::ListToolsResult` — same discriminator, cache fields
    /// (SEP-2549: ttlMs/cacheScope live in the body), pagination, and Tool item
    /// shape. Round-tripping through the SDK type proves wire compatibility, so
    /// we keep the generic hand-built builder without drifting from the spec.
    #[test]
    fn tools_list_envelope_matches_rmcp_list_tools_result() {
        let mut r = Router::new();
        r.register_tool(T("a")).register_tool(T("b"));
        let out = tools(&r, &ctx(None), &json!({})).unwrap();
        let parsed: rmcp::model::ListToolsResult =
            serde_json::from_value(out).expect("our tools/list is a valid rmcp ListToolsResult");
        assert_eq!(parsed.result_type, Some(rmcp::model::ResultType::COMPLETE));
        assert_eq!(parsed.tools.len(), 2);
        assert_eq!(parsed.cache_scope, Some(rmcp::model::CacheScope::Public));
        assert!(parsed.ttl_ms.is_some());
    }

    /// Drift tripwire: our `resources/read` envelope must be a valid
    /// `rmcp::model::ReadResourceResult` (resultType / ttlMs / cacheScope /
    /// contents field names track the SDK).
    #[test]
    fn read_envelope_matches_rmcp_read_resource_result() {
        let mut r = Router::new();
        r.register_resource(PublicRes);
        let out = read(&r, &ctx(None), &json!({ "uri": "mcp://public" })).unwrap();
        let parsed: rmcp::model::ReadResourceResult =
            serde_json::from_value(out).expect("our resources/read is a valid rmcp ReadResourceResult");
        assert_eq!(parsed.result_type, Some(rmcp::model::ResultType::COMPLETE));
        assert_eq!(parsed.cache_scope, Some(rmcp::model::CacheScope::Public));
        assert_eq!(parsed.contents.len(), 1);
    }
}
