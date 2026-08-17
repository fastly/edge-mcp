//! The stateless dispatch spine: per-request middleware plus method routing.
//!
//! Every request runs the same middleware chain before its method handler:
//!
//! 1. **Protocol version** — read from `_meta` (the body is the source of truth;
//!    the `MCP-Protocol-Version` header is only an untrusted fast-reject hint,
//!    handled upstream in the adapter). Missing → `-32602`; unsupported →
//!    `-32022`.
//! 2. **Client capabilities** — required per request; missing → `-32602`.
//!    Methods that need a negotiated extension (e.g. `tasks/*`) additionally
//!    require that capability → `-32021`.
//! 3. **Method routing** — built-ins and registered handlers. Unknown →
//!    `-32601`.
//!
//! A notification (no `id`) never produces a response, success or error.

use serde_json::Value;

use crate::jsonrpc::{ErrorCode, RpcError, RpcId, RpcRequest, RpcResponse};
use crate::methods;
use crate::router::{RequestCtx, Router};

/// The extension capability a method requires the client to have negotiated,
/// if any. Core methods require none.
fn required_capability(method: &str) -> Option<&'static str> {
    if method.starts_with("tasks/") {
        Some("io.modelcontextprotocol/tasks")
    } else {
        None
    }
}

/// Method-level required scopes for non-tool operations. `tools/call` is scoped
/// per-tool (see [`authorize`]); discovery/list/read return no requirement and
/// are available to any authenticated principal (they are also the only
/// shared-cacheable operations, so nothing scope-gated is ever served from a
/// shared cache).
fn method_scopes(method: &str) -> Vec<String> {
    match method {
        "tasks/get" => vec!["mcp:tasks:read".to_string()],
        "tasks/update" | "tasks/cancel" => vec!["mcp:tasks:write".to_string()],
        _ => Vec::new(),
    }
}

/// Default-deny scope authorization. Enforced only when a principal is present
/// (authentication enabled); anonymous demo mode has no principal and no
/// enforcement. `tools/call` requires the target tool's declared scopes — a
/// tool that declares none is not callable under auth. The principal must hold
/// **all** required scopes.
fn authorize(
    router: &Router,
    ctx: &RequestCtx,
    method: &str,
    params: &Value,
) -> Result<(), RpcError> {
    // `principal_scopes()` does not taint cacheability (authz is not a
    // content dependency on the principal).
    let Some(held) = ctx.principal_scopes() else {
        return Ok(()); // anonymous demo mode: no principal, no scope gate
    };

    let required: Vec<String> = if method == "tools/call" {
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| RpcError::invalid_params("tools/call requires a string params.name"))?;
        match router.tool(name) {
            // Default-deny: a tool with no declared scopes is not callable.
            Some(h) => h.required_scopes(),
            // Unknown tool: let the handler return the canonical invalid_params.
            None => return Ok(()),
        }
    } else {
        method_scopes(method)
    };

    if method == "tools/call" && required.is_empty() {
        return Err(RpcError::insufficient_scope(&[]).with_data(serde_json::json!({
            "requiredScopes": [],
            "reason": "tool declares no required scopes and is not callable under authentication",
        })));
    }

    let missing: Vec<String> = required
        .iter()
        .filter(|s| !held.iter().any(|h| h == *s))
        .cloned()
        .collect();
    if !missing.is_empty() {
        return Err(RpcError::insufficient_scope(&missing));
    }
    Ok(())
}

/// Dispatch a parsed request. Returns `None` for notifications (which never get
/// a response) and `Some(response)` otherwise.
pub fn dispatch(router: &Router, ctx: &RequestCtx, req: &RpcRequest) -> Option<RpcResponse> {
    // A notification carries no `id` and receives no response. None of this
    // server's methods are valid notifications (all are request/response), so a
    // notification must NOT trigger side effects — short-circuit before routing
    // so an id-less tools/call or tasks/* cannot mutate state silently.
    if req.is_notification() {
        return None;
    }

    let outcome = route(router, ctx, req);
    let id = req.id.clone().unwrap_or(RpcId::Null);
    Some(match outcome {
        Ok(value) => RpcResponse::result(id, value),
        Err(err) => RpcResponse::error(id, err),
    })
}

fn route(router: &Router, ctx: &RequestCtx, req: &RpcRequest) -> Result<Value, RpcError> {
    // 0. JSON-RPC version.
    if req.jsonrpc != "2.0" {
        return Err(RpcError::new(
            ErrorCode::INVALID_REQUEST,
            "jsonrpc must be \"2.0\"",
        ));
    }

    // 1. Protocol version (from _meta, per R3). rmcp's `ProtocolVersion` accepts
    //    any well-formed version string; `supports_version` is our authoritative
    //    2026-07-28-only gate (unknown but present version → -32022, not -32602).
    let version = ctx.meta.protocol_version().ok_or_else(|| {
        RpcError::invalid_params(
            "missing required _meta key io.modelcontextprotocol/protocolVersion",
        )
    })?;
    if !router.supports_version(version.as_str()) {
        return Err(RpcError::unsupported_protocol_version(version.as_str()));
    }

    // 2. Client capabilities.
    if ctx.meta.client_capabilities().is_none() {
        return Err(RpcError::invalid_params(
            "missing required _meta key io.modelcontextprotocol/clientCapabilities",
        ));
    }
    if let Some(cap) = required_capability(&req.method) {
        if !ctx.meta.has_extension_capability(cap) {
            return Err(RpcError::missing_required_capability(&[cap]));
        }
    }

    // 3. Authorization (default-deny scope enforcement; no-op in anonymous demo).
    let params = req.params_or_null();
    authorize(router, ctx, &req.method, &params)?;

    // 4. Method routing.
    match req.method.as_str() {
        "tools/call" => methods::call::handle(router, ctx, &params),
        "tools/list" => methods::list::tools(router, ctx, &params),
        "prompts/list" => methods::list::prompts(router, ctx, &params),
        "resources/list" => methods::list::resources(router, ctx, &params),
        "resources/read" => methods::list::read(router, ctx, &params),
        "server/discover" => methods::discover::handle(router, ctx, &params),
        "tasks/get" => methods::tasks::get(router, ctx, &params),
        "tasks/update" => methods::tasks::update(router, ctx, &params),
        "tasks/cancel" => methods::tasks::cancel(router, ctx, &params),
        other => Err(RpcError::method_not_found(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meta::{keys, Meta};
    use crate::result::{CallResult, CallResultExt};
    use crate::router::{RequestCtx, RoutingHeaders, ToolDef, ToolHandler, ToolOutcome};
    use crate::PROTOCOL_VERSION;
    use serde_json::json;

    struct EchoTool;
    impl ToolHandler for EchoTool {
        fn definition(&self) -> ToolDef {
            ToolDef {
                name: "echo".into(),
                title: None,
                description: "echoes its message".into(),
                input_schema: json!({ "type": "object" }),
                output_schema: None,
            }
        }
        fn call(&self, _ctx: &RequestCtx, args: &Value) -> Result<ToolOutcome, RpcError> {
            let msg = args.get("message").and_then(Value::as_str).unwrap_or("");
            Ok(ToolOutcome::Complete(CallResult::text(msg)))
        }
    }

    /// A tool that declares a required scope.
    struct ScopedTool;
    impl ToolHandler for ScopedTool {
        fn definition(&self) -> ToolDef {
            ToolDef {
                name: "scoped".into(),
                title: None,
                description: "requires a scope".into(),
                input_schema: json!({ "type": "object" }),
                output_schema: None,
            }
        }
        fn call(&self, _ctx: &RequestCtx, _args: &Value) -> Result<ToolOutcome, RpcError> {
            Ok(ToolOutcome::Complete(CallResult::text("ok")))
        }
        fn required_scopes(&self) -> Vec<String> {
            vec!["mcp:tools:scoped".into()]
        }
    }

    fn router() -> Router {
        let mut r = Router::new();
        r.register_tool(EchoTool);
        r.register_tool(ScopedTool);
        r
    }

    /// Build a request + matching ctx from a raw JSON-RPC value and a `_meta`.
    /// Anonymous (no principal).
    fn ctx_and_req(body: Value, meta: Value) -> (RequestCtx, RpcRequest) {
        let req: RpcRequest = serde_json::from_value(body).unwrap();
        let meta = Meta::from_params(&json!({ "_meta": meta }));
        (
            RequestCtx::new(meta, None, RoutingHeaders::default()),
            req,
        )
    }

    /// Build a request + ctx carrying an authenticated principal with `scopes`.
    fn ctx_and_req_auth(body: Value, scopes: &[&str]) -> (RequestCtx, RpcRequest) {
        let req: RpcRequest = serde_json::from_value(body).unwrap();
        let meta = Meta::from_params(&json!({ "_meta": good_meta() }));
        let principal = crate::auth::Principal {
            issuer: "iss".into(),
            subject: "u1".into(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            claims: Default::default(),
        };
        (
            RequestCtx::new(meta, Some(principal), RoutingHeaders::default()),
            req,
        )
    }

    fn good_meta() -> Value {
        json!({
            keys::PROTOCOL_VERSION: PROTOCOL_VERSION,
            keys::CLIENT_CAPABILITIES: {},
        })
    }

    #[test]
    fn routes_tools_call_to_handler() {
        // Anonymous (demo) mode: no principal, no scope gate.
        let (ctx, req) = ctx_and_req(
            json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
                   "params":{"name":"echo","arguments":{"message":"hi"}}}),
            good_meta(),
        );
        let resp = dispatch(&router(), &ctx, &req).unwrap();
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["result"]["resultType"], "complete");
        assert_eq!(v["result"]["content"][0]["text"], "hi");
        assert!(v.get("error").is_none());
    }

    #[test]
    fn authz_tool_without_declared_scopes_is_denied_under_auth() {
        // EchoTool declares no scopes -> default-deny once a principal is present.
        let (ctx, req) = ctx_and_req_auth(
            json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}}),
            &["mcp:tools:scoped"],
        );
        let v = serde_json::to_value(dispatch(&router(), &ctx, &req).unwrap()).unwrap();
        assert_eq!(v["error"]["code"], -32023);
    }

    #[test]
    fn authz_wrong_scope_is_denied() {
        let (ctx, req) = ctx_and_req_auth(
            json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"scoped"}}),
            &["mcp:tools:something-else"],
        );
        let v = serde_json::to_value(dispatch(&router(), &ctx, &req).unwrap()).unwrap();
        assert_eq!(v["error"]["code"], -32023);
        assert_eq!(v["error"]["data"]["requiredScopes"][0], "mcp:tools:scoped");
    }

    #[test]
    fn authz_correct_scope_is_allowed() {
        let (ctx, req) = ctx_and_req_auth(
            json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"scoped"}}),
            &["mcp:tools:scoped"],
        );
        let v = serde_json::to_value(dispatch(&router(), &ctx, &req).unwrap()).unwrap();
        assert_eq!(v["result"]["resultType"], "complete");
    }

    #[test]
    fn authz_tasks_get_requires_read_scope() {
        // Missing scope -> denied before the handler runs (no signer/store needed).
        let (ctx, req) = ctx_and_req_auth(
            json!({"jsonrpc":"2.0","id":1,"method":"tasks/get","params":{"taskId":"x"}}),
            &["mcp:tools:scoped"],
        );
        // Negotiate the tasks capability so the capability check passes first.
        let meta = Meta::from_params(&json!({"_meta":{
            keys::PROTOCOL_VERSION: PROTOCOL_VERSION,
            keys::CLIENT_CAPABILITIES: { "extensions": { "io.modelcontextprotocol/tasks": {} } }
        }}));
        let principal = crate::auth::Principal {
            issuer: "iss".into(), subject: "u1".into(),
            scopes: vec!["mcp:tools:scoped".into()], claims: Default::default(),
        };
        let ctx = RequestCtx::new(meta, Some(principal), ctx.headers.clone());
        let v = serde_json::to_value(dispatch(&router(), &ctx, &req).unwrap()).unwrap();
        assert_eq!(v["error"]["code"], -32023);
        assert_eq!(v["error"]["data"]["requiredScopes"][0], "mcp:tasks:read");
    }

    #[test]
    fn authz_does_not_taint_cacheability() {
        // A scope check on a list method must not make the response uncacheable.
        let (ctx, req) = ctx_and_req_auth(
            json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
            &["mcp:tools:scoped"],
        );
        let _ = dispatch(&router(), &ctx, &req);
        assert!(ctx.is_cacheable(), "authz scope read must not taint cacheability");
    }

    #[test]
    fn unknown_method_is_method_not_found() {
        let (ctx, req) = ctx_and_req(
            json!({"jsonrpc":"2.0","id":1,"method":"does/notexist"}),
            good_meta(),
        );
        let resp = dispatch(&router(), &ctx, &req).unwrap();
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["error"]["code"], -32601);
    }

    #[test]
    fn unknown_tool_name_is_invalid_params() {
        let (ctx, req) = ctx_and_req(
            json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nope"}}),
            good_meta(),
        );
        let resp = dispatch(&router(), &ctx, &req).unwrap();
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["error"]["code"], -32602);
    }

    #[test]
    fn unsupported_protocol_version_is_32022() {
        let (ctx, req) = ctx_and_req(
            json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}}),
            json!({ keys::PROTOCOL_VERSION: "1999-01-01", keys::CLIENT_CAPABILITIES: {} }),
        );
        let resp = dispatch(&router(), &ctx, &req).unwrap();
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["error"]["code"], -32022);
    }

    #[test]
    fn missing_protocol_version_is_invalid_params() {
        let (ctx, req) = ctx_and_req(
            json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}}),
            json!({ keys::CLIENT_CAPABILITIES: {} }),
        );
        let resp = dispatch(&router(), &ctx, &req).unwrap();
        assert_eq!(serde_json::to_value(&resp).unwrap()["error"]["code"], -32602);
    }

    #[test]
    fn tasks_method_without_capability_is_32021() {
        let (ctx, req) = ctx_and_req(
            json!({"jsonrpc":"2.0","id":1,"method":"tasks/get","params":{"taskId":"x"}}),
            good_meta(), // no tasks extension negotiated
        );
        let resp = dispatch(&router(), &ctx, &req).unwrap();
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["error"]["code"], -32021);
        assert_eq!(
            v["error"]["data"]["requiredCapabilities"][0],
            "io.modelcontextprotocol/tasks"
        );
    }

    #[test]
    fn notification_produces_no_response() {
        let (ctx, req) = ctx_and_req(
            json!({"jsonrpc":"2.0","method":"tools/call","params":{"name":"echo"}}),
            good_meta(),
        );
        assert!(dispatch(&router(), &ctx, &req).is_none());
    }

    #[test]
    fn dispatch_is_stateless_across_fresh_routers() {
        let body = json!({"jsonrpc":"2.0","id":9,"method":"tools/call",
                          "params":{"name":"echo","arguments":{"message":"x"}}});
        let (ctx1, req1) = ctx_and_req(body.clone(), good_meta());
        let (ctx2, req2) = ctx_and_req(body, good_meta());
        let a = serde_json::to_value(dispatch(&router(), &ctx1, &req1).unwrap()).unwrap();
        let b = serde_json::to_value(dispatch(&router(), &ctx2, &req2).unwrap()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn capability_taint_not_triggered_by_dispatch_without_principal() {
        // A no-principal request stays cacheable through dispatch middleware.
        let (ctx, req) = ctx_and_req(
            json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
                   "params":{"name":"echo","arguments":{"message":"hi"}}}),
            good_meta(),
        );
        let _ = dispatch(&router(), &ctx, &req);
        assert!(ctx.is_cacheable());
    }
}
