//! `tools/call` — dispatch into a registered tool handler, handle the MRTR
//! round trip, and serialize the outcome.

use serde_json::Value;

use crate::idempotency::{self, Reservation};
use crate::jsonrpc::RpcError;
use crate::mrtr::{self, Continuation};
use crate::router::{RequestCtx, Router, ToolOutcome};
use crate::tasks::{self, Task, TaskHandle, TaskStatus};

/// Handle a `tools/call` request.
///
/// * First call: `params.arguments` is passed to the tool.
/// * MRTR retry: `params.requestState` (an opaque token) is opened and
///   validated, its carried arguments are merged with `params.inputResponses`,
///   and the tool is resumed.
///
/// A tool-execution failure is reported inside the result (`isError: true`);
/// only protocol-level problems (unknown tool, bad params, invalid token)
/// surface as a JSON-RPC error.
pub fn handle(router: &Router, ctx: &RequestCtx, params: &Value) -> Result<Value, RpcError> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params("tools/call requires a string params.name"))?;

    let handler = router
        .tool(name)
        .ok_or_else(|| RpcError::invalid_params(format!("unknown tool: {name}")))?;

    // Resolve the effective arguments: either a fresh call or an MRTR resume.
    let arguments = match params.get("requestState").and_then(Value::as_str) {
        Some(token) => {
            let signer = signer(router)?;
            // Binding is checked against the current request's principal.
            let principal = ctx.principal().map(|p| p.id());
            let cont = mrtr::open_continuation(signer, token, ctx.now_unix(), principal, name)?;
            let Continuation { arguments, requested, .. } = cont;
            mrtr::merge_input_responses(arguments, params.get("inputResponses"), &requested)
        }
        // Absent arguments default to an empty object so schema validation and
        // handlers see a consistent shape.
        None => params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| Value::Object(Default::default())),
    };

    // Enforce the advertised input contract centrally, before the handler runs,
    // so client/model input cannot contradict it (CMCP-010).
    let def = handler.definition();
    crate::schema::validate(&def.input_schema, &arguments)
        .map_err(|e| RpcError::invalid_params(format!("arguments do not match inputSchema: {e}")))?;

    // Idempotency (CMCP-006): if the client supplies an idempotencyKey and the
    // server has an idempotency store, make execution exactly-once — replay a
    // stored result for duplicates instead of re-running the side effect.
    match (
        params.get("idempotencyKey").and_then(Value::as_str),
        router.idempotency_store(),
    ) {
        (Some(client_key), Some(store)) => {
            let (iss, sub) = ctx
                .principal()
                .map(|p| (p.issuer.clone(), p.subject.clone()))
                .unwrap_or_default();
            let key = idempotency::scope_key(&iss, &sub, name, client_key);
            match store
                .reserve(&key)
                .map_err(|e| RpcError::internal(format!("idempotency reserve: {e}")))?
            {
                Reservation::Cached(v) => Ok(v),
                Reservation::InProgress => Err(RpcError::invalid_params(
                    "a request with this idempotencyKey is already in progress",
                )),
                Reservation::Won => match execute_outcome(router, ctx, handler, name, &def, &arguments) {
                    Ok((value, terminal)) => {
                        // Only cache terminal side-effecting results; release the
                        // reservation for input_required / task outcomes so a
                        // legitimate follow-up can proceed.
                        if terminal {
                            store
                                .complete(&key, &value)
                                .map_err(|e| RpcError::internal(format!("idempotency complete: {e}")))?;
                        } else {
                            let _ = store.release(&key);
                        }
                        Ok(value)
                    }
                    Err(e) => {
                        let _ = store.release(&key);
                        Err(e)
                    }
                },
            }
        }
        _ => execute_outcome(router, ctx, handler, name, &def, &arguments).map(|(v, _)| v),
    }
}

/// Execute the resolved tool call and serialize its outcome. Returns the result
/// value plus `terminal` — true for a completed side-effecting result (safe to
/// cache for idempotency), false for `input_required` / `task` outcomes.
#[allow(clippy::borrowed_box)]
fn execute_outcome(
    router: &Router,
    ctx: &RequestCtx,
    handler: &dyn crate::router::ToolHandler,
    name: &str,
    def: &crate::router::ToolDef,
    arguments: &Value,
) -> Result<(Value, bool), RpcError> {
    match handler.call(ctx, arguments)? {
        ToolOutcome::Complete(result) => {
            // If the tool advertises an outputSchema and returned structured
            // content, validate the output too (guards against contract drift).
            if let (Some(out_schema), Some(structured)) =
                (def.output_schema.as_ref(), result.structured_content.as_ref())
            {
                crate::schema::validate(out_schema, structured).map_err(|e| {
                    RpcError::internal(format!("tool output violates outputSchema: {e}"))
                })?;
            }
            let v = serde_json::to_value(result)
                .map_err(|e| RpcError::internal(format!("failed to serialize call result: {e}")))?;
            Ok((v, true))
        }
        ToolOutcome::InputRequired(ir) => {
            let signer = signer(router)?;
            let (issuer, subject) = ctx
                .principal()
                .map(|p| (p.issuer.clone(), p.subject.clone()))
                .unwrap_or_default();
            let requested: Vec<String> = ir.input_requests.keys().cloned().collect();
            let cont = Continuation {
                tool: name.to_string(),
                issuer,
                subject,
                expires_at: ctx.now_unix() + mrtr::DEFAULT_REQUEST_STATE_TTL_SECS,
                arguments: ir.arguments_so_far,
                requested,
            };
            let token = mrtr::seal_continuation(signer, &cont)?;
            Ok((mrtr::input_required_result(ir.input_requests, token), false))
        }
        ToolOutcome::Task(creation) => {
            let signer = signer(router)?;
            let store = router
                .task_store()
                .ok_or_else(|| RpcError::internal("server is not configured for Tasks"))?;

            let (issuer, subject) = ctx
                .principal()
                .map(|p| (p.issuer.clone(), p.subject.clone()))
                .unwrap_or_default();
            let now = ctx.now_unix();
            let id = tasks::new_storage_id()?;
            // Round sub-second TTLs up so a small ttl_ms never yields an
            // already-expired task (expires_at == created_at).
            let expires_at = now + creation.ttl_ms.div_ceil(1000);

            let status = if creation.input_requests.is_some() {
                TaskStatus::InputRequired
            } else {
                TaskStatus::Working
            };
            let task = Task {
                id: id.clone(),
                status,
                tool: name.to_string(),
                issuer: issuer.clone(),
                subject: subject.clone(),
                created_at: now,
                expires_at,
                ttl_ms: creation.ttl_ms,
                poll_interval_ms: creation.poll_interval_ms,
                result: None,
                error: None,
                input_requests: creation.input_requests,
                input_responses: None,
                ready_at: creation.ready_at,
                pending_result: creation.pending_result,
            };

            // Durably persist before responding.
            store
                .create(&task)
                .map_err(|e| RpcError::internal(format!("persist task: {e}")))?;

            let handle = tasks::seal_handle(
                signer,
                &TaskHandle {
                    id,
                    issuer,
                    subject,
                    expires_at,
                },
            )?;
            Ok((task.to_create_result(&handle), false))
        }
    }
}

fn signer(router: &Router) -> Result<&dyn mrtr::Signer, RpcError> {
    router
        .signer()
        .ok_or_else(|| RpcError::internal("server is not configured with a token signer (MRTR/Tasks)"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Principal;
    use crate::meta::{keys, Meta};
    use crate::mrtr::{InputRequired, Signer, SignerError};
    use crate::result::{CallResult, CallResultExt};
    use crate::router::{RequestCtx, RoutingHeaders, ToolDef, ToolHandler};
    use crate::PROTOCOL_VERSION;
    use serde_json::{json, Map};

    /// Reversible test signer (integrity via a keyed checksum).
    struct TestSigner;
    impl Signer for TestSigner {
        fn seal(&self, plaintext: &[u8]) -> Result<String, SignerError> {
            use std::fmt::Write;
            let mut hex = String::new();
            for b in plaintext {
                write!(hex, "{b:02x}").unwrap();
            }
            let sum: u32 = plaintext.iter().map(|b| *b as u32).sum();
            Ok(format!("{hex}.{sum:08x}"))
        }
        fn open(&self, token: &str) -> Result<Vec<u8>, SignerError> {
            let (hex, mac) = token.split_once('.').ok_or_else(|| SignerError("m".into()))?;
            let bytes: Vec<u8> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
                .collect::<Result<_, _>>()
                .map_err(|_| SignerError("hex".into()))?;
            let sum: u32 = bytes.iter().map(|b| *b as u32).sum();
            if format!("{sum:08x}") != mac {
                return Err(SignerError("integrity".into()));
            }
            Ok(bytes)
        }
    }

    /// A tool that needs `city` before it can answer.
    struct WeatherTool;
    impl ToolHandler for WeatherTool {
        fn definition(&self) -> ToolDef {
            ToolDef {
                name: "weather".into(),
                title: None,
                description: "weather".into(),
                input_schema: json!({"type":"object"}),
                output_schema: None,
            }
        }
        fn call(&self, _ctx: &RequestCtx, args: &Value) -> Result<ToolOutcome, RpcError> {
            match args.get("city").and_then(Value::as_str) {
                Some(city) => Ok(ToolOutcome::Complete(CallResult::text(format!(
                    "sunny in {city}"
                )))),
                None => {
                    let mut reqs = Map::new();
                    reqs.insert("city".into(), json!({ "method": "elicitation/create" }));
                    Ok(ToolOutcome::InputRequired(InputRequired::new(
                        reqs,
                        args.clone(),
                    )))
                }
            }
        }
    }

    fn router() -> Router {
        let mut r = Router::new();
        r.register_tool(WeatherTool);
        r.with_signer(Box::new(TestSigner));
        r
    }

    fn ctx(principal: Option<Principal>, now: u64) -> RequestCtx {
        let meta = Meta::from_params(&json!({"_meta":{
            keys::PROTOCOL_VERSION: PROTOCOL_VERSION, keys::CLIENT_CAPABILITIES: {}
        }}));
        RequestCtx::new(meta, principal, RoutingHeaders::default()).with_now_unix(now)
    }

    fn principal() -> Principal {
        Principal {
            issuer: "iss".into(),
            subject: "u1".into(),
            scopes: vec![],
            claims: Default::default(),
        }
    }

    #[test]
    fn first_call_missing_input_returns_input_required() {
        let out = handle(&router(), &ctx(Some(principal()), 1000), &json!({"name":"weather"})).unwrap();
        assert_eq!(out["resultType"], "input_required");
        assert!(out["inputRequests"]["city"].is_object());
        assert!(!out["requestState"].as_str().unwrap().is_empty());
    }

    #[test]
    fn retry_with_input_responses_resumes_and_completes() {
        let r = router();
        // First call -> input_required + requestState.
        let first = handle(&r, &ctx(Some(principal()), 1000), &json!({"name":"weather"})).unwrap();
        let token = first["requestState"].as_str().unwrap().to_string();

        // Retry with the answer + echoed requestState (same principal).
        let retry = json!({
            "name": "weather",
            "requestState": token,
            "inputResponses": { "city": { "action": "accept", "content": "NYC" } }
        });
        let out = handle(&r, &ctx(Some(principal()), 1010), &retry).unwrap();
        assert_eq!(out["resultType"], "complete");
        assert_eq!(out["content"][0]["text"], "sunny in NYC");
    }

    #[test]
    fn retry_from_different_principal_is_rejected() {
        let r = router();
        let first = handle(&r, &ctx(Some(principal()), 1000), &json!({"name":"weather"})).unwrap();
        let token = first["requestState"].as_str().unwrap().to_string();

        let other = Principal {
            issuer: "iss".into(),
            subject: "attacker".into(),
            scopes: vec![],
            claims: Default::default(),
        };
        let retry = json!({
            "name": "weather", "requestState": token,
            "inputResponses": { "city": { "action": "accept", "content": "NYC" } }
        });
        let err = handle(&r, &ctx(Some(other), 1010), &retry).unwrap_err();
        assert_eq!(err.data.unwrap()["reason"], "principal_changed");
    }

    #[test]
    fn mrtr_without_signer_is_internal_error() {
        let mut r = Router::new();
        r.register_tool(WeatherTool); // no signer installed
        let err = handle(&r, &ctx(None, 1000), &json!({"name":"weather"})).unwrap_err();
        assert_eq!(err.code, -32603);
    }

    // --- Idempotency (CMCP-006) ------------------------------------------

    use crate::idempotency::{IdempotencyError, IdempotencyStore, Reservation};
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;
    use std::rc::Rc;

    /// A tool that counts how many times it actually executed a side effect.
    struct CountingTool(Rc<Cell<u32>>);
    impl ToolHandler for CountingTool {
        fn definition(&self) -> ToolDef {
            ToolDef {
                name: "count".into(),
                title: None,
                description: "counts executions".into(),
                input_schema: json!({ "type": "object" }),
                output_schema: None,
            }
        }
        fn call(&self, _ctx: &RequestCtx, _args: &Value) -> Result<ToolOutcome, RpcError> {
            let n = self.0.get() + 1;
            self.0.set(n);
            Ok(ToolOutcome::Complete(CallResult::text(format!("run {n}"))))
        }
    }

    /// Atomic in-memory idempotency store: pending marker + completed result.
    #[derive(Default)]
    struct MemIdem {
        map: RefCell<HashMap<String, Option<Value>>>, // None = pending, Some = complete
    }
    impl IdempotencyStore for MemIdem {
        fn reserve(&self, key: &str) -> Result<Reservation, IdempotencyError> {
            let mut m = self.map.borrow_mut();
            match m.get(key) {
                Some(Some(v)) => Ok(Reservation::Cached(v.clone())),
                Some(None) => Ok(Reservation::InProgress),
                None => {
                    m.insert(key.to_string(), None); // reserve pending
                    Ok(Reservation::Won)
                }
            }
        }
        fn complete(&self, key: &str, result: &Value) -> Result<(), IdempotencyError> {
            self.map.borrow_mut().insert(key.to_string(), Some(result.clone()));
            Ok(())
        }
        fn release(&self, key: &str) -> Result<(), IdempotencyError> {
            self.map.borrow_mut().remove(key);
            Ok(())
        }
    }

    #[test]
    fn idempotent_replay_returns_cached_without_re_executing() {
        let counter = Rc::new(Cell::new(0));
        let mut r = Router::new();
        r.register_tool(CountingTool(counter.clone()));
        r.with_signer(Box::new(TestSigner));
        r.with_idempotency_store(Box::new(MemIdem::default()));

        let body = json!({"name":"count","idempotencyKey":"abc"});
        let first = handle(&r, &ctx(Some(principal()), 1000), &body).unwrap();
        let second = handle(&r, &ctx(Some(principal()), 1001), &body).unwrap();

        assert_eq!(first["content"][0]["text"], "run 1");
        assert_eq!(second["content"][0]["text"], "run 1", "replay returns the cached result");
        assert_eq!(counter.get(), 1, "side effect executed exactly once");
    }

    #[test]
    fn idempotency_scoped_per_principal() {
        let counter = Rc::new(Cell::new(0));
        let mut r = Router::new();
        r.register_tool(CountingTool(counter.clone()));
        r.with_signer(Box::new(TestSigner));
        r.with_idempotency_store(Box::new(MemIdem::default()));

        let body = json!({"name":"count","idempotencyKey":"abc"});
        let _ = handle(&r, &ctx(Some(principal()), 1000), &body).unwrap();
        let other = Principal { issuer: "iss".into(), subject: "u2".into(), scopes: vec![], claims: Default::default() };
        let out = handle(&r, &ctx(Some(other), 1001), &body).unwrap();
        // Different principal, same client key -> not a replay; executes again.
        assert_eq!(out["content"][0]["text"], "run 2");
        assert_eq!(counter.get(), 2);
    }

    #[test]
    fn without_idempotency_key_every_call_executes() {
        let counter = Rc::new(Cell::new(0));
        let mut r = Router::new();
        r.register_tool(CountingTool(counter.clone()));
        r.with_signer(Box::new(TestSigner));
        r.with_idempotency_store(Box::new(MemIdem::default()));

        let body = json!({"name":"count"}); // no idempotencyKey
        let _ = handle(&r, &ctx(Some(principal()), 1000), &body).unwrap();
        let _ = handle(&r, &ctx(Some(principal()), 1001), &body).unwrap();
        assert_eq!(counter.get(), 2);
    }
}
