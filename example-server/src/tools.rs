//! Demo handlers exercising every result shape: a plain `complete` tool, an
//! MRTR (`input_required`) tool, a Task-backed tool, plus a prompt and a
//! resource. All are pure `mcp-core` — no Fastly dependency — so they run under
//! `cargo test` on the host.

use serde_json::{json, Map, Value};

use mcp_core::jsonrpc::RpcError;
use mcp_core::result::{CallResult, CallResultExt};
use mcp_core::router::{
    PromptDef, PromptHandler, RequestCtx, ResourceDef, ResourceHandler, Router, ToolDef,
    ToolHandler, ToolOutcome,
};
use mcp_core::tasks::TaskCreation;
use mcp_core::InputRequired;

/// Register the demo handlers and server info on a router.
pub fn register_handlers(router: &mut Router) {
    router.with_server_info(json!({ "name": "compute-mcp-example", "version": "0.1.0" }));
    router
        .register_tool(EchoTool)
        .register_tool(BookingTool)
        .register_tool(LongJobTool)
        .register_prompt(GreetingPrompt)
        .register_resource(ReadmeResource);
}

/// `echo` — a plain tool that completes immediately.
pub struct EchoTool;
impl ToolHandler for EchoTool {
    fn definition(&self) -> ToolDef {
        ToolDef {
            name: "echo".into(),
            title: Some("Echo".into()),
            description: "Echo a message back.".into(),
            input_schema: json!({
                "type": "object",
                "properties": { "message": { "type": "string" } },
                "required": ["message"]
            }),
            output_schema: None,
        }
    }
    fn call(&self, _ctx: &RequestCtx, args: &Value) -> Result<ToolOutcome, RpcError> {
        let message = args.get("message").and_then(Value::as_str).unwrap_or("");
        Ok(ToolOutcome::Complete(CallResult::text(message)))
    }
    fn required_scopes(&self) -> Vec<String> {
        vec!["mcp:tools:echo".into()]
    }
}

/// `book_table` — an MRTR tool: needs a `date` before it can complete.
pub struct BookingTool;
impl ToolHandler for BookingTool {
    fn definition(&self) -> ToolDef {
        ToolDef {
            name: "book_table".into(),
            title: Some("Book a table".into()),
            description: "Book a table; asks for a date if missing.".into(),
            input_schema: json!({
                "type": "object",
                "properties": { "date": { "type": "string" } }
            }),
            output_schema: None,
        }
    }
    fn call(&self, _ctx: &RequestCtx, args: &Value) -> Result<ToolOutcome, RpcError> {
        match args.get("date").and_then(Value::as_str) {
            Some(date) => Ok(ToolOutcome::Complete(CallResult::text(format!(
                "Booked a table for {date}."
            )))),
            None => {
                let mut requests = Map::new();
                requests.insert(
                    "date".into(),
                    json!({
                        "method": "elicitation/create",
                        "params": { "mode": "form", "message": "What date?" }
                    }),
                );
                Ok(ToolOutcome::InputRequired(InputRequired::new(
                    requests,
                    args.clone(),
                )))
            }
        }
    }
    fn required_scopes(&self) -> Vec<String> {
        vec!["mcp:tools:book_table".into()]
    }
}

/// `long_job` — a Task-backed tool that completes ~1s after creation.
pub struct LongJobTool;
impl ToolHandler for LongJobTool {
    fn definition(&self) -> ToolDef {
        ToolDef {
            name: "long_job".into(),
            title: Some("Long job".into()),
            description: "Start a long-running job; poll with tasks/get.".into(),
            input_schema: json!({ "type": "object" }),
            output_schema: None,
        }
    }
    fn call(&self, ctx: &RequestCtx, _args: &Value) -> Result<ToolOutcome, RpcError> {
        let ready_at = ctx.now_unix() + 1;
        Ok(ToolOutcome::Task(TaskCreation::deadline(
            60_000, // ttlMs
            500,    // pollIntervalMs
            ready_at,
            json!({ "content": [{ "type": "text", "text": "job finished" }] }),
        )))
    }
    fn required_scopes(&self) -> Vec<String> {
        vec!["mcp:tools:long_job".into()]
    }
}

/// A demo prompt.
pub struct GreetingPrompt;
impl PromptHandler for GreetingPrompt {
    fn definition(&self) -> PromptDef {
        PromptDef {
            name: "greeting".into(),
            description: Some("A friendly greeting prompt.".into()),
            arguments: vec![json!({ "name": "name", "required": false })],
        }
    }
    fn get(&self, _ctx: &RequestCtx, args: &Value) -> Result<Value, RpcError> {
        let name = args.get("name").and_then(Value::as_str).unwrap_or("world");
        Ok(json!({
            "messages": [
                { "role": "user", "content": { "type": "text", "text": format!("Say hello to {name}.") } }
            ]
        }))
    }
}

/// A demo resource.
pub struct ReadmeResource;
impl ResourceHandler for ReadmeResource {
    fn definition(&self) -> ResourceDef {
        ResourceDef {
            uri: "mcp://example/readme".into(),
            name: "readme".into(),
            description: Some("Example resource.".into()),
            mime_type: Some("text/plain".into()),
        }
    }
    fn read(&self, _ctx: &RequestCtx) -> Result<Value, RpcError> {
        Ok(json!([{
            "uri": "mcp://example/readme",
            "mimeType": "text/plain",
            "text": "This is an example MCP resource served from Fastly Compute."
        }]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_core::aead::{AeadKey, AeadSigner};
    use mcp_core::dispatch;
    use mcp_core::jsonrpc::{RpcRequest, RpcResponse};
    use mcp_core::meta::{keys, Meta};
    use mcp_core::router::RoutingHeaders;
    use mcp_core::tasks::{StoredTask, Task, TaskError, TaskStore};
    use mcp_core::{Principal, RequestCtx, Router, PROTOCOL_VERSION};
    use std::cell::RefCell;
    use std::collections::HashMap;

    #[derive(Default)]
    struct MemStore {
        map: RefCell<HashMap<String, (Task, u64)>>,
    }
    impl TaskStore for MemStore {
        fn create(&self, task: &Task) -> Result<(), TaskError> {
            self.map.borrow_mut().insert(task.id.clone(), (task.clone(), 1));
            Ok(())
        }
        fn load(&self, id: &str) -> Result<Option<StoredTask>, TaskError> {
            Ok(self
                .map
                .borrow()
                .get(id)
                .map(|(t, g)| StoredTask { task: t.clone(), generation: *g }))
        }
        fn update(&self, task: &Task, expected: u64) -> Result<(), TaskError> {
            let mut m = self.map.borrow_mut();
            let (_, g) = m.get(&task.id).ok_or_else(|| TaskError("missing".into()))?;
            if *g != expected {
                return Err(TaskError("gen".into()));
            }
            m.insert(task.id.clone(), (task.clone(), expected + 1));
            Ok(())
        }
    }

    fn router() -> Router {
        let mut r = Router::new();
        register_handlers(&mut r);
        r.with_signer(Box::new(
            AeadSigner::new(vec![AeadKey { kid: 1, key: [5u8; 32] }]).unwrap(),
        ));
        r.with_task_store(Box::new(MemStore::default()));
        r
    }

    fn call(router: &Router, now: u64, body: Value) -> RpcResponse {
        let req: RpcRequest = serde_json::from_value(body).unwrap();
        let meta = Meta::from_params(&json!({"_meta":{
            keys::PROTOCOL_VERSION: PROTOCOL_VERSION,
            keys::CLIENT_CAPABILITIES: { "extensions": { "io.modelcontextprotocol/tasks": {} } }
        }}));
        let principal = Principal {
            issuer: "iss".into(),
            subject: "u1".into(),
            // Grant the demo tool + task scopes so the authenticated e2e path
            // exercises successful authorization.
            scopes: vec![
                "mcp:tools:echo".into(),
                "mcp:tools:book_table".into(),
                "mcp:tools:long_job".into(),
                "mcp:tasks:read".into(),
                "mcp:tasks:write".into(),
            ],
            claims: Default::default(),
        };
        let ctx = RequestCtx::new(meta, Some(principal), RoutingHeaders::default()).with_now_unix(now);
        dispatch(router, &ctx, &req).unwrap()
    }

    fn result(resp: &RpcResponse) -> Value {
        serde_json::to_value(resp).unwrap()["result"].clone()
    }

    #[test]
    fn tools_list_shows_all_demo_tools() {
        let r = router();
        let v = result(&call(&r, 1000, json!({"jsonrpc":"2.0","id":1,"method":"tools/list"})));
        let names: Vec<&str> = v["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"echo"));
        assert!(names.contains(&"book_table"));
        assert!(names.contains(&"long_job"));
    }

    #[test]
    fn echo_missing_required_message_is_rejected_by_schema() {
        // The echo inputSchema requires `message`; central validation must
        // reject a call that omits it, before the handler runs (CMCP-010).
        let r = router();
        let resp = call(
            &r,
            1000,
            json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}),
        );
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["error"]["code"], -32602);
        assert!(v["error"]["message"].as_str().unwrap().contains("inputSchema"));
    }

    #[test]
    fn echo_completes() {
        let r = router();
        let v = result(&call(
            &r,
            1000,
            json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"message":"hi"}}}),
        ));
        assert_eq!(v["resultType"], "complete");
        assert_eq!(v["content"][0]["text"], "hi");
    }

    #[test]
    fn booking_mrtr_roundtrip() {
        let r = router();
        // No date -> input_required + requestState.
        let first = result(&call(
            &r,
            1000,
            json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"book_table"}}),
        ));
        assert_eq!(first["resultType"], "input_required");
        let token = first["requestState"].as_str().unwrap().to_string();
        // Retry with the date.
        let done = result(&call(
            &r,
            1005,
            json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
                "name":"book_table","requestState":token,
                "inputResponses":{"date":{"action":"accept","content":"2026-08-01"}}
            }}),
        ));
        assert_eq!(done["resultType"], "complete");
        assert_eq!(done["content"][0]["text"], "Booked a table for 2026-08-01.");
    }

    #[test]
    fn long_job_task_create_poll_complete() {
        let r = router();
        let created = result(&call(
            &r,
            1000,
            json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"long_job"}}),
        ));
        // Create result: resultType "task" with the task fields flattened at the
        // top level (spec CreateTaskResult — no `task` wrapper).
        assert_eq!(created["resultType"], "task");
        assert_eq!(created["status"], "working");
        let task_id = created["taskId"].as_str().unwrap().to_string();

        // Poll before the deadline: still working. tasks/get is a "complete"
        // result with the DetailedTask fields flattened.
        let polled = result(&call(
            &r,
            1000,
            json!({"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"taskId":task_id}}),
        ));
        assert_eq!(polled["resultType"], "complete");
        assert_eq!(polled["status"], "working");

        // Poll after the deadline: completed with result.
        let created2 = result(&call(
            &r,
            2000,
            json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"long_job"}}),
        ));
        let id2 = created2["taskId"].as_str().unwrap().to_string();
        let done = result(&call(
            &r,
            2002,
            json!({"jsonrpc":"2.0","id":4,"method":"tasks/get","params":{"taskId":id2}}),
        ));
        assert_eq!(done["status"], "completed");
        assert_eq!(done["result"]["content"][0]["text"], "job finished");
    }

    #[test]
    fn prompts_and_resources_list_and_read() {
        let r = router();
        let prompts = result(&call(&r, 1000, json!({"jsonrpc":"2.0","id":1,"method":"prompts/list"})));
        assert_eq!(prompts["prompts"][0]["name"], "greeting");

        let resources = result(&call(&r, 1000, json!({"jsonrpc":"2.0","id":2,"method":"resources/list"})));
        assert_eq!(resources["resources"][0]["uri"], "mcp://example/readme");

        let read = result(&call(
            &r,
            1000,
            json!({"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"mcp://example/readme"}}),
        ));
        assert_eq!(read["contents"][0]["mimeType"], "text/plain");
    }

    #[test]
    fn discover_advertises_tasks_extension() {
        let r = router();
        let v = result(&call(&r, 1000, json!({"jsonrpc":"2.0","id":1,"method":"server/discover"})));
        assert_eq!(v["capabilities"]["extensions"]["io.modelcontextprotocol/tasks"], json!({}));
        // serverInfo travels in _meta per the 2026-07-28 spec (rmcp DiscoverResult).
        assert_eq!(
            v["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
            "compute-mcp-example"
        );
    }
}
