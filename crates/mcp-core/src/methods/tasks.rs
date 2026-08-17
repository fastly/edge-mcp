//! `tasks/get`, `tasks/update`, `tasks/cancel`.
//!
//! Every handler opens and verifies the opaque `taskId` handle (signature →
//! `(iss, sub)` binding → expiry) **before** touching the store, then applies
//! read-time expiry to the loaded record. `tasks/get` also runs deadline-based
//! advancement (a `working` task past its `ready_at` completes).

use serde_json::Value;

use crate::jsonrpc::RpcError;
use crate::mrtr::Signer;
use crate::router::{RequestCtx, Router};
use crate::tasks::{self, StoredTask, TaskStatus};

fn deps(router: &Router) -> Result<(&dyn Signer, &dyn tasks::TaskStore), RpcError> {
    let signer = router
        .signer()
        .ok_or_else(|| RpcError::internal("server is not configured with a token signer"))?;
    let store = router
        .task_store()
        .ok_or_else(|| RpcError::internal("server is not configured for Tasks"))?;
    Ok((signer, store))
}

fn task_id_param(params: &Value) -> Result<&str, RpcError> {
    params
        .get("taskId")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params("requires a string params.taskId"))
}

/// Open the handle (pre-store verification) and load the task, applying
/// read-time expiry. Returns the handle string, the stored task, and its
/// generation.
fn open_and_load(
    router: &Router,
    ctx: &RequestCtx,
    params: &Value,
) -> Result<(String, StoredTask), RpcError> {
    let (signer, store) = deps(router)?;
    let handle_str = task_id_param(params)?.to_string();
    let principal = ctx.principal().map(|p| p.id());
    let handle = tasks::open_handle(signer, &handle_str, ctx.now_unix(), principal)?;

    let stored = store
        .load(&handle.id)
        .map_err(|e| RpcError::internal(format!("load task: {e}")))?
        .ok_or_else(tasks::task_not_found)?;

    if stored.task.is_expired(ctx.now_unix()) {
        return Err(tasks::task_not_found());
    }
    Ok((handle_str, stored))
}

pub fn get(router: &Router, ctx: &RequestCtx, params: &Value) -> Result<Value, RpcError> {
    let (handle_str, mut stored) = open_and_load(router, ctx, params)?;

    // Deadline-based advancement; persist if it changed.
    if tasks::advance(&mut stored.task, ctx.now_unix()) {
        let (_, store) = deps(router)?;
        // Best-effort CAS: if another instance advanced it first, reload.
        if store.update(&stored.task, stored.generation).is_err() {
            if let Ok(Some(fresh)) = store.load(&stored.task.id) {
                stored = fresh;
            }
        }
    }

    Ok(stored.task.to_get_result(&handle_str, ctx.now_unix()))
}

pub fn update(router: &Router, ctx: &RequestCtx, params: &Value) -> Result<Value, RpcError> {
    let (_handle_str, mut stored) = open_and_load(router, ctx, params)?;

    if stored.task.status != TaskStatus::InputRequired {
        return Err(RpcError::invalid_params("task is not awaiting input"));
    }

    // inputResponses must be an object (CMCP-005).
    let responses = params
        .get("inputResponses")
        .and_then(Value::as_object)
        .ok_or_else(|| RpcError::invalid_params("tasks/update requires an inputResponses object"))?;

    // Validate that EVERY requested input has an accepted response carrying
    // content. Any missing, declined, or malformed response leaves the task in
    // InputRequired (we return an error without persisting a transition), so an
    // approval/input gate cannot be bypassed with empty or partial input.
    let requested = stored.task.input_requests.clone().unwrap_or_default();
    let mut accepted = serde_json::Map::new();
    for id in requested.keys() {
        match responses.get(id) {
            Some(r) if r.get("action").and_then(Value::as_str) == Some("accept") => {
                let content = r.get("content").ok_or_else(|| {
                    RpcError::invalid_params(format!(
                        "inputResponses[{id}] was accepted but has no content"
                    ))
                })?;
                accepted.insert(id.clone(), content.clone());
            }
            Some(_) => {
                return Err(RpcError::invalid_params(format!(
                    "input '{id}' was not accepted; task remains awaiting input"
                )));
            }
            None => {
                return Err(RpcError::invalid_params(format!(
                    "missing required input response '{id}'; task remains awaiting input"
                )));
            }
        }
    }

    // All required inputs accepted: preserve them for the worker and resume.
    stored.task.input_responses = Some(accepted);
    stored.task.status = TaskStatus::Working;
    stored.task.input_requests = None;

    let (_, store) = deps(router)?;
    store
        .update(&stored.task, stored.generation)
        .map_err(|e| RpcError::internal(format!("update task: {e}")))?;

    // Spec `TaskAckResult`: the resumed state is observed via the next tasks/get.
    Ok(tasks::ack_result())
}

pub fn cancel(router: &Router, ctx: &RequestCtx, params: &Value) -> Result<Value, RpcError> {
    let (_handle_str, mut stored) = open_and_load(router, ctx, params)?;

    if stored.task.status.is_terminal() {
        // Idempotent: cancelling a finished task is acknowledged with no body.
        return Ok(tasks::ack_result());
    }
    // Every non-terminal state (Working, InputRequired) permits cancellation.
    stored.task.status = TaskStatus::Cancelled;

    let (_, store) = deps(router)?;
    store
        .update(&stored.task, stored.generation)
        .map_err(|e| RpcError::internal(format!("cancel task: {e}")))?;

    Ok(tasks::ack_result())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aead::{AeadKey, AeadSigner};
    use crate::auth::Principal;
    use crate::meta::{keys, Meta};
    use crate::router::{RequestCtx, RoutingHeaders};
    use crate::tasks::{Task, TaskError, TaskStore};
    use crate::PROTOCOL_VERSION;
    use serde_json::json;
    use std::cell::RefCell;
    use std::collections::HashMap;

    /// In-memory task store with a generation counter for CAS tests.
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
            Ok(self.map.borrow().get(id).map(|(t, g)| StoredTask {
                task: t.clone(),
                generation: *g,
            }))
        }
        fn update(&self, task: &Task, expected: u64) -> Result<(), TaskError> {
            let mut m = self.map.borrow_mut();
            let (_, g) = m.get(&task.id).ok_or_else(|| TaskError("missing".into()))?;
            if *g != expected {
                return Err(TaskError("generation mismatch".into()));
            }
            m.insert(task.id.clone(), (task.clone(), expected + 1));
            Ok(())
        }
    }

    fn router() -> Router {
        let mut r = Router::new();
        r.with_signer(Box::new(AeadSigner::new(vec![AeadKey { kid: 1, key: [3u8; 32] }]).unwrap()));
        r.with_task_store(Box::new(MemStore::default()));
        r
    }

    fn principal(sub: &str) -> Principal {
        Principal {
            issuer: "iss".into(),
            subject: sub.into(),
            scopes: vec![],
            claims: Default::default(),
        }
    }

    fn ctx(p: Option<Principal>, now: u64) -> RequestCtx {
        let meta = Meta::from_params(&json!({"_meta":{
            keys::PROTOCOL_VERSION: PROTOCOL_VERSION, keys::CLIENT_CAPABILITIES: {}
        }}));
        RequestCtx::new(meta, p, RoutingHeaders::default()).with_now_unix(now)
    }

    /// Create a task directly in the store and return its opaque handle.
    fn seed_task(router: &Router, now: u64, sub: &str, mut mutate: impl FnMut(&mut Task)) -> String {
        let id = tasks::new_storage_id().unwrap();
        let expires_at = now + 600;
        let mut task = Task {
            id: id.clone(),
            status: TaskStatus::Working,
            tool: "job".into(),
            issuer: "iss".into(),
            subject: sub.into(),
            created_at: now,
            expires_at,
            ttl_ms: 600_000,
            poll_interval_ms: 500,
            result: None,
            error: None,
            input_requests: None,
            input_responses: None,
            ready_at: None,
            pending_result: None,
        };
        mutate(&mut task);
        router.task_store().unwrap().create(&task).unwrap();
        tasks::seal_handle(
            router.signer().unwrap(),
            &tasks::TaskHandle { id, issuer: "iss".into(), subject: sub.into(), expires_at },
        )
        .unwrap()
    }

    #[test]
    fn get_advances_deadline_task_to_completed() {
        let r = router();
        let handle = seed_task(&r, 1000, "u1", |t| {
            t.ready_at = Some(1002);
            t.pending_result = Some(json!({ "done": true }));
        });
        // Before deadline: working. tasks/get flattens the DetailedTask fields.
        let v = get(&r, &ctx(Some(principal("u1")), 1001), &json!({ "taskId": handle })).unwrap();
        assert_eq!(v["resultType"], "complete");
        assert_eq!(v["status"], "working");
        // After deadline: completed with result.
        let v = get(&r, &ctx(Some(principal("u1")), 1002), &json!({ "taskId": handle })).unwrap();
        assert_eq!(v["status"], "completed");
        assert_eq!(v["result"]["done"], true);
    }

    #[test]
    fn wrong_principal_rejected_before_store() {
        let r = router();
        let handle = seed_task(&r, 1000, "u1", |_| {});
        let err = get(&r, &ctx(Some(principal("attacker")), 1001), &json!({ "taskId": handle }))
            .unwrap_err();
        assert!(err.message.contains("does not belong to this principal"));
    }

    #[test]
    fn expired_task_is_not_found() {
        let r = router();
        let handle = seed_task(&r, 1000, "u1", |t| t.expires_at = 1100);
        let err = get(&r, &ctx(Some(principal("u1")), 2000), &json!({ "taskId": handle })).unwrap_err();
        assert!(err.message.contains("not found or expired"));
    }

    /// Seed a task awaiting a single required input `city`.
    fn seed_input_required(r: &Router) -> String {
        seed_task(r, 1000, "u1", |t| {
            t.status = TaskStatus::InputRequired;
            let mut reqs = serde_json::Map::new();
            reqs.insert("city".into(), json!({ "method": "elicitation/create" }));
            t.input_requests = Some(reqs);
        })
    }

    #[test]
    fn update_resumes_when_all_required_inputs_accepted() {
        let r = router();
        let handle = seed_input_required(&r);
        let v = update(
            &r,
            &ctx(Some(principal("u1")), 1001),
            &json!({ "taskId": handle, "inputResponses": { "city": { "action": "accept", "content": "NYC" } } }),
        )
        .unwrap();
        // tasks/update returns a bare TaskAckResult; the resumed state is
        // observed via the next tasks/get.
        assert_eq!(v["resultType"], "complete");
        // The resumed task is working, and must NOT expose a result yet (the
        // input gate is never confused with tool output) — verified via get.
        let polled = get(&r, &ctx(Some(principal("u1")), 1002), &json!({ "taskId": handle })).unwrap();
        assert_eq!(polled["status"], "working");
        assert!(polled.get("result").is_none());
    }

    #[test]
    fn update_missing_required_input_stays_input_required() {
        let r = router();
        let handle = seed_input_required(&r);
        // Empty responses -> the required 'city' is missing.
        let err = update(
            &r,
            &ctx(Some(principal("u1")), 1001),
            &json!({ "taskId": handle, "inputResponses": {} }),
        )
        .unwrap_err();
        assert!(err.message.contains("missing required input response"), "got: {}", err.message);
        // The persisted task is still InputRequired (gate not bypassed).
        let v = get(&r, &ctx(Some(principal("u1")), 1002), &json!({ "taskId": handle })).unwrap();
        assert_eq!(v["status"], "input_required");
    }

    #[test]
    fn update_declined_input_stays_input_required() {
        let r = router();
        let handle = seed_input_required(&r);
        let err = update(
            &r,
            &ctx(Some(principal("u1")), 1001),
            &json!({ "taskId": handle, "inputResponses": { "city": { "action": "decline" } } }),
        )
        .unwrap_err();
        assert!(err.message.contains("was not accepted"), "got: {}", err.message);
    }

    #[test]
    fn update_accept_without_content_rejected() {
        let r = router();
        let handle = seed_input_required(&r);
        let err = update(
            &r,
            &ctx(Some(principal("u1")), 1001),
            &json!({ "taskId": handle, "inputResponses": { "city": { "action": "accept" } } }),
        )
        .unwrap_err();
        assert!(err.message.contains("no content"), "got: {}", err.message);
    }

    #[test]
    fn update_requires_input_responses_object() {
        let r = router();
        let handle = seed_input_required(&r);
        let err = update(&r, &ctx(Some(principal("u1")), 1001), &json!({ "taskId": handle }))
            .unwrap_err();
        assert!(err.message.contains("inputResponses object"), "got: {}", err.message);
    }

    #[test]
    fn update_on_non_input_task_rejected() {
        let r = router();
        let handle = seed_task(&r, 1000, "u1", |_| {}); // working
        let err = update(
            &r,
            &ctx(Some(principal("u1")), 1001),
            &json!({ "taskId": handle, "inputResponses": {} }),
        )
        .unwrap_err();
        assert!(err.message.contains("not awaiting input"));
    }

    #[test]
    fn cancel_non_terminal_task() {
        let r = router();
        let handle = seed_task(&r, 1000, "u1", |_| {});
        let v = cancel(&r, &ctx(Some(principal("u1")), 1001), &json!({ "taskId": handle })).unwrap();
        // Bare ack; the cancelled state is observed via tasks/get.
        assert_eq!(v["resultType"], "complete");
        let polled = get(&r, &ctx(Some(principal("u1")), 1002), &json!({ "taskId": handle })).unwrap();
        assert_eq!(polled["status"], "cancelled");
    }

    #[test]
    fn cancel_terminal_task_is_idempotent() {
        let r = router();
        let handle = seed_task(&r, 1000, "u1", |t| t.status = TaskStatus::Completed);
        let v = cancel(&r, &ctx(Some(principal("u1")), 1001), &json!({ "taskId": handle })).unwrap();
        // Idempotent bare ack; the still-completed state is observed via get.
        assert_eq!(v["resultType"], "complete");
        let polled = get(&r, &ctx(Some(principal("u1")), 1002), &json!({ "taskId": handle })).unwrap();
        assert_eq!(polled["status"], "completed");
    }
}
