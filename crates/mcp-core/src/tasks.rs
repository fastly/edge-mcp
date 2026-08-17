//! The Tasks extension (`io.modelcontextprotocol/tasks`).
//!
//! Poll-based, edge-native. A tool starts a task by returning
//! [`ToolOutcome::Task`](crate::router::ToolOutcome); the framework mints a
//! CSPRNG storage id, persists the [`Task`] durably (before responding), and
//! returns an opaque **task handle** as the `taskId`. The handle is an AEAD
//! token binding the storage id to the creating `(iss, sub)` principal, so
//! every `tasks/get` / `tasks/update` / `tasks/cancel` is verified *before* any
//! store lookup — a wrong-principal or forged request never touches the store.
//!
//! Expiry is enforced by an explicit `expires_at` checked at read time; a
//! backing store's native TTL is only a garbage-collection backstop (it may lag
//! well past expiry).
//!
//! Only `tasks/get` polling is offered in v1; `subscriptions/listen` streaming
//! is deferred (a long-lived stream fights the Compute wall-clock limit).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::jsonrpc::RpcError;
use crate::mrtr::Signer;

/// Task lifecycle status — the SDK's spec-tracked [`rmcp::model::TaskStatus`]
/// (SEP-2663). Terminal states (`completed`/`failed`/`cancelled`) are reported
/// by its inherent [`TaskStatus::is_terminal`]; our lifecycle transition rule
/// lives in [`TaskStatusExt`].
pub use rmcp::model::TaskStatus;

/// Lifecycle transition policy for [`TaskStatus`] (not part of the SDK type).
pub trait TaskStatusExt {
    /// Whether a transition is permitted by the lifecycle.
    fn can_transition_to(self, to: TaskStatus) -> bool;
}

impl TaskStatusExt for TaskStatus {
    fn can_transition_to(self, to: TaskStatus) -> bool {
        use TaskStatus::*;
        matches!(
            (self, to),
            (Working, InputRequired)
                | (Working, Completed)
                | (Working, Failed)
                | (Working, Cancelled)
                | (InputRequired, Working)
                | (InputRequired, Cancelled)
        )
    }
}

/// The durably-stored task record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Task {
    /// Internal storage id (CSPRNG). Not exposed to the client directly — the
    /// client sees the signed handle.
    pub id: String,
    pub status: TaskStatus,
    pub tool: String,
    pub issuer: String,
    pub subject: String,
    pub created_at: u64,
    /// Absolute expiry (Unix seconds), enforced at read time.
    pub expires_at: u64,
    pub ttl_ms: u64,
    pub poll_interval_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_requests: Option<serde_json::Map<String, Value>>,
    /// Accepted responses to a prior `input_required` gate, validated and
    /// preserved by `tasks/update` for the task worker to consume. The worker
    /// reads these when resuming; the core never writes them into `result`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_responses: Option<serde_json::Map<String, Value>>,
    /// Optional deadline-based auto-completion: when set and reached while
    /// `working`, the task transitions to `completed` with `pending_result`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_result: Option<Value>,
}

impl Task {
    pub fn is_expired(&self, now: u64) -> bool {
        now > self.expires_at
    }

    /// Build the SDK-typed base [`rmcp::model::Task`] wire view: the opaque
    /// handle as `taskId`, plus status, ISO-8601 timestamps, TTL, and poll
    /// interval. `updated_at` is the server's best estimate of when the state
    /// was last observed (we do not persist a separate update time).
    fn rmcp_task(&self, task_id_handle: &str, updated_at: u64) -> rmcp::model::Task {
        rmcp::model::Task::new(
            task_id_handle,
            self.status,
            unix_to_rfc3339(self.created_at),
            unix_to_rfc3339(updated_at),
        )
        .with_ttl_ms(self.ttl_ms)
        .with_poll_interval_ms(self.poll_interval_ms)
    }

    /// The `CreateTaskResult` returned when a tool starts a task
    /// (`resultType: "task"`, base task fields flattened at the top level, per
    /// the 2026-07-28 spec — no `task` wrapper). Payload (result / inputRequests)
    /// is observed via the subsequent `tasks/get`.
    pub fn to_create_result(&self, task_id_handle: &str) -> Value {
        let result = rmcp::model::CreateTaskResult::new(self.rmcp_task(task_id_handle, self.created_at));
        serde_json::to_value(result).unwrap_or(Value::Null)
    }

    /// The `tasks/get` result (`resultType: "complete"`, spec `DetailedTask`
    /// wire shape): the base task fields flattened, with the status-specific
    /// payload spliced alongside. `result`/`error` are opaque JSON (as in the
    /// SDK); `inputRequests` remains a passthrough map (input typing is U6).
    pub fn to_get_result(&self, task_id_handle: &str, now: u64) -> Value {
        let mut obj = match serde_json::to_value(self.rmcp_task(task_id_handle, now)) {
            Ok(Value::Object(m)) => m,
            _ => serde_json::Map::new(),
        };
        obj.insert("resultType".into(), Value::String("complete".into()));
        if let Some(r) = &self.result {
            obj.insert("result".into(), r.clone());
        }
        if let Some(e) = &self.error {
            obj.insert("error".into(), e.clone());
        }
        if let Some(ir) = &self.input_requests {
            obj.insert("inputRequests".into(), Value::Object(ir.clone()));
        }
        Value::Object(obj)
    }
}

/// The bare acknowledgement returned by `tasks/update` and `tasks/cancel`
/// (spec `TaskAckResult`, `resultType: "complete"`). Per the spec, task state
/// changes are observed via the next `tasks/get`, so the ack carries no body.
pub fn ack_result() -> Value {
    serde_json::to_value(rmcp::model::TaskAckResult::default()).unwrap_or(Value::Null)
}

/// Format Unix seconds (UTC) as an RFC 3339 / ISO 8601 timestamp, e.g.
/// `2026-07-28T12:34:56Z`. Pure civil-calendar arithmetic (Howard Hinnant's
/// `civil_from_days`) — no external clock or crate — so it is deterministic and
/// wasm-friendly.
fn unix_to_rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// A tool's request to start a task (`ToolOutcome::Task`).
pub struct TaskCreation {
    pub ttl_ms: u64,
    pub poll_interval_ms: u64,
    pub input_requests: Option<serde_json::Map<String, Value>>,
    /// Optional deadline-based completion (demo/simple async without workers).
    pub ready_at: Option<u64>,
    pub pending_result: Option<Value>,
}

impl TaskCreation {
    /// A task that auto-completes `after_secs` from now with `result`.
    pub fn deadline(ttl_ms: u64, poll_interval_ms: u64, ready_at: u64, result: Value) -> Self {
        TaskCreation {
            ttl_ms,
            poll_interval_ms,
            input_requests: None,
            ready_at: Some(ready_at),
            pending_result: Some(result),
        }
    }
}

/// The signed, opaque task handle carried as `taskId`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskHandle {
    pub id: String,
    pub issuer: String,
    pub subject: String,
    pub expires_at: u64,
}

/// A stored task plus its store generation, for optimistic-concurrency updates.
pub struct StoredTask {
    pub task: Task,
    pub generation: u64,
}

/// Durable task storage. The host binding implements this over an edge KV store
/// using compare-and-swap for `update`.
pub trait TaskStore {
    fn create(&self, task: &Task) -> Result<(), TaskError>;
    fn load(&self, id: &str) -> Result<Option<StoredTask>, TaskError>;
    /// Compare-and-swap update: fails if the stored generation moved.
    fn update(&self, task: &Task, expected_generation: u64) -> Result<(), TaskError>;
}

#[derive(Debug, Clone)]
pub struct TaskError(pub String);

impl std::fmt::Display for TaskError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Domain-separation tag for task-handle tokens (see [`crate::mrtr`]).
const DOMAIN_TASK_HANDLE: u8 = b'H';

/// Generate a CSPRNG storage id (128-bit, hex). Errors if the RNG is
/// unavailable — a task id MUST be unguessable, so a silent fallback is never
/// acceptable (it would make the KV key trivially enumerable).
pub fn new_storage_id() -> Result<String, RpcError> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes)
        .map_err(|e| RpcError::internal(format!("CSPRNG unavailable: {e}")))?;
    let mut s = String::with_capacity(32);
    use std::fmt::Write;
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    Ok(s)
}

/// Seal a task handle into an opaque `taskId`.
pub fn seal_handle(signer: &dyn Signer, handle: &TaskHandle) -> Result<String, RpcError> {
    let json = serde_json::to_vec(handle)
        .map_err(|e| RpcError::internal(format!("serialize task handle: {e}")))?;
    let mut bytes = Vec::with_capacity(1 + json.len());
    bytes.push(DOMAIN_TASK_HANDLE);
    bytes.extend_from_slice(&json);
    signer
        .seal(&bytes)
        .map_err(|e| RpcError::internal(format!("seal task handle: {e}")))
}

/// Open and verify a task handle *before* any store access: integrity, then
/// domain tag, then `(iss, sub)` principal binding, then expiry.
pub fn open_handle(
    signer: &dyn Signer,
    task_id: &str,
    now: u64,
    principal: Option<(&str, &str)>,
) -> Result<TaskHandle, RpcError> {
    let sealed = signer
        .open(task_id)
        .map_err(|_| RpcError::invalid_params("invalid or corrupt taskId"))?;
    let bytes = match sealed.split_first() {
        Some((&DOMAIN_TASK_HANDLE, rest)) => rest,
        _ => return Err(RpcError::invalid_params("invalid taskId")),
    };
    let handle: TaskHandle = serde_json::from_slice(bytes)
        .map_err(|_| RpcError::invalid_params("invalid taskId"))?;

    let (iss, sub) = principal.unwrap_or(("", ""));
    if handle.issuer != iss || handle.subject != sub {
        return Err(RpcError::invalid_params("taskId does not belong to this principal"));
    }
    if now > handle.expires_at {
        return Err(task_not_found());
    }
    Ok(handle)
}

/// The error for an absent/expired task.
pub fn task_not_found() -> RpcError {
    RpcError::new(crate::jsonrpc::ErrorCode::INVALID_PARAMS, "task not found or expired")
}

/// Pure deadline-based advancement: a `working` task whose `ready_at` has
/// arrived becomes `completed` with its `pending_result`. Returns `true` when
/// the task was changed.
pub fn advance(task: &mut Task, now: u64) -> bool {
    if task.status == TaskStatus::Working {
        if let Some(ready_at) = task.ready_at {
            if now >= ready_at {
                task.status = TaskStatus::Completed;
                task.result = task.pending_result.take();
                task.ready_at = None;
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aead::{AeadKey, AeadSigner};
    use serde_json::json;

    fn signer() -> AeadSigner {
        AeadSigner::new(vec![AeadKey { kid: 1, key: [7u8; 32] }]).unwrap()
    }

    fn task(now: u64) -> Task {
        Task {
            id: "abc".into(),
            status: TaskStatus::Working,
            tool: "longjob".into(),
            issuer: "iss".into(),
            subject: "u1".into(),
            created_at: now,
            expires_at: now + 600,
            ttl_ms: 600_000,
            poll_interval_ms: 1000,
            result: None,
            error: None,
            input_requests: None,
            input_responses: None,
            ready_at: Some(now + 2),
            pending_result: Some(json!({ "answer": 42 })),
        }
    }

    #[test]
    fn transitions_enforced() {
        assert!(TaskStatus::Working.can_transition_to(TaskStatus::Completed));
        assert!(TaskStatus::InputRequired.can_transition_to(TaskStatus::Working));
        assert!(!TaskStatus::Completed.can_transition_to(TaskStatus::Working));
        assert!(!TaskStatus::Cancelled.can_transition_to(TaskStatus::Working));
        assert!(TaskStatus::Completed.is_terminal());
        assert!(!TaskStatus::Working.is_terminal());
    }

    #[test]
    fn handle_roundtrip_and_principal_binding() {
        let s = signer();
        let h = TaskHandle {
            id: "abc".into(),
            issuer: "iss".into(),
            subject: "u1".into(),
            expires_at: 5000,
        };
        let token = seal_handle(&s, &h).unwrap();
        // correct principal opens
        assert_eq!(open_handle(&s, &token, 1000, Some(("iss", "u1"))).unwrap(), h);
        // wrong principal rejected before any store access
        assert!(open_handle(&s, &token, 1000, Some(("iss", "attacker"))).is_err());
        // expired handle -> not found
        assert!(open_handle(&s, &token, 9999, Some(("iss", "u1"))).is_err());
    }

    #[test]
    fn tampered_handle_rejected() {
        let s = signer();
        let token = seal_handle(
            &s,
            &TaskHandle { id: "abc".into(), issuer: "iss".into(), subject: "u1".into(), expires_at: 5000 },
        )
        .unwrap();
        let bad = format!("{}x", &token[..token.len() - 1]);
        assert!(open_handle(&s, &bad, 1000, Some(("iss", "u1"))).is_err());
    }

    #[test]
    fn task_handle_cannot_be_opened_as_continuation_and_vice_versa() {
        use crate::mrtr::{self, Continuation};
        let s = signer();

        // A sealed task handle must not open as an MRTR continuation.
        let handle_token = seal_handle(
            &s,
            &TaskHandle { id: "abc".into(), issuer: "iss".into(), subject: "u1".into(), expires_at: 9999 },
        )
        .unwrap();
        assert!(
            mrtr::open_continuation(&s, &handle_token, 1000, Some(("iss", "u1")), "tool").is_err(),
            "domain separation: a task handle must not open as a continuation"
        );

        // A sealed continuation must not open as a task handle.
        let cont_token = mrtr::seal_continuation(
            &s,
            &Continuation {
                tool: "tool".into(),
                issuer: "iss".into(),
                subject: "u1".into(),
                expires_at: 9999,
                arguments: json!({}),
                requested: vec![],
            },
        )
        .unwrap();
        assert!(
            open_handle(&s, &cont_token, 1000, Some(("iss", "u1"))).is_err(),
            "domain separation: a continuation must not open as a task handle"
        );
    }

    #[test]
    fn advance_completes_after_deadline() {
        let mut t = task(1000);
        assert!(!advance(&mut t, 1001), "not yet ready");
        assert_eq!(t.status, TaskStatus::Working);
        assert!(advance(&mut t, 1002), "deadline reached");
        assert_eq!(t.status, TaskStatus::Completed);
        assert_eq!(t.result.as_ref().unwrap()["answer"], 42);
        assert!(!advance(&mut t, 1003), "already completed, no further change");
    }

    #[test]
    fn expiry_check() {
        let t = task(1000);
        assert!(!t.is_expired(1500));
        assert!(t.is_expired(2000));
    }

    #[test]
    fn create_result_shape_is_flattened_task() {
        let t = task(1000); // working
        let v = t.to_create_result("HANDLE");
        assert_eq!(v["resultType"], "task");
        // Flattened at the top level — no `task` wrapper (this is the resolved
        // nest-vs-flatten answer per rmcp / the 2026-07-28 spec).
        assert!(v.get("task").is_none());
        assert_eq!(v["taskId"], "HANDLE");
        assert_eq!(v["status"], "working");
        assert_eq!(v["ttlMs"], 600_000);
        assert_eq!(v["pollIntervalMs"], 1000);
        assert_eq!(v["createdAt"], "1970-01-01T00:16:40Z");
    }

    #[test]
    fn get_result_shape_is_flattened_complete() {
        let mut t = task(1000);
        t.status = TaskStatus::Completed;
        t.result = Some(json!({ "answer": 42 }));
        let v = t.to_get_result("HANDLE", 2000);
        assert_eq!(v["resultType"], "complete");
        assert!(v.get("task").is_none());
        assert_eq!(v["taskId"], "HANDLE");
        assert_eq!(v["status"], "completed");
        assert_eq!(v["result"]["answer"], 42);
        assert_eq!(v["lastUpdatedAt"], "1970-01-01T00:33:20Z");
    }

    #[test]
    fn ack_result_is_bare_complete() {
        let v = ack_result();
        assert_eq!(v["resultType"], "complete");
        assert!(v.get("taskId").is_none());
        assert!(v.get("status").is_none());
    }

    #[test]
    fn rfc3339_formatting() {
        assert_eq!(unix_to_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(unix_to_rfc3339(1_000_000_000), "2001-09-09T01:46:40Z");
        assert_eq!(unix_to_rfc3339(1_753_660_800), "2025-07-28T00:00:00Z");
    }
}
