//! JSON-RPC 2.0 envelope and the MCP error model.
//!
//! MCP `2026-07-28` rides on JSON-RPC 2.0. This module models the request and
//! response envelopes and the error object, plus the MCP-specific error codes.
//! Two subtleties the wire format demands and this module handles:
//!
//! * **`id` type union.** A JSON-RPC `id` may be a string, an integer, or
//!   `null`, and it must be echoed back verbatim. See [`RpcId`].
//! * **missing vs. explicit-null `id`.** A *missing* `id` marks a notification
//!   (no response is produced); an explicit `id: null` is a (rare) request with
//!   a null id. `serde`'s `Option` collapses both to `None`, so the request
//!   `id` field uses a present-only deserializer to keep them distinct.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

/// A JSON-RPC request/response identifier.
///
/// Per the JSON-RPC 2.0 spec the id may be a string, an integer, or null, and
/// the server must echo the client's exact value. Numbers are constrained to
/// integers (fractional ids are not allowed by the spec).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcId {
    Number(i64),
    String(String),
    Null,
}

impl Serialize for RpcId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            RpcId::Number(n) => s.serialize_i64(*n),
            RpcId::String(v) => s.serialize_str(v),
            RpcId::Null => s.serialize_none(),
        }
    }
}

impl<'de> Deserialize<'de> for RpcId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        match Value::deserialize(d)? {
            Value::Null => Ok(RpcId::Null),
            Value::String(s) => Ok(RpcId::String(s)),
            Value::Number(n) => n
                .as_i64()
                .map(RpcId::Number)
                .ok_or_else(|| serde::de::Error::custom("JSON-RPC id number must be an integer")),
            _ => Err(serde::de::Error::custom(
                "JSON-RPC id must be a string, integer, or null",
            )),
        }
    }
}

/// Deserialize a *present* `id` field into `Some(..)`, preserving the
/// missing-vs-null distinction: `serde` only invokes this when the key exists,
/// so an absent `id` falls through to `Default` (`None`) and marks a
/// notification, while a present `id: null` becomes `Some(RpcId::Null)`.
fn de_present_id<'de, D>(d: D) -> Result<Option<RpcId>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Some(RpcId::deserialize(d)?))
}

fn jsonrpc_version() -> String {
    "2.0".to_string()
}

/// An inbound JSON-RPC request (or notification, when `id` is absent).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RpcRequest {
    #[serde(default = "jsonrpc_version")]
    pub jsonrpc: String,
    #[serde(
        default,
        deserialize_with = "de_present_id",
        skip_serializing_if = "Option::is_none"
    )]
    pub id: Option<RpcId>,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl RpcRequest {
    /// A request with no `id` is a notification and must not receive a response.
    pub fn is_notification(&self) -> bool {
        self.id.is_none()
    }

    /// The `params` value, or JSON `null` when omitted.
    pub fn params_or_null(&self) -> Value {
        self.params.clone().unwrap_or(Value::Null)
    }
}

/// An outbound JSON-RPC response. Exactly one of `result` / `error` is present;
/// the constructors enforce that invariant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcResponse {
    #[serde(default = "jsonrpc_version")]
    pub jsonrpc: String,
    pub id: RpcId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

impl RpcResponse {
    /// A success response echoing `id` with `result`.
    pub fn result(id: RpcId, result: Value) -> Self {
        RpcResponse {
            jsonrpc: jsonrpc_version(),
            id,
            result: Some(result),
            error: None,
        }
    }

    /// An error response echoing `id`.
    pub fn error(id: RpcId, error: RpcError) -> Self {
        RpcResponse {
            jsonrpc: jsonrpc_version(),
            id,
            result: None,
            error: Some(error),
        }
    }

    /// If this response carries an **internal** error, replace its (possibly
    /// sensitive) detail with a stable generic message plus `correlation_id`,
    /// and return the original message for server-side logging. Client-safe
    /// errors (invalid params, method not found, insufficient scope, …) are
    /// left untouched — their detail is actionable and non-sensitive (CWE-209).
    pub fn redact_internal(&mut self, correlation_id: &str) -> Option<String> {
        let err = self.error.as_mut()?;
        if err.code != ErrorCode::INTERNAL_ERROR {
            return None;
        }
        let original = std::mem::replace(&mut err.message, "internal error".to_string());
        err.data = Some(serde_json::json!({ "correlationId": correlation_id }));
        Some(original)
    }
}

/// A JSON-RPC error object.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl RpcError {
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        RpcError {
            code,
            message: message.into(),
            data: None,
        }
    }

    pub fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }

    // --- Constructors for the common MCP/JSON-RPC conditions ---

    pub fn method_not_found(method: &str) -> Self {
        RpcError::new(
            ErrorCode::METHOD_NOT_FOUND,
            format!("method not found: {method}"),
        )
    }

    pub fn invalid_params(detail: impl Into<String>) -> Self {
        RpcError::new(ErrorCode::INVALID_PARAMS, detail.into())
    }

    pub fn unsupported_protocol_version(got: &str) -> Self {
        RpcError::new(
            ErrorCode::UNSUPPORTED_PROTOCOL_VERSION,
            format!("unsupported protocol version: {got}"),
        )
    }

    /// `-32021` with the machine-readable list of capabilities the server needs.
    pub fn missing_required_capability(required: &[&str]) -> Self {
        RpcError::new(
            ErrorCode::MISSING_REQUIRED_CLIENT_CAPABILITY,
            "missing required client capability",
        )
        .with_data(serde_json::json!({ "requiredCapabilities": required }))
    }

    pub fn header_mismatch(detail: impl Into<String>) -> Self {
        RpcError::new(ErrorCode::HEADER_MISMATCH, detail.into())
    }

    /// `-32023` — the principal is authenticated but lacks the required
    /// scope(s). Carries the specific missing scopes so the client can request
    /// the right ones (never the full catalog).
    pub fn insufficient_scope(required: &[String]) -> Self {
        RpcError::new(ErrorCode::INSUFFICIENT_SCOPE, "insufficient scope").with_data(
            serde_json::json!({ "requiredScopes": required }),
        )
    }

    pub fn internal(detail: impl Into<String>) -> Self {
        RpcError::new(ErrorCode::INTERNAL_ERROR, detail.into())
    }
}

/// JSON-RPC standard and MCP-specific error codes.
///
/// MCP reserves `-32020..=-32099`; `-32000..=-32019` are legacy and must not be
/// allocated. `-32002` (resource-not-found) and `-32042` are retired in favor
/// of `-32602`.
pub struct ErrorCode;

impl ErrorCode {
    // JSON-RPC 2.0 standard codes.
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL_ERROR: i32 = -32603;

    // MCP 2026-07-28 codes. These three match the SDK's `rmcp::model::ErrorCode`
    // constants exactly (pinned by `mcp_error_codes_match_rmcp`).
    pub const HEADER_MISMATCH: i32 = -32020;
    pub const MISSING_REQUIRED_CLIENT_CAPABILITY: i32 = -32021;
    pub const UNSUPPORTED_PROTOCOL_VERSION: i32 = -32022;
    /// Authenticated but lacking the scope(s) required for the operation.
    ///
    /// The 2026-07-28 spec (as tracked by rmcp 3.1.1, which defines `-32020`/
    /// `-32021`/`-32022`) does **not** define a dedicated authorization/
    /// insufficient-scope code, so `-32023` is our deliberate, provisional
    /// choice in the MCP-reserved range. Not part of the SDK.
    pub const INSUFFICIENT_SCOPE: i32 = -32023;
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn id_roundtrips_number_string_and_null() {
        let cases = [
            (json!({"jsonrpc":"2.0","id":7,"method":"m"}), RpcId::Number(7)),
            (
                json!({"jsonrpc":"2.0","id":"abc","method":"m"}),
                RpcId::String("abc".into()),
            ),
            (json!({"jsonrpc":"2.0","id":null,"method":"m"}), RpcId::Null),
        ];
        for (raw, want) in cases {
            let req: RpcRequest = serde_json::from_value(raw).unwrap();
            assert_eq!(req.id, Some(want));
            assert!(!req.is_notification());
        }
    }

    #[test]
    fn missing_id_is_notification_and_serializes_without_id() {
        let req: RpcRequest =
            serde_json::from_value(json!({"jsonrpc":"2.0","method":"m"})).unwrap();
        assert!(req.is_notification());
        let out = serde_json::to_value(&req).unwrap();
        assert!(out.get("id").is_none(), "notification must omit id entirely");
    }

    #[test]
    fn explicit_null_id_is_distinct_from_missing() {
        let with_null: RpcRequest =
            serde_json::from_value(json!({"jsonrpc":"2.0","id":null,"method":"m"})).unwrap();
        assert_eq!(with_null.id, Some(RpcId::Null));
        assert!(!with_null.is_notification());
        // and it serializes back as an explicit null
        let out = serde_json::to_value(&with_null).unwrap();
        assert_eq!(out.get("id"), Some(&Value::Null));
    }

    #[test]
    fn fractional_id_is_rejected() {
        let err = serde_json::from_value::<RpcRequest>(json!({"id":1.5,"method":"m"}));
        assert!(err.is_err());
    }

    #[test]
    fn response_has_exactly_one_of_result_or_error() {
        let ok = RpcResponse::result(RpcId::Number(1), json!({"ok": true}));
        let v = serde_json::to_value(&ok).unwrap();
        assert!(v.get("result").is_some());
        assert!(v.get("error").is_none());

        let err = RpcResponse::error(RpcId::Null, RpcError::method_not_found("x"));
        let v = serde_json::to_value(&err).unwrap();
        assert!(v.get("error").is_some());
        assert!(v.get("result").is_none());
    }

    #[test]
    fn redact_internal_replaces_detail_and_returns_original() {
        let mut resp = RpcResponse::error(
            RpcId::Number(1),
            RpcError::internal("KVStore 'task_store' timed out at backend x"),
        );
        let original = resp.redact_internal("abcd1234").unwrap();
        assert!(original.contains("task_store"), "original returned for logging");
        let err = resp.error.unwrap();
        assert_eq!(err.code, ErrorCode::INTERNAL_ERROR);
        assert_eq!(err.message, "internal error");
        assert_eq!(err.data.unwrap()["correlationId"], "abcd1234");
    }

    #[test]
    fn redact_internal_leaves_client_safe_errors_untouched() {
        let mut resp = RpcResponse::error(RpcId::Number(1), RpcError::invalid_params("unknown tool: x"));
        assert!(resp.redact_internal("id").is_none());
        assert_eq!(resp.error.unwrap().message, "unknown tool: x");
    }

    /// Drift tripwire: our error-code constants must equal the SDK's
    /// `rmcp::model::ErrorCode` values. `-32023` (INSUFFICIENT_SCOPE) is
    /// intentionally absent from the SDK — the spec defines no authorization
    /// code — so it is asserted as a plain reserved-range literal only.
    #[test]
    fn mcp_error_codes_match_rmcp() {
        use rmcp::model::ErrorCode as R;
        assert_eq!(ErrorCode::HEADER_MISMATCH, R::HEADER_MISMATCH.0);
        assert_eq!(
            ErrorCode::MISSING_REQUIRED_CLIENT_CAPABILITY,
            R::MISSING_REQUIRED_CLIENT_CAPABILITY.0
        );
        assert_eq!(
            ErrorCode::UNSUPPORTED_PROTOCOL_VERSION,
            R::UNSUPPORTED_PROTOCOL_VERSION.0
        );
        assert_eq!(ErrorCode::METHOD_NOT_FOUND, R::METHOD_NOT_FOUND.0);
        assert_eq!(ErrorCode::INVALID_PARAMS, R::INVALID_PARAMS.0);
        assert_eq!(ErrorCode::INTERNAL_ERROR, R::INTERNAL_ERROR.0);
        assert_eq!(ErrorCode::PARSE_ERROR, R::PARSE_ERROR.0);
        // No SDK counterpart: provisional, MCP-reserved range.
        assert_eq!(ErrorCode::INSUFFICIENT_SCOPE, -32023);
    }

    #[test]
    fn missing_capability_error_carries_required_list() {
        let e = RpcError::missing_required_capability(&["io.modelcontextprotocol/tasks"]);
        assert_eq!(e.code, -32021);
        let data = e.data.unwrap();
        assert_eq!(data["requiredCapabilities"][0], "io.modelcontextprotocol/tasks");
    }
}
