//! Multi Round-Trip Requests (MRTR).
//!
//! When a tool needs mid-call input, it returns [`ToolOutcome::InputRequired`]
//! carrying the requests to ask the client and the arguments collected so far.
//! The framework seals a [`Continuation`] into an opaque `requestState` token;
//! the client answers and retries the original call with `inputResponses` plus
//! the echoed `requestState`, and *any* stateless instance resumes the work —
//! all the state rides in the token, no server session.
//!
//! The token is sealed via a [`Signer`] whose key material lives in the host
//! binding (so this crate stays platform-free). On the wire the token is
//! opaque; the binding's concrete signer is a versioned AEAD envelope
//! (`version || kid || nonce || ciphertext || tag`). Validation on retry is
//! layered and the failure modes are distinguished:
//!
//! * corrupt / forged / unknown-key token → invalid params (an error),
//! * expired, or a legitimately *changed* principal → a distinct
//!   "restart the call" signal (not alarming — the client simply starts over),
//! * a retry aimed at a different tool → invalid params.
//!
//! [`ToolOutcome::InputRequired`]: crate::router::ToolOutcome::InputRequired

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::jsonrpc::{ErrorCode, RpcError};

/// Default `requestState` lifetime. Kept short: with no server-side nonce store,
/// the expiry window plus principal/operation binding is the anti-replay
/// posture, and replay within the window is an accepted residual risk.
pub const DEFAULT_REQUEST_STATE_TTL_SECS: u64 = 300;

/// Seals and opens opaque continuation tokens. The concrete implementation
/// (AEAD + key ring, in the host binding) owns the key material and the wire
/// framing; this crate treats the token as an opaque string.
pub trait Signer {
    /// Seal plaintext into an opaque, integrity-protected token string.
    fn seal(&self, plaintext: &[u8]) -> Result<String, SignerError>;
    /// Open a token, verifying integrity/authenticity. Any tamper, unknown
    /// version, or unknown key yields an error.
    fn open(&self, token: &str) -> Result<Vec<u8>, SignerError>;
}

/// An opaque signer failure (never leaks key material or plaintext).
#[derive(Debug, Clone)]
pub struct SignerError(pub String);

impl std::fmt::Display for SignerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The self-contained state carried across an MRTR round trip.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Continuation {
    /// The tool the retry must target (operation binding).
    pub tool: String,
    /// Issuer of the principal that started the call (`""` when auth disabled).
    #[serde(default)]
    pub issuer: String,
    /// Subject of the principal that started the call (`""` when auth disabled).
    #[serde(default)]
    pub subject: String,
    /// Absolute expiry, Unix seconds.
    pub expires_at: u64,
    /// Arguments gathered so far, carried into the resumed call.
    pub arguments: Value,
    /// The input-request ids the tool elicited. Only these keys may be filled
    /// from the client's `inputResponses` on retry — this prevents a malicious
    /// client from overwriting arguments the tool did not ask for (argument
    /// injection into the sealed, trusted continuation state).
    #[serde(default)]
    pub requested: Vec<String>,
}

/// What a tool returns when it needs input mid-call. The framework wraps the
/// carried arguments into a signed [`Continuation`] and emits the
/// `input_required` result.
pub struct InputRequired {
    /// Requests to relay to the client, keyed by request id (e.g. an
    /// `elicitation/create`). The id also names the argument the answer fills.
    pub input_requests: Map<String, Value>,
    /// The arguments to carry forward (the original call arguments).
    pub arguments_so_far: Value,
}

impl InputRequired {
    pub fn new(input_requests: Map<String, Value>, arguments_so_far: Value) -> Self {
        InputRequired {
            input_requests,
            arguments_so_far,
        }
    }
}

fn invalid_token() -> RpcError {
    RpcError::invalid_params("invalid or corrupt requestState")
}

/// A distinct, non-alarming signal: the continuation can't be honored (expired
/// or the principal changed) and the client should simply restart the call.
fn restart(reason: &str) -> RpcError {
    RpcError::new(
        ErrorCode::INVALID_PARAMS,
        "continuation no longer valid — restart the call",
    )
    .with_data(serde_json::json!({ "restart": true, "reason": reason }))
}

/// Domain-separation tag for continuation tokens, bound into the sealed bytes
/// so a Task handle can never be opened as a continuation (or vice versa),
/// independent of the JSON schema.
const DOMAIN_CONTINUATION: u8 = b'C';

/// Seal a continuation into a `requestState` token.
pub fn seal_continuation(signer: &dyn Signer, cont: &Continuation) -> Result<String, RpcError> {
    let json = serde_json::to_vec(cont)
        .map_err(|e| RpcError::internal(format!("serialize continuation: {e}")))?;
    let mut bytes = Vec::with_capacity(1 + json.len());
    bytes.push(DOMAIN_CONTINUATION);
    bytes.extend_from_slice(&json);
    signer
        .seal(&bytes)
        .map_err(|e| RpcError::internal(format!("seal requestState: {e}")))
}

/// Open and validate a `requestState` token on retry.
///
/// `principal` is `(issuer, subject)` of the *current* request, or `None` when
/// auth is disabled. `now` is Unix seconds. Validation order: integrity →
/// domain → principal binding → expiry → operation binding.
pub fn open_continuation(
    signer: &dyn Signer,
    token: &str,
    now: u64,
    principal: Option<(&str, &str)>,
    expected_tool: &str,
) -> Result<Continuation, RpcError> {
    let sealed = signer.open(token).map_err(|_| invalid_token())?;
    let bytes = match sealed.split_first() {
        Some((&DOMAIN_CONTINUATION, rest)) => rest,
        _ => return Err(invalid_token()),
    };
    let cont: Continuation = serde_json::from_slice(bytes).map_err(|_| invalid_token())?;

    // Validation order matches Tasks (open_handle): integrity -> principal ->
    // expiry -> operation.
    let (iss, sub) = principal.unwrap_or(("", ""));
    if cont.issuer != iss || cont.subject != sub {
        return Err(restart("principal_changed"));
    }

    if now > cont.expires_at {
        return Err(restart("continuation_expired"));
    }

    if cont.tool != expected_tool {
        return Err(RpcError::invalid_params(format!(
            "requestState is bound to tool {}, not {}",
            cont.tool, expected_tool
        )));
    }

    Ok(cont)
}

/// Build the `input_required` result envelope.
///
/// The wire shape is identical to the SDK's [`rmcp::model::InputRequiredResult`]
/// (`resultType` / `inputRequests` / `requestState`) — pinned by
/// `envelope_matches_rmcp_input_required_result` below. We intentionally keep
/// `input_requests` an **opaque passthrough** map rather than adopting rmcp's
/// strict `InputRequests` (a closed untagged set of
/// `CreateMessageRequest`/`ElicitRequest`/`ListRootsRequest`): the stateless
/// server relays server-initiated requests verbatim and must stay
/// forward-compatible with request shapes the SDK's closed enum does not yet
/// model. The security-bearing part — the `requestState` continuation — is our
/// AEAD-sealed token, which rmcp models only as an opaque `String`.
pub fn input_required_result(input_requests: Map<String, Value>, request_state: String) -> Value {
    serde_json::json!({
        "resultType": "input_required",
        "inputRequests": input_requests,
        "requestState": request_state,
    })
}

/// Merge accepted `inputResponses` into the carried arguments. Each response id
/// names the argument it fills; `{ "action": "accept", "content": ... }` sets
/// `arguments[id] = content`. Only ids in `allowed` (the tool's elicited
/// request ids) are honored — responses for keys the tool did not ask for are
/// ignored, so a client cannot inject or overwrite other carried arguments.
pub fn merge_input_responses(
    mut arguments: Value,
    input_responses: Option<&Value>,
    allowed: &[String],
) -> Value {
    if let Some(map) = input_responses.and_then(Value::as_object) {
        if !arguments.is_object() {
            arguments = Value::Object(Map::new());
        }
        let obj = arguments.as_object_mut().unwrap();
        for (id, resp) in map {
            if !allowed.iter().any(|a| a == id) {
                continue; // not an elicited key — reject injection
            }
            let accepted = resp.get("action").and_then(Value::as_str) == Some("accept");
            if accepted {
                if let Some(content) = resp.get("content") {
                    obj.insert(id.clone(), content.clone());
                }
            }
        }
    }
    arguments
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::cell::Cell;

    /// A test-only signer with a keyed FNV checksum for integrity — enough to
    /// exercise tamper detection and the MRTR validation flow. The real AEAD
    /// signer (host binding, U6) replaces it in production.
    struct TestSigner {
        key: u64,
        fail_open: Cell<bool>,
    }
    impl TestSigner {
        fn new(key: u64) -> Self {
            TestSigner {
                key,
                fail_open: Cell::new(false),
            }
        }
        fn checksum(&self, data: &[u8]) -> u64 {
            let mut h = 0xcbf29ce484222325u64 ^ self.key;
            for b in data {
                h ^= *b as u64;
                h = h.wrapping_mul(0x100000001b3);
            }
            h
        }
    }
    impl Signer for TestSigner {
        fn seal(&self, plaintext: &[u8]) -> Result<String, SignerError> {
            use std::fmt::Write;
            let mut hex = String::new();
            for b in plaintext {
                write!(hex, "{b:02x}").unwrap();
            }
            Ok(format!("{}.{:016x}", hex, self.checksum(plaintext)))
        }
        fn open(&self, token: &str) -> Result<Vec<u8>, SignerError> {
            if self.fail_open.get() {
                return Err(SignerError("unknown key".into()));
            }
            let (hex, mac) = token
                .split_once('.')
                .ok_or_else(|| SignerError("malformed".into()))?;
            let bytes: Vec<u8> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
                .collect::<Result<_, _>>()
                .map_err(|_| SignerError("bad hex".into()))?;
            let want = format!("{:016x}", self.checksum(&bytes));
            if want != mac {
                return Err(SignerError("integrity check failed".into()));
            }
            Ok(bytes)
        }
    }

    fn cont(now: u64, tool: &str, iss: &str, sub: &str) -> Continuation {
        Continuation {
            tool: tool.into(),
            issuer: iss.into(),
            subject: sub.into(),
            expires_at: now + DEFAULT_REQUEST_STATE_TTL_SECS,
            arguments: json!({ "location": "NYC" }),
            requested: vec!["city".into()],
        }
    }

    #[test]
    fn seal_then_open_roundtrips_and_resumes() {
        let s = TestSigner::new(1);
        let c = cont(1000, "weather", "iss", "u1");
        let token = seal_continuation(&s, &c).unwrap();
        let got = open_continuation(&s, &token, 1010, Some(("iss", "u1")), "weather").unwrap();
        assert_eq!(got, c);
        assert_eq!(got.arguments["location"], "NYC");
    }

    #[test]
    fn tampered_token_is_rejected_before_logic() {
        let s = TestSigner::new(1);
        let token = seal_continuation(&s, &cont(1000, "weather", "iss", "u1")).unwrap();
        // Flip the first hex nibble to a different valid hex digit — changes the
        // decoded plaintext so the integrity check must fail on open.
        let first = token.chars().next().unwrap();
        let repl = if first == '0' { '1' } else { '0' };
        let tampered = format!("{repl}{}", &token[1..]);
        let err = open_continuation(&s, &tampered, 1010, Some(("iss", "u1")), "weather").unwrap_err();
        assert_eq!(err.code, -32602);
    }

    #[test]
    fn expired_token_signals_restart() {
        let s = TestSigner::new(1);
        let token = seal_continuation(&s, &cont(1000, "weather", "iss", "u1")).unwrap();
        let err = open_continuation(&s, &token, 1000 + 10_000, Some(("iss", "u1")), "weather")
            .unwrap_err();
        assert_eq!(err.data.unwrap()["reason"], "continuation_expired");
    }

    #[test]
    fn different_principal_signals_restart_not_tamper() {
        let s = TestSigner::new(1);
        let token = seal_continuation(&s, &cont(1000, "weather", "iss", "u1")).unwrap();
        let err = open_continuation(&s, &token, 1010, Some(("iss", "u2")), "weather").unwrap_err();
        let data = err.data.unwrap();
        assert_eq!(data["restart"], true);
        assert_eq!(data["reason"], "principal_changed");
    }

    #[test]
    fn operation_mismatch_is_invalid_params() {
        let s = TestSigner::new(1);
        let token = seal_continuation(&s, &cont(1000, "weather", "iss", "u1")).unwrap();
        let err = open_continuation(&s, &token, 1010, Some(("iss", "u1")), "different_tool")
            .unwrap_err();
        assert_eq!(err.code, -32602);
        assert!(err.data.is_none(), "operation mismatch is not a restart");
    }

    #[test]
    fn unknown_key_rejected() {
        let s = TestSigner::new(1);
        let token = seal_continuation(&s, &cont(1000, "weather", "iss", "u1")).unwrap();
        s.fail_open.set(true); // simulate a kid rolled off the ring
        let err = open_continuation(&s, &token, 1010, Some(("iss", "u1")), "weather").unwrap_err();
        assert_eq!(err.code, -32602);
    }

    #[test]
    fn input_responses_merge_fills_only_allowed_keys() {
        let args = json!({ "location": "NYC" });
        let responses = json!({
            "github_login": { "action": "accept", "content": "octocat" },
            "declined":     { "action": "decline", "content": "nope" },
            "injected":     { "action": "accept", "content": "evil" }
        });
        // Only github_login and declined were elicited; injected is not allowed.
        let allowed = vec!["github_login".to_string(), "declined".to_string()];
        let merged = merge_input_responses(args, Some(&responses), &allowed);
        assert_eq!(merged["location"], "NYC");
        assert_eq!(merged["github_login"], "octocat");
        assert!(merged.get("declined").is_none(), "declined responses are not merged");
        assert!(
            merged.get("injected").is_none(),
            "responses for non-elicited keys must be rejected (no argument injection)"
        );
    }

    #[test]
    fn input_required_result_shape() {
        let mut reqs = Map::new();
        reqs.insert("github_login".into(), json!({ "method": "elicitation/create" }));
        let v = input_required_result(reqs, "TOKEN".into());
        assert_eq!(v["resultType"], "input_required");
        assert_eq!(v["requestState"], "TOKEN");
        assert!(v["inputRequests"]["github_login"].is_object());
    }

    /// Drift tripwire: our hand-built envelope must serialize to the same
    /// discriminator and field names as the SDK's spec-tracked
    /// `rmcp::model::InputRequiredResult`. If the SDK's envelope shape changes,
    /// this fails and flags that our passthrough builder needs to follow. We pin
    /// the envelope only — not the strict `InputRequests` content typing, which
    /// we deliberately keep opaque (see `input_required_result`).
    #[test]
    fn envelope_matches_rmcp_input_required_result() {
        let sdk = serde_json::to_value(rmcp::model::InputRequiredResult::from_request_state("TOKEN"))
            .unwrap();
        assert_eq!(sdk["resultType"], "input_required");
        assert_eq!(sdk["requestState"], "TOKEN");

        let ours = input_required_result(Map::new(), "TOKEN".into());
        assert_eq!(ours["resultType"], sdk["resultType"]);
        assert_eq!(ours["requestState"], sdk["requestState"]);
        // The SDK skips `inputRequests` when absent; so do we (empty map aside).
        assert!(sdk.get("inputRequests").is_none());
    }
}
