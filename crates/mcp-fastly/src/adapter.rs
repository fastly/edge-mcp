//! The Fastly Compute request adapter (wasm-only).
//!
//! Translates a `fastly::Request` into an `mcp_core` dispatch and back:
//! pre-auth body-size cap → parse → authenticate → build [`RequestCtx`] →
//! dispatch → HTTP response. Routing headers are read only as untrusted hints;
//! the JSON-RPC body is authoritative.

use std::io::Read;

use fastly::http::StatusCode;
use fastly::{Request, Response};

use mcp_core::jsonrpc::{ErrorCode, RpcError, RpcId, RpcRequest, RpcResponse};
use mcp_core::{dispatch, Meta, RequestCtx, Router, RoutingHeaders};

use crate::auth::{www_authenticate, AuthError, JwtVerifier, TokenVerifier};
use crate::config::VerifierConfig;
use crate::stores;

/// Serve one MCP request. `router` carries the registered handlers and the
/// installed token signer; `config` is the loaded verifier configuration.
pub fn serve(router: &Router, config: &VerifierConfig, mut req: Request) -> Response {
    // Capture header hints before consuming the body.
    let protocol_version = req.get_header_str("mcp-protocol-version").map(str::to_owned);
    let mcp_method = req.get_header_str("mcp-method").map(str::to_owned);
    let mcp_name = req.get_header_str("mcp-name").map(str::to_owned);
    let authorization = req.get_header_str("authorization").map(str::to_owned);
    let content_length = req
        .get_header_str("content-length")
        .and_then(|v| v.parse::<usize>().ok());

    // 1. Pre-auth body-size fast reject (cheap, credential-independent DoS guard).
    let max = config.max_body_bytes;
    if content_length.map(|len| len > max).unwrap_or(false) {
        return too_large(max);
    }

    // 2. Authenticate BEFORE reading or parsing the body (CMCP-004). An
    //    unauthenticated or malformed-credential request never costs body-read,
    //    JSON parsing, or a JWKS fetch.
    let principal = match authenticate(config, authorization.as_deref()) {
        Ok(p) => p,
        Err(resp) => return resp,
    };

    // 3. Read the body (bounded) and parse the envelope exactly once.
    let mut buf = Vec::new();
    if req
        .take_body()
        .take((max as u64) + 1)
        .read_to_end(&mut buf)
        .is_err()
    {
        return json_response(StatusCode::BAD_REQUEST, &parse_error("could not read body"));
    }
    if buf.len() > max {
        return too_large(max);
    }
    // Reject batch arrays (unsupported in v1) via a cheap prefix check.
    if buf.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'[') {
        return json_response(
            StatusCode::BAD_REQUEST,
            &parse_error("JSON-RPC batch requests are not supported"),
        );
    }
    let request: RpcRequest = match serde_json::from_slice(&buf) {
        Ok(r) => r,
        Err(_) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                &RpcResponse::error(
                    RpcId::Null,
                    RpcError::new(ErrorCode::INVALID_REQUEST, "invalid JSON-RPC request"),
                ),
            )
        }
    };

    // 4. Build the request context.
    let params = request.params_or_null();
    let meta = Meta::from_params(&params);
    let headers = RoutingHeaders {
        mcp_method,
        mcp_name,
        protocol_version,
    };
    let ctx =
        RequestCtx::new(meta, principal, headers).with_now_unix(stores::now_unix());

    // 5. Dispatch.
    match dispatch(router, &ctx, &request) {
        None => Response::from_status(StatusCode::NO_CONTENT), // notification
        Some(mut response) => {
            // Sanitize internal errors before they reach the client: replace the
            // detail with a correlation id and log the real detail server-side
            // (CMCP-008). Client-safe errors are left untouched.
            let correlation = mcp_core::correlation_id();
            if let Some(original) = response.redact_internal(&correlation) {
                eprintln!("internal error [{correlation}]: {original}");
            }
            let status = http_status_for(&response);
            // Fail-closed edge caching: derive directives from the result's
            // cacheScope/ttlMs and the request's (possibly tainted) cacheability.
            let decision =
                crate::cache::decide(&request.method, response.result.as_ref(), ctx.is_cacheable());
            let mut http = json_response(status, &response);
            http.set_header("Cache-Control", &decision.cache_control);
            if let Some(key) = decision.surrogate_key {
                http.set_header("Surrogate-Key", key);
            }
            http
        }
    }
}

/// Resolve the principal, or return a ready 401 response on failure.
// The Err variant intentionally carries a full `Response` (the 401 to return);
// boxing it would add indirection on the hot path for no benefit.
#[allow(clippy::result_large_err)]
fn authenticate(
    config: &VerifierConfig,
    authorization: Option<&str>,
) -> Result<Option<mcp_core::Principal>, Response> {
    if !config.auth_required {
        return Ok(None);
    }
    // Require a syntactically-present Bearer token BEFORE fetching JWKS, so a
    // missing/malformed credential cannot induce an outbound issuer request
    // (CMCP-004).
    let token = match authorization.and_then(bearer_token) {
        Some(t) if !t.is_empty() => t,
        _ => return Err(unauthorized(config)),
    };

    let now = stores::now_unix();
    let jwks = stores::fetch_jwks(config).map_err(|_| unauthorized(config))?;
    match JwtVerifier::new(config, &jwks).verify(token, now) {
        Ok(principal) => Ok(Some(principal)),
        // Unknown kid: the issuer may have rotated. Attempt one rate-limited
        // refresh and retry. If the refresh is suppressed (recent, or the cache
        // is unavailable — fail-closed for issuer traffic), the original failure
        // stands (CMCP-011).
        Err(AuthError::UnknownKid) => {
            match stores::refresh_jwks_for_unknown_kid(config) {
                Ok(Some(fresh)) => JwtVerifier::new(config, &fresh)
                    .verify(token, now)
                    .map(Some)
                    .map_err(|_| unauthorized(config)),
                Ok(None) | Err(_) => Err(unauthorized(config)),
            }
        }
        Err(_) => Err(unauthorized(config)),
    }
}

/// Extract the token from an `Authorization: Bearer <token>` header (scheme is
/// case-insensitive). Returns `None` when the scheme is absent or malformed.
fn bearer_token(header: &str) -> Option<&str> {
    let (scheme, token) = header.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then(|| token.trim())
}

fn unauthorized(config: &VerifierConfig) -> Response {
    Response::from_status(StatusCode::UNAUTHORIZED)
        .with_header(
            "WWW-Authenticate",
            www_authenticate(&config.protected_resource_metadata_url),
        )
        .with_header("Content-Type", "application/json")
        .with_body(r#"{"error":"unauthorized"}"#)
}

fn too_large(max: usize) -> Response {
    Response::from_status(StatusCode::PAYLOAD_TOO_LARGE)
        .with_header("Content-Type", "application/json")
        .with_body(format!(r#"{{"error":"request body exceeds {max} bytes"}}"#))
}

fn parse_error(detail: &str) -> RpcResponse {
    RpcResponse::error(RpcId::Null, RpcError::new(ErrorCode::PARSE_ERROR, detail))
}

fn json_response(status: StatusCode, response: &RpcResponse) -> Response {
    let body = serde_json::to_string(response).unwrap_or_else(|_| "{}".to_string());
    Response::from_status(status)
        .with_header("Content-Type", "application/json")
        .with_body(body)
}

/// Map a JSON-RPC response to an HTTP status: client-side protocol errors →
/// 4xx, internal → 500, everything else (including tool `isError` results) →
/// 200.
fn http_status_for(response: &RpcResponse) -> StatusCode {
    match response.error.as_ref().map(|e| e.code) {
        None => StatusCode::OK,
        Some(code) => match code {
            ErrorCode::METHOD_NOT_FOUND => StatusCode::NOT_FOUND,
            ErrorCode::INTERNAL_ERROR => StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::INSUFFICIENT_SCOPE => StatusCode::FORBIDDEN,
            ErrorCode::PARSE_ERROR
            | ErrorCode::INVALID_REQUEST
            | ErrorCode::INVALID_PARAMS
            | ErrorCode::MISSING_REQUIRED_CLIENT_CAPABILITY
            | ErrorCode::UNSUPPORTED_PROTOCOL_VERSION
            | ErrorCode::HEADER_MISMATCH => StatusCode::BAD_REQUEST,
            _ => StatusCode::OK,
        },
    }
}
