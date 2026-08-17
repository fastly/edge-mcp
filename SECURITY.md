# Security

This is an **unmaintained reference implementation** (see the notice in
[`README.md`](README.md)). It aims to be *secure by default* and to model good
MCP security patterns, but it is not a managed product. Before any real
deployment, read this document, complete the deployment-layer controls below,
and adopt it into a maintained fork with its own patch process.

## What this codebase enforces

These controls are implemented and tested in this repository:

- **Fail-closed authentication.** Auth is required by default; running without
  it requires an explicit `auth_required="false"` **and**
  `allow_anonymous_demo="true"`. Missing/malformed config or a Config Store
  load failure fails closed. The shipped `fastly.toml` is secure; local
  unauthenticated runs use the clearly-labelled `fastly.demo.toml`.
- **ES256 JWT verification** with `kid`/signature, `exp`/`nbf` (≤30s leeway),
  issuer allowlist, and an issuer↔audience binding.
- **Default-deny scope authorization.** `tools/call` requires the target
  tool's declared scopes; `tasks/*` require task scopes. Insufficient scope →
  `-32023` / HTTP 403 naming only the missing scope.
- **Credential-cheap rejection.** A missing/malformed bearer is rejected before
  any JWKS fetch or body parse; bodies over the configured cap are rejected
  (HTTP 413) before parse/auth.
- **SSRF-guarded JWKS fetch** (HTTPS-only, host must match the issuer, via a
  statically-declared backend), with a response size cap and status check. The
  unknown-`kid` refresh is rate-limited per POP and **suppressed when the KV
  cache is unavailable** — so unknown-`kid` tokens cannot amplify requests to
  the IdP during a KV outage. (This is per-POP rate limiting, not an atomic
  global single-flight; concurrent requests on a POP may both refetch within the
  window. Client access remains fail-closed throughout; the bounded concern is
  issuer request volume.)
- **Signed, principal-bound continuation/task tokens** (AEAD, domain-separated,
  `(iss,sub)`-bound, expiring), verified before any store access.
- **Client idempotency keys** — best-effort duplicate suppression for
  side-effecting `tools/call` within a bounded retention window (not general
  exactly-once: the effect runs before the result is durably recorded, so a
  crash/KV-failure then a retry after expiry can re-execute; a handler needing
  true exactly-once must couple its effect with an idempotency record in its own
  transactional system).
- **Task-input gate integrity** — `tasks/update` validates and preserves
  responses; missing/declined input leaves the task awaiting input.
- **Central schema validation** of tool arguments before the handler runs. The
  validator enforces a documented JSON-Schema *subset*; tools advertising
  keywords outside it (e.g. `pattern`, `const`, `oneOf`) are **rejected at
  startup** (`Router::validate_registered_schemas`), so the advertised contract
  always equals the enforced subset rather than being silently under-enforced.
- **Fail-closed edge caching** — principal-dependent responses are never
  shared-cached; scope-gated operations are never cacheable.
- **Sanitized errors** — internal errors return a generic message + correlation
  id; detail is logged server-side only.
- **Reproducible builds** — committed `Cargo.lock`, pinned MSRV, CI with tests,
  clippy `-D warnings`, wasm build, and a RustSec advisory scan.

## What you MUST add before production

The following controls are deployment-layer or operational and are **not**
provided by this code. They are required for a production MCP service.

### Rate limiting, quotas, and cost control (ref: CMCP-003)

This server does not bound aggregate request, task, or cost volume. Add:

- **Edge rate limiting** using the Fastly rate limiter (`fastly::RateCounter` /
  ERL) — per-IP limits *before* authentication, and per-principal, per-tool
  limits after. Return a stable `429` and emit an audit event on throttle.
- **Task quotas** — cap concurrent/outstanding tasks per principal and
  globally, and clamp `ttlMs` and `pollIntervalMs` centrally rather than
  trusting handler-supplied values. (The code sets a KV GC margin but does not
  enforce a maximum TTL or an outstanding-task count.)
- **Cost budgets** — weight expensive tools and enforce per-principal budgets;
  apply admission control / circuit breakers around KV and any downstream API a
  tool calls, so a slow or failing dependency cannot cascade.

### Security audit logging and alerting (ref: CMCP-007)

This server logs only a redacted internal-error line. Add a **structured audit
log** shipped to a Fastly real-time **log endpoint**, emitting privacy-safe
events with a correlation id and a stable *hashed* principal id:

- authentication outcome (with reason class), authorization decision
  (allow/deny + required scope), tool/resource name invoked, task lifecycle
  transitions, invalid/expired token or handle, idempotency replay/in-progress,
  rate-limit triggers, and dependency (KV/JWKS/Secret Store) failures.
- **Never log** bearer tokens, raw claims, full tool arguments, continuation
  tokens, task handles, secrets, or unredacted tool output.
- Define alert thresholds (auth-failure spikes, denied-scope bursts, repeated
  invalid handles, task-creation spikes, issuer errors, storage pressure).

### Other operational hardening

- Keep the `issuer_jwks` backend timeout tight (≤10s) so a slow IdP fails fast.
- Provide an emergency JWKS purge/refresh procedure and document key rotation
  (both the AEAD signer key ring via `signer_current_kid` and issuer JWKS).
- Validate real Fastly behavior (CPU/memory limits, KV consistency, cache-purge
  propagation) on a live service — local Viceroy cannot reproduce these.
- Run the official MCP conformance suite when available. The protocol wire
  types are sourced from the official Rust SDK (`rmcp`, types-only) pinned to
  `2026-07-28`, so the shapes track the spec; the remaining hand-built shape
  (the MRTR `input_required` passthrough envelope) is pinned to the SDK type by
  a drift-tripwire test.

## Trust boundary reminder for consumers

MCP tool descriptions, prompt content, resource content, and tool results cross
into an AI trust boundary. A consuming client/agent must treat all of them as
**untrusted input** — isolate them from system instructions, and require human
confirmation for high-impact actions. This server returns deterministic demo
content; those obligations rest with the consumer.

## Reporting

This repository is unmaintained and will not receive security patches. If you
build on it, **fork it, take security ownership, and establish your own patch
SLA and vulnerability-reporting process.**
