# compute-mcp-server

A **reference implementation of the [Model Context Protocol](https://modelcontextprotocol.io)
`2026-07-28` (the stateless revision) on [Fastly Compute](https://www.fastly.com/products/compute),
in Rust.**

---

⚠️ **No ongoing maintenance — point-in-time example.** This repository is a reference
architecture built against the MCP
`2026-07-28` specification. It **will not be maintained** beyond the initial implementation. Expect no updates, bug
fixes, security patches, dependency bumps, issue responses, or pull-request
reviews. Fork it and adapt it to your needs; do not depend on this repository
itself receiving any changes.

---

MCP is how AI agents call external tools, prompts, and resources. The
`2026-07-28` revision made the protocol stateless — no `initialize` handshake,
no `Mcp-Session-Id`, per-request identity carried in `_meta`, cacheable list
responses, and continuation state carried in signed tokens or an external store.
That model lines up cleanly with edge compute: any instance behind a
round-robin load balancer can serve any request, list responses can be cached
at the edge, and there is no session to pin.

This repo is a worked example — a snapshot of one way to build such a server on
Fastly Compute — split so the protocol logic is reusable independently of the
platform.

## Status

This is a **reference implementation to learn from and build on — not a
certified or turnkey production service.** Read this before depending on it:

- **Unmaintained.** A point-in-time snapshot — no updates, fixes, or reviews
  (see the notice above). Fork it rather than depending on it.
- **Agent-generated.** The code and its tests were written by AI coding agents,
  not by hand — human input was at the direction, design, and decision level.
  Audit it yourself before relying on any of it.
- **Wire types come from the official SDK.** The protocol types are sourced
  from the official MCP Rust SDK ([`rmcp`](https://github.com/modelcontextprotocol/rust-sdk),
  adopted **types-only** — no async runtime or transport) pinned to protocol
  `2026-07-28`, so the JSON-RPC error/result model, `_meta`, content, task,
  discover, and list shapes track the spec rather than being hand-transcribed.
  Where we keep a hand-built shape (the MRTR `input_required` envelope, kept an
  opaque passthrough), a test pins it to the SDK type as a drift tripwire. Two
  items are deliberately outside the SDK: the `WWW-Authenticate` /
  protected-resource-metadata format (an RFC 9728 transport concern the
  types-only SDK does not model) and the `-32023` insufficient-scope code (no
  authorization code is defined by the spec, so ours is provisional).
- **Not conformance-tested.** It passes its own unit + local end-to-end tests;
  it has not been run against an official MCP conformance suite.
- **The framework API is unstable** (`Router`, `ToolHandler`, `Signer`,
  `TokenVerifier`, `TaskStore`). Pin an exact revision if you build on it.
- **Validate edge behavior on a real service.** Local Viceroy cannot reproduce
  the production CPU meter, KV consistency timing, or cache-purge propagation.

## What it implements

- Stateless JSON-RPC dispatch with the `_meta` identity/capability model
- `tools/list`, `tools/call`, `prompts/list`, `resources/list`,
  `resources/read`, and the optional `server/discover`
- **Multi Round-Trip Requests (MRTR)** — mid-call `input_required` with signed,
  principal-bound continuation tokens that any instance can resume
- The **Tasks extension** (`tasks/get` / `tasks/update` / `tasks/cancel`),
  KV-backed, with poll-based completion
- A pluggable **`TokenVerifier`** with a bundled ES256 JWT/JWKS verifier
- **Fail-closed** edge caching of list responses (`ttlMs` / `cacheScope`)

Deliberately **out of scope**: the full OAuth 2.1 authorization flow (only the
verifier interface + 401 challenge are here), the MCP Apps and Enterprise
Managed Authorization extensions, JSON-RPC batching, and the deprecated
`2025`-era surfaces (roots, sampling, logging, HTTP+SSE).

## Layout

| Crate | Role |
|-------|------|
| `crates/mcp-core` | Transport-agnostic protocol engine: JSON-RPC, `_meta`, dispatch, MRTR, Tasks, AEAD token signer. **No `fastly` dependency** — runs and tests on a plain host. |
| `crates/mcp-fastly` | Fastly Compute bindings: request adapter, ES256 JWT/JWKS `TokenVerifier`, fail-closed edge caching, Secret-Store `Signer`, KV-backed `TaskStore`. |
| `example-server` | A deployable Compute program with demo tools (plain, MRTR, task-backed) that exercises the whole stack. |

## Quick start

```bash
# 1. Fast native tests for the protocol core (no WASM toolchain needed):
cargo test -p mcp-core

# 2. Run the example server end-to-end under Viceroy and assert on it.
#    Needs the standalone viceroy >= 0.20 — the fastly CLI's bundled runtime is
#    too old for the fastly 0.13 crate ABI:
cargo install --locked viceroy
scripts/smoke-test.sh
```

The smoke test builds the wasm, starts Viceroy, and drives real HTTP JSON-RPC
through `tools/list`, `tools/call`, `server/discover`, an MRTR round-trip, a Task
create+poll, and protocol-version rejection.

## Adding a tool

Implement a handler from `mcp-core` and register it on the `Router` — the wire
format, cache metadata, `tools/list`, and `server/discover` are generated for
you:

```rust
struct Echo;
impl ToolHandler for Echo {
    fn definition(&self) -> ToolDef { /* name, description, inputSchema */ }
    fn call(&self, _ctx: &RequestCtx, args: &Value) -> Result<ToolOutcome, RpcError> {
        Ok(ToolOutcome::Complete(CallResult::text(/* … */)))
    }
}
// router.register_tool(Echo);
```

A tool can also return `ToolOutcome::InputRequired` (MRTR) or
`ToolOutcome::Task` (Tasks). See `example-server/src/tools.rs` for all three.

## Deploying

```bash
fastly compute build
fastly compute deploy
```

Provision the resources the server reads (see `fastly.toml` for exact names):
the `task_store` and `jwks_cache` KV Stores, the `auth` Secret Store (holding the
AEAD signing key ring), the `verifier` Config Store, and the `issuer_jwks`
backend. Set that backend's timeout tight (≤10s) so a slow IdP fails fast.

## Design notes

A few decisions worth knowing when reading the code:

- **Stateless by construction.** Continuation state for MRTR and Tasks rides in
  AEAD-sealed tokens bound to the `(issuer, subject)` principal, verified before
  any store access. There is no server-side session.
- **Fail-closed caching.** A response reaches the shared edge cache only if it is
  `cacheScope: public` *and* the handler never read the authenticated principal.
  A request that touches the principal is permanently marked uncacheable, and
  `tools/call` output is never shared-cached.
- **Auth is fail-closed by default.** Authentication is **required** unless the
  config *explicitly* opts out with both `auth_required = "false"` **and**
  `allow_anonymous_demo = "true"`. A missing, misspelled, or malformed
  `auth_required` value, or a Config Store load failure, results in a required-auth
  (or 503) posture — never a silently-open endpoint. The shipped `fastly.toml` is
  secure by default; local unauthenticated runs use the clearly-labelled
  `fastly.demo.toml`.
- **Edge budget.** The verifier prefers ES256 (fast to verify), the request body
  is capped before parsing/auth, and the JWKS is KV-cached — to stay within the
  Compute per-request CPU budget.
- **SDK types, our transport.** Protocol types are the official `rmcp` model
  types (adopted types-only: `rmcp = { default-features = false }`, no tokio
  runtime or transport compiled in), while the stateless dispatch spine, edge
  caching, auth, and Fastly bindings are ours. This kills wire-shape drift
  against the spec without pulling a server framework into the WASM binary.

## Security

The server is secure-by-default, but a production deployment must add
deployment-layer controls (edge rate limiting, task/cost quotas, and an audit-log
pipeline). [`SECURITY.md`](SECURITY.md) documents what the code enforces and what
you must add before going to production.

## License

Apache-2.0 — see [`LICENSE`](LICENSE). Copyright 2026 Fastly, Inc.
