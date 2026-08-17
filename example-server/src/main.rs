//! Example stateless MCP server for Fastly Compute.
//!
//! Registers the demo handlers ([`tools`]) on an `mcp-core` router, wires the
//! Fastly bindings (config, AEAD signer, KV task store), and serves each request
//! statelessly. The handlers themselves are platform-neutral and unit-tested on
//! the host; this entrypoint only compiles for `wasm32-wasip1`.

// On non-wasm (host) builds the entrypoint is a stub, so the handlers look
// unused — but they are exercised by `cargo test` and used by the wasm `main`.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
mod tools;

#[cfg(target_arch = "wasm32")]
fn main() {
    use mcp_core::Router;

    let req = fastly::Request::from_client();

    // Fail CLOSED on config-load failure: a Config Store outage must not
    // silently disable auth. (Auth is still opt-in per deployment via the
    // `auth_required` key — that is an explicit, present-config choice.)
    let config = match mcp_fastly::stores::load_config() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("config load failed: {e}");
            return fastly::Response::from_status(fastly::http::StatusCode::SERVICE_UNAVAILABLE)
                .with_body("configuration unavailable")
                .send_to_client();
        }
    };

    let mut router = Router::new();
    tools::register_handlers(&mut router);

    // Fail closed if any tool advertises a schema keyword the validator does not
    // enforce — the advertised contract must equal the enforced subset (CMCP-010).
    if let Err(e) = router.validate_registered_schemas() {
        eprintln!("schema registration error: {e}");
        return fastly::Response::from_status(fastly::http::StatusCode::SERVICE_UNAVAILABLE)
            .with_body("server misconfigured")
            .send_to_client();
    }

    // Install the AEAD signer (MRTR / Task handles) from the Secret Store.
    match mcp_fastly::stores::load_signer() {
        Ok(signer) => {
            router.with_signer(Box::new(signer));
        }
        Err(e) => {
            eprintln!("warning: no token signer configured ({e}); MRTR/Tasks disabled");
        }
    }

    // Durable task store (enables the Tasks extension).
    router.with_task_store(Box::new(mcp_fastly::kv_tasks::KvTaskStore::new()));

    // Idempotency store (exactly-once tools/call via a client idempotencyKey).
    router.with_idempotency_store(Box::new(
        mcp_fastly::kv_idempotency::KvIdempotencyStore::new(),
    ));

    mcp_fastly::adapter::serve(&router, &config, req).send_to_client();
}

#[cfg(not(target_arch = "wasm32"))]
fn main() {
    eprintln!(
        "example-server is a Fastly Compute program. Build it with:\n  \
         cargo build --release --target wasm32-wasip1 --package example-server\n\
         or run `fastly compute serve`. The tool handlers are covered by `cargo test`."
    );
}
