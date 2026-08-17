//! Handler registry, request context, and the definitions the `*/list` methods
//! project.
//!
//! The [`Router`] holds boxed trait-object handlers keyed by name (trait
//! objects rather than generics keep WASM monomorphization bounded). A
//! [`RequestCtx`] threads everything a handler needs — the `_meta` context, the
//! verified principal, and the untrusted routing headers — so there is no
//! ambient session state; the design is stateless by construction.

use std::cell::Cell;
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::auth::Principal;
use crate::jsonrpc::RpcError;
use crate::meta::Meta;
use crate::result::CallResult;
use crate::PROTOCOL_VERSION;

/// Untrusted HTTP routing hints. A gateway may set or strip these, so they are
/// never the source of truth — the body's JSON-RPC `method` and `_meta` are (see
/// dispatch middleware). They exist for mismatch detection and observability.
#[derive(Debug, Clone, Default)]
pub struct RoutingHeaders {
    pub mcp_method: Option<String>,
    pub mcp_name: Option<String>,
    pub protocol_version: Option<String>,
}

/// Per-request context handed to every handler.
///
/// Cache-leakage safety is enforced here (see [`RequestCtx::principal`] and
/// [`RequestCtx::is_cacheable`]): the context tracks whether the response may be
/// stored in a *shared* edge cache. It is fail-closed — a request carrying an
/// authenticated principal is not shared-cacheable unless the handler both
/// avoids reading the principal and explicitly asserts principal-independence.
pub struct RequestCtx {
    pub meta: Meta,
    pub headers: RoutingHeaders,
    principal: Option<Principal>,
    /// Whether the handler declared its output principal-independent. Initialized
    /// to `true` only when there is no principal at all (nothing to leak).
    independent: Cell<bool>,
    /// Set once any code reads the principal — permanently taints shared
    /// cacheability so a later `assert` cannot re-enable it.
    tainted: Cell<bool>,
    /// Wall-clock seconds since the Unix epoch, supplied by the host adapter.
    /// The core has no clock; MRTR/Task expiry checks read this so they stay
    /// deterministic and testable.
    now_unix: u64,
}

impl RequestCtx {
    pub fn new(meta: Meta, principal: Option<Principal>, headers: RoutingHeaders) -> Self {
        let no_principal = principal.is_none();
        RequestCtx {
            meta,
            headers,
            principal,
            independent: Cell::new(no_principal),
            tainted: Cell::new(false),
            now_unix: 0,
        }
    }

    /// Set the current wall-clock time (Unix seconds). The host adapter calls
    /// this once when building the context.
    pub fn with_now_unix(mut self, now: u64) -> Self {
        self.now_unix = now;
        self
    }

    pub fn now_unix(&self) -> u64 {
        self.now_unix
    }

    /// The only path to the authenticated principal. **Reading it taints shared
    /// cacheability** — any response derived from principal identity must not be
    /// stored under a shared cache key. Returns `None` when auth is disabled.
    pub fn principal(&self) -> Option<&Principal> {
        self.tainted.set(true);
        self.principal.as_ref()
    }

    /// Whether a principal is present, *without* tainting cacheability. Use for
    /// control flow that does not incorporate principal data into the response.
    pub fn has_principal(&self) -> bool {
        self.principal.is_some()
    }

    /// The principal's scopes for an authorization decision, **without**
    /// tainting cacheability — an authz check does not make the response
    /// principal-specific. Returns `None` when auth is disabled (no principal).
    pub fn principal_scopes(&self) -> Option<&[String]> {
        self.principal.as_ref().map(|p| p.scopes.as_slice())
    }

    /// A handler asserts its output does not depend on the principal, opting the
    /// response back into shared caching. No effect once [`principal`] has been
    /// read (the taint is permanent).
    ///
    /// [`principal`]: RequestCtx::principal
    pub fn mark_principal_independent(&self) {
        self.independent.set(true);
    }

    /// Whether the response is eligible for a *shared* edge cache: the handler
    /// declared principal-independence and never read the principal.
    pub fn is_cacheable(&self) -> bool {
        self.independent.get() && !self.tainted.get()
    }
}

/// The result of invoking a tool.
///
/// Extended in later units with `InputRequired(mrtr::InputRequired)` (MRTR, U5)
/// and `Task(tasks::TaskCreation)` (Tasks extension, U8). Kept to the completed
/// case here so the dispatch spine compiles and is exercised independently.
pub enum ToolOutcome {
    /// A completed call (`resultType: "complete"`).
    Complete(CallResult),
    /// The tool needs mid-call input (`resultType: "input_required"`, MRTR).
    /// The framework seals the carried arguments into a `requestState` token.
    InputRequired(crate::mrtr::InputRequired),
    /// The tool started a long-running task (`resultType: "task"`). The
    /// framework persists it durably and returns an opaque task handle.
    Task(crate::tasks::TaskCreation),
}

/// A tool's advertised definition, as it appears in `tools/list`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolDef {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
    #[serde(rename = "outputSchema", skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<Value>,
}

/// A prompt's advertised definition, as it appears in `prompts/list`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PromptDef {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<Value>,
}

/// A resource's advertised definition, as it appears in `resources/list`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResourceDef {
    pub uri: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// A registered tool: advertises a [`ToolDef`] and executes calls.
pub trait ToolHandler {
    fn definition(&self) -> ToolDef;
    fn call(&self, ctx: &RequestCtx, arguments: &Value) -> Result<ToolOutcome, RpcError>;

    /// Scopes the principal must hold to invoke this tool. **Default-deny:** a
    /// tool that returns an empty set is not callable when authentication is
    /// enabled (it must opt in by declaring at least one scope). Enforcement is
    /// skipped only in anonymous demo mode, where there is no principal.
    fn required_scopes(&self) -> Vec<String> {
        Vec::new()
    }
}

/// A registered prompt.
pub trait PromptHandler {
    fn definition(&self) -> PromptDef;
    fn get(&self, ctx: &RequestCtx, arguments: &Value) -> Result<Value, RpcError>;
}

/// A registered resource.
pub trait ResourceHandler {
    fn definition(&self) -> ResourceDef;
    fn read(&self, ctx: &RequestCtx) -> Result<Value, RpcError>;
}

/// The stateless handler registry and protocol configuration.
///
/// `BTreeMap` gives deterministic `*/list` ordering (stable golden tests).
#[derive(Default)]
pub struct Router {
    tools: BTreeMap<String, Box<dyn ToolHandler>>,
    prompts: BTreeMap<String, Box<dyn PromptHandler>>,
    resources: BTreeMap<String, Box<dyn ResourceHandler>>,
    supported_versions: Vec<String>,
    /// Extension capability ids the server advertises via `server/discover`
    /// (e.g. `io.modelcontextprotocol/tasks`). Populated by the Tasks unit.
    extensions: Vec<String>,
    /// Max items per `*/list` page. `0` means unlimited.
    list_page_size: usize,
    /// Optional `serverInfo` (name/version) surfaced by `server/discover`.
    server_info: Option<Value>,
    /// Signer for MRTR `requestState` and Task handle tokens. Supplied by the
    /// host binding (it holds the key material); `None` disables MRTR/Tasks.
    signer: Option<Box<dyn crate::mrtr::Signer>>,
    /// Durable task store. Installing it enables the Tasks extension and
    /// advertises the `io.modelcontextprotocol/tasks` capability.
    task_store: Option<Box<dyn crate::tasks::TaskStore>>,
    /// Optional idempotency store enabling exactly-once `tools/call` via a
    /// client-supplied `idempotencyKey`.
    idempotency_store: Option<Box<dyn crate::idempotency::IdempotencyStore>>,
}

impl Router {
    /// A router supporting only the current [`PROTOCOL_VERSION`].
    pub fn new() -> Self {
        Router {
            supported_versions: vec![PROTOCOL_VERSION.to_string()],
            list_page_size: 250,
            ..Default::default()
        }
    }

    /// Set the `*/list` page size (mainly for tests / tuning). `0` = unlimited.
    pub fn with_list_page_size(&mut self, n: usize) -> &mut Self {
        self.list_page_size = n;
        self
    }

    pub fn list_page_size(&self) -> usize {
        self.list_page_size
    }

    pub fn register_tool(&mut self, handler: impl ToolHandler + 'static) -> &mut Self {
        let def = handler.definition();
        self.tools.insert(def.name, Box::new(handler));
        self
    }

    pub fn register_prompt(&mut self, handler: impl PromptHandler + 'static) -> &mut Self {
        let def = handler.definition();
        self.prompts.insert(def.name, Box::new(handler));
        self
    }

    pub fn register_resource(&mut self, handler: impl ResourceHandler + 'static) -> &mut Self {
        let def = handler.definition();
        self.resources.insert(def.uri, Box::new(handler));
        self
    }

    /// Advertise an extension capability (id under
    /// `capabilities.extensions` in `server/discover`).
    pub fn register_extension(&mut self, id: impl Into<String>) -> &mut Self {
        self.extensions.push(id.into());
        self
    }

    pub fn supports_version(&self, version: &str) -> bool {
        self.supported_versions.iter().any(|v| v == version)
    }

    pub fn tool(&self, name: &str) -> Option<&dyn ToolHandler> {
        self.tools.get(name).map(|b| b.as_ref())
    }

    pub fn prompt(&self, name: &str) -> Option<&dyn PromptHandler> {
        self.prompts.get(name).map(|b| b.as_ref())
    }

    pub fn resource(&self, uri: &str) -> Option<&dyn ResourceHandler> {
        self.resources.get(uri).map(|b| b.as_ref())
    }

    pub fn tool_defs(&self) -> Vec<ToolDef> {
        self.tools.values().map(|h| h.definition()).collect()
    }

    /// Fail-closed schema guard: verify every registered tool's advertised
    /// input/output schema uses only keywords the central validator enforces
    /// (see [`crate::schema::unsupported_keywords`]). A server should call this
    /// once at startup and refuse to serve on `Err`, so an advertised contract
    /// can never be silently under-enforced (CMCP-010).
    pub fn validate_registered_schemas(&self) -> Result<(), String> {
        for def in self.tool_defs() {
            let mut bad = crate::schema::unsupported_keywords(&def.input_schema);
            if let Some(out) = &def.output_schema {
                bad.extend(crate::schema::unsupported_keywords(out));
            }
            if !bad.is_empty() {
                bad.sort();
                bad.dedup();
                return Err(format!(
                    "tool '{}' advertises schema keyword(s) the validator does not enforce: {} \
                     — use the supported subset or extend crate::schema",
                    def.name,
                    bad.join(", ")
                ));
            }
        }
        Ok(())
    }

    pub fn prompt_defs(&self) -> Vec<PromptDef> {
        self.prompts.values().map(|h| h.definition()).collect()
    }

    pub fn resource_defs(&self) -> Vec<ResourceDef> {
        self.resources.values().map(|h| h.definition()).collect()
    }

    pub fn extensions(&self) -> &[String] {
        &self.extensions
    }

    /// Set the `serverInfo` (e.g. `{"name": "...", "version": "..."}`) that
    /// `server/discover` reports.
    pub fn with_server_info(&mut self, info: Value) -> &mut Self {
        self.server_info = Some(info);
        self
    }

    pub fn server_info(&self) -> Option<&Value> {
        self.server_info.as_ref()
    }

    /// Install the token signer (MRTR `requestState`, Task handles).
    pub fn with_signer(&mut self, signer: Box<dyn crate::mrtr::Signer>) -> &mut Self {
        self.signer = Some(signer);
        self
    }

    pub fn signer(&self) -> Option<&dyn crate::mrtr::Signer> {
        self.signer.as_deref()
    }

    /// Install the durable task store and enable the Tasks extension.
    pub fn with_task_store(&mut self, store: Box<dyn crate::tasks::TaskStore>) -> &mut Self {
        self.task_store = Some(store);
        self.register_extension("io.modelcontextprotocol/tasks");
        self
    }

    pub fn task_store(&self) -> Option<&dyn crate::tasks::TaskStore> {
        self.task_store.as_deref()
    }

    /// Install an idempotency store, enabling exactly-once `tools/call` when a
    /// client supplies an `idempotencyKey`.
    pub fn with_idempotency_store(
        &mut self,
        store: Box<dyn crate::idempotency::IdempotencyStore>,
    ) -> &mut Self {
        self.idempotency_store = Some(store);
        self
    }

    pub fn idempotency_store(&self) -> Option<&dyn crate::idempotency::IdempotencyStore> {
        self.idempotency_store.as_deref()
    }

    pub fn has_tools(&self) -> bool {
        !self.tools.is_empty()
    }

    pub fn has_prompts(&self) -> bool {
        !self.prompts.is_empty()
    }

    pub fn has_resources(&self) -> bool {
        !self.resources.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meta::keys;
    use crate::result::CallResultExt;
    use serde_json::json;

    fn ctx_with(principal: Option<Principal>) -> RequestCtx {
        let meta = Meta::from_params(&json!({
            "_meta": { keys::PROTOCOL_VERSION: PROTOCOL_VERSION }
        }));
        RequestCtx::new(meta, principal, RoutingHeaders::default())
    }

    fn a_principal() -> Principal {
        Principal {
            issuer: "https://issuer.example.com".into(),
            subject: "user-1".into(),
            scopes: vec![],
            claims: Default::default(),
        }
    }

    struct SchemaTool {
        name: &'static str,
        schema: Value,
    }
    impl ToolHandler for SchemaTool {
        fn definition(&self) -> ToolDef {
            ToolDef {
                name: self.name.into(),
                title: None,
                description: "t".into(),
                input_schema: self.schema.clone(),
                output_schema: None,
            }
        }
        fn call(&self, _: &RequestCtx, _: &Value) -> Result<ToolOutcome, RpcError> {
            Ok(ToolOutcome::Complete(crate::result::CallResult::text("ok")))
        }
    }

    #[test]
    fn validate_registered_schemas_accepts_supported_subset() {
        let mut r = Router::new();
        r.register_tool(SchemaTool {
            name: "ok",
            schema: json!({ "type": "object", "properties": { "m": { "type": "string" } } }),
        });
        assert!(r.validate_registered_schemas().is_ok());
    }

    #[test]
    fn validate_registered_schemas_rejects_unsupported_keyword() {
        let mut r = Router::new();
        r.register_tool(SchemaTool {
            name: "bad",
            schema: json!({ "type": "string", "pattern": "^x$" }),
        });
        let err = r.validate_registered_schemas().unwrap_err();
        assert!(err.contains("bad") && err.contains("pattern"), "got: {err}");
    }

    #[test]
    fn no_principal_is_cacheable_by_default() {
        let ctx = ctx_with(None);
        assert!(ctx.is_cacheable());
    }

    #[test]
    fn principal_present_is_fail_closed() {
        let ctx = ctx_with(Some(a_principal()));
        assert!(!ctx.is_cacheable(), "auth-bearing request must default uncacheable");
    }

    #[test]
    fn handler_can_assert_independence_when_principal_unread() {
        let ctx = ctx_with(Some(a_principal()));
        ctx.mark_principal_independent();
        assert!(ctx.is_cacheable());
    }

    #[test]
    fn reading_principal_permanently_taints_even_after_assert() {
        let ctx = ctx_with(Some(a_principal()));
        let _ = ctx.principal(); // taint
        ctx.mark_principal_independent(); // must not re-enable
        assert!(!ctx.is_cacheable());
    }

    #[test]
    fn has_principal_does_not_taint() {
        let ctx = ctx_with(Some(a_principal()));
        ctx.mark_principal_independent();
        assert!(ctx.has_principal());
        assert!(ctx.is_cacheable(), "has_principal must not taint cacheability");
    }
}
