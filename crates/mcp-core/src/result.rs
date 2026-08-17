//! MCP `tools/call` result types — sourced from the official SDK (`rmcp::model`).
//!
//! [`CallResult`] is an alias for rmcp's `CallToolResult` — the spec-tracked
//! result carrying the `resultType` discriminator, `content`, `structuredContent`,
//! and `isError`. [`Content`] is rmcp's `ContentBlock` and [`ResultType`] is
//! rmcp's `ResultType`; both are spec-tracked.
//!
//! `CallToolResult` is `#[non_exhaustive]`, so we can't add inherent methods or
//! construct it with a struct literal here. Our constructor ergonomics are
//! restored via the [`CallResultExt`] trait (names chosen to avoid collision
//! with rmcp's inherent `success`/`error`). Bring the trait into scope to use
//! `CallResult::text(..)` etc.

use serde_json::Value;

pub use rmcp::model::{CallToolResult as CallResult, ContentBlock as Content, ResultType};

/// Constructor ergonomics for [`CallResult`] (rmcp's `CallToolResult`).
pub trait CallResultExt {
    /// A successful result with the given content blocks (`resultType: complete`).
    fn complete(content: Vec<Content>) -> Self;
    /// A successful result carrying a single text block.
    fn text(s: impl Into<String>) -> Self;
    /// A tool-**execution** error (the call completed; the tool reported
    /// failure). Reported in the result with `isError: true` — distinct from a
    /// protocol error, which is a JSON-RPC error object.
    fn tool_error(message: impl Into<String>) -> Self;
    /// Attach structured content to a result.
    fn with_structured(self, value: Value) -> Self;
}

impl CallResultExt for CallResult {
    fn complete(content: Vec<Content>) -> Self {
        CallResult::success(content)
    }
    fn text(s: impl Into<String>) -> Self {
        CallResult::success(vec![Content::text(s)])
    }
    fn tool_error(message: impl Into<String>) -> Self {
        CallResult::error(vec![Content::text(message)])
    }
    fn with_structured(mut self, value: Value) -> Self {
        self.structured_content = Some(value);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn call_result_serializes_to_spec_shape() {
        let r = CallResult::text("hello");
        assert_eq!(
            serde_json::to_value(&r).unwrap(),
            json!({
                "resultType": "complete",
                "content": [{ "type": "text", "text": "hello" }],
                "isError": false
            })
        );
    }

    #[test]
    fn tool_error_sets_is_error_in_result_not_jsonrpc() {
        let r = CallResult::tool_error("boom");
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["isError"], true);
        assert_eq!(v["resultType"], "complete");
        assert_eq!(v["content"][0]["text"], "boom");
    }

    #[test]
    fn with_structured_attaches_structured_content() {
        let r = CallResult::text("x").with_structured(json!({ "k": 1 }));
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["structuredContent"]["k"], 1);
    }
}
