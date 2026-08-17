//! Built-in MCP method implementations.
//!
//! These are framework-provided: they introspect the [`Router`](crate::router::Router)
//! registry to answer `*/list`, `*/read`, and `server/discover`, and route
//! `tools/call` into the registered handler. Only `tools/call` (and prompt /
//! resource fetch) reach user code; the rest are generated so cache metadata
//! and capability advertisement stay consistent.

pub mod call;
pub mod discover;
pub mod list;
pub mod tasks;

use crate::jsonrpc::RpcError;

/// Default freshness hint for cacheable list/read responses (5 minutes).
pub const DEFAULT_LIST_TTL_MS: u64 = 300_000;

/// `cacheScope` values.
pub const CACHE_SCOPE_PUBLIC: &str = "public";
pub const CACHE_SCOPE_PRIVATE: &str = "private";

/// Split `items` into a page starting at the opaque `cursor` (an offset, for
/// v1) and compute the `nextCursor` when more remain. `page_size` of `0` means
/// unlimited.
pub fn paginate<T>(
    items: Vec<T>,
    cursor: Option<&str>,
    page_size: usize,
) -> Result<(Vec<T>, Option<String>), RpcError> {
    let n = items.len();
    let offset = match cursor {
        Some(c) => c
            .parse::<usize>()
            .map_err(|_| RpcError::invalid_params("invalid pagination cursor"))?,
        None => 0,
    };
    let start = offset.min(n);
    let take = if page_size == 0 { n } else { page_size };
    let end = start.saturating_add(take).min(n);
    let next = if end < n { Some(end.to_string()) } else { None };
    let page = items.into_iter().skip(start).take(take).collect();
    Ok((page, next))
}
