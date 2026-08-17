//! Fastly edge-data-store access (wasm-only).
//!
//! Loads verifier configuration (Config Store), the AEAD signing key ring
//! (Secret Store), and the JWKS (fetched via the declared backend, cached in a
//! KV Store with a read-time expiry). All host calls live here so the rest of
//! the crate stays host-testable.

use std::io::Read;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fastly::config_store::ConfigStore;
use fastly::kv_store::KVStore;
use fastly::secret_store::SecretStore;
use fastly::Request;

use mcp_core::aead::{AeadKey, AeadSigner};

use crate::auth::JwkSet;
use crate::config::VerifierConfig;

const CONFIG_STORE: &str = "verifier";
const SECRET_STORE: &str = "auth";
const JWKS_KV_STORE: &str = "jwks_cache";
const JWKS_KEY: &str = "jwks";
/// Max age of a cached JWKS, independent of the upstream `Cache-Control`.
const JWKS_MAX_AGE_SECS: u64 = 3600;
/// Hard cap on a JWKS document (ample for an EC key set; bounds memory).
const MAX_JWKS_BYTES: usize = 256 * 1024;

/// Current Unix time in seconds (WASI clock).
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Load and validate the verifier configuration from the Config Store.
pub fn load_config() -> Result<VerifierConfig, String> {
    let store = ConfigStore::try_open(CONFIG_STORE).map_err(|e| format!("config store: {e}"))?;
    VerifierConfig::from_lookup(|k| store.get(k)).map_err(|e| e.0)
}

/// Load the AEAD signer key ring from the Secret Store.
///
/// Keys are named `mrtr-aead-key-<kid>` (1..=4). The current (sealing) kid is
/// read from the Config Store key `signer_current_kid`; if unset it defaults to
/// the highest present. The current key is placed first so it is used for
/// sealing; the rest remain openable so in-flight tokens survive rotation.
pub fn load_signer() -> Result<AeadSigner, String> {
    let store = SecretStore::open(SECRET_STORE).map_err(|e| format!("secret store: {e}"))?;

    let mut found: Vec<AeadKey> = Vec::new();
    for kid in 1u8..=4 {
        if let Some(secret) = store.try_get(&format!("mrtr-aead-key-{kid}")).ok().flatten() {
            let bytes = secret.plaintext().to_vec();
            let key = decode_key(&bytes)
                .ok_or_else(|| format!("key {kid} must be 32 raw or base64 bytes"))?;
            found.push(AeadKey { kid, key });
        }
    }
    if found.is_empty() {
        return Err("no AEAD keys configured (mrtr-aead-key-1..4)".into());
    }

    // Honor the operator-configured current kid (CMCP-011); fall back to the
    // highest present.
    let configured = ConfigStore::try_open(CONFIG_STORE)
        .ok()
        .and_then(|c| c.get("signer_current_kid"))
        .and_then(|v| v.trim().parse::<u8>().ok());
    let current = configured
        .filter(|kid| found.iter().any(|k| k.kid == *kid))
        .unwrap_or_else(|| found.iter().map(|k| k.kid).max().expect("found is non-empty"));
    found.sort_by_key(|k| if k.kid == current { 0 } else { 1 + k.kid as u16 });

    AeadSigner::new(found).map_err(|e| e.0)
}

fn decode_key(bytes: &[u8]) -> Option<[u8; 32]> {
    if bytes.len() == 32 {
        let mut k = [0u8; 32];
        k.copy_from_slice(bytes);
        return Some(k);
    }
    // Try base64 (standard or url-safe, padded or not) of a 32-byte key.
    use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
    use base64::Engine;
    let s = std::str::from_utf8(bytes).ok()?.trim().trim_end_matches('=');
    let decoded = STANDARD_NO_PAD
        .decode(s)
        .or_else(|_| URL_SAFE_NO_PAD.decode(s))
        .ok()?;
    if decoded.len() == 32 {
        let mut k = [0u8; 32];
        k.copy_from_slice(&decoded);
        Some(k)
    } else {
        None
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct CachedJwks {
    expires_at: u64,
    /// The raw JWKS document, stored verbatim to avoid a re-serialize round trip.
    jwks_raw: String,
}

/// Minimum interval between JWKS refetches triggered by an unknown `kid`.
/// Bounds refresh-storm amplification against the IdP when an attacker sends
/// tokens with random unknown kids (CMCP-011).
const MIN_REFRESH_INTERVAL_SECS: u64 = 60;

/// Return the JWKS, from the KV cache when fresh, otherwise fetched via the
/// declared backend and re-cached. Expiry is enforced by an embedded
/// `expires_at` (KV native TTL is only a backstop).
pub fn fetch_jwks(config: &VerifierConfig) -> Result<JwkSet, String> {
    config.validate_jwks_uri().map_err(|e| e.0)?;
    let now = now_unix();
    if let Some((jwks, fetched_at)) = read_cached_jwks() {
        if now < fetched_at + JWKS_MAX_AGE_SECS {
            return jwks; // fresh
        }
    }
    fetch_and_cache(config, now)
}

/// Attempt a rate-limited JWKS refresh after an unknown `kid`, so a
/// newly-rotated issuer key can be picked up before the normal cache TTL
/// expires (CMCP-011). Returns:
///
/// * `Ok(Some(jwks))` — a fresh set was fetched (the cache existed and was
///   older than [`MIN_REFRESH_INTERVAL_SECS`]);
/// * `Ok(None)` — refresh **suppressed**: either the cache was refreshed
///   recently, or it is missing/unreadable. Suppressing when the cache is
///   unavailable is deliberate and **fail-closed for issuer traffic**: it
///   stops unknown-`kid` tokens from amplifying requests to the IdP during a KV
///   outage. The caller treats `None` as "no retry" (verification fails).
///
/// This is per-POP rate limiting, not an atomic global single-flight; two
/// concurrent requests on the same POP may both refetch within the window.
pub fn refresh_jwks_for_unknown_kid(config: &VerifierConfig) -> Result<Option<JwkSet>, String> {
    config.validate_jwks_uri().map_err(|e| e.0)?;
    let now = now_unix();
    match read_cached_jwks() {
        // Cache present and stale enough: refresh once.
        Some((_, fetched_at)) if now >= fetched_at + MIN_REFRESH_INTERVAL_SECS => {
            fetch_and_cache(config, now).map(Some)
        }
        // Cache present but fresh: suppress (don't hammer the IdP).
        Some(_) => Ok(None),
        // No readable cache (missing/KV outage): suppress, so unknown-kid
        // tokens cannot amplify issuer traffic while the cache is degraded.
        None => Ok(None),
    }
}

/// Read + parse the cached JWKS, returning it with the time it was fetched.
fn read_cached_jwks() -> Option<(Result<JwkSet, String>, u64)> {
    let store = KVStore::open(JWKS_KV_STORE).ok()??;
    let mut lookup = store.lookup(JWKS_KEY).ok()?;
    let bytes = lookup.take_body().into_bytes();
    let cached: CachedJwks = serde_json::from_slice(&bytes).ok()?;
    let fetched_at = cached.expires_at.saturating_sub(JWKS_MAX_AGE_SECS);
    let parsed = JwkSet::parse(cached.jwks_raw.as_bytes()).map_err(|_| "cached jwks parse".to_string());
    Some((parsed, fetched_at))
}

/// Fetch the JWKS fresh via the declared backend (SSRF allowlist) and re-cache.
///
/// NOTE: connect/first-byte timeouts for a slow IdP are configured on the
/// `issuer_jwks` backend at the service level, not per-request — keep that
/// backend's timeout tight (<=10s recommended).
fn fetch_and_cache(config: &VerifierConfig, now: u64) -> Result<JwkSet, String> {
    let resp = Request::get(&config.jwks_uri)
        .send(&config.jwks_backend)
        .map_err(|e| format!("jwks fetch: {e}"))?;

    // Only cache/trust a successful response; never poison the cache with an
    // error page from the IdP.
    if !resp.get_status().is_success() {
        return Err(format!("jwks fetch returned status {}", resp.get_status()));
    }

    // Bounded read (memory guard against a misbehaving/compromised issuer).
    let mut body = Vec::new();
    resp.into_body()
        .take((MAX_JWKS_BYTES as u64) + 1)
        .read_to_end(&mut body)
        .map_err(|e| format!("jwks read: {e}"))?;
    if body.len() > MAX_JWKS_BYTES {
        return Err("jwks document too large".to_string());
    }

    let jwks = JwkSet::parse(&body).map_err(|_| "jwks parse".to_string())?;

    // Best-effort re-cache, storing the exact bytes verbatim (valid UTF-8 since
    // it parsed as JSON). Overwrite so a rotated key set replaces the stale one.
    if let Ok(Some(store)) = KVStore::open(JWKS_KV_STORE) {
        if let Ok(value) = serde_json::to_vec(&CachedJwks {
            expires_at: now + JWKS_MAX_AGE_SECS,
            jwks_raw: String::from_utf8(body).unwrap_or_default(),
        }) {
            let _ = store
                .build_insert()
                .time_to_live(Duration::from_secs(JWKS_MAX_AGE_SECS))
                .execute(JWKS_KEY, value);
        }
    }

    Ok(jwks)
}
