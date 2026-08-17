//! Verifier and adapter configuration (platform-neutral).
//!
//! Values come from a Config Store at runtime, but parsing and validation are
//! pure so they can be unit-tested on the host. This is also where the
//! JWKS-fetch SSRF guard lives: the fetch may only target a statically declared
//! backend whose host matches the issuer, over HTTPS.

/// Parsed verifier/adapter configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierConfig {
    /// Whether a valid bearer token is required. **Defaults to `true`** — the
    /// endpoint is fail-closed. Running open requires `auth_required = "false"`
    /// AND [`allow_anonymous_demo`](Self::allow_anonymous_demo) = `"true"`.
    pub auth_required: bool,
    /// Explicit, development-only acknowledgement required to run without
    /// authentication. Absent this, `auth_required = "false"` is a
    /// configuration error rather than a silently-open endpoint.
    pub allow_anonymous_demo: bool,
    /// Expected token issuer (`iss`).
    pub issuer: String,
    /// Audiences registered for this issuer; a token's `aud` must intersect
    /// this set (the issuer↔audience binding).
    pub audiences: Vec<String>,
    /// Absolute HTTPS URL of the issuer's JWKS document.
    pub jwks_uri: String,
    /// Name of the statically declared Fastly backend the JWKS fetch must use
    /// (Compute can only reach declared backends — a natural SSRF allowlist).
    pub jwks_backend: String,
    /// Statically configured protected-resource-metadata URL for the 401
    /// `WWW-Authenticate` challenge (never derived from a request header).
    pub protected_resource_metadata_url: String,
    /// Reject bodies larger than this before parsing/auth (pre-auth DoS guard).
    pub max_body_bytes: usize,
    /// Clock-skew leeway for `exp`/`nbf`, capped small.
    pub leeway_secs: u64,
}

/// Maximum accepted clock-skew leeway for JWT validation (30s).
pub const MAX_LEEWAY_SECS: u64 = 30;
/// Default pre-auth body cap (1 MiB).
pub const DEFAULT_MAX_BODY_BYTES: usize = 1_048_576;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "config error: {}", self.0)
    }
}

fn host_of(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://"))?;
    let end = rest.find(['/', ':']).unwrap_or(rest.len());
    Some(&rest[..end])
}

/// Strictly parse a boolean config value. Absent → `default`. Present values
/// are trimmed and matched case-insensitively against `true`/`false`; anything
/// else is a hard error rather than a silent fall-through to `false` — so a
/// typo like `"True"` or `" yes"` fails loudly (closed) instead of quietly
/// disabling a security control (CWE-636).
fn parse_bool(value: Option<String>, key: &str, default: bool) -> Result<bool, ConfigError> {
    match value {
        None => Ok(default),
        Some(v) => match v.trim().to_ascii_lowercase().as_str() {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(ConfigError(format!(
                "{key} must be \"true\" or \"false\""
            ))),
        },
    }
}

impl VerifierConfig {
    /// Build from a lookup closure over the Config Store (`get(key) -> Option<value>`).
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        // Fail-closed: absent/typo'd auth_required means auth REQUIRED.
        let auth_required = parse_bool(get("auth_required"), "auth_required", true)?;
        let allow_anonymous_demo =
            parse_bool(get("allow_anonymous_demo"), "allow_anonymous_demo", false)?;

        let issuer = get("issuer").unwrap_or_default();
        let audiences = get("audience")
            .map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
            .unwrap_or_default();
        let jwks_uri = get("jwks_uri").unwrap_or_default();
        let jwks_backend = get("jwks_backend").unwrap_or_else(|| "issuer_jwks".to_string());
        let protected_resource_metadata_url =
            get("protected_resource_metadata_url").unwrap_or_default();
        let max_body_bytes = get("max_body_bytes")
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_MAX_BODY_BYTES);
        let leeway_secs = get("leeway_secs")
            .and_then(|v| v.parse().ok())
            .unwrap_or(MAX_LEEWAY_SECS)
            .min(MAX_LEEWAY_SECS);

        let cfg = VerifierConfig {
            auth_required,
            allow_anonymous_demo,
            issuer,
            audiences,
            jwks_uri,
            jwks_backend,
            protected_resource_metadata_url,
            max_body_bytes,
            leeway_secs,
        };

        if cfg.auth_required {
            cfg.validate_for_auth()?;
        } else if !cfg.allow_anonymous_demo {
            // Refuse to construct a silently-open endpoint. Running without auth
            // must be an explicit, named choice.
            return Err(ConfigError(
                "auth_required is false but allow_anonymous_demo is not \"true\" — \
                 refusing to serve an anonymous endpoint. Set auth_required=\"true\" \
                 for production, or allow_anonymous_demo=\"true\" for a local demo."
                    .into(),
            ));
        }
        Ok(cfg)
    }

    /// Validate the configuration required when auth is enabled, including the
    /// JWKS-fetch SSRF guard.
    pub fn validate_for_auth(&self) -> Result<(), ConfigError> {
        if self.issuer.is_empty() {
            return Err(ConfigError("issuer is required when auth is enabled".into()));
        }
        if self.audiences.is_empty() {
            return Err(ConfigError("at least one audience is required".into()));
        }
        if self.protected_resource_metadata_url.is_empty() {
            return Err(ConfigError("protected_resource_metadata_url is required".into()));
        }
        self.validate_jwks_uri()
    }

    /// SSRF guard: the JWKS URI must be HTTPS and share the issuer's host.
    pub fn validate_jwks_uri(&self) -> Result<(), ConfigError> {
        if !self.jwks_uri.starts_with("https://") {
            return Err(ConfigError("jwks_uri must be https".into()));
        }
        let jwks_host = host_of(&self.jwks_uri)
            .ok_or_else(|| ConfigError("jwks_uri has no host".into()))?;
        let issuer_host = host_of(&self.issuer)
            .ok_or_else(|| ConfigError("issuer has no host".into()))?;
        if jwks_host != issuer_host {
            return Err(ConfigError(format!(
                "jwks_uri host {jwks_host} does not match issuer host {issuer_host}"
            )));
        }
        Ok(())
    }

    /// Whether a token's `aud` claim satisfies the issuer↔audience binding.
    pub fn audience_matches(&self, token_auds: &[String]) -> bool {
        token_auds.iter().any(|a| self.audiences.iter().any(|c| c == a))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> =
            pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k: &str| map.get(k).cloned()
    }

    #[test]
    fn absent_auth_key_fails_closed() {
        // No auth_required key at all -> auth is REQUIRED, so config that lacks
        // issuer/audience/etc is a hard error rather than a silent open endpoint.
        let err = VerifierConfig::from_lookup(lookup(&[])).unwrap_err();
        assert!(err.0.contains("issuer"), "absent key must require auth, got: {}", err.0);
    }

    #[test]
    fn auth_false_without_demo_flag_is_rejected() {
        let err = VerifierConfig::from_lookup(lookup(&[("auth_required", "false")])).unwrap_err();
        assert!(err.0.contains("allow_anonymous_demo"), "got: {}", err.0);
    }

    #[test]
    fn explicit_demo_mode_is_allowed() {
        let cfg = VerifierConfig::from_lookup(lookup(&[
            ("auth_required", "false"),
            ("allow_anonymous_demo", "true"),
        ]))
        .unwrap();
        assert!(!cfg.auth_required);
        assert!(cfg.allow_anonymous_demo);
    }

    #[test]
    fn mixed_case_true_still_requires_auth() {
        // The classic footgun: "True" must NOT be read as false/open.
        let err = VerifierConfig::from_lookup(lookup(&[("auth_required", "True")])).unwrap_err();
        assert!(err.0.contains("issuer"), "\"True\" must mean auth required, got: {}", err.0);
    }

    #[test]
    fn whitespace_padded_value_is_parsed() {
        let err = VerifierConfig::from_lookup(lookup(&[("auth_required", "  true ")])).unwrap_err();
        assert!(err.0.contains("issuer"), "padded true must require auth, got: {}", err.0);
    }

    #[test]
    fn invalid_boolean_is_rejected() {
        let err = VerifierConfig::from_lookup(lookup(&[("auth_required", "yes")])).unwrap_err();
        assert!(err.0.contains("auth_required must be"), "got: {}", err.0);
    }

    #[test]
    fn caps_and_leeway_defaults() {
        let cfg = VerifierConfig::from_lookup(lookup(&[
            ("auth_required", "false"),
            ("allow_anonymous_demo", "true"),
            ("leeway_secs", "9000"),
        ]))
        .unwrap();
        assert_eq!(cfg.max_body_bytes, DEFAULT_MAX_BODY_BYTES);
        assert_eq!(cfg.leeway_secs, MAX_LEEWAY_SECS);
    }

    #[test]
    fn auth_enabled_requires_full_config() {
        let err = VerifierConfig::from_lookup(lookup(&[("auth_required", "true")])).unwrap_err();
        assert!(err.0.contains("issuer"));
    }

    #[test]
    fn valid_auth_config_parses() {
        let cfg = VerifierConfig::from_lookup(lookup(&[
            ("auth_required", "true"),
            ("issuer", "https://issuer.example.com"),
            ("audience", "https://mcp.example.com, https://other.example.com"),
            ("jwks_uri", "https://issuer.example.com/.well-known/jwks.json"),
            ("protected_resource_metadata_url", "https://mcp.example.com/.well-known/oauth-protected-resource"),
        ]))
        .unwrap();
        assert!(cfg.auth_required);
        assert_eq!(cfg.audiences.len(), 2);
        assert!(cfg.audience_matches(&["https://mcp.example.com".into()]));
        assert!(!cfg.audience_matches(&["https://evil.example.com".into()]));
    }

    #[test]
    fn ssrf_guard_rejects_http_jwks() {
        let cfg = VerifierConfig {
            auth_required: true,
            allow_anonymous_demo: false,
            issuer: "https://issuer.example.com".into(),
            audiences: vec!["a".into()],
            jwks_uri: "http://issuer.example.com/jwks".into(),
            jwks_backend: "issuer_jwks".into(),
            protected_resource_metadata_url: "https://mcp/prm".into(),
            max_body_bytes: 1024,
            leeway_secs: 30,
        };
        assert!(cfg.validate_jwks_uri().is_err());
    }

    #[test]
    fn ssrf_guard_rejects_host_mismatch() {
        let cfg = VerifierConfig {
            auth_required: true,
            allow_anonymous_demo: false,
            issuer: "https://issuer.example.com".into(),
            audiences: vec!["a".into()],
            jwks_uri: "https://evil.example.com/jwks".into(),
            jwks_backend: "issuer_jwks".into(),
            protected_resource_metadata_url: "https://mcp/prm".into(),
            max_body_bytes: 1024,
            leeway_secs: 30,
        };
        let err = cfg.validate_jwks_uri().unwrap_err();
        assert!(err.0.contains("does not match issuer host"));
    }

    #[test]
    fn ssrf_guard_accepts_matching_https_host() {
        let cfg = VerifierConfig {
            auth_required: true,
            allow_anonymous_demo: false,
            issuer: "https://issuer.example.com".into(),
            audiences: vec!["a".into()],
            jwks_uri: "https://issuer.example.com/.well-known/jwks.json".into(),
            jwks_backend: "issuer_jwks".into(),
            protected_resource_metadata_url: "https://mcp/prm".into(),
            max_body_bytes: 1024,
            leeway_secs: 30,
        };
        assert!(cfg.validate_jwks_uri().is_ok());
    }
}
