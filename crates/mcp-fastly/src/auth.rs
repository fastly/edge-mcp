//! Bearer-token verification (platform-neutral, host-testable).
//!
//! [`JwtVerifier`] validates an ES256 JWT against a JWKS and the
//! [`VerifierConfig`]: signature (by `kid`), `exp`/`nbf` within a bounded
//! leeway, issuer match, and the issuer↔audience binding (`aud` must intersect
//! the audiences registered for this issuer — an allowlist of issuers alone is
//! not enough). On success it yields an [`mcp_core::Principal`].
//!
//! ES256 (P-256 / SHA-256) is the supported algorithm — fast to verify within
//! the Compute CPU budget and WASM-friendly (RustCrypto `p256`, no `ring`).
//! The JWKS fetch and KV caching happen in the wasm adapter; this module is the
//! pure verification core.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::Deserialize;
use serde_json::Value;

use mcp_core::Principal;

use crate::config::VerifierConfig;

/// A JSON Web Key (EC P-256 only, for ES256).
#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    #[serde(default)]
    pub kty: String,
    #[serde(default)]
    pub crv: String,
    #[serde(default)]
    pub kid: String,
    #[serde(default)]
    pub x: String,
    #[serde(default)]
    pub y: String,
}

impl Jwk {
    fn verifying_key(&self) -> Result<VerifyingKey, AuthError> {
        if self.kty != "EC" || self.crv != "P-256" {
            return Err(AuthError::BadKey);
        }
        let x = b64url(&self.x)?;
        let y = b64url(&self.y)?;
        if x.len() != 32 || y.len() != 32 {
            return Err(AuthError::BadKey);
        }
        let mut sec1 = Vec::with_capacity(65);
        sec1.push(0x04); // uncompressed point
        sec1.extend_from_slice(&x);
        sec1.extend_from_slice(&y);
        VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| AuthError::BadKey)
    }
}

/// A JWKS document.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct JwkSet {
    #[serde(default)]
    pub keys: Vec<Jwk>,
}

impl JwkSet {
    pub fn parse(bytes: &[u8]) -> Result<Self, AuthError> {
        serde_json::from_slice(bytes).map_err(|_| AuthError::Malformed("jwks"))
    }

    /// Find the key for a `kid`; if the token omits `kid` and there is exactly
    /// one key, use it.
    fn find(&self, kid: Option<&str>) -> Result<&Jwk, AuthError> {
        match kid {
            Some(k) => self.keys.iter().find(|j| j.kid == k).ok_or(AuthError::UnknownKid),
            None if self.keys.len() == 1 => Ok(&self.keys[0]),
            None => Err(AuthError::UnknownKid),
        }
    }
}

/// A verification failure. Never carries token contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    MissingToken,
    Malformed(&'static str),
    UnsupportedAlg,
    UnknownKid,
    BadKey,
    BadSignature,
    Expired,
    NotYetValid,
    IssuerMismatch,
    AudienceMismatch,
    MissingClaim(&'static str),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "authentication failed: {self:?}")
    }
}

/// Verifies a bearer token, yielding a [`Principal`].
pub trait TokenVerifier {
    fn verify(&self, token: &str, now: u64) -> Result<Principal, AuthError>;
}

/// The bundled ES256 JWT verifier.
pub struct JwtVerifier<'a> {
    pub config: &'a VerifierConfig,
    pub jwks: &'a JwkSet,
}

impl<'a> JwtVerifier<'a> {
    pub fn new(config: &'a VerifierConfig, jwks: &'a JwkSet) -> Self {
        JwtVerifier { config, jwks }
    }
}

fn b64url(s: &str) -> Result<Vec<u8>, AuthError> {
    URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('=').as_bytes())
        .map_err(|_| AuthError::Malformed("base64url"))
}

fn aud_list(aud: Option<&Value>) -> Vec<String> {
    match aud {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(a)) => a.iter().filter_map(|v| v.as_str().map(String::from)).collect(),
        _ => vec![],
    }
}

impl TokenVerifier for JwtVerifier<'_> {
    fn verify(&self, token: &str, now: u64) -> Result<Principal, AuthError> {
        if token.is_empty() {
            return Err(AuthError::MissingToken);
        }
        let mut parts = token.split('.');
        let (h, p, s) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(h), Some(p), Some(s), None) => (h, p, s),
            _ => return Err(AuthError::Malformed("structure")),
        };

        // Header: require ES256.
        let header: Value =
            serde_json::from_slice(&b64url(h)?).map_err(|_| AuthError::Malformed("header"))?;
        if header.get("alg").and_then(Value::as_str) != Some("ES256") {
            return Err(AuthError::UnsupportedAlg);
        }
        let kid = header.get("kid").and_then(Value::as_str);

        // Signature over "header.payload".
        let jwk = self.jwks.find(kid)?;
        let vk = jwk.verifying_key()?;
        let sig_bytes = b64url(s)?;
        let sig = Signature::from_slice(&sig_bytes).map_err(|_| AuthError::Malformed("sig"))?;
        // The signing input is the "header.payload" prefix already present in the
        // token — slice it instead of reallocating.
        let signing_input = &token[..h.len() + 1 + p.len()];
        vk.verify(signing_input.as_bytes(), &sig)
            .map_err(|_| AuthError::BadSignature)?;

        // Claims.
        let payload: Value =
            serde_json::from_slice(&b64url(p)?).map_err(|_| AuthError::Malformed("payload"))?;

        let exp = payload.get("exp").and_then(Value::as_u64).ok_or(AuthError::MissingClaim("exp"))?;
        if now > exp.saturating_add(self.config.leeway_secs) {
            return Err(AuthError::Expired);
        }
        if let Some(nbf) = payload.get("nbf").and_then(Value::as_u64) {
            if now.saturating_add(self.config.leeway_secs) < nbf {
                return Err(AuthError::NotYetValid);
            }
        }

        let iss = payload.get("iss").and_then(Value::as_str).unwrap_or_default();
        if iss != self.config.issuer {
            return Err(AuthError::IssuerMismatch);
        }

        let auds = aud_list(payload.get("aud"));
        if !self.config.audience_matches(&auds) {
            return Err(AuthError::AudienceMismatch);
        }

        let subject = payload
            .get("sub")
            .and_then(Value::as_str)
            .ok_or(AuthError::MissingClaim("sub"))?
            .to_string();
        let scopes = payload
            .get("scope")
            .and_then(Value::as_str)
            .map(|s| s.split(' ').map(String::from).collect())
            .unwrap_or_default();
        let claims = payload.as_object().cloned().unwrap_or_default();

        Ok(Principal {
            issuer: iss.to_string(),
            subject,
            scopes,
            claims,
        })
    }
}

/// The `WWW-Authenticate` challenge value for a 401. The metadata URL is taken
/// from configuration, never from a request header (header-injection guard).
///
/// Note: the `WWW-Authenticate` challenge and protected-resource-metadata
/// document are HTTP-transport / RFC 9728 concerns that live outside the MCP
/// wire types — the official SDK (`rmcp`, adopted types-only here) does not
/// model them, so there is nothing to reconcile against. The `resource_metadata`
/// parameter and PRM document format follow RFC 9728 and the 2026-07-28
/// authorization spec.
pub fn www_authenticate(prm_url: &str) -> String {
    format!("Bearer resource_metadata=\"{prm_url}\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, SigningKey};
    use serde_json::json;

    fn b64(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// A fixed ES256 keypair + the JWKS advertising its public key.
    fn keypair() -> (SigningKey, JwkSet) {
        let sk = SigningKey::from_slice(&[0x11u8; 32]).unwrap();
        let vk = sk.verifying_key();
        let point = vk.to_encoded_point(false);
        let jwk = Jwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            kid: "test-key".into(),
            x: b64(point.x().unwrap()),
            y: b64(point.y().unwrap()),
        };
        (sk, JwkSet { keys: vec![jwk] })
    }

    fn mint(sk: &SigningKey, claims: Value) -> String {
        let header = b64(br#"{"alg":"ES256","kid":"test-key","typ":"JWT"}"#);
        let payload = b64(serde_json::to_string(&claims).unwrap().as_bytes());
        let signing_input = format!("{header}.{payload}");
        let sig: Signature = sk.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", b64(&sig.to_bytes()))
    }

    fn config() -> VerifierConfig {
        VerifierConfig {
            auth_required: true,
            allow_anonymous_demo: false,
            issuer: "https://issuer.example.com".into(),
            audiences: vec!["https://mcp.example.com".into()],
            jwks_uri: "https://issuer.example.com/jwks".into(),
            jwks_backend: "issuer_jwks".into(),
            protected_resource_metadata_url: "https://mcp.example.com/prm".into(),
            max_body_bytes: 1024,
            leeway_secs: 30,
        }
    }

    fn valid_claims() -> Value {
        json!({
            "iss": "https://issuer.example.com",
            "sub": "user-42",
            "aud": "https://mcp.example.com",
            "exp": 10_000,
            "nbf": 900,
            "scope": "read write"
        })
    }

    #[test]
    fn valid_token_yields_principal() {
        let (sk, jwks) = keypair();
        let cfg = config();
        let v = JwtVerifier::new(&cfg, &jwks);
        let p = v.verify(&mint(&sk, valid_claims()), 1000).unwrap();
        assert_eq!(p.issuer, "https://issuer.example.com");
        assert_eq!(p.subject, "user-42");
        assert_eq!(p.scopes, vec!["read", "write"]);
    }

    #[test]
    fn expired_token_rejected() {
        let (sk, jwks) = keypair();
        let cfg = config();
        let v = JwtVerifier::new(&cfg, &jwks);
        // now well past exp + leeway
        assert_eq!(v.verify(&mint(&sk, valid_claims()), 20_000), Err(AuthError::Expired));
    }

    #[test]
    fn not_yet_valid_rejected() {
        let (sk, jwks) = keypair();
        let cfg = config();
        let v = JwtVerifier::new(&cfg, &jwks);
        // now well before nbf - leeway
        assert_eq!(v.verify(&mint(&sk, valid_claims()), 100), Err(AuthError::NotYetValid));
    }

    #[test]
    fn wrong_issuer_rejected() {
        let (sk, jwks) = keypair();
        let cfg = config();
        let mut claims = valid_claims();
        claims["iss"] = json!("https://evil.example.com");
        let v = JwtVerifier::new(&cfg, &jwks);
        assert_eq!(v.verify(&mint(&sk, claims), 1000), Err(AuthError::IssuerMismatch));
    }

    #[test]
    fn wrong_audience_rejected_even_with_right_issuer() {
        let (sk, jwks) = keypair();
        let cfg = config();
        let mut claims = valid_claims();
        claims["aud"] = json!("https://other-resource.example.com");
        let v = JwtVerifier::new(&cfg, &jwks);
        assert_eq!(v.verify(&mint(&sk, claims), 1000), Err(AuthError::AudienceMismatch));
    }

    #[test]
    fn tampered_signature_rejected() {
        let (sk, jwks) = keypair();
        let cfg = config();
        let token = mint(&sk, valid_claims());
        // Corrupt the payload but keep the old signature.
        let mut parts: Vec<&str> = token.split('.').collect();
        let forged_payload = b64(
            serde_json::to_string(&json!({
                "iss":"https://issuer.example.com","sub":"admin",
                "aud":"https://mcp.example.com","exp":10_000
            }))
            .unwrap()
            .as_bytes(),
        );
        parts[1] = &forged_payload;
        let forged = parts.join(".");
        let v = JwtVerifier::new(&cfg, &jwks);
        assert_eq!(v.verify(&forged, 1000), Err(AuthError::BadSignature));
    }

    #[test]
    fn unknown_kid_rejected() {
        let (sk, _) = keypair();
        let cfg = config();
        let empty = JwkSet::default();
        let v = JwtVerifier::new(&cfg, &empty);
        assert_eq!(v.verify(&mint(&sk, valid_claims()), 1000), Err(AuthError::UnknownKid));
    }

    #[test]
    fn non_es256_alg_rejected() {
        let cfg = config();
        let (_, jwks) = keypair();
        let header = b64(br#"{"alg":"none","kid":"test-key"}"#);
        let payload = b64(br#"{"iss":"x"}"#);
        let token = format!("{header}.{payload}.");
        let v = JwtVerifier::new(&cfg, &jwks);
        assert_eq!(v.verify(&token, 1000), Err(AuthError::UnsupportedAlg));
    }

    #[test]
    fn empty_token_is_missing() {
        let cfg = config();
        let jwks = JwkSet::default();
        let v = JwtVerifier::new(&cfg, &jwks);
        assert_eq!(v.verify("", 1000), Err(AuthError::MissingToken));
    }

    #[test]
    fn www_authenticate_uses_configured_url() {
        assert_eq!(
            www_authenticate("https://mcp.example.com/prm"),
            "Bearer resource_metadata=\"https://mcp.example.com/prm\""
        );
    }
}
