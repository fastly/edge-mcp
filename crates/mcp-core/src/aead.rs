//! A concrete [`Signer`](crate::mrtr::Signer) backed by ChaCha20-Poly1305 AEAD.
//!
//! This is the production sealer for MRTR `requestState` and Task handles. It is
//! platform-agnostic (pure RustCrypto, WASM-compatible), so it lives in the core
//! and is unit-tested here; the host binding supplies the key bytes (from its
//! Secret Store) and constructs it.
//!
//! **Wire envelope** (then base64url, no padding):
//! `version(1) ‖ kid(1) ‖ nonce(12) ‖ ciphertext+tag`.
//!
//! * `version` lets `open` reject unknown formats explicitly — no
//!   trial-decryption oracle.
//! * `kid` selects the key from a ring, so rotation depth is decoupled from
//!   token lifetime: keep several keys and an old token still opens until its
//!   `kid` is dropped. Sealing always uses the first (current) key.
//! * AEAD provides confidentiality (partial inputs may be sensitive) and
//!   integrity in one primitive.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

use crate::mrtr::{Signer, SignerError};

const VERSION: u8 = 1;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

/// A single keyring entry: a 1-byte id and a 32-byte key.
pub struct AeadKey {
    pub kid: u8,
    pub key: [u8; KEY_LEN],
}

/// ChaCha20-Poly1305 signer over a `kid`-indexed key ring. Seals with the first
/// key; opens with whichever key the token's `kid` names.
pub struct AeadSigner {
    keys: Vec<AeadKey>,
}

impl AeadSigner {
    /// Construct from a key ring. The first key is the current (sealing) key;
    /// the rest are accepted on open to support rotation. Errors if empty.
    pub fn new(keys: Vec<AeadKey>) -> Result<Self, SignerError> {
        if keys.is_empty() {
            return Err(SignerError("AEAD signer requires at least one key".into()));
        }
        Ok(AeadSigner { keys })
    }

    fn cipher_for(&self, kid: u8) -> Option<ChaCha20Poly1305> {
        self.keys
            .iter()
            .find(|k| k.kid == kid)
            .map(|k| ChaCha20Poly1305::new(Key::from_slice(&k.key)))
    }
}

impl Signer for AeadSigner {
    fn seal(&self, plaintext: &[u8]) -> Result<String, SignerError> {
        let current = &self.keys[0];
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&current.key));

        let mut nonce_bytes = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| SignerError(format!("nonce generation failed: {e}")))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| SignerError("AEAD encryption failed".into()))?;

        let mut envelope = Vec::with_capacity(2 + NONCE_LEN + ciphertext.len());
        envelope.push(VERSION);
        envelope.push(current.kid);
        envelope.extend_from_slice(&nonce_bytes);
        envelope.extend_from_slice(&ciphertext);

        Ok(URL_SAFE_NO_PAD.encode(envelope))
    }

    fn open(&self, token: &str) -> Result<Vec<u8>, SignerError> {
        let envelope = URL_SAFE_NO_PAD
            .decode(token.as_bytes())
            .map_err(|_| SignerError("invalid token encoding".into()))?;

        // version(1) + kid(1) + nonce(12) + at least the AEAD tag(16)
        if envelope.len() < 2 + NONCE_LEN + 16 {
            return Err(SignerError("token too short".into()));
        }
        if envelope[0] != VERSION {
            return Err(SignerError(format!("unknown token version {}", envelope[0])));
        }
        let kid = envelope[1];
        let cipher = self
            .cipher_for(kid)
            .ok_or_else(|| SignerError(format!("unknown key id {kid}")))?;

        let nonce = Nonce::from_slice(&envelope[2..2 + NONCE_LEN]);
        let ciphertext = &envelope[2 + NONCE_LEN..];

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| SignerError("AEAD authentication failed".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(kid: u8, fill: u8) -> AeadKey {
        AeadKey {
            kid,
            key: [fill; KEY_LEN],
        }
    }

    #[test]
    fn seal_open_roundtrip() {
        let s = AeadSigner::new(vec![key(1, 0xaa)]).unwrap();
        let token = s.seal(b"hello world").unwrap();
        assert_eq!(s.open(&token).unwrap(), b"hello world");
    }

    #[test]
    fn distinct_nonces_produce_distinct_tokens() {
        let s = AeadSigner::new(vec![key(1, 0xaa)]).unwrap();
        let a = s.seal(b"same").unwrap();
        let b = s.seal(b"same").unwrap();
        assert_ne!(a, b, "random nonce should make each sealing unique");
    }

    #[test]
    fn tampered_ciphertext_fails_authentication() {
        let s = AeadSigner::new(vec![key(1, 0xaa)]).unwrap();
        let token = s.seal(b"secret").unwrap();
        let mut raw = URL_SAFE_NO_PAD.decode(&token).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01; // flip a tag/ciphertext bit
        let tampered = URL_SAFE_NO_PAD.encode(raw);
        assert!(s.open(&tampered).is_err());
    }

    #[test]
    fn unknown_version_rejected() {
        let s = AeadSigner::new(vec![key(1, 0xaa)]).unwrap();
        let token = s.seal(b"x").unwrap();
        let mut raw = URL_SAFE_NO_PAD.decode(&token).unwrap();
        raw[0] = 0xff; // bogus version
        let bad = URL_SAFE_NO_PAD.encode(raw);
        let err = s.open(&bad).unwrap_err();
        assert!(err.0.contains("unknown token version"));
    }

    #[test]
    fn rotation_old_kid_still_opens_new_kid_seals() {
        // Ring: current kid=2, previous kid=1.
        let signer_v2 = AeadSigner::new(vec![key(2, 0xbb), key(1, 0xaa)]).unwrap();
        // A token sealed under the old key (kid=1) alone...
        let signer_v1 = AeadSigner::new(vec![key(1, 0xaa)]).unwrap();
        let old_token = signer_v1.seal(b"in flight").unwrap();
        // ...still opens against the ring that carries kid=1 as previous.
        assert_eq!(signer_v2.open(&old_token).unwrap(), b"in flight");
        // New seals use the current key (kid=2).
        let new_token = signer_v2.seal(b"fresh").unwrap();
        assert_eq!(URL_SAFE_NO_PAD.decode(&new_token).unwrap()[1], 2);
    }

    #[test]
    fn kid_rolled_off_ring_is_rejected() {
        let old = AeadSigner::new(vec![key(9, 0x11)]).unwrap();
        let token = old.seal(b"orphan").unwrap();
        let current = AeadSigner::new(vec![key(2, 0xbb), key(1, 0xaa)]).unwrap();
        let err = current.open(&token).unwrap_err();
        assert!(err.0.contains("unknown key id"));
    }

    #[test]
    fn empty_ring_rejected() {
        assert!(AeadSigner::new(vec![]).is_err());
    }
}
