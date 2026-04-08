use argon2::{Argon2, PasswordHash, PasswordVerifier};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;

pub const SESSION_COOKIE: &str = "aivpn_admin_session";
pub const CSRF_COOKIE: &str = "aivpn_admin_csrf";
const SESSION_TTL_SECS: i64 = 12 * 60 * 60;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionClaims {
    pub user: String,
    pub exp: i64,
    pub nonce: String,
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("failed to serialize session claims: {0}")]
    Serialize(String),
}

pub fn verify_password_hash(password: &str, password_hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(password_hash) {
        Ok(v) => v,
        Err(_) => return false,
    };

    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

pub fn generate_csrf_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn create_session_token(user: &str, secret: &[u8]) -> Result<String, AuthError> {
    let claims = SessionClaims {
        user: user.to_string(),
        exp: Utc::now().timestamp() + SESSION_TTL_SECS,
        nonce: generate_csrf_token(),
    };

    let claims_json = serde_json::to_vec(&claims)
        .map_err(|e| AuthError::Serialize(e.to_string()))?;

    let claims_b64 = URL_SAFE_NO_PAD.encode(&claims_json);
    let signature = sign_bytes(&claims_json, secret);
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature);

    Ok(format!("{claims_b64}.{sig_b64}"))
}

pub fn verify_session_token(
    token: &str,
    expected_user: &str,
    secret: &[u8],
) -> Option<SessionClaims> {
    let (claims_b64, sig_b64) = token.split_once('.')?;

    let claims_json = URL_SAFE_NO_PAD.decode(claims_b64).ok()?;
    let provided_sig = URL_SAFE_NO_PAD.decode(sig_b64).ok()?;

    let expected_sig = sign_bytes(&claims_json, secret);
    if provided_sig.len() != expected_sig.len()
        || !bool::from(provided_sig.ct_eq(expected_sig.as_slice()))
    {
        return None;
    }

    let claims: SessionClaims = serde_json::from_slice(&claims_json).ok()?;
    if claims.user != expected_user {
        return None;
    }
    if claims.exp < Utc::now().timestamp() {
        return None;
    }

    Some(claims)
}

fn sign_bytes(payload: &[u8], secret: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret)
        .expect("HMAC can use keys of any length");
    mac.update(payload);

    let mut out = [0u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_round_trip() {
        let secret = b"0123456789abcdef0123456789abcdef";
        let token = create_session_token("admin", secret).unwrap();

        let claims = verify_session_token(&token, "admin", secret)
            .expect("session must verify");
        assert_eq!(claims.user, "admin");
    }

    #[test]
    fn session_rejects_wrong_user() {
        let secret = b"0123456789abcdef0123456789abcdef";
        let token = create_session_token("admin", secret).unwrap();
        assert!(verify_session_token(&token, "other", secret).is_none());
    }
}
