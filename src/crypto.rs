use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use base64ct::{Base64UrlUnpadded, Encoding};
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Verify PKCE S256: challenge == BASE64URL-NOPAD(SHA256(verifier))
pub fn verify_pkce(verifier: &str, challenge: &str) -> bool {
    let hash = Sha256::digest(verifier.as_bytes());
    Base64UrlUnpadded::encode_string(&hash) == challenge
}

pub fn hash_secret(secret: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(secret.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("Argon2 error: {e}"))
}

pub fn verify_hashed_secret(secret: &str, hash: &str) -> bool {
    PasswordHash::new(hash)
        .map(|h| Argon2::default().verify_password(secret.as_bytes(), &h).is_ok())
        .unwrap_or(false)
}

/// 32 random bytes → 43-char base64url token (no padding).
pub fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    Base64UrlUnpadded::encode_string(&bytes)
}

/// SHA-256 hash of a token for storage (tokens are high-entropy; Argon2 unnecessary).
pub fn hash_token(token: &str) -> String {
    let hash = Sha256::digest(token.as_bytes());
    Base64UrlUnpadded::encode_string(&hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use base64ct::{Base64UrlUnpadded, Encoding};

    #[test]
    fn pkce_correct_verifier_passes() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let hash = Sha256::digest(verifier.as_bytes());
        let challenge = Base64UrlUnpadded::encode_string(&hash);
        assert!(verify_pkce(verifier, &challenge));
    }

    #[test]
    fn pkce_wrong_verifier_fails() {
        assert!(!verify_pkce("wrong_verifier", "some_challenge"));
    }

    #[test]
    fn argon2_hash_and_verify_roundtrip() {
        let secret = "super-secret";
        let hash = hash_secret(secret).unwrap();
        assert!(verify_hashed_secret(secret, &hash));
        assert!(!verify_hashed_secret("wrong", &hash));
    }

    #[test]
    fn tokens_are_unique_and_43_chars() {
        let t1 = generate_token();
        let t2 = generate_token();
        assert_ne!(t1, t2);
        assert_eq!(t1.len(), 43);
    }

    #[test]
    fn token_hash_is_deterministic() {
        assert_eq!(hash_token("abc"), hash_token("abc"));
        assert_ne!(hash_token("abc"), hash_token("def"));
    }
}
