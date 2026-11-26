use crate::core::{KeelwayError, Principal};
use base64::Engine as _;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

const JWKS_TIMEOUT_SECS: u64 = 5;
const JWKS_CACHE_MAX_ENTRIES: usize = 64;
const JWKS_CACHE_TTL_SECS: u64 = 300;
const JWKS_REFRESH_COOLDOWN_SECS: u64 = 10;
const MIN_HS256_SECRET_BYTES: usize = 32;
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

fn default_org_claim() -> String {
    "org_id".to_owned()
}

fn default_agent_claim() -> String {
    "agent_id".to_owned()
}

fn default_roles_claim() -> String {
    "roles".to_owned()
}

/// Configuration for stateless JWT/OIDC bearer authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtConfig {
    pub issuer: String,
    pub audience: String,
    #[serde(default)]
    pub hs256_secret: Option<String>,
    #[serde(default)]
    pub ed25519_public_key_hex: Option<String>,
    #[serde(default)]
    pub jwks_url: Option<String>,
    #[serde(default = "default_org_claim")]
    pub org_claim: String,
    #[serde(default = "default_agent_claim")]
    pub agent_claim: String,
    #[serde(default = "default_roles_claim")]
    pub roles_claim: String,
}

struct CachedJwk {
    key: DecodingKey,
    inserted_at: Instant,
}

/// Stateless JWT/OIDC verifier that validates signatures, standard claims, and maps claims to `Principal`.
pub struct JwtVerifier {
    config: JwtConfig,
    hs256_key: Option<DecodingKey>,
    eddsa_key: Option<DecodingKey>,
    http_client: reqwest::Client,
    jwks_cache: RwLock<HashMap<String, CachedJwk>>,
    last_jwks_fetch: RwLock<Option<Instant>>,
}

impl JwtVerifier {
    /// Constructs a `JwtVerifier` from `JwtConfig`, validating key material and claim mappings.
    pub fn new(config: JwtConfig) -> Result<Self, KeelwayError> {
        if config.issuer.trim().is_empty() {
            return Err(KeelwayError::Config(
                "jwt issuer must not be empty".to_owned(),
            ));
        }
        if config.audience.trim().is_empty() {
            return Err(KeelwayError::Config(
                "jwt audience must not be empty".to_owned(),
            ));
        }
        if config.org_claim.trim().is_empty()
            || config.agent_claim.trim().is_empty()
            || config.roles_claim.trim().is_empty()
        {
            return Err(KeelwayError::Config(
                "jwt claim mapping names must not be empty".to_owned(),
            ));
        }

        let hs256_key = match config.hs256_secret.as_deref() {
            Some("") => {
                return Err(KeelwayError::Config(
                    "jwt hs256_secret must not be empty".to_owned(),
                ));
            }
            Some(secret) if secret.len() < MIN_HS256_SECRET_BYTES => {
                return Err(KeelwayError::Config(format!(
                    "jwt hs256_secret must be at least {MIN_HS256_SECRET_BYTES} bytes"
                )));
            }
            Some(secret) => Some(DecodingKey::from_secret(secret.as_bytes())),
            None => None,
        };

        let eddsa_key = match config.ed25519_public_key_hex.as_deref() {
            Some(raw) if !raw.trim().is_empty() => Some(parse_ed25519_key(raw.trim())?),
            Some(_) => {
                return Err(KeelwayError::Config(
                    "jwt ed25519_public_key_hex must not be empty".to_owned(),
                ));
            }
            None => None,
        };

        if let Some(url) = config.jwks_url.as_deref() {
            let trimmed = url.trim();
            if trimmed.is_empty() {
                return Err(KeelwayError::Config(
                    "jwt jwks_url must not be empty".to_owned(),
                ));
            }
            if !is_allowed_jwks_url(trimmed) {
                return Err(KeelwayError::Config(
                    "jwt jwks_url must use https:// (except local loopback http://localhost, http://127.0.0.1, or http://[::1])"
                        .to_owned(),
                ));
            }
        }

        if hs256_key.is_none() && eddsa_key.is_none() && config.jwks_url.is_none() {
            return Err(KeelwayError::Config(
                "jwt config requires at least one of hs256_secret, ed25519_public_key_hex, or jwks_url"
                    .to_owned(),
            ));
        }

        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(JWKS_TIMEOUT_SECS))
            .build()
            .map_err(|e| KeelwayError::Config(format!("failed to build JWKS HTTP client: {e}")))?;

        Ok(Self {
            config,
            hs256_key,
            eddsa_key,
            http_client,
            jwks_cache: RwLock::new(HashMap::new()),
            last_jwks_fetch: RwLock::new(None),
        })
    }

    /// Verifies a bearer JWT and maps its claims to an authenticated `Principal`.
    pub async fn verify_token(&self, token: &str) -> Result<Principal, KeelwayError> {
        let (principal, _) = self.verify_token_with_exp(token).await?;
        Ok(principal)
    }

    /// Verifies a bearer JWT, returning the authenticated `Principal` and optional `exp` timestamp.
    pub async fn verify_token_with_exp(
        &self,
        token: &str,
    ) -> Result<(Principal, Option<u64>), KeelwayError> {
        let token = token.trim();
        if token.is_empty() {
            return Err(KeelwayError::Auth("empty bearer token".to_owned()));
        }

        let header = decode_header(token)
            .map_err(|e| KeelwayError::Auth(format!("invalid JWT header: {e}")))?;

        let decoding_key = self
            .resolve_decoding_key(header.alg, header.kid.as_deref())
            .await?;

        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.audience]);
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.leeway = 0;

        let token_data = decode::<Map<String, Value>>(token, &decoding_key, &validation)
            .map_err(|e| KeelwayError::Auth(format!("JWT verification failed: {e}")))?;

        let exp = token_data.claims.get("exp").and_then(Value::as_u64);
        let principal = self.claims_to_principal(&token_data.claims)?;
        Ok((principal, exp))
    }

    async fn resolve_decoding_key(
        &self,
        alg: Algorithm,
        kid: Option<&str>,
    ) -> Result<DecodingKey, KeelwayError> {
        match alg {
            Algorithm::HS256 => self.hs256_key.clone().ok_or_else(|| {
                KeelwayError::Auth("HS256 token rejected: no HS256 secret configured".to_owned())
            }),
            Algorithm::EdDSA => {
                if let Some(key) = &self.eddsa_key {
                    return Ok(key.clone());
                }
                if self.config.jwks_url.is_some() {
                    return self.resolve_jwk(kid).await;
                }
                Err(KeelwayError::Auth(
                    "EdDSA token rejected: no Ed25519 key or JWKS configured".to_owned(),
                ))
            }
            Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::ES256
            | Algorithm::ES384
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512 => {
                if self.config.jwks_url.is_some() {
                    self.resolve_jwk(kid).await
                } else {
                    Err(KeelwayError::Auth(format!(
                        "algorithm {alg:?} rejected: no JWKS endpoint configured"
                    )))
                }
            }
            other => Err(KeelwayError::Auth(format!(
                "unsupported JWT algorithm: {other:?}"
            ))),
        }
    }

    async fn resolve_jwk(&self, kid: Option<&str>) -> Result<DecodingKey, KeelwayError> {
        let kid = kid.filter(|k| !k.trim().is_empty()).ok_or_else(|| {
            KeelwayError::Auth("JWT header missing required 'kid' for JWKS lookup".to_owned())
        })?;

        if let Some(key) = self.get_cached_jwk(kid) {
            return Ok(key);
        }

        if let Ok(guard) = self.last_jwks_fetch.read()
            && let Some(last_fetch) = *guard
            && last_fetch.elapsed() < Duration::from_secs(JWKS_REFRESH_COOLDOWN_SECS)
        {
            return Err(KeelwayError::Auth(
                "JWKS key not found (refresh cooldown active)".to_owned(),
            ));
        }

        let jwks_url = self
            .config
            .jwks_url
            .as_deref()
            .ok_or_else(|| KeelwayError::Auth("JWKS URL not configured".to_owned()))?;

        if let Ok(mut guard) = self.last_jwks_fetch.write() {
            *guard = Some(Instant::now());
        }

        let response = self
            .http_client
            .get(jwks_url)
            .send()
            .await
            .map_err(|e| KeelwayError::Auth(format!("JWKS fetch failed: {e}")))?;

        if !response.status().is_success() {
            return Err(KeelwayError::Auth(format!(
                "JWKS endpoint returned HTTP {}",
                response.status()
            )));
        }

        let payload: Value = response
            .json()
            .await
            .map_err(|e| KeelwayError::Auth(format!("invalid JWKS payload: {e}")))?;

        let keys = payload
            .get("keys")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                KeelwayError::Auth("invalid JWKS payload: missing 'keys' array".to_owned())
            })?;

        let jwks: Vec<Jwk> = keys
            .iter()
            .filter_map(|entry| serde_json::from_value::<Jwk>(entry.clone()).ok())
            .collect();

        self.cache_jwks(&jwks)?;

        self.get_cached_jwk(kid)
            .ok_or_else(|| KeelwayError::Auth(format!("no matching JWK found for kid '{kid}'")))
    }

    fn get_cached_jwk(&self, kid: &str) -> Option<DecodingKey> {
        let guard = self.jwks_cache.read().ok()?;
        let entry = guard.get(kid)?;
        if entry.inserted_at.elapsed() < Duration::from_secs(JWKS_CACHE_TTL_SECS) {
            Some(entry.key.clone())
        } else {
            None
        }
    }

    fn cache_jwks(&self, jwks: &[Jwk]) -> Result<(), KeelwayError> {
        let mut guard = self
            .jwks_cache
            .write()
            .map_err(|_| KeelwayError::Auth("JWKS cache lock poisoned".to_owned()))?;

        let now = Instant::now();
        let ttl = Duration::from_secs(JWKS_CACHE_TTL_SECS);
        guard.retain(|_, v| now.duration_since(v.inserted_at) < ttl);

        for jwk in jwks {
            let Some(kid) = jwk.common.key_id.as_deref() else {
                continue;
            };
            if let Ok(key) = DecodingKey::from_jwk(jwk) {
                if guard.len() >= JWKS_CACHE_MAX_ENTRIES && !guard.contains_key(kid) {
                    if let Some(oldest_kid) = guard
                        .iter()
                        .min_by_key(|(_, v)| v.inserted_at)
                        .map(|(k, _)| k.clone())
                    {
                        guard.remove(&oldest_kid);
                    }
                }
                guard.insert(
                    kid.to_owned(),
                    CachedJwk {
                        key,
                        inserted_at: now,
                    },
                );
            }
        }
        Ok(())
    }

    fn claims_to_principal(&self, claims: &Map<String, Value>) -> Result<Principal, KeelwayError> {
        let org_id = extract_non_empty_claim(claims, &self.config.org_claim)?;
        let agent_id = extract_non_empty_claim(claims, &self.config.agent_claim)?;
        let roles = extract_roles_claim(claims, &self.config.roles_claim)?;

        Ok(Principal {
            org_id,
            agent_id,
            roles,
        })
    }
}

fn is_allowed_jwks_url(url: &str) -> bool {
    if url.starts_with("https://") {
        return true;
    }
    for prefix in ["http://localhost", "http://127.0.0.1", "http://[::1]"] {
        if let Some(rest) = url.strip_prefix(prefix)
            && (rest.is_empty() || rest.starts_with(':') || rest.starts_with('/'))
        {
            return true;
        }
    }
    false
}

fn parse_ed25519_key(raw: &str) -> Result<DecodingKey, KeelwayError> {
    if raw.starts_with("-----BEGIN ") {
        return DecodingKey::from_ed_pem(raw.as_bytes())
            .map_err(|e| KeelwayError::Config(format!("invalid Ed25519 PEM public key: {e}")));
    }

    let bytes = hex::decode(raw)
        .map_err(|e| KeelwayError::Config(format!("invalid Ed25519 public key hex: {e}")))?;

    let raw_key_bytes = if bytes.len() == 32 {
        bytes.as_slice()
    } else if bytes.len() == 44 && bytes.starts_with(&ED25519_SPKI_PREFIX) {
        &bytes[12..]
    } else {
        return Err(KeelwayError::Config(format!(
            "invalid Ed25519 public key length: expected 32-byte raw key or 44-byte SPKI DER, got {} bytes",
            bytes.len()
        )));
    };

    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw_key_bytes);
    DecodingKey::from_ed_components(&b64)
        .map_err(|e| KeelwayError::Config(format!("invalid Ed25519 public key: {e}")))
}

fn extract_non_empty_claim(
    claims: &Map<String, Value>,
    claim_name: &str,
) -> Result<String, KeelwayError> {
    let val = claims
        .get(claim_name)
        .ok_or_else(|| KeelwayError::Auth(format!("missing required JWT claim '{claim_name}'")))?;
    let s = val
        .as_str()
        .ok_or_else(|| KeelwayError::Auth(format!("JWT claim '{claim_name}' must be a string")))?;
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(KeelwayError::Auth(format!(
            "JWT claim '{claim_name}' must not be empty"
        )));
    }
    Ok(trimmed.to_owned())
}

fn extract_roles_claim(
    claims: &Map<String, Value>,
    claim_name: &str,
) -> Result<Vec<String>, KeelwayError> {
    let Some(val) = claims.get(claim_name) else {
        return Ok(Vec::new());
    };
    match val {
        Value::Array(items) => {
            let mut roles = Vec::with_capacity(items.len());
            for item in items {
                let s = item.as_str().ok_or_else(|| {
                    KeelwayError::Auth(format!(
                        "JWT roles claim '{claim_name}' array elements must be strings"
                    ))
                })?;
                let trimmed = s.trim();
                if !trimmed.is_empty() {
                    roles.push(trimmed.to_owned());
                }
            }
            Ok(roles)
        }
        Value::String(s) => Ok(s.split_whitespace().map(str::to_owned).collect()),
        _ => Err(KeelwayError::Auth(format!(
            "JWT roles claim '{claim_name}' must be an array of strings or whitespace-delimited string"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde_json::json;

    fn test_config() -> JwtConfig {
        JwtConfig {
            issuer: "https://idp.keelway.test".to_owned(),
            audience: "keelway-gateway".to_owned(),
            hs256_secret: Some("super-secret-signing-key-32-bytes!".to_owned()),
            ed25519_public_key_hex: None,
            jwks_url: None,
            org_claim: "org_id".to_owned(),
            agent_claim: "agent_id".to_owned(),
            roles_claim: "roles".to_owned(),
        }
    }

    fn sign_hs256(claims: Value, secret: &str) -> String {
        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap_or_default()
    }

    #[tokio::test]
    async fn valid_hs256_jwt_maps_claims_to_principal() -> Result<(), KeelwayError> {
        let cfg = test_config();
        let secret = cfg.hs256_secret.clone().unwrap_or_default();
        let verifier = JwtVerifier::new(cfg)?;

        let exp = (Utc::now().timestamp() + 300) as u64;
        let token = sign_hs256(
            json!({
                "iss": "https://idp.keelway.test",
                "aud": "keelway-gateway",
                "exp": exp,
                "org_id": "acme-corp",
                "agent_id": "billing-agent",
                "roles": ["reader", "operator"]
            }),
            &secret,
        );

        let principal = verifier.verify_token(&token).await?;
        assert_eq!(principal.org_id, "acme-corp");
        assert_eq!(principal.agent_id, "billing-agent");
        assert_eq!(principal.roles, vec!["reader", "operator"]);
        Ok(())
    }

    #[tokio::test]
    async fn expired_jwt_fails_closed() -> Result<(), KeelwayError> {
        let cfg = test_config();
        let secret = cfg.hs256_secret.clone().unwrap_or_default();
        let verifier = JwtVerifier::new(cfg)?;

        let exp = (Utc::now().timestamp() - 60) as u64;
        let token = sign_hs256(
            json!({
                "iss": "https://idp.keelway.test",
                "aud": "keelway-gateway",
                "exp": exp,
                "org_id": "acme-corp",
                "agent_id": "billing-agent"
            }),
            &secret,
        );

        let err = verifier.verify_token(&token).await;
        assert!(matches!(err, Err(KeelwayError::Auth(_))));
        Ok(())
    }

    #[tokio::test]
    async fn wrong_issuer_fails_closed() -> Result<(), KeelwayError> {
        let cfg = test_config();
        let secret = cfg.hs256_secret.clone().unwrap_or_default();
        let verifier = JwtVerifier::new(cfg)?;

        let exp = (Utc::now().timestamp() + 300) as u64;
        let token = sign_hs256(
            json!({
                "iss": "https://evil-idp.example",
                "aud": "keelway-gateway",
                "exp": exp,
                "org_id": "acme-corp",
                "agent_id": "billing-agent"
            }),
            &secret,
        );

        let err = verifier.verify_token(&token).await;
        assert!(matches!(err, Err(KeelwayError::Auth(_))));
        Ok(())
    }

    #[tokio::test]
    async fn wrong_audience_fails_closed() -> Result<(), KeelwayError> {
        let cfg = test_config();
        let secret = cfg.hs256_secret.clone().unwrap_or_default();
        let verifier = JwtVerifier::new(cfg)?;

        let exp = (Utc::now().timestamp() + 300) as u64;
        let token = sign_hs256(
            json!({
                "iss": "https://idp.keelway.test",
                "aud": "other-service",
                "exp": exp,
                "org_id": "acme-corp",
                "agent_id": "billing-agent"
            }),
            &secret,
        );

        let err = verifier.verify_token(&token).await;
        assert!(matches!(err, Err(KeelwayError::Auth(_))));
        Ok(())
    }

    #[tokio::test]
    async fn tampered_signature_fails_closed() -> Result<(), KeelwayError> {
        let cfg = test_config();
        let verifier = JwtVerifier::new(cfg)?;

        let exp = (Utc::now().timestamp() + 300) as u64;
        let token = sign_hs256(
            json!({
                "iss": "https://idp.keelway.test",
                "aud": "keelway-gateway",
                "exp": exp,
                "org_id": "acme-corp",
                "agent_id": "billing-agent"
            }),
            "wrong-signing-key",
        );

        let err = verifier.verify_token(&token).await;
        assert!(matches!(err, Err(KeelwayError::Auth(_))));
        Ok(())
    }

    #[tokio::test]
    async fn missing_required_claims_fail_closed() -> Result<(), KeelwayError> {
        let cfg = test_config();
        let secret = cfg.hs256_secret.clone().unwrap_or_default();
        let verifier = JwtVerifier::new(cfg)?;

        let exp = (Utc::now().timestamp() + 300) as u64;
        let token = sign_hs256(
            json!({
                "iss": "https://idp.keelway.test",
                "aud": "keelway-gateway",
                "exp": exp,
                "org_id": "acme-corp"
            }),
            &secret,
        );

        let err = verifier.verify_token(&token).await;
        assert!(matches!(err, Err(KeelwayError::Auth(_))));
        Ok(())
    }

    #[tokio::test]
    async fn nbf_in_future_fails_closed() -> Result<(), KeelwayError> {
        let cfg = test_config();
        let secret = cfg.hs256_secret.clone().unwrap_or_default();
        let verifier = JwtVerifier::new(cfg)?;

        let now = Utc::now().timestamp();
        let token = sign_hs256(
            json!({
                "iss": "https://idp.keelway.test",
                "aud": "keelway-gateway",
                "nbf": (now + 300) as u64,
                "exp": (now + 600) as u64,
                "org_id": "acme-corp",
                "agent_id": "billing-agent"
            }),
            &secret,
        );

        let err = verifier.verify_token(&token).await;
        assert!(matches!(err, Err(KeelwayError::Auth(_))));
        Ok(())
    }

    #[test]
    fn weak_hs256_secret_is_rejected() {
        let mut cfg = test_config();
        cfg.hs256_secret = Some("too-short-secret".to_owned());

        let err = JwtVerifier::new(cfg);
        assert!(matches!(err, Err(KeelwayError::Config(_))));
    }

    #[test]
    fn plain_http_non_local_jwks_url_is_rejected() {
        let mut cfg = test_config();
        cfg.hs256_secret = None;
        cfg.jwks_url = Some("http://idp.example.com/.well-known/jwks.json".to_owned());
        assert!(matches!(
            JwtVerifier::new(cfg),
            Err(KeelwayError::Config(_))
        ));

        let mut spoofed_local = test_config();
        spoofed_local.hs256_secret = None;
        spoofed_local.jwks_url = Some("http://localhost.evil.com/jwks.json".to_owned());
        assert!(matches!(
            JwtVerifier::new(spoofed_local),
            Err(KeelwayError::Config(_))
        ));

        let mut local_cfg = test_config();
        local_cfg.hs256_secret = None;
        local_cfg.jwks_url = Some("http://127.0.0.1:8080/.well-known/jwks.json".to_owned());
        assert!(JwtVerifier::new(local_cfg).is_ok());
    }

    #[tokio::test]
    async fn spki_ed25519_key_verifies_token_and_returns_exp() -> Result<(), KeelwayError> {
        let seed: [u8; 32] = [7u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let pub_bytes = signing_key.verifying_key().to_bytes();

        let mut spki_bytes = Vec::with_capacity(44);
        spki_bytes.extend_from_slice(&ED25519_SPKI_PREFIX);
        spki_bytes.extend_from_slice(&pub_bytes);

        let mut pkcs8_der = Vec::with_capacity(48);
        pkcs8_der.extend_from_slice(&[
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ]);
        pkcs8_der.extend_from_slice(&seed);

        let mut cfg = test_config();
        cfg.hs256_secret = None;
        cfg.ed25519_public_key_hex = Some(hex::encode(&spki_bytes));
        let verifier = JwtVerifier::new(cfg)?;

        let exp = (Utc::now().timestamp() + 300) as u64;
        let token = encode(
            &Header::new(Algorithm::EdDSA),
            &json!({
                "iss": "https://idp.keelway.test",
                "aud": "keelway-gateway",
                "exp": exp,
                "org_id": "acme-corp",
                "agent_id": "eddsa-agent",
                "roles": ["admin"]
            }),
            &EncodingKey::from_ed_der(&pkcs8_der),
        )
        .unwrap_or_default();

        let (principal, got_exp) = verifier.verify_token_with_exp(&token).await?;
        assert_eq!(principal.org_id, "acme-corp");
        assert_eq!(principal.agent_id, "eddsa-agent");
        assert_eq!(principal.roles, vec!["admin"]);
        assert_eq!(got_exp, Some(exp));
        Ok(())
    }
}
