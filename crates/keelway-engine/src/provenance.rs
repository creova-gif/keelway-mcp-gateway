use crate::core::KeelwayError;
use base64::Engine as _;
use base64::engine::general_purpose::{
    STANDARD as BASE64_STANDARD, STANDARD_NO_PAD as BASE64_STANDARD_NO_PAD,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// Ed25519 signer for audit tape receipts and provenance attestation.
#[derive(Clone)]
pub struct TapeSigner {
    signing_key: SigningKey,
    key_id: String,
}

impl std::fmt::Debug for TapeSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TapeSigner")
            .field("key_id", &self.key_id)
            .field("verifying_key_hex", &self.verifying_key_hex())
            .finish()
    }
}

impl TapeSigner {
    /// Parses a 32-byte Ed25519 seed from either a 64-character hex string or a base64 string.
    pub fn from_seed_str(raw: &str) -> Result<Self, KeelwayError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(KeelwayError::Config(
                "Ed25519 signing seed cannot be empty".to_owned(),
            ));
        }

        let decoded = if trimmed.len() == 64 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
            hex::decode(trimmed)
                .map_err(|e| KeelwayError::Config(format!("invalid hex Ed25519 seed: {e}")))?
        } else {
            BASE64_STANDARD
                .decode(trimmed)
                .or_else(|_| BASE64_STANDARD_NO_PAD.decode(trimmed))
                .map_err(|e| {
                    KeelwayError::Config(format!(
                        "invalid Ed25519 seed (expected 64-char hex or base64 32-byte seed): {e}"
                    ))
                })?
        };

        let seed: [u8; 32] = decoded.as_slice().try_into().map_err(|_| {
            KeelwayError::Config(format!(
                "invalid Ed25519 seed length: expected 32 bytes, got {}",
                decoded.len()
            ))
        })?;

        let signing_key = SigningKey::from_bytes(&seed);
        let key_id = compute_key_id(&signing_key.verifying_key());
        Ok(Self {
            signing_key,
            key_id,
        })
    }

    /// Returns the hex-encoded 32-byte Ed25519 verifying (public) key.
    pub fn verifying_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    /// Returns the deterministic key identifier (first 16 hex chars of SHA-256 of the verifying key).
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Signs `message` with the Ed25519 signing key and returns the 64-byte signature as lowercase hex.
    pub fn sign_hex(&self, message: &[u8]) -> String {
        let signature: Signature = self.signing_key.sign(message);
        hex::encode(signature.to_bytes())
    }

    /// Verifies a hex-encoded Ed25519 signature against `verifying_key_hex` and `message`.
    pub fn verify_hex(
        verifying_key_hex: &str,
        message: &[u8],
        signature_hex: &str,
    ) -> Result<(), KeelwayError> {
        let vk_bytes = hex::decode(verifying_key_hex.trim())
            .map_err(|e| KeelwayError::Tape(format!("invalid verifying key hex: {e}")))?;
        let vk_arr: [u8; 32] = vk_bytes.as_slice().try_into().map_err(|_| {
            KeelwayError::Tape(format!(
                "invalid verifying key length: expected 32 bytes, got {}",
                vk_bytes.len()
            ))
        })?;
        let verifying_key = VerifyingKey::from_bytes(&vk_arr)
            .map_err(|e| KeelwayError::Tape(format!("invalid Ed25519 verifying key: {e}")))?;

        let sig_bytes = hex::decode(signature_hex.trim())
            .map_err(|e| KeelwayError::Tape(format!("invalid signature hex: {e}")))?;
        let signature = Signature::from_slice(&sig_bytes)
            .map_err(|e| KeelwayError::Tape(format!("invalid Ed25519 signature: {e}")))?;

        verifying_key
            .verify(message, &signature)
            .map_err(|e| KeelwayError::Tape(format!("Ed25519 signature verification failed: {e}")))
    }
}

fn compute_key_id(verifying_key: &VerifyingKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifying_key.to_bytes());
    let digest_hex = hex::encode(hasher.finalize());
    digest_hex.chars().take(16).collect()
}

/// Extracts a valid 32-hex W3C `trace_id` from a `traceparent` header
/// (`00-<32-hex-trace-id>-<16-hex-span-id>-<2-hex-flags>`), or generates a fresh
/// 32-hex trace ID from a random UUIDv4.
pub fn extract_or_generate_trace_id(traceparent: Option<&str>) -> String {
    if let Some(raw) = traceparent {
        if let Some(trace_id) = parse_w3c_trace_id(raw.trim()) {
            return trace_id;
        }
    }
    uuid::Uuid::new_v4().simple().to_string()
}

fn parse_w3c_trace_id(header: &str) -> Option<String> {
    let mut parts = header.split('-');
    let version = parts.next()?;
    let trace_id = parts.next()?;
    let span_id = parts.next()?;
    let flags = parts.next()?;
    if parts.next().is_some() {
        return None;
    }

    if version != "00" {
        return None;
    }
    if trace_id.len() != 32
        || !trace_id.bytes().all(|b| b.is_ascii_hexdigit())
        || !trace_id.bytes().any(|b| b != b'0')
    {
        return None;
    }
    if span_id.len() != 16
        || !span_id.bytes().all(|b| b.is_ascii_hexdigit())
        || !span_id.bytes().any(|b| b != b'0')
    {
        return None;
    }
    if flags.len() != 2 || !flags.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }

    Some(trace_id.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SEED_HEX: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

    #[test]
    fn sign_and_verify_roundtrip_hex_and_base64() -> Result<(), KeelwayError> {
        let signer_hex = TapeSigner::from_seed_str(TEST_SEED_HEX)?;
        let seed_bytes = hex::decode(TEST_SEED_HEX)
            .map_err(|e| KeelwayError::Config(format!("decode test seed: {e}")))?;
        let b64_seed = BASE64_STANDARD.encode(&seed_bytes);
        let signer_b64 = TapeSigner::from_seed_str(&b64_seed)?;

        assert_eq!(signer_hex.key_id().len(), 16);
        assert_eq!(signer_hex.key_id(), signer_b64.key_id());
        assert_eq!(
            signer_hex.verifying_key_hex(),
            signer_b64.verifying_key_hex()
        );

        let message = b"keelway-receipt-entry-hash-v1";
        let sig = signer_hex.sign_hex(message);
        TapeSigner::verify_hex(&signer_hex.verifying_key_hex(), message, &sig)?;
        TapeSigner::verify_hex(&signer_b64.verifying_key_hex(), message, &sig)?;
        Ok(())
    }

    #[test]
    fn tampered_message_fails_verification() -> Result<(), KeelwayError> {
        let signer = TapeSigner::from_seed_str(TEST_SEED_HEX)?;
        let sig = signer.sign_hex(b"original-payload");
        let res = TapeSigner::verify_hex(&signer.verifying_key_hex(), b"tampered-payload", &sig);
        assert!(res.is_err());
        Ok(())
    }

    #[test]
    fn invalid_seed_fails() {
        assert!(TapeSigner::from_seed_str("").is_err());
        assert!(TapeSigner::from_seed_str("not-valid-seed").is_err());
        assert!(TapeSigner::from_seed_str("abcd").is_err());
        let short_b64 = BASE64_STANDARD.encode([1u8; 16]);
        assert!(TapeSigner::from_seed_str(&short_b64).is_err());
    }

    #[test]
    fn w3c_traceparent_extraction_and_fallback() {
        let valid = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        assert_eq!(
            extract_or_generate_trace_id(Some(valid)),
            "4bf92f3577b34da6a3ce929d0e0e4736"
        );

        let uppercase = "00-4BF92F3577B34DA6A3CE929D0E0E4736-00F067AA0BA902B7-01";
        assert_eq!(
            extract_or_generate_trace_id(Some(uppercase)),
            "4bf92f3577b34da6a3ce929d0e0e4736"
        );

        let invalid_cases = [
            None,
            Some(""),
            Some("01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
            Some("00-00000000000000000000000000000000-00f067aa0ba902b7-01"),
            Some("00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01"),
            Some("00-short-00f067aa0ba902b7-01"),
            Some("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra"),
        ];

        for case in invalid_cases {
            let generated = extract_or_generate_trace_id(case);
            assert_eq!(generated.len(), 32);
            assert!(generated.bytes().all(|b| b.is_ascii_hexdigit()));
        }
    }
}
