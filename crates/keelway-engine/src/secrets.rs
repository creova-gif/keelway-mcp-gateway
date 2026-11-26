use crate::core::KeelwayError;
use aho_corasick::AhoCorasick;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use regex::Regex;
use serde_json::Value;
use std::borrow::Cow;
use std::collections::BTreeSet;
use std::fs;
use std::sync::LazyLock;

const MIN_SECRET_LEN: usize = 8;
pub const REDACTED_PLACEHOLDER: &str = "[REDACTED]";

static AWS_ACCESS_KEY_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"\bAKIA[0-9A-Z]{16}\b").ok());
static GITHUB_TOKEN_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b").ok());
static PEM_PRIVATE_KEY_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----")
        .ok()
});

/// Pluggable secret resolution trait (env, file, future GCP Secret Manager + OIDC).
pub trait SecretProvider: Send + Sync {
    fn resolve(&self, reference: &str) -> Result<String, KeelwayError>;
}

/// Default Milestone 1 provider resolving `secret://env/<VAR>` and `secret://file/<PATH>`.
#[derive(Debug, Default, Clone)]
pub struct DefaultSecretProvider;

impl SecretProvider for DefaultSecretProvider {
    fn resolve(&self, reference: &str) -> Result<String, KeelwayError> {
        if let Some(var_name) = reference.strip_prefix("secret://env/") {
            if var_name.is_empty() {
                return Err(KeelwayError::Secret(
                    "empty environment variable name in secret://env/".to_owned(),
                ));
            }
            std::env::var(var_name).map_err(|_| {
                KeelwayError::Secret(format!("environment variable '{var_name}' is not set"))
            })
        } else if let Some(file_path) = reference.strip_prefix("secret://file/") {
            if file_path.is_empty() {
                return Err(KeelwayError::Secret(
                    "empty file path in secret://file/".to_owned(),
                ));
            }
            let raw = fs::read_to_string(file_path).map_err(|e| {
                KeelwayError::Secret(format!("failed to read secret file '{file_path}': {e}"))
            })?;
            Ok(raw.trim_end_matches(['\r', '\n']).to_owned())
        } else if reference.starts_with("secret://gcp/") {
            Err(KeelwayError::Secret(
                "GCP Secret Manager provider is a Milestone 2+ plugin seam; use secret://env/ or secret://file/ in Milestone 1".to_owned(),
            ))
        } else if reference.starts_with("secret://") {
            Err(KeelwayError::Secret(format!(
                "unsupported secret scheme in '{reference}'"
            )))
        } else {
            Ok(reference.to_owned())
        }
    }
}

/// In-memory Aho-Corasick scrubber for gateway-managed secrets (>= 8 bytes)
/// across raw, JSON-escaped, URL-encoded, and Base64 wire encodings, with
/// optional built-in egress credential pattern scrubbing.
#[derive(Debug, Clone)]
pub struct SecretScrubber {
    automaton: Option<AhoCorasick>,
    max_pattern_len: usize,
    pattern_scrubbing: bool,
}

impl SecretScrubber {
    pub fn new<I, S>(secrets: I) -> Result<Self, KeelwayError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut patterns: BTreeSet<String> = BTreeSet::new();
        for s in secrets {
            let raw = s.as_ref();
            if raw.len() < MIN_SECRET_LEN {
                continue;
            }
            patterns.insert(raw.to_owned());

            // JSON-escaped form (strip outer quotes from serde_json::to_string)
            if let Ok(json_quoted) = serde_json::to_string(raw) {
                let inner = json_quoted
                    .strip_prefix('"')
                    .and_then(|v| v.strip_suffix('"'))
                    .unwrap_or(&json_quoted);
                if inner.len() >= MIN_SECRET_LEN {
                    patterns.insert(inner.to_owned());
                }
            }

            // URL-encoded form
            let url_enc = utf8_percent_encode(raw, NON_ALPHANUMERIC).to_string();
            if url_enc.len() >= MIN_SECRET_LEN {
                patterns.insert(url_enc);
            }

            // Base64 standard encoding
            let b64 = BASE64_STANDARD.encode(raw.as_bytes());
            if b64.len() >= MIN_SECRET_LEN {
                patterns.insert(b64);
            }
        }

        if patterns.is_empty() {
            return Ok(Self {
                automaton: None,
                max_pattern_len: 0,
                pattern_scrubbing: true,
            });
        }

        let max_pattern_len = patterns.iter().map(String::len).max().unwrap_or(0);
        let pattern_vec: Vec<String> = patterns.into_iter().collect();
        let automaton = AhoCorasick::new(&pattern_vec)
            .map_err(|e| KeelwayError::Secret(format!("failed to build secret scrubber: {e}")))?;

        Ok(Self {
            automaton: Some(automaton),
            max_pattern_len,
            pattern_scrubbing: true,
        })
    }

    pub fn empty() -> Self {
        Self {
            automaton: None,
            max_pattern_len: 0,
            pattern_scrubbing: true,
        }
    }

    /// Enables or disables built-in egress credential pattern scrubbing.
    pub fn with_pattern_scrubbing(mut self, enabled: bool) -> Self {
        self.pattern_scrubbing = enabled;
        self
    }

    pub fn max_pattern_len(&self) -> usize {
        self.max_pattern_len
    }

    /// Scrubs all registered secret patterns (and optional built-in credential patterns) from `input`.
    pub fn scrub_str(&self, input: &str) -> String {
        let mut out = match &self.automaton {
            Some(ac) => {
                let mut buf = String::with_capacity(input.len());
                let mut last = 0usize;
                for m in ac.find_iter(input) {
                    buf.push_str(&input[last..m.start()]);
                    buf.push_str(REDACTED_PLACEHOLDER);
                    last = m.end();
                }
                buf.push_str(&input[last..]);
                buf
            }
            None => input.to_owned(),
        };

        if self.pattern_scrubbing {
            for re in [
                AWS_ACCESS_KEY_RE.as_ref(),
                GITHUB_TOKEN_RE.as_ref(),
                PEM_PRIVATE_KEY_RE.as_ref(),
            ]
            .into_iter()
            .flatten()
            {
                if let Cow::Owned(replaced) = re.replace_all(&out, REDACTED_PLACEHOLDER) {
                    out = replaced;
                }
            }
        }

        out
    }

    /// Recursively scrubs a JSON value and returns `(scrubbed_value, redacted_json_pointers)`.
    pub fn scrub_json(&self, value: &Value) -> (Value, Vec<String>) {
        let mut redacted_fields = Vec::new();
        let scrubbed = self.scrub_json_inner(value, "", &mut redacted_fields);
        (scrubbed, redacted_fields)
    }

    fn scrub_json_inner(
        &self,
        value: &Value,
        pointer: &str,
        redacted_fields: &mut Vec<String>,
    ) -> Value {
        match value {
            Value::String(s) => {
                let scrubbed = self.scrub_str(s);
                if scrubbed != *s {
                    redacted_fields.push(pointer.to_owned());
                }
                Value::String(scrubbed)
            }
            Value::Array(items) => {
                let mapped = items
                    .iter()
                    .enumerate()
                    .map(|(i, item)| {
                        let child_ptr = format!("{pointer}/{i}");
                        self.scrub_json_inner(item, &child_ptr, redacted_fields)
                    })
                    .collect();
                Value::Array(mapped)
            }
            Value::Object(map) => {
                let mut out = serde_json::Map::with_capacity(map.len());
                for (k, v) in map {
                    let escaped_key = k.replace('~', "~0").replace('/', "~1");
                    let child_ptr = format!("{pointer}/{escaped_key}");
                    out.insert(
                        k.clone(),
                        self.scrub_json_inner(v, &child_ptr, redacted_fields),
                    );
                }
                Value::Object(out)
            }
            other => other.clone(),
        }
    }

    /// Creates a streaming scrubber using a `max_secret_len - 1` sliding window across SSE chunks.
    pub fn streaming(&self) -> StreamingScrubber<'_> {
        StreamingScrubber {
            scrubber: self,
            pending: String::new(),
        }
    }
}

/// Sliding-window streaming scrubber so secrets straddling SSE chunk boundaries cannot leak.
pub struct StreamingScrubber<'a> {
    scrubber: &'a SecretScrubber,
    pending: String,
}

impl<'a> StreamingScrubber<'a> {
    /// Appends a new chunk and returns the safe-to-emit scrubbed prefix.
    pub fn push_chunk(&mut self, chunk: &str) -> String {
        if self.scrubber.max_pattern_len <= 1 {
            return self.scrubber.scrub_str(chunk);
        }
        self.pending.push_str(chunk);
        let scrubbed = self.scrubber.scrub_str(&self.pending);
        let keep_bytes = self.scrubber.max_pattern_len.saturating_sub(1);
        if scrubbed.len() <= keep_bytes {
            self.pending = scrubbed;
            return String::new();
        }
        // Find a valid UTF-8 char boundary at or before `scrubbed.len() - keep_bytes`.
        let mut split_idx = scrubbed.len().saturating_sub(keep_bytes);
        while split_idx > 0 && !scrubbed.is_char_boundary(split_idx) {
            split_idx -= 1;
        }
        let emit = scrubbed[..split_idx].to_owned();
        self.pending = scrubbed[split_idx..].to_owned();
        emit
    }

    /// Flushes and scrubs any remaining buffered bytes at end-of-stream.
    pub fn finish(&mut self) -> String {
        let tail = std::mem::take(&mut self.pending);
        self.scrubber.scrub_str(&tail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn scrubs_raw_json_url_and_base64_variants() -> Result<(), KeelwayError> {
        let secret = "ghp_super_secret_token_12345"; // gitleaks:allow
        let scrubber = SecretScrubber::new([secret])?;
        let b64 = BASE64_STANDARD.encode(secret.as_bytes());
        let url = utf8_percent_encode(secret, NON_ALPHANUMERIC).to_string();

        let payload = format!("raw={secret} b64={b64} url={url}");
        let out = scrubber.scrub_str(&payload);
        assert!(!out.contains(secret));
        assert!(!out.contains(&b64));
        assert!(!out.contains(&url));
        assert_eq!(out, "raw=[REDACTED] b64=[REDACTED] url=[REDACTED]");
        Ok(())
    }

    #[test]
    fn ignores_short_secrets_below_eight_bytes() -> Result<(), KeelwayError> {
        let scrubber = SecretScrubber::new(["short12"])?;
        assert_eq!(scrubber.scrub_str("value=short12"), "value=short12");
        Ok(())
    }

    #[test]
    fn streaming_scrubber_catches_chunk_straddling_secret() -> Result<(), KeelwayError> {
        let secret = "sk_live_boundary_secret_987654"; // gitleaks:allow
        let scrubber = SecretScrubber::new([secret])?;
        let mut stream = scrubber.streaming();
        let mut assembled = String::new();
        // Split right through the middle of the secret
        assembled.push_str(&stream.push_chunk("hello sk_live_bound")); // gitleaks:allow
        assembled.push_str(&stream.push_chunk("ary_secret_987654 world")); // gitleaks:allow
        assembled.push_str(&stream.finish());
        assert!(!assembled.contains(secret));
        assert_eq!(assembled, "hello [REDACTED] world");
        Ok(())
    }

    #[test]
    fn scrub_json_records_exact_redacted_field_pointers() -> Result<(), KeelwayError> {
        let secret = "db_password_very_secret_99"; // gitleaks:allow
        let scrubber = SecretScrubber::new([secret])?;
        let args = json!({
            "repo": "sorvex/keelway",
            "nested": { "token": format!("Bearer {secret}") }
        });
        let (scrubbed, fields) = scrubber.scrub_json(&args);
        assert_eq!(fields, vec!["/nested/token".to_owned()]);
        assert_eq!(scrubbed["nested"]["token"], "Bearer [REDACTED]");
        assert_eq!(scrubbed["repo"], "sorvex/keelway");
        Ok(())
    }

    #[test]
    fn scrubs_unregistered_aws_access_key_id() {
        let scrubber = SecretScrubber::empty();
        let key = concat!("AKIA", "IOSFODNN7EXAMPLE");
        let input = format!("aws_key={key} short=AKIA123");
        let out = scrubber.scrub_str(&input);
        assert!(!out.contains(key));
        assert_eq!(out, "aws_key=[REDACTED] short=AKIA123");
    }

    #[test]
    fn scrubs_unregistered_github_tokens_in_text_and_json() {
        let scrubber = SecretScrubber::empty();
        let pat = concat!("ghp_", "0123456789abcdef0123456789abcdef0123");
        let oauth = concat!("gho_", "abcdefghijklmnopqrstuvwxyz012345");
        let payload = json!({
            "auth": format!("token {pat}"),
            "secondary": oauth,
        });
        let (scrubbed, fields) = scrubber.scrub_json(&payload);
        assert_eq!(scrubbed["auth"], "token [REDACTED]");
        assert_eq!(scrubbed["secondary"], "[REDACTED]");
        assert_eq!(fields, vec!["/auth".to_owned(), "/secondary".to_owned()]);
    }

    #[test]
    fn scrubs_unregistered_pem_private_key() {
        let scrubber = SecretScrubber::empty();
        let pem = concat!(
            "-----BEGIN RSA ",
            "PRIVATE KEY-----\nMIIEowIBAAKCAQEAtest\n-----END RSA ",
            "PRIVATE KEY-----"
        );
        let input = format!("prefix\n{pem}\nsuffix");
        let out = scrubber.scrub_str(&input);
        assert!(!out.contains("BEGIN RSA"));
        assert!(!out.contains("MIIEowIBAAKCAQEAtest"));
        assert_eq!(out, "prefix\n[REDACTED]\nsuffix");
    }

    #[test]
    fn with_pattern_scrubbing_false_disables_builtin_patterns() -> Result<(), KeelwayError> {
        let registered = "registered_secret_value_123";
        let scrubber = SecretScrubber::new([registered])?.with_pattern_scrubbing(false);
        let aws_key = concat!("AKIA", "IOSFODNN7EXAMPLE");
        let gh_token = concat!("ghp_", "0123456789abcdef0123456789abcdef0123");
        let pem = concat!(
            "-----BEGIN RSA ",
            "PRIVATE KEY-----\nabc\n-----END RSA ",
            "PRIVATE KEY-----"
        );
        let input = format!("{registered} {aws_key} {gh_token} {pem}");
        let out = scrubber.scrub_str(&input);
        assert!(!out.contains(registered));
        assert!(out.contains(aws_key));
        assert!(out.contains(gh_token));
        assert!(out.contains(pem));
        Ok(())
    }
}
