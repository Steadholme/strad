use std::{net::SocketAddr, path::PathBuf, str::FromStr, time::Duration};

pub const MAX_FILE_BYTES: i64 = 524_288_000;
pub const CHUNK_BYTES: i64 = 8_388_608;
pub const OWNER_BYTES: i64 = 10 * 1024 * 1024 * 1024;
pub const MAX_ANALYSES: i32 = 25;
pub const MAX_IN_FLIGHT: i64 = 3;
pub const CURRENT_SCHEMA_VERSION: i64 = 2;
pub const CANONICAL_HOST: &str = "rikune.w33d.xyz";
pub const CANONICAL_ROUTE: &str = "rikune-root";
pub const TOKENIZER_NAME: &str = "cl100k_base";
pub const TOKENIZER_PACKAGE: &str = "tiktoken-rs@0.7";
pub const TOKENIZER_VOCAB_SHA256: &str =
    "223921b76ee99bde995b7ff738513eef100fb51d18c93597a113bcffe865b2a7";

#[derive(Clone)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub database_url: String,
    pub gateway_hmac_key: Vec<u8>,
    pub gateway_zone_hmac_key: Vec<u8>,
    pub verdict_decision_token: String,
    pub verdict_url: String,
    pub bridge_token: String,
    pub bridge_url: String,
    pub newapi_key: String,
    pub newapi_url: String,
    pub newapi_model: String,
    pub newapi_context_tokens: u32,
    pub rikune_file_server_api_key: String,
    pub upload_root: PathBuf,
    pub template_root: PathBuf,
    pub canonical_host: String,
    pub canonical_route: String,
    pub expected_zone: String,
    pub session_lease: Duration,
    pub session_ttl: Duration,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("bind_addr", &self.bind_addr)
            .field("verdict_url", &self.verdict_url)
            .field("bridge_url", &self.bridge_url)
            .field("newapi_url", &self.newapi_url)
            .field("newapi_model", &self.newapi_model)
            .field("upload_root", &self.upload_root)
            .field("template_root", &self.template_root)
            .field("canonical_host", &self.canonical_host)
            .field("canonical_route", &self.canonical_route)
            .field("expected_zone", &self.expected_zone)
            .finish_non_exhaustive()
    }
}

impl Config {
    pub fn from_env() -> std::result::Result<Self, String> {
        let gateway_hmac_key = required_secret("GATEWAY_HMAC_KEY")?;
        let gateway_zone_hmac_key = required_secret("GATEWAY_ZONE_HMAC_KEY")?;
        let verdict_decision_token = required_secret_string("VERDICT_DECISION_TOKEN")?;
        let bridge_token = required_secret_string("STRAD_BRIDGE_TOKEN")?;
        let newapi_key = required_secret_string("STRAD_NEWAPI_KEY")?;
        let rikune_file_server_api_key = required_secret_string("RIKUNE_FILE_SERVER_API_KEY")?;
        let values: [(&str, &[u8]); 6] = [
            ("GATEWAY_HMAC_KEY", &gateway_hmac_key),
            ("GATEWAY_ZONE_HMAC_KEY", &gateway_zone_hmac_key),
            ("VERDICT_DECISION_TOKEN", verdict_decision_token.as_bytes()),
            ("STRAD_BRIDGE_TOKEN", bridge_token.as_bytes()),
            ("STRAD_NEWAPI_KEY", newapi_key.as_bytes()),
            (
                "RIKUNE_FILE_SERVER_API_KEY",
                rikune_file_server_api_key.as_bytes(),
            ),
        ];
        for (index, (left_name, left)) in values.iter().enumerate() {
            for (right_name, right) in values.iter().skip(index + 1) {
                if left == right {
                    return Err(format!("{left_name} must be distinct from {right_name}"));
                }
            }
        }

        let database_url = required("STRAD_DATABASE_URL")?;
        let bind_addr = env_or("STRAD_BIND_ADDR", "0.0.0.0:9360")
            .parse()
            .map_err(|_| "STRAD_BIND_ADDR must be a socket address".to_string())?;
        let verdict_url = exact_http_url(
            "VERDICT_URL",
            "http://verdict:9140/api/v2/check",
            "/api/v2/check",
            "verdict",
            9140,
        )?;
        let bridge_url = exact_base_url(
            "STRAD_BRIDGE_URL",
            "http://rikune-analyzer:18090",
            "rikune-analyzer",
            18090,
        )?;
        let newapi_url = exact_http_url(
            "STRAD_NEWAPI_URL",
            "http://newapi:9080/v1/chat/completions",
            "/v1/chat/completions",
            "newapi",
            9080,
        )?;
        let newapi_model = required("STRAD_NEWAPI_MODEL")?;
        if !valid_model_alias(&newapi_model) {
            return Err("STRAD_NEWAPI_MODEL is invalid".to_string());
        }
        let newapi_context_tokens: u32 = required("STRAD_NEWAPI_CONTEXT_TOKENS")?
            .parse()
            .map_err(|_| "STRAD_NEWAPI_CONTEXT_TOKENS must be an integer".to_string())?;
        if newapi_context_tokens < 32_768 {
            return Err("STRAD_NEWAPI_CONTEXT_TOKENS must be at least 32768".to_string());
        }
        if required("STRAD_TOKENIZER_VOCAB_SHA256")? != TOKENIZER_VOCAB_SHA256 {
            return Err("STRAD_TOKENIZER_VOCAB_SHA256 does not match the pinned vocabulary".into());
        }
        let upload_root = PathBuf::from(env_or("STRAD_UPLOAD_ROOT", "/var/lib/strad/uploads"));
        if !upload_root.is_absolute() {
            return Err("STRAD_UPLOAD_ROOT must be absolute".to_string());
        }
        let template_root = PathBuf::from(env_or("STRAD_TEMPLATE_ROOT", "/app/templates"));
        if !template_root.is_absolute() {
            return Err("STRAD_TEMPLATE_ROOT must be absolute".to_string());
        }

        Ok(Self {
            bind_addr,
            database_url,
            gateway_hmac_key,
            gateway_zone_hmac_key,
            verdict_decision_token,
            verdict_url,
            bridge_token,
            bridge_url,
            newapi_key,
            newapi_url,
            newapi_model,
            newapi_context_tokens,
            rikune_file_server_api_key,
            upload_root,
            template_root,
            canonical_host: CANONICAL_HOST.to_string(),
            canonical_route: CANONICAL_ROUTE.to_string(),
            expected_zone: "external".to_string(),
            session_lease: Duration::from_secs(30 * 60),
            session_ttl: Duration::from_secs(24 * 60 * 60),
        })
    }

    #[cfg(test)]
    pub fn for_tests(root: PathBuf) -> Self {
        Self {
            bind_addr: "127.0.0.1:0".parse().expect("static socket"),
            database_url: "postgres://unused".into(),
            gateway_hmac_key: vec![b'i'; 32],
            gateway_zone_hmac_key: vec![b'z'; 32],
            verdict_decision_token: "v".repeat(32),
            verdict_url: "http://verdict:9140/api/v2/check".into(),
            bridge_token: "b".repeat(32),
            bridge_url: "http://rikune-analyzer:18090".into(),
            newapi_key: "n".repeat(32),
            newapi_url: "http://newapi:9080/v1/chat/completions".into(),
            newapi_model: "test-model".into(),
            newapi_context_tokens: 32_768,
            rikune_file_server_api_key: "f".repeat(32),
            upload_root: root.clone(),
            template_root: root,
            canonical_host: CANONICAL_HOST.into(),
            canonical_route: CANONICAL_ROUTE.into(),
            expected_zone: "external".into(),
            session_lease: Duration::from_secs(1800),
            session_ttl: Duration::from_secs(86400),
        }
    }
}

pub fn valid_model_alias(model: &str) -> bool {
    !model.is_empty()
        && model.len() <= 128
        && model.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
}

fn required(name: &str) -> std::result::Result<String, String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{name} is required"))
}

fn required_secret(name: &str) -> std::result::Result<Vec<u8>, String> {
    let value = required(name)?;
    if value.len() < 32 {
        return Err(format!("{name} must contain at least 32 bytes"));
    }
    Ok(value.into_bytes())
}

fn required_secret_string(name: &str) -> std::result::Result<String, String> {
    let bytes = required_secret(name)?;
    String::from_utf8(bytes).map_err(|_| format!("{name} must be valid UTF-8"))
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn exact_http_url(
    name: &str,
    default: &str,
    path: &str,
    expected_host: &str,
    expected_port: u16,
) -> std::result::Result<String, String> {
    let raw = env_or(name, default);
    validate_exact_http_url(name, &raw, path, expected_host, expected_port)?;
    Ok(raw.trim_end_matches('/').to_string())
}

fn validate_exact_http_url(
    name: &str,
    raw: &str,
    path: &str,
    expected_host: &str,
    expected_port: u16,
) -> std::result::Result<(), String> {
    let parsed = reqwest::Url::from_str(raw).map_err(|_| format!("{name} is invalid"))?;
    if parsed.scheme() != "http"
        || parsed.path() != path
        || parsed.host_str() != Some(expected_host)
        || parsed.port_or_known_default() != Some(expected_port)
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.username() != ""
        || parsed.password().is_some()
    {
        return Err(format!(
            "{name} must target the expected internal HTTP endpoint"
        ));
    }
    Ok(())
}

fn exact_base_url(
    name: &str,
    default: &str,
    expected_host: &str,
    expected_port: u16,
) -> std::result::Result<String, String> {
    let raw = env_or(name, default);
    let parsed = reqwest::Url::from_str(&raw).map_err(|_| format!("{name} is invalid"))?;
    if parsed.scheme() != "http"
        || parsed.path() != "/"
        || parsed.host_str() != Some(expected_host)
        || parsed.port_or_known_default() != Some(expected_port)
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.username() != ""
        || parsed.password().is_some()
    {
        return Err(format!(
            "{name} must target the expected internal HTTP base URL"
        ));
    }
    Ok(raw.trim_end_matches('/').to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_endpoints_are_bound_to_the_expected_service_host_and_port() {
        assert!(validate_exact_http_url(
            "STRAD_NEWAPI_URL",
            "http://newapi:9080/v1/chat/completions",
            "/v1/chat/completions",
            "newapi",
            9080,
        )
        .is_ok());
        for hostile in [
            "http://127.0.0.1:9080/v1/chat/completions",
            "http://newapi.evil:9080/v1/chat/completions",
            "http://newapi:9081/v1/chat/completions",
            "http://newapi:9080/v1/chat/completions?next=http://metadata/",
            "http://user@newapi:9080/v1/chat/completions",
        ] {
            assert!(validate_exact_http_url(
                "STRAD_NEWAPI_URL",
                hostile,
                "/v1/chat/completions",
                "newapi",
                9080,
            )
            .is_err());
        }
    }

    #[test]
    fn model_aliases_use_one_shared_fail_closed_policy() {
        assert!(valid_model_alias("glm-5.2"));
        assert!(valid_model_alias("vendor/model_name:v1"));
        assert!(!valid_model_alias(""));
        assert!(!valid_model_alias("model with spaces"));
        assert!(!valid_model_alias("model?query"));
        assert!(!valid_model_alias("模型"));
        assert!(!valid_model_alias(&"a".repeat(129)));
    }
}
