use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Request, State},
    http::{header, HeaderMap, HeaderValue, Method},
    middleware::Next,
    response::Response,
};
use hmac::{Hmac, Mac};
use rand::{distributions::Alphanumeric, Rng};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::{config::Config, error::AppError};

pub const CSRF_COOKIE: &str = "__Host-csrf";
pub const HEADER_SUBJECT: &str = "x-auth-subject";
pub const HEADER_EMAIL: &str = "x-auth-email";
pub const HEADER_GROUPS: &str = "x-auth-groups";
pub const HEADER_SIG: &str = "x-auth-sig";
pub const HEADER_ZONE: &str = "x-gateway-zone";
pub const HEADER_ZONE_SIG: &str = "x-gateway-zone-sig";

#[derive(Clone, Debug)]
pub struct Identity {
    pub subject: String,
    pub email: Option<String>,
    pub zone: String,
    pub request_id: Uuid,
}

#[derive(Clone)]
pub struct AuthVerifier {
    identity_key: Vec<u8>,
    zone_key: Vec<u8>,
    canonical_host: String,
    canonical_route: String,
    expected_zone: String,
}

impl std::fmt::Debug for AuthVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthVerifier")
            .field("canonical_host", &self.canonical_host)
            .field("canonical_route", &self.canonical_route)
            .field("expected_zone", &self.expected_zone)
            .finish_non_exhaustive()
    }
}

impl AuthVerifier {
    pub fn new(config: &Config) -> Self {
        Self {
            identity_key: config.gateway_hmac_key.clone(),
            zone_key: config.gateway_zone_hmac_key.clone(),
            canonical_host: config.canonical_host.clone(),
            canonical_route: config.canonical_route.clone(),
            expected_zone: config.expected_zone.clone(),
        }
    }

    pub fn verify_at(&self, headers: &HeaderMap, minute: i64) -> Result<Identity, AppError> {
        let raw_subject = exactly_one(headers, HEADER_SUBJECT)?;
        let raw_groups = optional_exactly_one(headers, HEADER_GROUPS)?.unwrap_or_default();
        let raw_sig = exactly_one(headers, HEADER_SIG)?;
        if !is_lower_hex_64(raw_sig) {
            return Err(unauthenticated());
        }
        let identity_ok = [minute, minute - 1].into_iter().any(|window| {
            let expected = sign_identity(&self.identity_key, raw_subject, raw_groups, window);
            raw_sig.ct_eq(expected.as_slice()).into()
        });
        if !identity_ok {
            return Err(unauthenticated());
        }

        let raw_zone = exactly_one(headers, HEADER_ZONE)?;
        let raw_zone_sig = exactly_one(headers, HEADER_ZONE_SIG)?;
        let raw_host = exactly_one(headers, header::HOST.as_str())?;
        if raw_zone != self.expected_zone.as_bytes()
            || !raw_host.eq_ignore_ascii_case(self.canonical_host.as_bytes())
            || !is_lower_hex_64(raw_zone_sig)
        {
            return Err(unauthenticated());
        }
        let zone_ok = [minute, minute - 1].into_iter().any(|window| {
            let expected = sign_zone(
                &self.zone_key,
                self.canonical_route.as_bytes(),
                self.canonical_host.as_bytes(),
                raw_zone,
                window,
            );
            raw_zone_sig.ct_eq(expected.as_slice()).into()
        });
        if !zone_ok {
            return Err(unauthenticated());
        }

        let verified_subject = std::str::from_utf8(raw_subject).map_err(|_| unauthenticated())?;
        let subject = canonicalize_subject(verified_subject)?;
        let zone = std::str::from_utf8(raw_zone)
            .map_err(|_| unauthenticated())?
            .to_string();
        let email = optional_exactly_one(headers, HEADER_EMAIL)?
            .map(|value| {
                std::str::from_utf8(value)
                    .map(str::trim)
                    .map(str::to_string)
            })
            .transpose()
            .map_err(|_| unauthenticated())?
            .filter(|value| !value.is_empty() && value.len() <= 512 && !has_control(value));
        Ok(Identity {
            subject,
            email,
            zone,
            request_id: Uuid::new_v4(),
        })
    }

    pub fn verify(&self, headers: &HeaderMap) -> Result<Identity, AppError> {
        self.verify_at(headers, unix_minute())
    }
}

pub async fn identity_middleware(
    State(verifier): State<AuthVerifier>,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let identity = verifier.verify(request.headers())?;
    if !matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    ) {
        verify_same_origin(request.headers(), &verifier.canonical_host)?;
    }
    request.extensions_mut().insert(identity);
    Ok(next.run(request).await)
}

pub async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    headers.insert(
        header::VARY,
        HeaderValue::from_static("Cookie, Authorization"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'",
        ),
    );
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    response
}

pub fn verify_same_origin(headers: &HeaderMap, canonical_host: &str) -> Result<(), AppError> {
    let host = mutation_header(headers, header::HOST.as_str())?;
    if !host.eq_ignore_ascii_case(canonical_host.as_bytes()) {
        return Err(AppError::invalid(
            "invalid_request",
            "Host is not canonical.",
        ));
    }
    let origin = mutation_header(headers, header::ORIGIN.as_str())?;
    let expected = format!("https://{canonical_host}");
    if origin != expected.as_bytes() {
        return Err(AppError::invalid(
            "invalid_request",
            "Origin is not canonical.",
        ));
    }
    Ok(())
}

fn mutation_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a [u8], AppError> {
    let mut values = headers.get_all(name).iter();
    let first = values.next().ok_or_else(csrf_error)?;
    if values.next().is_some() {
        return Err(csrf_error());
    }
    Ok(first.as_bytes())
}

pub fn verify_csrf(headers: &HeaderMap, submitted: &str) -> Result<(), AppError> {
    if submitted.len() != 48 || !submitted.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return Err(AppError::api(
            axum::http::StatusCode::FORBIDDEN,
            "forbidden",
            "The request could not be verified.",
            false,
        ));
    }
    let cookie = cookie(headers, CSRF_COOKIE).ok_or_else(csrf_error)?;
    if !bool::from(cookie.as_bytes().ct_eq(submitted.as_bytes())) {
        return Err(csrf_error());
    }
    Ok(())
}

pub fn csrf_from_headers(headers: &HeaderMap) -> Result<&str, AppError> {
    let value = exactly_one(headers, "x-csrf-token")?;
    std::str::from_utf8(value).map_err(|_| csrf_error())
}

pub fn new_csrf_token() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(48)
        .map(char::from)
        .collect()
}

pub fn csrf_cookie(token: &str) -> String {
    format!("{CSRF_COOKIE}={token}; Path=/; Secure; SameSite=Lax; Max-Age=3600")
}

pub fn existing_or_new_csrf(headers: &HeaderMap) -> String {
    cookie(headers, CSRF_COOKIE)
        .filter(|value| value.len() == 48 && value.bytes().all(|byte| byte.is_ascii_alphanumeric()))
        .unwrap_or_else(new_csrf_token)
}

fn exactly_one<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a [u8], AppError> {
    let mut values = headers.get_all(name).iter();
    let first = values.next().ok_or_else(unauthenticated)?;
    if values.next().is_some() {
        return Err(unauthenticated());
    }
    Ok(first.as_bytes())
}

fn optional_exactly_one<'a>(
    headers: &'a HeaderMap,
    name: &str,
) -> Result<Option<&'a [u8]>, AppError> {
    let mut values = headers.get_all(name).iter();
    let Some(first) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(unauthenticated());
    }
    Ok(Some(first.as_bytes()))
}

fn canonicalize_subject(raw: &str) -> Result<String, AppError> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.len() > 240
        || has_control(trimmed)
        || trimmed.starts_with("user:user:")
    {
        return Err(unauthenticated());
    }
    let canonical = if trimmed.starts_with("user:") {
        trimmed.to_string()
    } else {
        format!("user:{trimmed}")
    };
    if canonical == "user:" || canonical.len() > 245 {
        return Err(unauthenticated());
    }
    Ok(canonical)
}

fn has_control(value: &str) -> bool {
    value.chars().any(char::is_control)
}

fn sign_identity(key: &[u8], subject: &[u8], groups: &[u8], minute: i64) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC supports arbitrary key size");
    mac.update(subject);
    mac.update(b"\n");
    mac.update(groups);
    mac.update(b"\n");
    mac.update(minute.to_string().as_bytes());
    hex::encode(mac.finalize().into_bytes()).into_bytes()
}

fn sign_zone(key: &[u8], route: &[u8], host: &[u8], zone: &[u8], minute: i64) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC supports arbitrary key size");
    mac.update(b"holdfast.gateway-zone.v1\n");
    mac.update(route);
    mac.update(b"\n");
    mac.update(host);
    mac.update(b"\n");
    mac.update(zone);
    mac.update(b"\n");
    mac.update(minute.to_string().as_bytes());
    hex::encode(mac.finalize().into_bytes()).into_bytes()
}

fn is_lower_hex_64(value: &[u8]) -> bool {
    value.len() == 64
        && value
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn unix_minute() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| (value.as_secs() / 60) as i64)
        .unwrap_or(0)
}

fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    for value in headers.get_all(header::COOKIE) {
        let Ok(raw) = value.to_str() else { continue };
        for pair in raw.split(';') {
            if let Some((key, value)) = pair.trim().split_once('=') {
                if key.trim() == name {
                    return Some(value.trim().to_string());
                }
            }
        }
    }
    None
}

fn unauthenticated() -> AppError {
    AppError::api(
        axum::http::StatusCode::UNAUTHORIZED,
        "unauthenticated",
        "Gateway identity verification failed.",
        false,
    )
}

fn csrf_error() -> AppError {
    AppError::api(
        axum::http::StatusCode::FORBIDDEN,
        "forbidden",
        "The request could not be verified.",
        false,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers(verifier: &AuthVerifier, subject: &str, groups: &str, minute: i64) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("rikune.w33d.xyz"));
        headers.insert(HEADER_SUBJECT, HeaderValue::from_str(subject).unwrap());
        headers.insert(HEADER_GROUPS, HeaderValue::from_str(groups).unwrap());
        headers.insert(
            HEADER_SIG,
            HeaderValue::from_bytes(&sign_identity(
                &verifier.identity_key,
                subject.as_bytes(),
                groups.as_bytes(),
                minute,
            ))
            .unwrap(),
        );
        headers.insert(HEADER_ZONE, HeaderValue::from_static("external"));
        headers.insert(
            HEADER_ZONE_SIG,
            HeaderValue::from_bytes(&sign_zone(
                &verifier.zone_key,
                b"rikune-root",
                b"rikune.w33d.xyz",
                b"external",
                minute,
            ))
            .unwrap(),
        );
        headers
    }

    #[test]
    fn verifies_raw_then_canonicalizes_and_accepts_previous_minute() {
        let config = Config::for_tests(std::env::temp_dir());
        let verifier = AuthVerifier::new(&config);
        let identity = verifier
            .verify_at(&headers(&verifier, "alice", "ops", 41), 42)
            .unwrap();
        assert_eq!(identity.subject, "user:alice");
        assert_eq!(identity.zone, "external");
    }

    #[test]
    fn accepts_sluice_identity_when_empty_groups_header_is_omitted() {
        let config = Config::for_tests(std::env::temp_dir());
        let verifier = AuthVerifier::new(&config);
        let mut signed = headers(&verifier, "alice", "", 42);
        signed.remove(HEADER_GROUPS);

        let identity = verifier.verify_at(&signed, 42).unwrap();
        assert_eq!(identity.subject, "user:alice");
    }

    #[test]
    fn rejects_double_prefix_duplicate_or_wrong_zone_signature() {
        let config = Config::for_tests(std::env::temp_dir());
        let verifier = AuthVerifier::new(&config);
        assert!(verifier
            .verify_at(&headers(&verifier, "user:user:alice", "", 42), 42)
            .is_err());
        let mut duplicate = headers(&verifier, "alice", "", 42);
        duplicate.append(HEADER_SUBJECT, HeaderValue::from_static("bob"));
        assert!(verifier.verify_at(&duplicate, 42).is_err());
        let mut duplicate_groups = headers(&verifier, "alice", "ops", 42);
        duplicate_groups.append(HEADER_GROUPS, HeaderValue::from_static("analysts"));
        assert!(verifier.verify_at(&duplicate_groups, 42).is_err());
        let mut wrong = headers(&verifier, "alice", "", 42);
        wrong.insert(
            HEADER_ZONE_SIG,
            HeaderValue::from_static(
                "a000000000000000000000000000000000000000000000000000000000000000",
            ),
        );
        assert!(verifier.verify_at(&wrong, 42).is_err());
    }

    #[test]
    fn rejects_legacy_host_and_legacy_host_zone_binding() {
        let config = Config::for_tests(std::env::temp_dir());
        let verifier = AuthVerifier::new(&config);

        let mut legacy_host = headers(&verifier, "alice", "", 42);
        legacy_host.insert(header::HOST, HeaderValue::from_static("analyze.w33d.xyz"));
        assert!(verifier.verify_at(&legacy_host, 42).is_err());

        let mut legacy_zone_binding = headers(&verifier, "alice", "", 42);
        legacy_zone_binding.insert(
            HEADER_ZONE_SIG,
            HeaderValue::from_bytes(&sign_zone(
                &verifier.zone_key,
                b"rikune-root",
                b"analyze.w33d.xyz",
                b"external",
                42,
            ))
            .unwrap(),
        );
        assert!(verifier.verify_at(&legacy_zone_binding, 42).is_err());
    }

    #[test]
    fn mutation_origin_is_exactly_the_canonical_rikune_host() {
        let mut canonical = HeaderMap::new();
        canonical.insert(header::HOST, HeaderValue::from_static("rikune.w33d.xyz"));
        canonical.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://rikune.w33d.xyz"),
        );
        assert!(verify_same_origin(&canonical, "rikune.w33d.xyz").is_ok());

        for legacy in [
            ("analyze.w33d.xyz", "https://rikune.w33d.xyz"),
            ("rikune.w33d.xyz", "https://analyze.w33d.xyz"),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(header::HOST, HeaderValue::from_static(legacy.0));
            headers.insert(header::ORIGIN, HeaderValue::from_static(legacy.1));
            assert!(verify_same_origin(&headers, "rikune.w33d.xyz").is_err());
        }
    }
}
