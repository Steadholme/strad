use std::time::Duration;

use futures_util::StreamExt;
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{config::Config, error::AppError};

pub const PUBLIC_TOOLS: [&str; 4] = [
    "analysis.create",
    "analysis.read",
    "analysis.conversation",
    "analysis.upload.cancel",
];

pub fn is_public_tool(value: &str) -> bool {
    PUBLIC_TOOLS.contains(&value)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionEnvelopeV1 {
    pub version: i64,
    pub decision_id: String,
    pub decision_digest: String,
    pub subject_version: i64,
    pub application_sub: String,
    pub credential_id: String,
    pub credential_version: i64,
    pub policy_epoch: i64,
    pub revocation_epoch: i64,
    pub request_sha256: String,
    pub mcp_session_digest: String,
    pub issued_at: i64,
    pub expires_at: i64,
}

impl ExecutionEnvelopeV1 {
    pub fn validate_binding(
        &self,
        application_sub: &str,
        request_sha256: &str,
        now: OffsetDateTime,
    ) -> Result<(), AppError> {
        let now = now.unix_timestamp();
        if self.version != 1
            || self.application_sub != application_sub
            || self.request_sha256 != request_sha256
            || !is_sha256(&self.decision_digest)
            || self.decision_id.is_empty()
            || !is_sha256(&self.request_sha256)
            || !is_sha256(&self.mcp_session_digest)
            || self.subject_version <= 0
            || self.credential_version <= 0
            || self.policy_epoch <= 0
            || self.revocation_epoch <= 0
            || !valid_access_credential_id(&self.credential_id)
            || self.issued_at > now.saturating_add(5)
            || self.expires_at <= now
            || self.expires_at <= self.issued_at
            || self.expires_at.saturating_sub(self.issued_at) > 30
        {
            return Err(invalid_envelope());
        }
        Ok(())
    }
}

fn valid_access_credential_id(value: &str) -> bool {
    value.starts_with("acr_")
        && value.len() > 4
        && value.len() <= 200
        && value[4..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FacadeToolRequest {
    pub application_sub: String,
    pub operation_id: Uuid,
    pub request_sha256: String,
    pub correlation_id: Uuid,
    pub resource: String,
    pub body: serde_json::Value,
    pub execution: ExecutionEnvelopeV1,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FacadeUploadChunkRequest {
    pub application_sub: String,
    pub request_sha256: String,
    pub correlation_id: Uuid,
    pub content_range: String,
    pub chunk_sha256: String,
    pub content_base64: String,
    pub execution: ExecutionEnvelopeV1,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FacadeUploadMutationRequest {
    pub application_sub: String,
    pub operation_id: Uuid,
    pub request_sha256: String,
    pub correlation_id: Uuid,
    pub execution: ExecutionEnvelopeV1,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationReconciliationRequest {
    pub application_sub: String,
    pub reconciliation_id: Uuid,
    pub completed: bool,
    pub response_status: Option<i32>,
    pub response_body: Option<serde_json::Value>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationOutcome {
    InsufficientScope,
    Deny,
    Indeterminate,
    StaleDecision,
    ExpiredDecision,
    DecisionDigestMismatch,
    AuthorizationUnavailable,
}

impl AuthorizationOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InsufficientScope => "insufficient_scope",
            Self::Deny => "deny",
            Self::Indeterminate => "indeterminate",
            Self::StaleDecision => "stale_decision",
            Self::ExpiredDecision => "expired_decision",
            Self::DecisionDigestMismatch => "decision_digest_mismatch",
            Self::AuthorizationUnavailable => "authorization_unavailable",
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationAuditRequest {
    pub application_sub: String,
    pub authorization_event_id: Uuid,
    pub outcome: AuthorizationOutcome,
    pub canonical_tool: Option<String>,
    pub operation_id: Option<Uuid>,
    pub decision_digest: Option<String>,
    pub correlation_id: Uuid,
}

impl AuthorizationAuditRequest {
    pub fn validate(&self) -> Result<(), AppError> {
        if self
            .canonical_tool
            .as_deref()
            .is_some_and(|tool| !is_public_tool(tool))
            || self
                .decision_digest
                .as_deref()
                .is_some_and(|digest| !is_sha256(digest))
            || matches!(self.outcome, AuthorizationOutcome::InsufficientScope)
                && self.decision_digest.is_some()
        {
            return Err(AppError::invalid(
                "invalid_request",
                "Authorization audit does not match the frozen contract.",
            ));
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct ExecutionFenceClient {
    http: reqwest::Client,
    endpoint: String,
    token: String,
}

impl std::fmt::Debug for ExecutionFenceClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecutionFenceClient")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum FenceResponse {
    Active(ActiveFenceResponse),
    Inactive(InactiveFenceResponse),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveFenceResponse {
    active: bool,
    subject_version: i64,
    policy_epoch: i64,
    revocation_epoch: i64,
    checked_at: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InactiveFenceResponse {
    active: bool,
}

impl ExecutionFenceClient {
    pub fn new(config: &Config) -> Result<Self, String> {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(3))
            .redirect(Policy::none())
            .build()
            .map_err(|_| "failed to build Access execution-fence client".to_string())?;
        Ok(Self {
            http,
            endpoint: config.access_execution_fence_url.clone(),
            token: config.access_execution_fence_token.clone(),
        })
    }

    pub async fn check(&self, envelope: &ExecutionEnvelopeV1) -> Result<(), AppError> {
        let response = self
            .http
            .post(&self.endpoint)
            .bearer_auth(&self.token)
            .header(reqwest::header::CACHE_CONTROL, "no-store")
            .header(reqwest::header::PRAGMA, "no-cache")
            .json(envelope)
            .send()
            .await
            .map_err(|_| fence_unavailable())?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(if response.status().is_client_error() {
                AppError::api(
                    axum::http::StatusCode::UNAUTHORIZED,
                    "unauthenticated",
                    "Application execution authorization is no longer active.",
                    false,
                )
            } else {
                fence_unavailable()
            });
        }
        let bytes = bounded_response_body(response, 1024).await?;
        let body: FenceResponse =
            serde_json::from_slice(&bytes).map_err(|_| fence_unavailable())?;
        let checked_now = OffsetDateTime::now_utc().unix_timestamp();
        match body {
            FenceResponse::Inactive(InactiveFenceResponse { active: false }) => {
                Err(inactive_fence())
            }
            FenceResponse::Active(ActiveFenceResponse {
                active: true,
                subject_version,
                policy_epoch,
                revocation_epoch,
                checked_at,
            }) if subject_version == envelope.subject_version
                && policy_epoch == envelope.policy_epoch
                && revocation_epoch == envelope.revocation_epoch
                && checked_at >= checked_now.saturating_sub(5)
                && checked_at <= checked_now.saturating_add(5) =>
            {
                Ok(())
            }
            FenceResponse::Active(ActiveFenceResponse { active: true, .. }) => {
                Err(inactive_fence())
            }
            FenceResponse::Active(_) | FenceResponse::Inactive(_) => Err(fence_unavailable()),
        }
    }

    pub async fn readiness_probe(&self) -> Result<(), AppError> {
        // Access authenticates this request before validating it. Zero versions make
        // the exact-shape envelope deterministically inactive before any transaction
        // or execution claim is opened.
        let sentinel = ExecutionEnvelopeV1 {
            version: 1,
            decision_id: "strad-readiness-probe".to_string(),
            decision_digest: "0".repeat(64),
            subject_version: 0,
            application_sub: "application:stradreadiness".to_string(),
            credential_id: "acr_stradreadiness".to_string(),
            credential_version: 0,
            policy_epoch: 0,
            revocation_epoch: 0,
            request_sha256: "0".repeat(64),
            mcp_session_digest: "0".repeat(64),
            issued_at: 1,
            expires_at: 1,
        };
        let response = self
            .http
            .post(&self.endpoint)
            .bearer_auth(&self.token)
            .header(reqwest::header::CACHE_CONTROL, "no-store")
            .header(reqwest::header::PRAGMA, "no-cache")
            .json(&sentinel)
            .send()
            .await
            .map_err(|_| fence_unavailable())?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(fence_unavailable());
        }
        let bytes = bounded_response_body(response, 1024).await?;
        let body: InactiveFenceResponse =
            serde_json::from_slice(&bytes).map_err(|_| fence_unavailable())?;
        if body.active {
            return Err(fence_unavailable());
        }
        Ok(())
    }
}

async fn bounded_response_body(
    response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, AppError> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(fence_unavailable());
    }
    let mut stream = response.bytes_stream();
    let mut body = Vec::with_capacity(limit.min(1024));
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| fence_unavailable())?;
        if chunk.len() > limit.saturating_sub(body.len()) {
            return Err(fence_unavailable());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

pub fn canonical_application_request_sha(
    application_sub: &str,
    canonical_tool: &str,
    resource: &str,
    body: &serde_json::Value,
) -> Result<String, AppError> {
    let encoded = serde_json::to_vec(body)
        .map_err(|_| AppError::Invariant("application request is not serializable"))?;
    let mut digest = Sha256::new();
    for part in [
        application_sub.as_bytes(),
        canonical_tool.as_bytes(),
        resource.as_bytes(),
        encoded.as_slice(),
    ] {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    Ok(hex::encode(digest.finalize()))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn invalid_envelope() -> AppError {
    AppError::invalid(
        "invalid_request",
        "ExecutionEnvelopeV1 does not match this request.",
    )
}

fn fence_unavailable() -> AppError {
    AppError::unavailable(
        "authorization_unavailable",
        "The final application execution fence is unavailable.",
    )
}

fn inactive_fence() -> AppError {
    AppError::api(
        axum::http::StatusCode::UNAUTHORIZED,
        "unauthenticated",
        "Application execution authorization is no longer active.",
        false,
    )
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        convert::Infallible,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        },
    };

    use axum::{
        body::Body,
        extract::State,
        http::{header, HeaderMap, StatusCode},
        response::{IntoResponse, Response},
        routing::post,
        Json, Router,
    };
    use bytes::Bytes;

    use super::*;

    #[derive(Clone)]
    struct ProbeState {
        token: String,
        bodies: Arc<Mutex<Vec<serde_json::Value>>>,
        claim_count: Arc<AtomicUsize>,
    }

    async fn probe_handler(
        State(state): State<ProbeState>,
        headers: HeaderMap,
        Json(body): Json<serde_json::Value>,
    ) -> Response {
        if headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            != Some(format!("Bearer {}", state.token).as_str())
        {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        if body
            .get("subject_version")
            .and_then(serde_json::Value::as_i64)
            .is_some_and(|version| version > 0)
        {
            state.claim_count.fetch_add(1, Ordering::SeqCst);
        }
        state.bodies.lock().unwrap().push(body);
        Json(serde_json::json!({"active": false})).into_response()
    }

    async fn spawn_server(router: Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (format!("http://{address}"), task)
    }

    fn test_fence_client(
        endpoint: String,
        token: String,
        timeout: Duration,
    ) -> ExecutionFenceClient {
        ExecutionFenceClient {
            http: reqwest::Client::builder()
                .timeout(timeout)
                .connect_timeout(timeout)
                .redirect(Policy::none())
                .build()
                .unwrap(),
            endpoint,
            token,
        }
    }

    #[test]
    fn request_digest_is_length_delimited_and_owner_bound() {
        let body = serde_json::json!({"filename":"sample.bin","total_bytes":7});
        let first = canonical_application_request_sha(
            "application:first",
            "analysis.create",
            "collection",
            &body,
        )
        .unwrap();
        let second = canonical_application_request_sha(
            "application:second",
            "analysis.create",
            "collection",
            &body,
        )
        .unwrap();
        assert_eq!(first.len(), 64);
        assert_ne!(first, second);
    }

    #[tokio::test]
    async fn readiness_probe_is_authenticated_bounded_and_side_effect_free() {
        let state = ProbeState {
            token: "f".repeat(32),
            bodies: Arc::new(Mutex::new(Vec::new())),
            claim_count: Arc::new(AtomicUsize::new(0)),
        };
        let router = Router::new()
            .route("/fence", post(probe_handler))
            .route(
                "/hang",
                post(|| async {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    Json(serde_json::json!({"active": false}))
                }),
            )
            .with_state(state.clone());
        let (origin, task) = spawn_server(router).await;
        let timeout = Duration::from_millis(100);

        let client = test_fence_client(format!("{origin}/fence"), state.token.clone(), timeout);
        client.readiness_probe().await.unwrap();
        {
            let bodies = state.bodies.lock().unwrap();
            assert_eq!(bodies.len(), 1);
            let keys = bodies[0]
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            assert_eq!(
                keys,
                BTreeSet::from([
                    "version",
                    "decision_id",
                    "decision_digest",
                    "subject_version",
                    "application_sub",
                    "credential_id",
                    "credential_version",
                    "policy_epoch",
                    "revocation_epoch",
                    "request_sha256",
                    "mcp_session_digest",
                    "issued_at",
                    "expires_at",
                ])
            );
        }
        assert_eq!(state.claim_count.load(Ordering::SeqCst), 0);

        assert!(
            test_fence_client(format!("{origin}/fence"), "x".repeat(32), timeout,)
                .readiness_probe()
                .await
                .is_err()
        );
        assert!(
            test_fence_client(format!("{origin}/missing"), state.token.clone(), timeout,)
                .readiness_probe()
                .await
                .is_err()
        );
        let started_at = std::time::Instant::now();
        assert!(
            test_fence_client(format!("{origin}/hang"), state.token, timeout)
                .readiness_probe()
                .await
                .is_err()
        );
        assert!(started_at.elapsed() < Duration::from_millis(500));
        assert_eq!(state.claim_count.load(Ordering::SeqCst), 0);
        task.abort();
    }

    #[tokio::test]
    async fn fence_response_stream_stops_at_the_frozen_byte_limit() {
        let emitted = Arc::new(AtomicUsize::new(0));
        let stream_counter = emitted.clone();
        let router = Router::new().route(
            "/fence",
            post(move || {
                let counter = stream_counter.clone();
                async move {
                    let stream = async_stream::stream! {
                        for _ in 0..10 {
                            tokio::time::sleep(Duration::from_millis(20)).await;
                            counter.fetch_add(1, Ordering::SeqCst);
                            yield Ok::<Bytes, Infallible>(Bytes::from(vec![b'x'; 600]));
                        }
                    };
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(Body::from_stream(stream))
                        .unwrap()
                }
            }),
        );
        let (origin, task) = spawn_server(router).await;
        let client = test_fence_client(
            format!("{origin}/fence"),
            "f".repeat(32),
            Duration::from_secs(1),
        );
        assert!(client.readiness_probe().await.is_err());
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(emitted.load(Ordering::SeqCst), 2);
        task.abort();
    }
}
