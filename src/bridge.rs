use std::{path::Path, time::Duration};

use futures_util::{StreamExt, TryStreamExt};
use reqwest::{redirect::Policy, StatusCode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio_util::codec::{BytesCodec, FramedRead};
use uuid::Uuid;

use crate::{config::Config, error::AppError};

const JSON_BODY_LIMIT: usize = 1024 * 1024;
const ARTIFACT_BODY_LIMIT: usize = 2 * 1024 * 1024;

#[derive(Clone)]
pub struct BridgeClient {
    http: reqwest::Client,
    base_url: String,
    token: String,
}

impl std::fmt::Debug for BridgeClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BridgeClient")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowStartRequest<'a> {
    pub action: &'static str,
    pub sample_id: &'a str,
    pub goal: &'static str,
    pub depth: &'static str,
    pub backend_policy: &'static str,
    pub allow_transformations: bool,
    pub allow_live_execution: bool,
    pub force_refresh: bool,
    pub include_raw_result: bool,
}

impl<'a> WorkflowStartRequest<'a> {
    pub fn static_balanced(sample_id: &'a str) -> Self {
        Self {
            action: "start",
            sample_id,
            goal: "static",
            depth: "balanced",
            backend_policy: "auto",
            allow_transformations: false,
            allow_live_execution: false,
            force_refresh: false,
            include_raw_result: false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowPromoteRequest<'a> {
    pub action: &'static str,
    pub plan_id: &'a str,
    pub through_stage: &'static str,
    pub allow_transformations: bool,
    pub allow_live_execution: bool,
    pub force_refresh: bool,
    pub include_raw_result: bool,
}

impl<'a> WorkflowPromoteRequest<'a> {
    pub fn function_map(plan_id: &'a str) -> Self {
        Self {
            action: "promote",
            plan_id,
            through_stage: "function_map",
            allow_transformations: false,
            allow_live_execution: false,
            force_refresh: false,
            include_raw_result: false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowStatusRequest<'a> {
    pub action: &'static str,
    pub plan_id: &'a str,
    pub include_raw_result: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowResult {
    pub plan_id: String,
    pub stage_statuses: Vec<StageStatus>,
    pub function_index_ready: bool,
    #[serde(deserialize_with = "required_nullable")]
    pub current_stage: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub latest_stage: Option<String>,
    pub artifact_selectors: Vec<ArtifactSelector>,
    #[serde(deserialize_with = "required_nullable")]
    pub artifact_selector_summary: Option<ArtifactSelectorSummary>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactSelector {
    pub selector_id: String,
    pub sample_id: String,
    pub artifact_id: String,
    pub artifact_type: String,
    pub path: String,
    #[serde(deserialize_with = "required_nullable")]
    pub sha256: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub mime: Option<String>,
    pub stage: String,
    pub source: ArtifactSelectorSource,
    pub suggested_read_mode: String,
    pub read_args: ArtifactSelectorReadArgs,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactSelectorSource {
    Stage,
    Run,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactSelectorReadArgs {
    pub sample_id: String,
    pub artifact_id: String,
    pub read_mode: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactSelectorSummary {
    pub total_artifact_refs: u64,
    pub selectable_artifact_refs: u64,
    pub selector_count: u64,
    pub omitted_count: u64,
    #[serde(deserialize_with = "required_nullable")]
    pub latest_stage: Option<String>,
    pub by_type: std::collections::BTreeMap<String, u64>,
    pub by_stage: std::collections::BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StageStatus {
    pub stage: String,
    pub status: String,
    #[serde(default)]
    pub execution_state: Option<String>,
    #[serde(default)]
    pub recovery_state: Option<String>,
    #[serde(default)]
    pub job_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseCheckpointRequest<'a> {
    pub sample_id: &'a str,
    pub parent_artifact_id: Option<&'a str>,
    pub session_tag: String,
    pub producer: CaseProducer<'a>,
    pub state: CaseState,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseProducer<'a> {
    pub kind: &'static str,
    pub agent_name: &'a str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseState {
    pub objective: String,
    pub decisions: Vec<String>,
    pub open_questions: Vec<String>,
    pub attempted_actions: Vec<String>,
    pub active_claim_ids: Vec<String>,
    pub pinned_artifact_ids: Vec<String>,
    pub next_actions: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseCheckpointResult {
    pub case_id: String,
    #[serde(alias = "artifact_id")]
    pub checkpoint_artifact_id: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextPackRequest<'a> {
    pub sample_id: &'a str,
    pub goal: String,
    pub token_budget: u32,
    pub evidence_scope: &'static str,
    pub claim_scope: &'static str,
    pub include_case: bool,
    pub case_id: &'a str,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ContextPackResult {
    #[serde(flatten)]
    pub value: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactReadRequest<'a> {
    pub sample_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_type: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<&'a str>,
    pub read_mode: &'static str,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ArtifactReadResult {
    #[serde(flatten)]
    pub value: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UploadResult {
    pub sample_id: String,
    pub file_type: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteResult {
    pub sample_id: String,
    pub outcome: DeleteOutcome,
    #[serde(default)]
    pub deletion_id: Option<Uuid>,
    pub reclaimed: Reclaimed,
    pub completed_at: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeleteOutcome {
    Deleted,
    AlreadyAbsent,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reclaimed {
    pub files: u64,
    pub bytes: u64,
    pub db_rows: u64,
    pub kb_rows: u64,
    pub cache_entries: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationResult {
    pub operation_id: Uuid,
    pub state: OperationState,
    #[serde(default)]
    pub result: Option<serde_json::Value>,
    #[serde(default)]
    pub error: Option<BridgeError>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    Pending,
    Succeeded,
    Failed,
    Unknown,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeError {
    pub code: String,
    pub retryable: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope<T> {
    ok: bool,
    data: Option<T>,
    error: Option<BridgeError>,
}

fn required_nullable<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingResult {
    operation_id: Uuid,
    state: String,
    status_url: String,
}

pub enum MutationOutcome<T> {
    Complete(T),
    Pending,
}

impl BridgeClient {
    pub fn new(config: &Config) -> std::result::Result<Self, String> {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .redirect(Policy::none())
            .build()
            .map_err(|_| "failed to build analyzer bridge client".to_string())?;
        Ok(Self {
            http,
            base_url: config.bridge_url.clone(),
            token: config.bridge_token.clone(),
        })
    }

    pub async fn workflow_start(
        &self,
        operation_id: Uuid,
        request: &WorkflowStartRequest<'_>,
    ) -> Result<MutationOutcome<WorkflowResult>, AppError> {
        self.mutation(
            "/internal/v1/workflows/start",
            operation_id,
            request,
            Duration::from_secs(120),
            JSON_BODY_LIMIT,
        )
        .await
    }

    pub async fn workflow_promote(
        &self,
        operation_id: Uuid,
        request: &WorkflowPromoteRequest<'_>,
    ) -> Result<MutationOutcome<WorkflowResult>, AppError> {
        self.mutation(
            "/internal/v1/workflows/promote",
            operation_id,
            request,
            Duration::from_secs(30),
            JSON_BODY_LIMIT,
        )
        .await
    }

    pub async fn workflow_status(&self, plan_id: &str) -> Result<WorkflowResult, AppError> {
        self.direct(
            "/internal/v1/workflows/status",
            &WorkflowStatusRequest {
                action: "status",
                plan_id,
                include_raw_result: false,
            },
            Duration::from_secs(15),
            JSON_BODY_LIMIT,
        )
        .await
    }

    pub async fn checkpoint(
        &self,
        operation_id: Uuid,
        request: &CaseCheckpointRequest<'_>,
    ) -> Result<MutationOutcome<CaseCheckpointResult>, AppError> {
        self.mutation(
            "/internal/v1/cases/checkpoint",
            operation_id,
            request,
            Duration::from_secs(30),
            JSON_BODY_LIMIT,
        )
        .await
    }

    pub async fn context_pack(
        &self,
        request: &ContextPackRequest<'_>,
    ) -> Result<ContextPackResult, AppError> {
        self.direct(
            "/internal/v1/context/pack",
            request,
            Duration::from_secs(30),
            JSON_BODY_LIMIT,
        )
        .await
    }

    pub async fn artifact_read(
        &self,
        request: &ArtifactReadRequest<'_>,
    ) -> Result<ArtifactReadResult, AppError> {
        let selectors = [
            request.artifact_id.is_some(),
            request.artifact_type.is_some(),
            request.path.is_some(),
        ]
        .into_iter()
        .filter(|selected| *selected)
        .count();
        if selectors != 1 || !matches!(request.read_mode, "profile" | "summary" | "content") {
            return Err(AppError::invalid(
                "invalid_request",
                "Artifact selector is invalid.",
            ));
        }
        self.direct(
            "/internal/v1/artifacts/read",
            request,
            Duration::from_secs(30),
            ARTIFACT_BODY_LIMIT,
        )
        .await
    }

    pub async fn upload_sample(
        &self,
        operation_id: Uuid,
        path: &Path,
        content_length: u64,
        content_sha256: &str,
    ) -> Result<MutationOutcome<UploadResult>, AppError> {
        if !(1..=524_288_000).contains(&content_length) || !is_sha256(content_sha256) {
            return Err(AppError::Invariant("invalid local upload descriptor"));
        }
        let request_sha = hex::encode(Sha256::digest(
            format!("sample-upload\n{content_length}\n{content_sha256}").as_bytes(),
        ));
        let file = tokio::fs::File::open(path).await?;
        let stream = FramedRead::new(file, BytesCodec::new()).map_ok(|bytes| bytes.freeze());
        let response = self
            .http
            .post(format!("{}/internal/v1/samples/upload", self.base_url))
            .bearer_auth(&self.token)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .header(reqwest::header::CONTENT_LENGTH, content_length)
            .header("x-content-sha256", content_sha256)
            .header("x-operation-id", operation_id.to_string())
            .header("x-request-sha256", request_sha)
            .timeout(Duration::from_secs(900))
            .body(reqwest::Body::wrap_stream(stream))
            .send()
            .await
            .map_err(|_| analyzer_unavailable())?;
        decode_mutation_response(response, JSON_BODY_LIMIT, operation_id).await
    }

    pub async fn delete_sample(
        &self,
        operation_id: Uuid,
        sample_id: &str,
        sha256: &str,
        reason: Option<&str>,
    ) -> Result<MutationOutcome<DeleteResult>, AppError> {
        #[derive(Serialize)]
        #[serde(deny_unknown_fields)]
        struct DeleteRequest<'a> {
            sample_id: &'a str,
            confirm_sha256: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            reason: Option<&'a str>,
        }
        self.mutation(
            "/internal/v1/samples/delete",
            operation_id,
            &DeleteRequest {
                sample_id,
                confirm_sha256: sha256,
                reason,
            },
            Duration::from_secs(300),
            JSON_BODY_LIMIT,
        )
        .await
    }

    pub async fn operation(&self, operation_id: Uuid) -> Result<OperationResult, AppError> {
        let response = self
            .http
            .get(format!(
                "{}/internal/v1/operations/{operation_id}",
                self.base_url
            ))
            .bearer_auth(&self.token)
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .map_err(|_| analyzer_unavailable())?;
        let result: OperationResult = decode_complete_response(response, JSON_BODY_LIMIT).await?;
        let valid = result.operation_id == operation_id
            && match result.state {
                OperationState::Pending | OperationState::Unknown => {
                    result.result.is_none() && result.error.is_none()
                }
                OperationState::Succeeded => result.result.is_some() && result.error.is_none(),
                OperationState::Failed => result.result.is_none() && result.error.is_some(),
            };
        if !valid {
            return Err(AppError::Invariant("bridge operation schema drift"));
        }
        Ok(result)
    }

    pub async fn ready(&self) -> Result<(), AppError> {
        let response = self
            .http
            .get(format!("{}/readyz", self.base_url))
            .bearer_auth(&self.token)
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|_| analyzer_unavailable())?;
        if response.status() == StatusCode::OK {
            Ok(())
        } else {
            Err(analyzer_unavailable())
        }
    }

    async fn mutation<T, R>(
        &self,
        path: &str,
        operation_id: Uuid,
        body: &T,
        timeout: Duration,
        max_body: usize,
    ) -> Result<MutationOutcome<R>, AppError>
    where
        T: Serialize + ?Sized,
        R: DeserializeOwned,
    {
        let encoded = serde_json::to_vec(body)
            .map_err(|_| AppError::Invariant("failed to serialize bridge request"))?;
        let request_sha = hex::encode(Sha256::digest(&encoded));
        let response = self
            .http
            .post(format!("{}{}", self.base_url, path))
            .bearer_auth(&self.token)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header("x-operation-id", operation_id.to_string())
            .header("x-request-sha256", request_sha)
            .timeout(timeout)
            .body(encoded)
            .send()
            .await
            .map_err(|_| analyzer_unavailable())?;
        decode_mutation_response(response, max_body, operation_id).await
    }

    async fn direct<T, R>(
        &self,
        path: &str,
        body: &T,
        timeout: Duration,
        max_body: usize,
    ) -> Result<R, AppError>
    where
        T: Serialize + ?Sized,
        R: DeserializeOwned,
    {
        let encoded = serde_json::to_vec(body)
            .map_err(|_| AppError::Invariant("failed to serialize bridge request"))?;
        let response = self
            .http
            .post(format!("{}{}", self.base_url, path))
            .bearer_auth(&self.token)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .timeout(timeout)
            .body(encoded)
            .send()
            .await
            .map_err(|_| analyzer_unavailable())?;
        decode_complete_response(response, max_body).await
    }
}

async fn decode_mutation_response<T: DeserializeOwned>(
    response: reqwest::Response,
    max_body: usize,
    operation_id: Uuid,
) -> Result<MutationOutcome<T>, AppError> {
    if response.status() == StatusCode::ACCEPTED {
        let envelope: Envelope<PendingResult> = decode_envelope(response, max_body).await?;
        let expected_url = format!("/internal/v1/operations/{operation_id}");
        let valid = envelope.ok
            && envelope.error.is_none()
            && envelope.data.as_ref().is_some_and(|pending| {
                pending.operation_id == operation_id
                    && pending.state == "pending"
                    && pending.status_url == expected_url
            });
        if !valid {
            return Err(AppError::Invariant("bridge pending schema drift"));
        }
        return Ok(MutationOutcome::Pending);
    }
    decode_complete_response(response, max_body)
        .await
        .map(MutationOutcome::Complete)
}

async fn decode_complete_response<T: DeserializeOwned>(
    response: reqwest::Response,
    max_body: usize,
) -> Result<T, AppError> {
    let status = response.status();
    if status != StatusCode::OK {
        let envelope: Envelope<serde_json::Value> = decode_envelope(response, max_body).await?;
        if envelope.ok || envelope.data.is_some() {
            return Err(AppError::Invariant("bridge failure schema drift"));
        }
        let error = envelope
            .error
            .ok_or(AppError::Invariant("bridge failure omitted error"))?;
        return Err(map_bridge_error(status, &error));
    }
    let envelope: Envelope<T> = decode_envelope(response, max_body).await?;
    if !envelope.ok || envelope.error.is_some() {
        return Err(AppError::unavailable(
            "analyzer_unavailable",
            "The analyzer is temporarily unavailable.",
        ));
    }
    envelope
        .data
        .ok_or(AppError::Invariant("bridge success omitted data"))
}

async fn decode_envelope<T: DeserializeOwned>(
    response: reqwest::Response,
    max_body: usize,
) -> Result<Envelope<T>, AppError> {
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| analyzer_unavailable())?;
        if body.len().saturating_add(chunk.len()) > max_body {
            return Err(AppError::Invariant("bridge response exceeded body limit"));
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| AppError::Invariant("bridge schema drift"))
}

fn map_bridge_error(status: StatusCode, error: &BridgeError) -> AppError {
    match error.code.as_str() {
        "E_SAMPLE_CONFIRMATION_MISMATCH" => {
            AppError::Invariant("analyzer rejected Strad's sample confirmation")
        }
        "E_SAMPLE_BUSY" => AppError::api(
            axum::http::StatusCode::CONFLICT,
            "state_conflict",
            "The analyzer sample is busy.",
            true,
        ),
        "analyzer_contract_violation" => {
            AppError::Invariant("analyzer bridge reported contract violation")
        }
        "analyzer_unavailable" => analyzer_unavailable(),
        _ if matches!(
            status,
            StatusCode::SERVICE_UNAVAILABLE | StatusCode::GATEWAY_TIMEOUT
        ) =>
        {
            analyzer_unavailable()
        }
        _ if status == StatusCode::CONFLICT => AppError::api(
            axum::http::StatusCode::CONFLICT,
            "state_conflict",
            "The analyzer operation conflicts with current state.",
            error.retryable,
        ),
        _ => AppError::Invariant("unexpected analyzer bridge error"),
    }
}

fn analyzer_unavailable() -> AppError {
    AppError::unavailable(
        "analyzer_unavailable",
        "The analyzer is temporarily unavailable.",
    )
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn start_and_promote_are_static_only() {
        let start = serde_json::to_value(WorkflowStartRequest::static_balanced(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ))
        .unwrap();
        assert_eq!(start["goal"], "static");
        assert_eq!(start["allow_live_execution"], false);
        assert_eq!(start["allow_transformations"], false);
        let promote = serde_json::to_value(WorkflowPromoteRequest::function_map("plan_1")).unwrap();
        assert_eq!(promote["through_stage"], "function_map");
        assert_eq!(promote["include_raw_result"], false);
    }

    #[test]
    fn workflow_projection_requires_the_frozen_seven_keys() {
        let projection = json!({
            "plan_id": "plan_1",
            "stage_statuses": [],
            "function_index_ready": false,
            "current_stage": null,
            "latest_stage": null,
            "artifact_selectors": [],
            "artifact_selector_summary": null
        });
        assert!(serde_json::from_value::<WorkflowResult>(projection.clone()).is_ok());

        for required in [
            "plan_id",
            "stage_statuses",
            "function_index_ready",
            "current_stage",
            "latest_stage",
            "artifact_selectors",
            "artifact_selector_summary",
        ] {
            let mut incomplete = projection.clone();
            incomplete.as_object_mut().unwrap().remove(required);
            assert!(
                serde_json::from_value::<WorkflowResult>(incomplete).is_err(),
                "{required} must be present"
            );
        }

        let mut extended = projection;
        extended["raw_result"] = json!({});
        assert!(serde_json::from_value::<WorkflowResult>(extended).is_err());
    }
}
