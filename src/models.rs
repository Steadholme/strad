use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct UploadSession {
    pub id: Uuid,
    pub operation_id: Uuid,
    #[serde(skip_serializing)]
    pub owner_sub: String,
    #[serde(skip_serializing)]
    pub request_sha256: String,
    pub filename: String,
    pub total_bytes: i64,
    pub chunk_size: i32,
    pub chunk_count: i32,
    pub received_bytes: i64,
    pub state: String,
    #[serde(skip_serializing)]
    pub staging_key: String,
    #[serde(skip_serializing)]
    pub lease_token: Option<Uuid>,
    pub assembled_sha256: Option<String>,
    pub sample_id: Option<String>,
    pub analysis_id: Uuid,
    pub frozen_status: Option<i32>,
    pub frozen_location: Option<String>,
    pub frozen_body: Option<serde_json::Value>,
    pub error_code: Option<String>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct UploadChunk {
    pub upload_id: Uuid,
    pub chunk_index: i32,
    pub start_byte: i64,
    pub end_byte: i64,
    pub byte_size: i32,
    pub sha256: String,
    #[serde(skip_serializing)]
    pub storage_key: String,
    pub committed_at: OffsetDateTime,
}

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct Analysis {
    pub id: Uuid,
    #[serde(skip_serializing)]
    pub owner_sub: String,
    pub upload_id: Uuid,
    pub sample_id: Option<String>,
    pub display_name: String,
    pub state: String,
    pub plan_id: Option<String>,
    pub case_id: Option<String>,
    pub case_artifact_id: Option<String>,
    pub current_stage: Option<String>,
    pub latest_stage: Option<String>,
    pub retained_from_seq: i64,
    pub next_event_seq: i64,
    pub retention_until: OffsetDateTime,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct AnalysisEvent {
    pub seq: i64,
    pub analysis_id: Uuid,
    #[serde(rename = "type")]
    pub event_type: String,
    pub payload: serde_json::Value,
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct Artifact {
    pub id: Uuid,
    pub analysis_id: Uuid,
    #[serde(skip_serializing)]
    pub owner_sub: String,
    pub upstream_artifact_id: String,
    pub artifact_type: String,
    pub artifact_ref: String,
    #[serde(skip_serializing)]
    pub path: String,
    pub sha256: String,
    pub mime: Option<String>,
    pub metadata: serde_json::Value,
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct Conversation {
    pub id: Uuid,
    pub analysis_id: Uuid,
    #[serde(skip_serializing)]
    pub owner_sub: String,
    pub title: String,
    pub persona_id: String,
    pub custom_persona: Option<String>,
    pub next_seq: i64,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct Turn {
    pub id: Uuid,
    pub conversation_id: Uuid,
    pub analysis_id: Uuid,
    #[serde(skip_serializing)]
    pub owner_sub: String,
    pub client_seq: i64,
    pub operation_id: Uuid,
    pub request_sha256: String,
    pub state: String,
    pub context_marker: Option<String>,
    pub context_sha256: Option<String>,
    pub context_pack: Option<serde_json::Value>,
    #[serde(skip_serializing)]
    pub frozen_request: Option<serde_json::Value>,
    pub frozen_prompt_sha256: Option<String>,
    #[serde(skip_serializing)]
    pub generation_lease_token: Option<Uuid>,
    pub provider_attempt: i32,
    pub error_code: Option<String>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct Message {
    pub id: Uuid,
    pub turn_id: Uuid,
    pub conversation_id: Uuid,
    pub analysis_id: Uuid,
    #[serde(skip_serializing)]
    pub owner_sub: String,
    pub seq: i64,
    pub role: String,
    pub client_seq: Option<i64>,
    pub status: String,
    pub content: String,
    pub token_count: i32,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Serialize)]
pub struct UploadStatus {
    #[serde(flatten)]
    pub session: UploadSession,
    pub chunks: Vec<UploadChunk>,
    pub missing_ranges: Vec<ByteRange>,
    pub finalize_operation_id: Uuid,
    pub cancel_operation_id: Uuid,
}

#[derive(Clone, Debug, Serialize)]
pub struct ByteRange {
    pub start: i64,
    pub end: i64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateAnalysisInput {
    pub filename: String,
    pub total_bytes: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct CreateAnalysisOutput {
    pub analysis_id: Uuid,
    pub upload_id: Uuid,
    pub operation_id: Uuid,
    pub finalize_operation_id: Uuid,
    pub cancel_operation_id: Uuid,
    pub chunk_size: i64,
    pub chunk_count: i32,
    pub upload_location: String,
    pub analysis_location: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateConversationInput {
    pub title: String,
    pub persona_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdatePersonaInput {
    pub persona_id: String,
    pub custom_persona: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateTurnInput {
    pub client_seq: i64,
    pub message: String,
}
