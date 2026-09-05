use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone, Debug, sqlx::FromRow, Serialize)]
pub struct ApplicationAuditEvent {
    pub id: Uuid,
    pub application_sub: String,
    pub authorization_event_id: Uuid,
    pub event_kind: String,
    pub outcome: String,
    pub canonical_tool: Option<String>,
    pub operation_id: Option<Uuid>,
    pub decision_digest: Option<String>,
    pub correlation_id: Uuid,
    pub details: serde_json::Value,
    pub created_at: OffsetDateTime,
}
