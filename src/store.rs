use std::time::Duration;

use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgPoolOptions, PgPool, Postgres, Row, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    config::{CHUNK_BYTES, MAX_ANALYSES, MAX_IN_FLIGHT, OWNER_BYTES},
    error::{AppError, Result},
    models::{
        Analysis, AnalysisEvent, Artifact, ByteRange, Conversation, Message, Turn, UploadChunk,
        UploadSession, UploadStatus,
    },
};

const UPLOAD_COLUMNS: &str = "id,operation_id,owner_sub,request_sha256,filename,total_bytes,chunk_size,chunk_count,received_bytes,state,staging_key,lease_token,assembled_sha256,sample_id,analysis_id,frozen_status,frozen_location,frozen_body,error_code,created_at,updated_at,expires_at";
const ANALYSIS_COLUMNS: &str = "id,owner_sub,upload_id,sample_id,display_name,state,plan_id,case_id,case_artifact_id,current_stage,latest_stage,retained_from_seq,next_event_seq,retention_until,created_at,updated_at";
const CHUNK_COLUMNS: &str =
    "upload_id,chunk_index,start_byte,end_byte,byte_size,sha256,storage_key,committed_at";
const CONVERSATION_COLUMNS: &str =
    "id,analysis_id,owner_sub,title,persona_id,custom_persona,next_seq,created_at,updated_at";
const TURN_COLUMNS: &str = "id,conversation_id,analysis_id,owner_sub,client_seq,operation_id,request_sha256,model_alias,state,context_marker,context_sha256,context_pack,frozen_request,frozen_prompt_sha256,generation_lease_token,provider_attempt,error_code,created_at,updated_at";
const TURN_COLUMNS_T: &str = "t.id,t.conversation_id,t.analysis_id,t.owner_sub,t.client_seq,t.operation_id,t.request_sha256,t.model_alias,t.state,t.context_marker,t.context_sha256,t.context_pack,t.frozen_request,t.frozen_prompt_sha256,t.generation_lease_token,t.provider_attempt,t.error_code,t.created_at,t.updated_at";
const MESSAGE_COLUMNS: &str = "id,turn_id,conversation_id,analysis_id,owner_sub,seq,role,client_seq,status,content,token_count,created_at,updated_at";
const ARTIFACT_COLUMNS: &str = "id,analysis_id,owner_sub,upstream_artifact_id,artifact_type,artifact_ref,path,sha256,mime,metadata,created_at";

#[derive(Clone, Debug)]
pub struct Store {
    pool: PgPool,
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ChunkClaim {
    Replay,
    Claimed {
        session: UploadSession,
        lease_token: Uuid,
    },
}

#[derive(Debug)]
pub struct FinalizeClaim {
    pub session: UploadSession,
    pub chunks: Vec<UploadChunk>,
    pub lease_token: Uuid,
}

#[derive(Debug)]
pub struct CreatedUpload {
    pub upload: UploadSession,
    pub analysis: Analysis,
}

#[derive(Debug, sqlx::FromRow)]
pub struct ClaimedOutbox {
    pub id: Uuid,
    pub aggregate_id: Uuid,
    pub owner_sub: String,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub lease_token: Uuid,
}

#[derive(Debug, sqlx::FromRow)]
pub struct RecoveryChunk {
    pub upload_id: Uuid,
    pub chunk_index: i32,
    pub byte_size: i32,
    pub sha256: String,
    pub storage_key: String,
}

#[derive(Debug, sqlx::FromRow)]
pub struct CleanupJob {
    pub id: Uuid,
    pub owner_sub: String,
    pub analysis_id: Uuid,
    pub upload_id: Uuid,
    pub manifest: serde_json::Value,
    pub manifest_sha256: String,
    pub lease_token: Uuid,
    pub attempts: i32,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DeletePlan {
    pub analysis_id: Uuid,
    pub cleanup_job_id: Uuid,
}

#[derive(Debug, sqlx::FromRow)]
pub struct SampleDeleteClaim {
    pub sample_id: String,
    pub sha256: String,
    pub delete_operation_id: Uuid,
}

#[derive(Debug, Clone)]
pub struct IdempotencyReplay {
    pub status: i32,
    pub location: Option<String>,
    pub body: Option<serde_json::Value>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct OwnerQuota {
    pub used_bytes: i64,
    pub reserved_bytes: i64,
    pub analysis_count: i32,
    pub byte_limit: i64,
    pub analysis_limit: i32,
}

impl Store {
    pub async fn connect(database_url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(16)
            .min_connections(1)
            .acquire_timeout(Duration::from_secs(5))
            .connect(database_url)
            .await?;
        Ok(Self { pool })
    }

    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    pub async fn recover_expired_upload_leases(&self) -> Result<u64> {
        Ok(sqlx::query(
            "UPDATE upload_sessions SET state=CASE WHEN state='forwarding' THEN 'upstream_uncertain' \
             WHEN state='assembling' THEN 'uploading' ELSE state END,lease_token=NULL,leased_at=NULL,\
             lease_until=NULL,error_code=CASE WHEN state='forwarding' AND error_code IS DISTINCT FROM \
             'cancel_requested' THEN 'analyzer_uncertain' \
             ELSE error_code END,updated_at=now() WHERE lease_until<now() AND state IN \
             ('uploading','assembling','forwarding')",
        )
        .execute(&self.pool)
        .await?
        .rows_affected())
    }

    pub async fn create_upload(
        &self,
        owner_sub: &str,
        filename: &str,
        total_bytes: i64,
        operation_id: Uuid,
        request_sha256: &str,
    ) -> Result<CreatedUpload> {
        let upload_id = Uuid::new_v4();
        let analysis_id = Uuid::new_v4();
        let staging_key = Uuid::new_v4();
        let chunk_count = ((total_bytes + CHUNK_BYTES - 1) / CHUNK_BYTES) as i32;
        let location = format!("/api/uploads/{upload_id}");
        let finalize_operation_id = server_operation_id("upload-finalize", &upload_id.to_string());
        let cancel_operation_id = server_operation_id("upload-cancel", &upload_id.to_string());
        let response = json!({
            "analysis_id": analysis_id,
            "upload_id": upload_id,
            "operation_id": operation_id,
            "finalize_operation_id": finalize_operation_id,
            "cancel_operation_id": cancel_operation_id,
            "chunk_size": CHUNK_BYTES,
            "chunk_count": chunk_count,
            "upload_location": location,
            "analysis_location": format!("/analyses/{analysis_id}")
        });

        let mut tx = self.pool.begin().await?;
        claim_idempotency(
            &mut tx,
            owner_sub,
            "POST /api/analyses",
            operation_id,
            request_sha256,
        )
        .await?;
        sqlx::query(
            "INSERT INTO owner_quotas(owner_sub) VALUES($1) ON CONFLICT(owner_sub) DO NOTHING",
        )
        .bind(owner_sub)
        .execute(&mut *tx)
        .await?;
        let quota = sqlx::query(
            "SELECT used_bytes,reserved_bytes,analysis_count FROM owner_quotas \
             WHERE owner_sub=$1 FOR UPDATE",
        )
        .bind(owner_sub)
        .fetch_one(&mut *tx)
        .await?;
        let used: i64 = quota.get("used_bytes");
        let reserved: i64 = quota.get("reserved_bytes");
        let count: i32 = quota.get("analysis_count");
        let in_flight: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM analyses WHERE owner_sub=$1 AND state IN \
             ('created','uploading','uploaded','starting','start_uncertain','analyzing','promoting')",
        )
        .bind(owner_sub)
        .fetch_one(&mut *tx)
        .await?;
        if total_bytes <= 0
            || used.saturating_add(reserved).saturating_add(total_bytes) > OWNER_BYTES
        {
            return Err(AppError::api(
                axum::http::StatusCode::TOO_MANY_REQUESTS,
                "quota_exceeded",
                "Storage quota would be exceeded.",
                false,
            ));
        }
        if count >= MAX_ANALYSES || in_flight >= MAX_IN_FLIGHT {
            return Err(AppError::api(
                axum::http::StatusCode::TOO_MANY_REQUESTS,
                "quota_exceeded",
                "Analysis quota would be exceeded.",
                false,
            ));
        }
        sqlx::query(
            "UPDATE owner_quotas SET reserved_bytes=reserved_bytes+$2, \
             analysis_count=analysis_count+1,updated_at=now() WHERE owner_sub=$1",
        )
        .bind(owner_sub)
        .bind(total_bytes)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO upload_sessions(\
             id,operation_id,owner_sub,request_sha256,filename,total_bytes,chunk_count,\
             reserved_bytes,state,staging_key,analysis_id,expires_at) \
             VALUES($1,$2,$3,$4,$5,$6,$7,$6,'reserved',$8,$9,now()+interval '24 hours')",
        )
        .bind(upload_id)
        .bind(operation_id)
        .bind(owner_sub)
        .bind(request_sha256)
        .bind(filename)
        .bind(total_bytes)
        .bind(chunk_count)
        .bind(staging_key.to_string())
        .bind(analysis_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO analyses(id,owner_sub,upload_id,display_name,state,retention_until) \
             VALUES($1,$2,$3,$4,'created',now()+interval '30 days')",
        )
        .bind(analysis_id)
        .bind(owner_sub)
        .bind(upload_id)
        .bind(filename)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE idempotency_operations SET state='completed',lease_token=NULL,leased_at=NULL,\
             lease_until=NULL,resource_location=$4,response_status=201,response_body=$5,updated_at=now() \
             WHERE owner_sub=$1 AND scope='POST /api/analyses' AND operation_id=$2 \
             AND request_sha256=$3",
        )
        .bind(owner_sub)
        .bind(operation_id)
        .bind(request_sha256)
        .bind(&location)
        .bind(&response)
        .execute(&mut *tx)
        .await?;
        insert_outbox(
            &mut tx,
            analysis_id,
            owner_sub,
            "analysis.created",
            json!({"analysis_id":analysis_id,"state":"created"}),
        )
        .await?;
        tx.commit().await?;
        let upload = self.get_upload(owner_sub, upload_id).await?;
        let analysis = self.get_analysis(owner_sub, analysis_id).await?;
        Ok(CreatedUpload { upload, analysis })
    }

    pub async fn get_upload(&self, owner_sub: &str, upload_id: Uuid) -> Result<UploadSession> {
        let query =
            format!("SELECT {UPLOAD_COLUMNS} FROM upload_sessions WHERE id=$1 AND owner_sub=$2");
        sqlx::query_as::<_, UploadSession>(&query)
            .bind(upload_id)
            .bind(owner_sub)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(AppError::not_found)
    }

    pub async fn upload_status(&self, owner_sub: &str, upload_id: Uuid) -> Result<UploadStatus> {
        let session = self.get_upload(owner_sub, upload_id).await?;
        let chunks = self.upload_chunks(owner_sub, upload_id).await?;
        let mut missing_ranges = Vec::new();
        let mut seen = vec![false; session.chunk_count as usize];
        for chunk in &chunks {
            if let Some(slot) = seen.get_mut(chunk.chunk_index as usize) {
                *slot = true;
            }
        }
        for (index, present) in seen.into_iter().enumerate() {
            if !present {
                let start = index as i64 * CHUNK_BYTES;
                missing_ranges.push(ByteRange {
                    start,
                    end: (start + CHUNK_BYTES - 1).min(session.total_bytes - 1),
                });
            }
        }
        Ok(UploadStatus {
            finalize_operation_id: server_operation_id("upload-finalize", &session.id.to_string()),
            cancel_operation_id: server_operation_id("upload-cancel", &session.id.to_string()),
            session,
            chunks,
            missing_ranges,
        })
    }

    pub async fn upload_chunks(
        &self,
        owner_sub: &str,
        upload_id: Uuid,
    ) -> Result<Vec<UploadChunk>> {
        let query = format!(
            "SELECT {CHUNK_COLUMNS} FROM upload_chunks c JOIN upload_sessions u ON u.id=c.upload_id \
             WHERE c.upload_id=$1 AND u.owner_sub=$2 ORDER BY c.chunk_index"
        );
        Ok(sqlx::query_as::<_, UploadChunk>(&query)
            .bind(upload_id)
            .bind(owner_sub)
            .fetch_all(&self.pool)
            .await?)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn claim_chunk(
        &self,
        owner_sub: &str,
        upload_id: Uuid,
        index: i32,
        start: i64,
        end: i64,
        byte_size: i32,
        sha256: &str,
    ) -> Result<ChunkClaim> {
        let mut tx = self.pool.begin().await?;
        let query = format!(
            "SELECT {UPLOAD_COLUMNS} FROM upload_sessions WHERE id=$1 AND owner_sub=$2 FOR UPDATE"
        );
        let session = sqlx::query_as::<_, UploadSession>(&query)
            .bind(upload_id)
            .bind(owner_sub)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(AppError::not_found)?;
        if !matches!(session.state.as_str(), "reserved" | "uploading")
            || session.expires_at <= OffsetDateTime::now_utc()
        {
            return Err(AppError::conflict(
                "state_conflict",
                "The upload is not accepting chunks.",
            ));
        }
        validate_chunk_descriptor(&session, index, start, end, byte_size)?;
        let existing = sqlx::query_as::<_, UploadChunk>(&format!(
            "SELECT {CHUNK_COLUMNS} FROM upload_chunks WHERE upload_id=$1 AND chunk_index=$2"
        ))
        .bind(upload_id)
        .bind(index)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(existing) = existing {
            if existing.start_byte == start
                && existing.end_byte == end
                && existing.byte_size == byte_size
                && existing.sha256 == sha256
            {
                tx.commit().await?;
                return Ok(ChunkClaim::Replay);
            }
            return Err(AppError::conflict(
                "chunk_conflict",
                "This chunk index was already committed with different content.",
            ));
        }
        if session.lease_token.is_some() {
            return Err(AppError::conflict(
                "state_conflict",
                "Another upload operation is in progress.",
            ));
        }
        let lease_token = Uuid::new_v4();
        sqlx::query(
            "UPDATE upload_sessions SET state='uploading',lease_token=$3,leased_at=now(),\
             lease_until=now()+interval '30 minutes',updated_at=now() \
             WHERE id=$1 AND owner_sub=$2",
        )
        .bind(upload_id)
        .bind(owner_sub)
        .bind(lease_token)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(ChunkClaim::Claimed {
            session,
            lease_token,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn commit_chunk(
        &self,
        owner_sub: &str,
        upload_id: Uuid,
        lease_token: Uuid,
        index: i32,
        start: i64,
        end: i64,
        byte_size: i32,
        sha256: &str,
        storage_key: &str,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let locked: Option<Uuid> = sqlx::query_scalar(
            "SELECT lease_token FROM upload_sessions WHERE id=$1 AND owner_sub=$2 FOR UPDATE",
        )
        .bind(upload_id)
        .bind(owner_sub)
        .fetch_optional(&mut *tx)
        .await?
        .flatten();
        if locked != Some(lease_token) {
            return Err(AppError::conflict(
                "state_conflict",
                "The upload lease changed before commit.",
            ));
        }
        sqlx::query(
            "INSERT INTO upload_chunks(upload_id,chunk_index,start_byte,end_byte,byte_size,sha256,storage_key) \
             VALUES($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(upload_id)
        .bind(index)
        .bind(start)
        .bind(end)
        .bind(byte_size)
        .bind(sha256)
        .bind(storage_key)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE upload_sessions SET received_bytes=received_bytes+$4,lease_token=NULL,\
             leased_at=NULL,lease_until=NULL,updated_at=now() WHERE id=$1 AND owner_sub=$2 AND lease_token=$3",
        )
        .bind(upload_id)
        .bind(owner_sub)
        .bind(lease_token)
        .bind(byte_size as i64)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn abandon_upload_lease(
        &self,
        owner_sub: &str,
        upload_id: Uuid,
        lease_token: Uuid,
        error_code: &str,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE upload_sessions SET lease_token=NULL,leased_at=NULL,lease_until=NULL,\
             error_code=$4,updated_at=now() WHERE id=$1 AND owner_sub=$2 AND lease_token=$3",
        )
        .bind(upload_id)
        .bind(owner_sub)
        .bind(lease_token)
        .bind(error_code)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn claim_finalize(&self, owner_sub: &str, upload_id: Uuid) -> Result<FinalizeClaim> {
        let mut tx = self.pool.begin().await?;
        let query = format!(
            "SELECT {UPLOAD_COLUMNS} FROM upload_sessions WHERE id=$1 AND owner_sub=$2 FOR UPDATE"
        );
        let session = sqlx::query_as::<_, UploadSession>(&query)
            .bind(upload_id)
            .bind(owner_sub)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(AppError::not_found)?;
        if session.state == "finalized" {
            return Err(AppError::conflict(
                "state_conflict",
                "The upload is already finalized.",
            ));
        }
        if !matches!(session.state.as_str(), "reserved" | "uploading")
            || session.lease_token.is_some()
        {
            return Err(AppError::conflict(
                "state_conflict",
                "The upload cannot be finalized in its current state.",
            ));
        }
        let chunks = sqlx::query_as::<_, UploadChunk>(&format!(
            "SELECT {CHUNK_COLUMNS} FROM upload_chunks WHERE upload_id=$1 ORDER BY chunk_index"
        ))
        .bind(upload_id)
        .fetch_all(&mut *tx)
        .await?;
        if chunks.len() != session.chunk_count as usize
            || chunks
                .iter()
                .map(|chunk| chunk.byte_size as i64)
                .sum::<i64>()
                != session.total_bytes
            || chunks
                .iter()
                .enumerate()
                .any(|(index, chunk)| chunk.chunk_index != index as i32)
        {
            return Err(AppError::conflict(
                "state_conflict",
                "All upload ranges must be committed before finalize.",
            ));
        }
        let lease_token = Uuid::new_v4();
        sqlx::query(
            "UPDATE upload_sessions SET state='assembling',lease_token=$3,leased_at=now(),\
             lease_until=now()+interval '30 minutes',attempt=attempt+1,updated_at=now() \
             WHERE id=$1 AND owner_sub=$2",
        )
        .bind(upload_id)
        .bind(owner_sub)
        .bind(lease_token)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(FinalizeClaim {
            session,
            chunks,
            lease_token,
        })
    }

    pub async fn mark_forwarding(
        &self,
        owner_sub: &str,
        upload_id: Uuid,
        lease_token: Uuid,
        sha256: &str,
    ) -> Result<()> {
        let sample_id = format!("sha256:{sha256}");
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(&sample_id)
            .execute(&mut *tx)
            .await?;
        let deleting: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM sample_objects WHERE sample_id=$1 AND lifecycle='deleting')",
        )
        .bind(&sample_id)
        .fetch_one(&mut *tx)
        .await?;
        if deleting {
            return Err(AppError::conflict(
                "state_conflict",
                "The shared sample is being deleted.",
            ));
        }
        let changed = sqlx::query(
            "UPDATE upload_sessions SET state='forwarding',assembled_sha256=$4,\
             lease_until=now()+interval '30 minutes',updated_at=now() \
             WHERE id=$1 AND owner_sub=$2 AND lease_token=$3 AND state='assembling'",
        )
        .bind(upload_id)
        .bind(owner_sub)
        .bind(lease_token)
        .bind(sha256)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(AppError::conflict(
                "state_conflict",
                "The upload lease changed before forwarding.",
            ));
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn mark_upstream_uncertain(&self, upload_id: Uuid, lease_token: Uuid) -> Result<()> {
        sqlx::query(
            "UPDATE upload_sessions SET state='upstream_uncertain',lease_token=NULL,leased_at=NULL,\
             lease_until=NULL,error_code='analyzer_uncertain',updated_at=now() \
             WHERE id=$1 AND lease_token=$2 AND state='forwarding'",
        )
        .bind(upload_id)
        .bind(lease_token)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn complete_finalize(
        &self,
        owner_sub: &str,
        upload_id: Uuid,
        lease_token: Option<Uuid>,
        sha256: &str,
        file_type: &str,
    ) -> Result<Analysis> {
        let sample_id = format!("sha256:{sha256}");
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(&sample_id)
            .execute(&mut *tx)
            .await?;
        let upload_query = format!(
            "SELECT {UPLOAD_COLUMNS} FROM upload_sessions WHERE id=$1 AND owner_sub=$2 FOR UPDATE"
        );
        let upload = sqlx::query_as::<_, UploadSession>(&upload_query)
            .bind(upload_id)
            .bind(owner_sub)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(AppError::not_found)?;
        if !matches!(upload.state.as_str(), "forwarding" | "upstream_uncertain")
            || upload.assembled_sha256.as_deref() != Some(sha256)
            || (upload.state == "forwarding" && upload.lease_token != lease_token)
        {
            return Err(AppError::conflict(
                "state_conflict",
                "The upload cannot be finalized from its current state.",
            ));
        }
        let lifecycle: Option<String> = sqlx::query_scalar(
            "SELECT lifecycle FROM sample_objects WHERE sample_id=$1 FOR UPDATE",
        )
        .bind(&sample_id)
        .fetch_optional(&mut *tx)
        .await?;
        if lifecycle.as_deref() == Some("deleting") {
            return Err(AppError::conflict(
                "state_conflict",
                "The shared sample is being deleted.",
            ));
        }
        sqlx::query(
            "INSERT INTO sample_objects(sample_id,sha256,byte_size,file_type,ref_count,lifecycle) \
             VALUES($1,$2,$3,$4,1,'active') \
             ON CONFLICT(sample_id) DO UPDATE SET ref_count=sample_objects.ref_count+1,\
             file_type=CASE WHEN sample_objects.file_type='unknown' THEN EXCLUDED.file_type \
             ELSE sample_objects.file_type END,lifecycle='active',delete_after=NULL,\
             delete_operation_id=NULL,updated_at=now()",
        )
        .bind(&sample_id)
        .bind(sha256)
        .bind(upload.total_bytes)
        .bind(file_type)
        .execute(&mut *tx)
        .await?;
        let used_bytes: i64 = sqlx::query_scalar(
            "UPDATE owner_quotas SET reserved_bytes=reserved_bytes-$2,used_bytes=used_bytes+$2,\
             updated_at=now() WHERE owner_sub=$1 AND reserved_bytes >= $2 RETURNING used_bytes",
        )
        .bind(owner_sub)
        .bind(upload.total_bytes)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(AppError::Invariant(
            "owner quota would underflow on finalize",
        ))?;
        if file_type == "unknown" {
            sqlx::query(
                "UPDATE upload_sessions SET state='finalized',sample_id=$3,lease_token=NULL,leased_at=NULL,\
                 lease_until=NULL,frozen_status=NULL,frozen_location=NULL,frozen_body=NULL,\
                 error_code='unknown_file_disposition_waiting',updated_at=now() \
                 WHERE id=$1 AND owner_sub=$2",
            )
            .bind(upload_id)
            .bind(owner_sub)
            .bind(&sample_id)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE analyses SET sample_id=$3,state='failed',updated_at=now() \
                 WHERE id=$1 AND owner_sub=$2",
            )
            .bind(upload.analysis_id)
            .bind(owner_sub)
            .bind(&sample_id)
            .execute(&mut *tx)
            .await?;
            insert_outbox(
                &mut tx,
                upload.analysis_id,
                owner_sub,
                "analysis.failed",
                json!({"analysis_id":upload.analysis_id,"state":"failed","error_code":"unknown_file_type"}),
            )
            .await?;
        } else {
            let frozen_body = json!({
                "analysis_id": upload.analysis_id,
                "sample_id": sample_id,
                "state": "uploaded"
            });
            sqlx::query(
                "UPDATE upload_sessions SET state='finalized',sample_id=$3,lease_token=NULL,leased_at=NULL,\
                 lease_until=NULL,frozen_status=202,frozen_location=$4,frozen_body=$5,\
                 error_code=CASE WHEN error_code='cancel_requested' THEN error_code ELSE NULL END,updated_at=now() \
                 WHERE id=$1 AND owner_sub=$2",
            )
            .bind(upload_id)
            .bind(owner_sub)
            .bind(&sample_id)
            .bind(format!("/analyses/{}", upload.analysis_id))
            .bind(&frozen_body)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE analyses SET sample_id=$3,state='uploaded',updated_at=now() \
                 WHERE id=$1 AND owner_sub=$2",
            )
            .bind(upload.analysis_id)
            .bind(owner_sub)
            .bind(&sample_id)
            .execute(&mut *tx)
            .await?;
            insert_outbox(
                &mut tx,
                upload.analysis_id,
                owner_sub,
                "analysis.uploaded",
                json!({"analysis_id":upload.analysis_id,"state":"uploaded"}),
            )
            .await?;
        }
        if file_type != "unknown" && used_bytes >= OWNER_BYTES.saturating_mul(80) / 100 {
            let claimed = sqlx::query(
                "INSERT INTO notification_claims(owner_sub,kind,window_start) \
                 VALUES($1,'storage_80pct',date_trunc('day',now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC') \
                 ON CONFLICT(owner_sub,kind,window_start) DO NOTHING",
            )
            .bind(owner_sub)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if claimed == 1 {
                insert_outbox(
                    &mut tx,
                    upload.analysis_id,
                    owner_sub,
                    "quota.storage_80pct",
                    json!({"analysis_id":upload.analysis_id,"kind":"storage_80pct"}),
                )
                .await?;
            }
        }
        tx.commit().await?;
        self.get_analysis(owner_sub, upload.analysis_id).await
    }

    pub async fn fail_unknown_file(
        &self,
        owner_sub: &str,
        upload_id: Uuid,
        lease_token: Uuid,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(
            "SELECT analysis_id,total_bytes FROM upload_sessions \
             WHERE id=$1 AND owner_sub=$2 AND lease_token=$3 FOR UPDATE",
        )
        .bind(upload_id)
        .bind(owner_sub)
        .bind(lease_token)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::conflict("state_conflict", "The upload lease changed."))?;
        let analysis_id: Uuid = row.get("analysis_id");
        let total_bytes: i64 = row.get("total_bytes");
        sqlx::query(
            "UPDATE owner_quotas SET reserved_bytes=reserved_bytes-$2,updated_at=now() \
             WHERE owner_sub=$1 AND reserved_bytes >= $2",
        )
        .bind(owner_sub)
        .bind(total_bytes)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE upload_sessions SET state='failed',lease_token=NULL,leased_at=NULL,lease_until=NULL,\
             error_code='unknown_file_type',updated_at=now() WHERE id=$1",
        )
        .bind(upload_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE analyses SET state='failed',updated_at=now() WHERE id=$1 AND owner_sub=$2",
        )
        .bind(analysis_id)
        .bind(owner_sub)
        .execute(&mut *tx)
        .await?;
        insert_outbox(
            &mut tx,
            analysis_id,
            owner_sub,
            "analysis.failed",
            json!({"analysis_id":analysis_id,"state":"failed","error_code":"unknown_file_type"}),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn dispose_finalized_unknown(
        &self,
        owner_sub: &str,
        upload_id: Uuid,
        sha256: &str,
    ) -> Result<bool> {
        let sample_id = format!("sha256:{sha256}");
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(&sample_id)
            .execute(&mut *tx)
            .await?;
        let upload = sqlx::query(&format!(
            "SELECT {UPLOAD_COLUMNS} FROM upload_sessions WHERE id=$1 AND owner_sub=$2 FOR UPDATE"
        ))
        .bind(upload_id)
        .bind(owner_sub)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(AppError::not_found)?;
        let state: String = upload.get("state");
        let stored_sample: Option<String> = upload.get("sample_id");
        let analysis_id: Uuid = upload.get("analysis_id");
        let total_bytes: i64 = upload.get("total_bytes");
        if state == "failed" {
            tx.commit().await?;
            return Ok(true);
        }
        if state != "finalized" || stored_sample.as_deref() != Some(&sample_id) {
            return Err(AppError::conflict(
                "state_conflict",
                "The unknown sample is not durably finalized.",
            ));
        }
        let pending: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM upload_sessions WHERE assembled_sha256=$1 AND id<>$2 \
             AND state IN ('assembling','forwarding','upstream_uncertain'))",
        )
        .bind(sha256)
        .bind(upload_id)
        .fetch_one(&mut *tx)
        .await?;
        let sample = sqlx::query(
            "SELECT ref_count,file_type,lifecycle FROM sample_objects WHERE sample_id=$1 FOR UPDATE",
        )
        .bind(&sample_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(AppError::Invariant("finalized unknown sample is missing"))?;
        let ref_count: i32 = sample.get("ref_count");
        let file_type: String = sample.get("file_type");
        let lifecycle: String = sample.get("lifecycle");
        if ref_count <= 0 || file_type != "unknown" {
            return Err(AppError::Invariant(
                "unknown sample disposition violated reference invariants",
            ));
        }
        let disposition_waiting = pending || lifecycle == "deleting";
        let analysis_was_failed: bool = sqlx::query_scalar(
            "SELECT state='failed' FROM analyses WHERE id=$1 AND owner_sub=$2 FOR UPDATE",
        )
        .bind(analysis_id)
        .bind(owner_sub)
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE analyses SET state='failed',sample_id=CASE WHEN $3 THEN sample_id ELSE NULL END,\
             updated_at=now() \
             WHERE id=$1 AND owner_sub=$2",
        )
        .bind(analysis_id)
        .bind(owner_sub)
        .bind(disposition_waiting)
        .execute(&mut *tx)
        .await?;
        if !analysis_was_failed {
            insert_outbox(
                &mut tx,
                analysis_id,
                owner_sub,
                "analysis.failed",
                json!({"analysis_id":analysis_id,"state":"failed","error_code":"unknown_file_type"}),
            )
            .await?;
        }
        if disposition_waiting {
            sqlx::query(
                "UPDATE upload_sessions SET error_code='unknown_file_disposition_waiting',\
                 frozen_status=NULL,frozen_location=NULL,frozen_body=NULL,updated_at=now() WHERE id=$1",
            )
            .bind(upload_id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return Ok(false);
        }
        if ref_count == 1 {
            let delete_operation = Uuid::new_v4();
            sqlx::query(
                "UPDATE sample_objects SET ref_count=0,lifecycle='delete_pending',delete_after=now(),\
                 delete_operation_id=$2,updated_at=now() WHERE sample_id=$1",
            )
            .bind(&sample_id)
            .bind(delete_operation)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE upload_sessions SET state='expired',sample_id=NULL,\
                 error_code='unknown_file_disposition',frozen_status=NULL,frozen_location=NULL,\
                 frozen_body=NULL,updated_at=now() WHERE id=$1",
            )
            .bind(upload_id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return Ok(false);
        } else {
            sqlx::query(
                "UPDATE sample_objects SET ref_count=ref_count-1,updated_at=now() WHERE sample_id=$1",
            )
            .bind(&sample_id)
            .execute(&mut *tx)
            .await?;
        }
        let quota = sqlx::query(
            "UPDATE owner_quotas SET used_bytes=used_bytes-$2,updated_at=now() \
             WHERE owner_sub=$1 AND used_bytes >= $2",
        )
        .bind(owner_sub)
        .bind(total_bytes)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if quota != 1 {
            return Err(AppError::Invariant(
                "owner quota would underflow for unknown sample",
            ));
        }
        sqlx::query(
            "UPDATE upload_sessions SET state='failed',sample_id=NULL,error_code='unknown_file_type',\
             frozen_status=NULL,frozen_location=NULL,frozen_body=NULL,updated_at=now() WHERE id=$1",
        )
        .bind(upload_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    pub async fn expire_uncertain_upload(
        &self,
        upload: &UploadSession,
        force: bool,
    ) -> Result<bool> {
        let digest = upload
            .assembled_sha256
            .as_deref()
            .ok_or(AppError::Invariant("uncertain upload omitted digest"))?;
        let sample_id = format!("sha256:{digest}");
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(&sample_id)
            .execute(&mut *tx)
            .await?;
        let locked = sqlx::query(&format!(
            "SELECT {UPLOAD_COLUMNS},updated_at<=now()-interval '24 hours' AS disposition_due \
             FROM upload_sessions WHERE id=$1 AND owner_sub=$2 FOR UPDATE"
        ))
        .bind(upload.id)
        .bind(&upload.owner_sub)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(AppError::not_found)?;
        let state: String = locked.get("state");
        let disposition_due: bool = locked.get("disposition_due");
        if state != "upstream_uncertain" || (!force && !disposition_due) {
            tx.commit().await?;
            return Ok(false);
        }
        let pending: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM upload_sessions WHERE assembled_sha256=$1 AND id<>$2 \
             AND state IN ('assembling','forwarding','upstream_uncertain'))",
        )
        .bind(digest)
        .bind(upload.id)
        .fetch_one(&mut *tx)
        .await?;
        if pending {
            tx.commit().await?;
            return Ok(false);
        }
        let sample = sqlx::query(
            "SELECT ref_count,lifecycle FROM sample_objects WHERE sample_id=$1 FOR UPDATE",
        )
        .bind(&sample_id)
        .fetch_optional(&mut *tx)
        .await?;
        if force {
            terminal_uncertain_upload(
                &mut tx,
                upload,
                "analyzer_operation_failed",
                "reserved_bytes",
            )
            .await?;
            tx.commit().await?;
            return Ok(true);
        }
        let can_finish_without_delete = sample.as_ref().is_some_and(|row| {
            row.get::<i32, _>("ref_count") > 0 || row.get::<String, _>("lifecycle") == "deleted"
        });
        if can_finish_without_delete {
            terminal_uncertain_upload(
                &mut tx,
                upload,
                "analyzer_unknown_expired",
                "reserved_bytes",
            )
            .await?;
            tx.commit().await?;
            return Ok(true);
        }
        let delete_operation = Uuid::new_v4();
        match sample {
            None => {
                sqlx::query(
                    "INSERT INTO sample_objects(sample_id,sha256,byte_size,file_type,ref_count,lifecycle,\
                     delete_after,delete_operation_id) VALUES($1,$2,$3,'unknown',0,'delete_pending',now(),$4)",
                )
                .bind(&sample_id)
                .bind(digest)
                .bind(upload.total_bytes)
                .bind(delete_operation)
                .execute(&mut *tx)
                .await?;
            }
            Some(row)
                if row.get::<i32, _>("ref_count") == 0
                    && row.get::<String, _>("lifecycle") != "deleting" =>
            {
                sqlx::query(
                    "UPDATE sample_objects SET lifecycle='delete_pending',delete_after=now(),\
                     delete_operation_id=COALESCE(delete_operation_id,$2),updated_at=now() \
                     WHERE sample_id=$1",
                )
                .bind(&sample_id)
                .bind(delete_operation)
                .execute(&mut *tx)
                .await?;
            }
            Some(_) => {}
        }
        sqlx::query(
            "UPDATE upload_sessions SET state='expired',error_code='analyzer_unknown_disposition',\
             lease_token=NULL,leased_at=NULL,lease_until=NULL,updated_at=now() WHERE id=$1",
        )
        .bind(upload.id)
        .execute(&mut *tx)
        .await?;
        let analysis_changed = sqlx::query(
            "UPDATE analyses SET state='failed',updated_at=now() \
             WHERE id=$1 AND owner_sub=$2 AND state<>'failed'",
        )
        .bind(upload.analysis_id)
        .bind(&upload.owner_sub)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if analysis_changed == 1 {
            insert_outbox(
                &mut tx,
                upload.analysis_id,
                &upload.owner_sub,
                "analysis.failed",
                json!({"analysis_id":upload.analysis_id,"state":"failed","error_code":"analyzer_unknown_expired"}),
            )
            .await?;
        }
        tx.commit().await?;
        Ok(false)
    }

    pub async fn disposition_uploads(&self, limit: i64) -> Result<Vec<UploadSession>> {
        let query = format!(
            "SELECT {UPLOAD_COLUMNS} FROM upload_sessions WHERE \
             (state='expired' AND error_code IN ('unknown_file_disposition','analyzer_unknown_disposition')) \
             OR (state='finalized' AND error_code='unknown_file_disposition_waiting') \
             ORDER BY updated_at,id LIMIT $1"
        );
        Ok(sqlx::query_as::<_, UploadSession>(&query)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?)
    }

    pub async fn complete_unknown_disposition(&self, upload: &UploadSession) -> Result<bool> {
        let digest = upload
            .assembled_sha256
            .as_deref()
            .ok_or(AppError::Invariant("upload disposition omitted digest"))?;
        let sample_id = format!("sha256:{digest}");
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(&sample_id)
            .execute(&mut *tx)
            .await?;
        let locked = sqlx::query(&format!(
            "SELECT {UPLOAD_COLUMNS} FROM upload_sessions WHERE id=$1 AND owner_sub=$2 FOR UPDATE"
        ))
        .bind(upload.id)
        .bind(&upload.owner_sub)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(AppError::not_found)?;
        let state: String = locked.get("state");
        let error_code: Option<String> = locked.get("error_code");
        if state != "expired"
            || !matches!(
                error_code.as_deref(),
                Some("unknown_file_disposition" | "analyzer_unknown_disposition")
            )
        {
            tx.commit().await?;
            return Ok(false);
        }
        let sample = sqlx::query(
            "SELECT ref_count,lifecycle FROM sample_objects WHERE sample_id=$1 FOR UPDATE",
        )
        .bind(&sample_id)
        .fetch_optional(&mut *tx)
        .await?;
        let disposition_complete = sample.as_ref().is_some_and(|row| {
            row.get::<i32, _>("ref_count") > 0 || row.get::<String, _>("lifecycle") == "deleted"
        });
        if !disposition_complete {
            tx.commit().await?;
            return Ok(false);
        }
        let quota_column = if error_code.as_deref() == Some("unknown_file_disposition") {
            "used_bytes"
        } else {
            "reserved_bytes"
        };
        let terminal_code = if quota_column == "used_bytes" {
            "unknown_file_type"
        } else {
            "analyzer_unknown_expired"
        };
        terminal_uncertain_upload(&mut tx, upload, terminal_code, quota_column).await?;
        tx.commit().await?;
        Ok(true)
    }

    pub async fn cancelled_finalized_uploads(
        &self,
        limit: i64,
    ) -> Result<Vec<(String, Uuid, Uuid)>> {
        Ok(sqlx::query_as(
            "SELECT owner_sub,analysis_id,operation_id FROM upload_sessions WHERE state='finalized' \
             AND error_code='cancel_requested' ORDER BY updated_at,id LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn cancellable_requested_uploads(&self, limit: i64) -> Result<Vec<(String, Uuid)>> {
        Ok(sqlx::query_as(
            "SELECT owner_sub,id FROM upload_sessions WHERE \
             ((error_code='cancel_requested' AND state IN ('reserved','uploading')) \
              OR state='cancel_pending') AND lease_token IS NULL \
             ORDER BY updated_at,id LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn begin_cancel(&self, owner_sub: &str, upload_id: Uuid) -> Result<UploadSession> {
        let mut tx = self.pool.begin().await?;
        let query = format!(
            "SELECT {UPLOAD_COLUMNS} FROM upload_sessions WHERE id=$1 AND owner_sub=$2 FOR UPDATE"
        );
        let upload = sqlx::query_as::<_, UploadSession>(&query)
            .bind(upload_id)
            .bind(owner_sub)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(AppError::not_found)?;
        if upload.state == "cancelled" {
            tx.commit().await?;
            return Ok(upload);
        }
        if matches!(upload.state.as_str(), "finalized" | "failed" | "expired") {
            return Err(AppError::conflict(
                "state_conflict",
                "The upload cannot be cancelled.",
            ));
        }
        if upload.lease_token.is_some()
            || matches!(
                upload.state.as_str(),
                "assembling" | "forwarding" | "upstream_uncertain"
            )
        {
            sqlx::query(
                "UPDATE upload_sessions SET error_code='cancel_requested',updated_at=now() \
                 WHERE id=$1 AND owner_sub=$2",
            )
            .bind(upload_id)
            .bind(owner_sub)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return Ok(upload);
        }
        sqlx::query(
            "UPDATE upload_sessions SET state='cancel_pending',lease_token=NULL,leased_at=NULL,\
             lease_until=NULL,updated_at=now() WHERE id=$1 AND owner_sub=$2",
        )
        .bind(upload_id)
        .bind(owner_sub)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(upload)
    }

    pub async fn complete_cancel(&self, owner_sub: &str, upload_id: Uuid) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(
            "SELECT analysis_id,total_bytes,state FROM upload_sessions \
             WHERE id=$1 AND owner_sub=$2 FOR UPDATE",
        )
        .bind(upload_id)
        .bind(owner_sub)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(AppError::not_found)?;
        let state: String = row.get("state");
        if state == "cancelled" {
            tx.commit().await?;
            return Ok(());
        }
        if state != "cancel_pending" {
            return Err(AppError::conflict(
                "state_conflict",
                "The upload is not pending cancellation.",
            ));
        }
        let analysis_id: Uuid = row.get("analysis_id");
        let total_bytes: i64 = row.get("total_bytes");
        sqlx::query(
            "UPDATE owner_quotas SET reserved_bytes=reserved_bytes-$2,updated_at=now() \
             WHERE owner_sub=$1 AND reserved_bytes >= $2",
        )
        .bind(owner_sub)
        .bind(total_bytes)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE upload_sessions SET state='cancelled',filename='deleted',frozen_body=NULL,\
             frozen_location=NULL,error_code=NULL,updated_at=now() WHERE id=$1",
        )
        .bind(upload_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE analyses SET state='failed',display_name='deleted',updated_at=now() \
             WHERE id=$1 AND owner_sub=$2",
        )
        .bind(analysis_id)
        .bind(owner_sub)
        .execute(&mut *tx)
        .await?;
        insert_outbox(
            &mut tx,
            analysis_id,
            owner_sub,
            "upload.cancelled",
            json!({"analysis_id":analysis_id,"state":"failed"}),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn list_analyses(&self, owner_sub: &str) -> Result<Vec<Analysis>> {
        let query = format!(
            "SELECT {ANALYSIS_COLUMNS} FROM analyses WHERE owner_sub=$1 AND deleted_at IS NULL \
             ORDER BY created_at DESC,id DESC LIMIT 100"
        );
        Ok(sqlx::query_as::<_, Analysis>(&query)
            .bind(owner_sub)
            .fetch_all(&self.pool)
            .await?)
    }

    pub async fn owner_quota(&self, owner_sub: &str) -> Result<OwnerQuota> {
        let row = sqlx::query(
            "SELECT used_bytes,reserved_bytes,analysis_count FROM owner_quotas WHERE owner_sub=$1",
        )
        .bind(owner_sub)
        .fetch_optional(&self.pool)
        .await?;
        Ok(match row {
            Some(row) => OwnerQuota {
                used_bytes: row.get("used_bytes"),
                reserved_bytes: row.get("reserved_bytes"),
                analysis_count: row.get("analysis_count"),
                byte_limit: OWNER_BYTES,
                analysis_limit: MAX_ANALYSES,
            },
            None => OwnerQuota {
                used_bytes: 0,
                reserved_bytes: 0,
                analysis_count: 0,
                byte_limit: OWNER_BYTES,
                analysis_limit: MAX_ANALYSES,
            },
        })
    }

    pub async fn idempotency_replay(
        &self,
        owner_sub: &str,
        scope: &str,
        operation_id: Uuid,
        request_sha256: &str,
    ) -> Result<Option<IdempotencyReplay>> {
        let row = sqlx::query(
            "SELECT request_sha256,state,lease_until,response_status,resource_location,response_body \
             FROM idempotency_operations WHERE owner_sub=$1 AND scope=$2 AND operation_id=$3",
        )
        .bind(owner_sub)
        .bind(scope)
        .bind(operation_id)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let bound_sha: String = row.get("request_sha256");
        if bound_sha != request_sha256 {
            return Err(AppError::conflict(
                "idempotency_mismatch",
                "The idempotency key is bound to a different request.",
            ));
        }
        let state: String = row.get("state");
        let lease_until: Option<OffsetDateTime> = row.get("lease_until");
        if state == "leased" && lease_until.is_some_and(|until| until <= OffsetDateTime::now_utc())
        {
            return Ok(None);
        }
        if state != "completed" {
            return Err(AppError::conflict(
                "state_conflict",
                "The operation is still pending reconciliation.",
            ));
        }
        let status: Option<i32> = row.get("response_status");
        Ok(Some(IdempotencyReplay {
            status: status.ok_or(AppError::Invariant(
                "completed idempotency record omitted status",
            ))?,
            location: row.get("resource_location"),
            body: row.get("response_body"),
        }))
    }

    pub async fn claim_http_operation(
        &self,
        owner_sub: &str,
        scope: &str,
        operation_id: Uuid,
        request_sha256: &str,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        claim_idempotency(&mut tx, owner_sub, scope, operation_id, request_sha256).await?;
        tx.commit().await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn complete_http_operation(
        &self,
        owner_sub: &str,
        scope: &str,
        operation_id: Uuid,
        request_sha256: &str,
        response_status: i32,
        location: &str,
        response_body: &serde_json::Value,
    ) -> Result<()> {
        let changed = sqlx::query(
            "UPDATE idempotency_operations SET state='completed',lease_token=NULL,leased_at=NULL,\
             lease_until=NULL,response_status=$5,resource_location=$6,response_body=$7,updated_at=now() \
             WHERE owner_sub=$1 AND scope=$2 AND operation_id=$3 AND request_sha256=$4 \
             AND state='leased'",
        )
        .bind(owner_sub)
        .bind(scope)
        .bind(operation_id)
        .bind(request_sha256)
        .bind(response_status)
        .bind(location)
        .bind(response_body)
        .execute(&self.pool)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(AppError::conflict(
                "state_conflict",
                "The HTTP operation lease changed before completion.",
            ));
        }
        Ok(())
    }

    pub async fn get_analysis(&self, owner_sub: &str, analysis_id: Uuid) -> Result<Analysis> {
        let query = format!(
            "SELECT {ANALYSIS_COLUMNS} FROM analyses WHERE id=$1 AND owner_sub=$2 AND deleted_at IS NULL"
        );
        sqlx::query_as::<_, Analysis>(&query)
            .bind(analysis_id)
            .bind(owner_sub)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(AppError::not_found)
    }

    pub async fn assert_analysis_owner(&self, owner_sub: &str, analysis_id: Uuid) -> Result<()> {
        let owned: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM analyses WHERE id=$1 AND owner_sub=$2)",
        )
        .bind(analysis_id)
        .bind(owner_sub)
        .fetch_one(&self.pool)
        .await?;
        if !owned {
            return Err(AppError::not_found());
        }
        Ok(())
    }

    pub async fn artifacts(&self, owner_sub: &str, analysis_id: Uuid) -> Result<Vec<Artifact>> {
        let query = format!(
            "SELECT {ARTIFACT_COLUMNS} FROM artifacts WHERE analysis_id=$1 AND owner_sub=$2 \
             ORDER BY created_at,id"
        );
        Ok(sqlx::query_as::<_, Artifact>(&query)
            .bind(analysis_id)
            .bind(owner_sub)
            .fetch_all(&self.pool)
            .await?)
    }

    pub async fn get_artifact(
        &self,
        owner_sub: &str,
        analysis_id: Uuid,
        artifact_id: Uuid,
    ) -> Result<Artifact> {
        let query = format!(
            "SELECT {ARTIFACT_COLUMNS} FROM artifacts \
             WHERE id=$1 AND analysis_id=$2 AND owner_sub=$3"
        );
        sqlx::query_as::<_, Artifact>(&query)
            .bind(artifact_id)
            .bind(analysis_id)
            .bind(owner_sub)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(AppError::not_found)
    }

    pub async fn begin_promote(
        &self,
        owner_sub: &str,
        analysis_id: Uuid,
        operation_id: Uuid,
        request_sha256: &str,
    ) -> Result<Analysis> {
        let mut tx = self.pool.begin().await?;
        let query = format!(
            "SELECT {ANALYSIS_COLUMNS} FROM analyses WHERE id=$1 AND owner_sub=$2 AND deleted_at IS NULL FOR UPDATE"
        );
        let analysis = sqlx::query_as::<_, Analysis>(&query)
            .bind(analysis_id)
            .bind(owner_sub)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(AppError::not_found)?;
        if analysis.plan_id.is_none()
            || !matches!(analysis.state.as_str(), "analyzing" | "degraded")
        {
            return Err(AppError::conflict(
                "state_conflict",
                "The analysis cannot be promoted in its current state.",
            ));
        }
        let unresolved: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM idempotency_operations WHERE owner_sub=$1 \
             AND scope='worker:promote:'||$2::text AND state IN ('leased','downstream_uncertain'))",
        )
        .bind(owner_sub)
        .bind(analysis_id)
        .fetch_one(&mut *tx)
        .await?;
        if unresolved {
            return Err(AppError::conflict(
                "state_conflict",
                "A previous promotion is still being reconciled.",
            ));
        }
        claim_idempotency(
            &mut tx,
            owner_sub,
            "POST /api/analyses/:id/promote",
            operation_id,
            request_sha256,
        )
        .await?;
        sqlx::query("UPDATE analyses SET state='promoting',updated_at=now() WHERE id=$1")
            .bind(analysis_id)
            .execute(&mut *tx)
            .await?;
        insert_outbox(
            &mut tx,
            analysis_id,
            owner_sub,
            "analysis.promoting",
            json!({"analysis_id":analysis_id,"state":"promoting"}),
        )
        .await?;
        tx.commit().await?;
        Ok(analysis)
    }

    pub async fn complete_promote(
        &self,
        owner_sub: &str,
        analysis_id: Uuid,
        operation_id: Uuid,
        downstream_uncertain: bool,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let state = if downstream_uncertain {
            "downstream_uncertain"
        } else {
            "completed"
        };
        let status = if downstream_uncertain {
            None
        } else {
            Some(202)
        };
        sqlx::query(
            "UPDATE idempotency_operations SET state=$5,lease_token=NULL,leased_at=NULL,lease_until=NULL,\
             response_status=$6,resource_location=$4,response_body=CASE WHEN $6 IS NULL THEN NULL ELSE jsonb_build_object('analysis_id',$3::text,'state','promoting') END,updated_at=now() \
             WHERE owner_sub=$1 AND scope='POST /api/analyses/:id/promote' AND operation_id=$2",
        )
        .bind(owner_sub)
        .bind(operation_id)
        .bind(analysis_id)
        .bind(format!("/analyses/{analysis_id}"))
        .bind(state)
        .bind(status)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn claim_start(&self) -> Result<Option<Analysis>> {
        let mut tx = self.pool.begin().await?;
        let lease_token = Uuid::new_v4();
        let query = format!(
            "SELECT {ANALYSIS_COLUMNS} FROM analyses WHERE state='uploaded' AND deleted_at IS NULL \
             ORDER BY updated_at,id FOR UPDATE SKIP LOCKED LIMIT 1"
        );
        let analysis = sqlx::query_as::<_, Analysis>(&query)
            .fetch_optional(&mut *tx)
            .await?;
        if let Some(analysis) = &analysis {
            sqlx::query(
                "UPDATE analyses SET state='starting',poll_lease_token=$2,\
                 poll_lease_until=now()+interval '5 minutes',updated_at=now() WHERE id=$1",
            )
            .bind(analysis.id)
            .bind(lease_token)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(analysis)
    }

    pub async fn finish_start(
        &self,
        analysis: &Analysis,
        plan_id: Option<&str>,
        uncertain: bool,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let state = if uncertain {
            "start_uncertain"
        } else {
            "analyzing"
        };
        let changed = sqlx::query(
            "UPDATE analyses SET state=$3,plan_id=COALESCE($4,plan_id),last_polled_at=now(),\
             poll_lease_token=NULL,poll_lease_until=NULL,updated_at=now() \
             WHERE id=$1 AND owner_sub=$2 AND state IN ('starting','start_uncertain')",
        )
        .bind(analysis.id)
        .bind(&analysis.owner_sub)
        .bind(state)
        .bind(plan_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(AppError::conflict(
                "state_conflict",
                "The analysis start claim changed.",
            ));
        }
        insert_outbox(
            &mut tx,
            analysis.id,
            &analysis.owner_sub,
            if uncertain {
                "analysis.start_uncertain"
            } else {
                "analysis.started"
            },
            json!({"analysis_id":analysis.id,"state":state}),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn analyses_for_poll(&self, limit: i64) -> Result<Vec<Analysis>> {
        let query = format!(
            "SELECT {ANALYSIS_COLUMNS} FROM analyses WHERE state IN ('analyzing','promoting','degraded') \
             AND plan_id IS NOT NULL AND deleted_at IS NULL ORDER BY COALESCE(updated_at,created_at) LIMIT $1"
        );
        Ok(sqlx::query_as::<_, Analysis>(&query)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?)
    }

    pub async fn apply_workflow_status(
        &self,
        analysis: &Analysis,
        state: &str,
        current_stage: Option<&str>,
        latest_stage: Option<&str>,
        event_type: &str,
        payload: serde_json::Value,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "UPDATE analyses SET state=$3,current_stage=$4,latest_stage=$5,last_polled_at=now(),updated_at=now() \
             WHERE id=$1 AND owner_sub=$2 AND deleted_at IS NULL",
        )
        .bind(analysis.id)
        .bind(&analysis.owner_sub)
        .bind(state)
        .bind(current_stage)
        .bind(latest_stage)
        .execute(&mut *tx)
        .await?;
        insert_outbox(
            &mut tx,
            analysis.id,
            &analysis.owner_sub,
            event_type,
            payload,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn save_case(
        &self,
        analysis: &Analysis,
        case_id: &str,
        artifact_id: &str,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE analyses SET case_id=$3,case_artifact_id=$4,updated_at=now() \
             WHERE id=$1 AND owner_sub=$2 AND deleted_at IS NULL",
        )
        .bind(analysis.id)
        .bind(&analysis.owner_sub)
        .bind(case_id)
        .bind(artifact_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn claim_outbox(&self) -> Result<Option<ClaimedOutbox>> {
        let token = Uuid::new_v4();
        let row = sqlx::query_as::<_, ClaimedOutbox>(
            "WITH candidate AS (SELECT id FROM outbox WHERE \
             (state='pending' AND next_attempt_at<=now()) OR (state='leased' AND lease_until<now()) \
             ORDER BY created_at,id FOR UPDATE SKIP LOCKED LIMIT 1) \
             UPDATE outbox o SET state='leased',lease_token=$1,leased_at=now(),lease_until=now()+interval '60 seconds',\
             attempts=attempts+1 FROM candidate c WHERE o.id=c.id \
             RETURNING o.id,o.aggregate_id,o.owner_sub,o.event_type,o.payload,o.lease_token",
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn deliver_outbox(&self, claimed: &ClaimedOutbox) -> Result<AnalysisEvent> {
        let mut tx = self.pool.begin().await?;
        let outbox_state =
            sqlx::query("SELECT state,lease_token FROM outbox WHERE id=$1 FOR UPDATE")
                .bind(claimed.id)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(AppError::Invariant("claimed outbox disappeared"))?;
        let state: String = outbox_state.get("state");
        let token: Option<Uuid> = outbox_state.get("lease_token");
        if state != "leased" || token != Some(claimed.lease_token) {
            return Err(AppError::conflict(
                "state_conflict",
                "The outbox lease changed.",
            ));
        }
        let existing = sqlx::query_as::<_, AnalysisEvent>(
            "SELECT seq,analysis_id,event_type,payload,created_at FROM analysis_events \
             WHERE source_outbox_id=$1",
        )
        .bind(claimed.id)
        .fetch_optional(&mut *tx)
        .await?;
        let event = if let Some(existing) = existing {
            existing
        } else {
            let seq: i64 = sqlx::query_scalar(
                "SELECT next_event_seq FROM analyses WHERE id=$1 AND owner_sub=$2 FOR UPDATE",
            )
            .bind(claimed.aggregate_id)
            .bind(&claimed.owner_sub)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(AppError::Invariant("outbox aggregate is missing"))?;
            let event = sqlx::query_as::<_, AnalysisEvent>(
                "INSERT INTO analysis_events(analysis_id,owner_sub,seq,source_outbox_id,event_type,payload,expires_at) \
                 VALUES($1,$2,$3,$4,$5,$6,now()+interval '30 days') \
                 ON CONFLICT(source_outbox_id) DO NOTHING \
                 RETURNING seq,analysis_id,event_type,payload,created_at",
            )
            .bind(claimed.aggregate_id)
            .bind(&claimed.owner_sub)
            .bind(seq)
            .bind(claimed.id)
            .bind(&claimed.event_type)
            .bind(&claimed.payload)
            .fetch_optional(&mut *tx)
            .await?;
            if let Some(event) = event {
                sqlx::query(
                    "UPDATE analyses SET next_event_seq=next_event_seq+1 WHERE id=$1 AND owner_sub=$2",
                )
                .bind(claimed.aggregate_id)
                .bind(&claimed.owner_sub)
                .execute(&mut *tx)
                .await?;
                event
            } else {
                sqlx::query_as::<_, AnalysisEvent>(
                    "SELECT seq,analysis_id,event_type,payload,created_at FROM analysis_events WHERE source_outbox_id=$1",
                )
                .bind(claimed.id)
                .fetch_one(&mut *tx)
                .await?
            }
        };
        sqlx::query(
            "INSERT INTO event_deliveries(outbox_id,sink,delivery_key) VALUES($1,'analysis-events',$2) \
             ON CONFLICT(outbox_id,sink) DO NOTHING",
        )
        .bind(claimed.id)
        .bind(format!("{}:{}", claimed.aggregate_id, event.seq))
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE outbox SET state='delivered',lease_token=NULL,leased_at=NULL,lease_until=NULL,\
             delivered_at=now() WHERE id=$1 AND lease_token=$2",
        )
        .bind(claimed.id)
        .bind(claimed.lease_token)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(event)
    }

    pub async fn fail_outbox(&self, claimed: &ClaimedOutbox, code: &str) -> Result<()> {
        sqlx::query(
            "UPDATE outbox SET state=CASE WHEN attempts>=20 THEN 'dead' ELSE 'pending' END,\
             lease_token=NULL,leased_at=NULL,lease_until=NULL,last_error_code=$3,\
             dead_at=CASE WHEN attempts>=20 THEN now() ELSE NULL END,\
             next_attempt_at=now()+LEAST(interval '10 minutes',interval '5 seconds' * power(2,LEAST(attempts,7))) \
             WHERE id=$1 AND lease_token=$2",
        )
        .bind(claimed.id)
        .bind(claimed.lease_token)
        .bind(code)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn events_after(
        &self,
        owner_sub: &str,
        analysis_id: Uuid,
        after: i64,
        limit: i64,
    ) -> Result<Vec<AnalysisEvent>> {
        Ok(sqlx::query_as::<_, AnalysisEvent>(
            "SELECT seq,analysis_id,event_type,payload,created_at FROM analysis_events \
             WHERE analysis_id=$1 AND owner_sub=$2 AND seq>$3 ORDER BY seq LIMIT $4",
        )
        .bind(analysis_id)
        .bind(owner_sub)
        .bind(after)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn reap_events(&self) -> Result<u64> {
        let mut tx = self.pool.begin().await?;
        let affected: Vec<Uuid> = sqlx::query_scalar(
            "SELECT a.id FROM analyses a WHERE EXISTS (SELECT 1 FROM analysis_events e \
             WHERE e.analysis_id=a.id AND e.expires_at<=now()) FOR UPDATE",
        )
        .fetch_all(&mut *tx)
        .await?;
        let deleted = sqlx::query("DELETE FROM analysis_events WHERE expires_at<=now()")
            .execute(&mut *tx)
            .await?
            .rows_affected();
        for analysis_id in affected {
            sqlx::query(
                "UPDATE analyses SET retained_from_seq=COALESCE(\
                 (SELECT min(seq) FROM analysis_events WHERE analysis_id=$1),next_event_seq) WHERE id=$1",
            )
            .bind(analysis_id)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(deleted)
    }

    pub async fn create_conversation(
        &self,
        owner_sub: &str,
        analysis_id: Uuid,
        title: &str,
        persona_id: &str,
        operation_id: Uuid,
        request_sha256: &str,
    ) -> Result<Conversation> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "SELECT id FROM analyses WHERE id=$1 AND owner_sub=$2 AND deleted_at IS NULL FOR UPDATE",
        )
        .bind(analysis_id)
        .bind(owner_sub)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(AppError::not_found)?;
        claim_idempotency(
            &mut tx,
            owner_sub,
            "POST /api/analyses/:id/conversations",
            operation_id,
            request_sha256,
        )
        .await?;
        let id = Uuid::new_v4();
        let query = format!(
            "INSERT INTO conversations(id,analysis_id,owner_sub,title,persona_id) VALUES($1,$2,$3,$4,$5) \
             RETURNING {CONVERSATION_COLUMNS}"
        );
        let conversation = sqlx::query_as::<_, Conversation>(&query)
            .bind(id)
            .bind(analysis_id)
            .bind(owner_sub)
            .bind(title)
            .bind(persona_id)
            .fetch_one(&mut *tx)
            .await?;
        let location = format!(
            "/analyses/{analysis_id}/conversation?conversation_id={}",
            conversation.id
        );
        sqlx::query(
            "UPDATE idempotency_operations SET state='completed',lease_token=NULL,leased_at=NULL,\
             lease_until=NULL,response_status=201,resource_location=$4,response_body=$5,updated_at=now() \
             WHERE owner_sub=$1 AND scope='POST /api/analyses/:id/conversations' \
             AND operation_id=$2 AND request_sha256=$3",
        )
        .bind(owner_sub)
        .bind(operation_id)
        .bind(request_sha256)
        .bind(location)
        .bind(json!({"conversation": conversation}))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(conversation)
    }

    pub async fn conversations(
        &self,
        owner_sub: &str,
        analysis_id: Uuid,
    ) -> Result<Vec<Conversation>> {
        self.get_analysis(owner_sub, analysis_id).await?;
        let query = format!(
            "SELECT {CONVERSATION_COLUMNS} FROM conversations WHERE analysis_id=$1 AND owner_sub=$2 \
             ORDER BY updated_at DESC,id DESC LIMIT 100"
        );
        Ok(sqlx::query_as::<_, Conversation>(&query)
            .bind(analysis_id)
            .bind(owner_sub)
            .fetch_all(&self.pool)
            .await?)
    }

    pub async fn latest_context_preview(
        &self,
        owner_sub: &str,
        analysis_id: Uuid,
    ) -> Result<Option<serde_json::Value>> {
        self.get_analysis(owner_sub, analysis_id).await?;
        Ok(sqlx::query_scalar(
            "SELECT context_pack FROM turns WHERE analysis_id=$1 AND owner_sub=$2 \
             AND context_pack IS NOT NULL ORDER BY updated_at DESC,id DESC LIMIT 1",
        )
        .bind(analysis_id)
        .bind(owner_sub)
        .fetch_optional(&self.pool)
        .await?
        .flatten())
    }

    pub async fn get_conversation(
        &self,
        owner_sub: &str,
        analysis_id: Uuid,
        conversation_id: Uuid,
    ) -> Result<Conversation> {
        let query = format!(
            "SELECT {CONVERSATION_COLUMNS} FROM conversations WHERE id=$1 AND analysis_id=$2 AND owner_sub=$3"
        );
        sqlx::query_as::<_, Conversation>(&query)
            .bind(conversation_id)
            .bind(analysis_id)
            .bind(owner_sub)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(AppError::not_found)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_persona(
        &self,
        owner_sub: &str,
        analysis_id: Uuid,
        conversation_id: Uuid,
        persona_id: &str,
        custom_persona: Option<&str>,
        operation_id: Uuid,
        request_sha256: &str,
    ) -> Result<Conversation> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "SELECT id FROM conversations WHERE id=$1 AND analysis_id=$2 AND owner_sub=$3 FOR UPDATE",
        )
        .bind(conversation_id)
        .bind(analysis_id)
        .bind(owner_sub)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(AppError::not_found)?;
        claim_idempotency(
            &mut tx,
            owner_sub,
            "POST /api/analyses/:id/conversations/:cid/persona",
            operation_id,
            request_sha256,
        )
        .await?;
        let query = format!(
            "UPDATE conversations SET persona_id=$4,custom_persona=$5,updated_at=now() \
             WHERE id=$1 AND analysis_id=$2 AND owner_sub=$3 RETURNING {CONVERSATION_COLUMNS}"
        );
        let conversation = sqlx::query_as::<_, Conversation>(&query)
            .bind(conversation_id)
            .bind(analysis_id)
            .bind(owner_sub)
            .bind(persona_id)
            .bind(custom_persona)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(AppError::not_found)?;
        sqlx::query(
            "UPDATE idempotency_operations SET state='completed',lease_token=NULL,leased_at=NULL,\
             lease_until=NULL,response_status=200,resource_location=$4,response_body=$5,updated_at=now() \
             WHERE owner_sub=$1 AND scope='POST /api/analyses/:id/conversations/:cid/persona' \
             AND operation_id=$2 AND request_sha256=$3",
        )
        .bind(owner_sub)
        .bind(operation_id)
        .bind(request_sha256)
        .bind(format!("/analyses/{analysis_id}/conversation"))
        .bind(json!({"conversation": conversation}))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(conversation)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_turn(
        &self,
        owner_sub: &str,
        analysis_id: Uuid,
        conversation_id: Uuid,
        operation_id: Uuid,
        client_seq: i64,
        request_sha256: &str,
        model_alias: &str,
        message: &str,
    ) -> Result<Turn> {
        let mut tx = self.pool.begin().await?;
        let conversation = sqlx::query_as::<_, Conversation>(&format!(
            "SELECT {CONVERSATION_COLUMNS} FROM conversations WHERE id=$1 AND analysis_id=$2 AND owner_sub=$3 FOR UPDATE"
        ))
        .bind(conversation_id)
        .bind(analysis_id)
        .bind(owner_sub)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(AppError::not_found)?;
        if let Some(existing) = sqlx::query_as::<_, Turn>(&format!(
            "SELECT {TURN_COLUMNS} FROM turns WHERE conversation_id=$1 AND client_seq=$2"
        ))
        .bind(conversation_id)
        .bind(client_seq)
        .fetch_optional(&mut *tx)
        .await?
        {
            if existing.operation_id == operation_id && existing.request_sha256 == request_sha256 {
                tx.commit().await?;
                return Ok(existing);
            }
            return Err(AppError::conflict(
                "idempotency_mismatch",
                "The client sequence is already bound to different content.",
            ));
        }
        claim_idempotency(
            &mut tx,
            owner_sub,
            "POST /api/analyses/:id/conversations/:cid/turns",
            operation_id,
            request_sha256,
        )
        .await?;
        let turn_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let assistant_id = Uuid::new_v4();
        let user_seq = conversation.next_seq;
        let assistant_seq = user_seq + 1;
        sqlx::query(
            "INSERT INTO turns(id,conversation_id,analysis_id,owner_sub,client_seq,operation_id,request_sha256,model_alias,state) \
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,'accepted')",
        )
        .bind(turn_id)
        .bind(conversation_id)
        .bind(analysis_id)
        .bind(owner_sub)
        .bind(client_seq)
        .bind(operation_id)
        .bind(request_sha256)
        .bind(model_alias)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO messages(id,turn_id,conversation_id,analysis_id,owner_sub,seq,role,client_seq,status,content) \
             VALUES($1,$2,$3,$4,$5,$6,'user',$7,'committed',$8),\
                   ($9,$2,$3,$4,$5,$10,'assistant',NULL,'streaming','')",
        )
        .bind(user_id)
        .bind(turn_id)
        .bind(conversation_id)
        .bind(analysis_id)
        .bind(owner_sub)
        .bind(user_seq)
        .bind(client_seq)
        .bind(message)
        .bind(assistant_id)
        .bind(assistant_seq)
        .execute(&mut *tx)
        .await?;
        sqlx::query("UPDATE conversations SET next_seq=$2,updated_at=now() WHERE id=$1")
            .bind(conversation_id)
            .bind(assistant_seq + 1)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "UPDATE idempotency_operations SET state='completed',lease_token=NULL,leased_at=NULL,\
             lease_until=NULL,response_status=202,resource_location=$4,response_body=$5,updated_at=now() \
             WHERE owner_sub=$1 AND scope='POST /api/analyses/:id/conversations/:cid/turns' \
             AND operation_id=$2 AND request_sha256=$3",
        )
        .bind(owner_sub)
        .bind(operation_id)
        .bind(request_sha256)
        .bind(format!(
            "/api/analyses/{analysis_id}/conversations/{conversation_id}/turns/{turn_id}"
        ))
        .bind(json!({
            "turn_id": turn_id,
            "state": "accepted",
            "model_alias": model_alias
        }))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        self.get_turn(owner_sub, analysis_id, conversation_id, turn_id)
            .await
    }

    pub async fn get_turn(
        &self,
        owner_sub: &str,
        analysis_id: Uuid,
        conversation_id: Uuid,
        turn_id: Uuid,
    ) -> Result<Turn> {
        let query = format!(
            "SELECT {TURN_COLUMNS} FROM turns WHERE id=$1 AND conversation_id=$2 AND analysis_id=$3 AND owner_sub=$4"
        );
        sqlx::query_as::<_, Turn>(&query)
            .bind(turn_id)
            .bind(conversation_id)
            .bind(analysis_id)
            .bind(owner_sub)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(AppError::not_found)
    }

    pub async fn messages(&self, owner_sub: &str, conversation_id: Uuid) -> Result<Vec<Message>> {
        let query = format!(
            "SELECT {MESSAGE_COLUMNS} FROM messages WHERE conversation_id=$1 AND owner_sub=$2 ORDER BY seq DESC LIMIT 64"
        );
        Ok(sqlx::query_as::<_, Message>(&query)
            .bind(conversation_id)
            .bind(owner_sub)
            .fetch_all(&self.pool)
            .await?)
    }

    pub async fn conversation_projection(
        &self,
        owner_sub: &str,
        analysis_id: Uuid,
        conversation_id: Uuid,
    ) -> Result<(Vec<serde_json::Value>, i64)> {
        self.get_conversation(owner_sub, analysis_id, conversation_id)
            .await?;
        let mut messages = sqlx::query_as::<_, Message>(&format!(
            "SELECT {MESSAGE_COLUMNS} FROM (SELECT * FROM messages WHERE conversation_id=$1 \
             AND analysis_id=$2 AND owner_sub=$3 ORDER BY seq DESC LIMIT 64) recent ORDER BY seq"
        ))
        .bind(conversation_id)
        .bind(analysis_id)
        .bind(owner_sub)
        .fetch_all(&self.pool)
        .await?;
        let next_client_seq: i64 = sqlx::query_scalar(
            "SELECT COALESCE(max(client_seq),0)+1 FROM turns WHERE conversation_id=$1 \
             AND analysis_id=$2 AND owner_sub=$3",
        )
        .bind(conversation_id)
        .bind(analysis_id)
        .bind(owner_sub)
        .fetch_one(&self.pool)
        .await?;
        let mut projection = Vec::with_capacity(messages.len());
        for message in &mut messages {
            let rows = sqlx::query(
                "SELECT citation_ref,resolved,artifact_id,excerpt,excerpt_start,excerpt_end,\
                 excerpt_sha256 FROM citations WHERE message_id=$1 AND analysis_id=$2 \
                 AND owner_sub=$3 ORDER BY citation_ref",
            )
            .bind(message.id)
            .bind(analysis_id)
            .bind(owner_sub)
            .fetch_all(&self.pool)
            .await?;
            let citations: Vec<serde_json::Value> = rows
                .iter()
                .map(|row| {
                    json!({
                        "citation_ref": row.get::<String, _>("citation_ref"),
                        "resolved": row.get::<bool, _>("resolved"),
                        "artifact_id": row.get::<Option<Uuid>, _>("artifact_id"),
                        "excerpt": row.get::<Option<String>, _>("excerpt"),
                        "excerpt_start": row.get::<Option<i64>, _>("excerpt_start"),
                        "excerpt_end": row.get::<Option<i64>, _>("excerpt_end"),
                        "excerpt_sha256": row.get::<Option<String>, _>("excerpt_sha256")
                    })
                })
                .collect();
            if message.role == "assistant" {
                let resolved: Vec<String> = citations
                    .iter()
                    .filter(|citation| {
                        citation
                            .get("resolved")
                            .and_then(serde_json::Value::as_bool)
                            .unwrap_or(false)
                    })
                    .filter_map(|citation| {
                        citation
                            .get("citation_ref")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_owned)
                    })
                    .collect();
                message.content =
                    crate::citation::annotate_uncited_markdown(&message.content, &resolved);
            }
            let mut value = serde_json::to_value(&*message)
                .map_err(|_| AppError::Invariant("message projection is not serializable"))?;
            value
                .as_object_mut()
                .ok_or(AppError::Invariant("message projection is not an object"))?
                .insert("citations".to_string(), serde_json::Value::Array(citations));
            projection.push(value);
        }
        Ok((projection, next_client_seq))
    }

    pub async fn claim_turn(&self) -> Result<Option<Turn>> {
        let lease = Uuid::new_v4();
        let query = format!(
            "WITH candidate AS (SELECT id FROM turns WHERE state IN ('accepted','grounding','generating') \
             AND (generation_lease_until IS NULL OR generation_lease_until<now()) ORDER BY created_at,id \
             FOR UPDATE SKIP LOCKED LIMIT 1) UPDATE turns t SET generation_lease_token=$1,\
             generation_leased_at=now(),generation_lease_until=now()+interval '5 minutes',\
             provider_attempt=provider_attempt+1,updated_at=now() \
             FROM candidate c WHERE t.id=c.id RETURNING {TURN_COLUMNS_T}"
        );
        Ok(sqlx::query_as::<_, Turn>(&query)
            .bind(lease)
            .fetch_optional(&self.pool)
            .await?)
    }

    pub async fn assistant_message(&self, turn_id: Uuid) -> Result<Message> {
        sqlx::query_as::<_, Message>(&format!(
            "SELECT {MESSAGE_COLUMNS} FROM messages WHERE turn_id=$1 AND role='assistant'"
        ))
        .bind(turn_id)
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    pub async fn freeze_turn_context(
        &self,
        turn: &Turn,
        context_marker: &str,
        context_sha256: &str,
        context_pack: &serde_json::Value,
        frozen_request: &serde_json::Value,
        prompt_sha256: &str,
    ) -> Result<()> {
        let changed = sqlx::query(
            "UPDATE turns SET state='generating',context_marker=$3,context_sha256=$4,context_pack=$5,\
             frozen_request=$6,frozen_prompt_sha256=$7,provider_started_at=now(),updated_at=now() \
             WHERE id=$1 AND generation_lease_token=$2 AND state IN ('accepted','grounding')",
        )
        .bind(turn.id)
        .bind(turn.generation_lease_token)
        .bind(context_marker)
        .bind(context_sha256)
        .bind(context_pack)
        .bind(frozen_request)
        .bind(prompt_sha256)
        .execute(&self.pool)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(AppError::conflict(
                "state_conflict",
                "The generation lease changed.",
            ));
        }
        Ok(())
    }

    pub async fn append_assistant(&self, turn: &Turn, chunk: &str, token_count: i32) -> Result<()> {
        let changed = sqlx::query(
            "UPDATE messages SET content=content||$3,token_count=$4,updated_at=now() \
             WHERE turn_id=$1 AND role='assistant' AND EXISTS(SELECT 1 FROM turns t \
             WHERE t.id=$1 AND t.generation_lease_token=$2 AND t.state='generating')",
        )
        .bind(turn.id)
        .bind(turn.generation_lease_token)
        .bind(chunk)
        .bind(token_count)
        .execute(&self.pool)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(AppError::conflict(
                "state_conflict",
                "The generation lease changed.",
            ));
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn finish_turn(
        &self,
        turn: &Turn,
        state: &str,
        message_status: &str,
        error_code: Option<&str>,
        prompt_tokens: i32,
        completion_tokens: i32,
        model: &str,
    ) -> Result<()> {
        if model != turn.model_alias {
            return Err(AppError::Invariant(
                "turn model does not match the persisted model",
            ));
        }
        let mut tx = self.pool.begin().await?;
        let changed = sqlx::query(
            "UPDATE turns SET state=$3,error_code=$4,terminal_at=now(),generation_lease_token=NULL,\
             generation_leased_at=NULL,generation_lease_until=NULL,updated_at=now() \
             WHERE id=$1 AND generation_lease_token=$2 AND state IN ('accepted','grounding','generating')",
        )
        .bind(turn.id)
        .bind(turn.generation_lease_token)
        .bind(state)
        .bind(error_code)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(AppError::conflict(
                "state_conflict",
                "The generation lease changed.",
            ));
        }
        sqlx::query(
            "UPDATE messages SET status=$2,updated_at=now() WHERE turn_id=$1 AND role='assistant'",
        )
        .bind(turn.id)
        .bind(message_status)
        .execute(&mut *tx)
        .await?;
        if matches!(state, "completed" | "partial") {
            sqlx::query(
                "INSERT INTO ai_usage(owner_sub,analysis_id,turn_id,prompt_tokens,completion_tokens,model_alias) \
                 VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(turn_id) DO NOTHING",
            )
            .bind(&turn.owner_sub)
            .bind(turn.analysis_id)
            .bind(turn.id)
            .bind(prompt_tokens)
            .bind(completion_tokens)
            .bind(model)
            .execute(&mut *tx)
            .await?;
        }
        insert_outbox(
            &mut tx,
            turn.analysis_id,
            &turn.owner_sub,
            "conversation.turn",
            json!({"analysis_id":turn.analysis_id,"conversation_id":turn.conversation_id,"turn_id":turn.id,"state":state}),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn release_turn_for_retry(&self, turn: &Turn, error_code: &str) -> Result<()> {
        let changed = sqlx::query(
            "UPDATE turns SET state=CASE WHEN state='generating' THEN 'generating' ELSE 'accepted' END,\
             error_code=$3,generation_lease_token=NULL,\
             generation_leased_at=NULL,generation_lease_until=NULL,updated_at=now() \
             WHERE id=$1 AND generation_lease_token=$2 AND state IN ('accepted','grounding','generating')",
        )
        .bind(turn.id)
        .bind(turn.generation_lease_token)
        .bind(error_code)
        .execute(&self.pool)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(AppError::conflict(
                "state_conflict",
                "The generation lease changed.",
            ));
        }
        Ok(())
    }

    pub async fn artifact_for_ref(
        &self,
        owner_sub: &str,
        analysis_id: Uuid,
        artifact_ref: &str,
    ) -> Result<Option<Artifact>> {
        let query = format!(
            "SELECT {ARTIFACT_COLUMNS} FROM artifacts WHERE analysis_id=$1 AND owner_sub=$2 AND artifact_ref=$3"
        );
        Ok(sqlx::query_as::<_, Artifact>(&query)
            .bind(analysis_id)
            .bind(owner_sub)
            .bind(artifact_ref)
            .fetch_optional(&self.pool)
            .await?)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_context_artifact(
        &self,
        owner_sub: &str,
        analysis_id: Uuid,
        upstream_artifact_id: &str,
        artifact_type: &str,
        artifact_ref: &str,
        path: &str,
        sha256: &str,
        mime: Option<&str>,
        source: &str,
    ) -> Result<Artifact> {
        let query = format!(
            "INSERT INTO artifacts(id,analysis_id,owner_sub,upstream_artifact_id,artifact_type,\
             artifact_ref,path,sha256,mime,metadata) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) \
             ON CONFLICT(analysis_id,upstream_artifact_id) DO UPDATE SET artifact_type=EXCLUDED.artifact_type,\
             artifact_ref=EXCLUDED.artifact_ref,mime=EXCLUDED.mime,metadata=EXCLUDED.metadata \
             WHERE artifacts.path=EXCLUDED.path AND artifacts.sha256=EXCLUDED.sha256 \
             RETURNING {ARTIFACT_COLUMNS}"
        );
        sqlx::query_as::<_, Artifact>(&query)
            .bind(Uuid::new_v4())
            .bind(analysis_id)
            .bind(owner_sub)
            .bind(upstream_artifact_id)
            .bind(artifact_type)
            .bind(artifact_ref)
            .bind(path)
            .bind(sha256)
            .bind(mime)
            .bind(json!({"source":source}))
            .fetch_optional(&self.pool)
            .await?
            .ok_or(AppError::Invariant(
                "context artifact changed immutable path or digest",
            ))
    }

    pub async fn save_citation(
        &self,
        message_id: Uuid,
        analysis_id: Uuid,
        owner_sub: &str,
        citation_ref: &str,
        artifact: Option<&Artifact>,
        excerpt: Option<(&str, i64, i64, &str)>,
    ) -> Result<()> {
        let (artifact_id, excerpt_text, start, end, sha) = match (artifact, excerpt) {
            (Some(artifact), Some((text, start, end, sha))) => (
                Some(artifact.id),
                Some(text),
                Some(start),
                Some(end),
                Some(sha),
            ),
            _ => (None, None, None, None, None),
        };
        sqlx::query(
            "INSERT INTO citations(id,message_id,artifact_id,analysis_id,owner_sub,citation_ref,resolved,\
             excerpt,excerpt_start,excerpt_end,excerpt_sha256) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) \
             ON CONFLICT(message_id,citation_ref) DO UPDATE SET artifact_id=EXCLUDED.artifact_id,\
             resolved=EXCLUDED.resolved,excerpt=EXCLUDED.excerpt,excerpt_start=EXCLUDED.excerpt_start,\
             excerpt_end=EXCLUDED.excerpt_end,excerpt_sha256=EXCLUDED.excerpt_sha256,created_at=now()",
        )
        .bind(Uuid::new_v4())
        .bind(message_id)
        .bind(artifact_id)
        .bind(analysis_id)
        .bind(owner_sub)
        .bind(citation_ref)
        .bind(artifact_id.is_some())
        .bind(excerpt_text)
        .bind(start)
        .bind(end)
        .bind(sha)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn unresolved_citation_work(&self) -> Result<Option<(Turn, Message)>> {
        let message_id: Option<Uuid> = sqlx::query_scalar(
            "SELECT m.id FROM messages m JOIN turns t ON t.id=m.turn_id \
             WHERE m.role='assistant' AND m.content LIKE '%[ref:%' \
             AND t.state IN ('completed','partial') AND (\
               (NOT EXISTS(SELECT 1 FROM citations c WHERE c.message_id=m.id) \
                AND m.updated_at<=now()-interval '30 seconds') OR \
               EXISTS(SELECT 1 FROM citations c WHERE c.message_id=m.id AND c.resolved=false \
                      AND c.created_at<=now()-interval '30 seconds')) \
             ORDER BY m.updated_at,m.id LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await?;
        let Some(message_id) = message_id else {
            return Ok(None);
        };
        let message = sqlx::query_as::<_, Message>(&format!(
            "SELECT {MESSAGE_COLUMNS} FROM messages WHERE id=$1 AND role='assistant'"
        ))
        .bind(message_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(AppError::Invariant(
            "unresolved citation message is missing",
        ))?;
        let turn = sqlx::query_as::<_, Turn>(&format!(
            "SELECT {TURN_COLUMNS} FROM turns WHERE id=$1 AND state IN ('completed','partial')"
        ))
        .bind(message.turn_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(AppError::Invariant(
            "unresolved citation turn is not terminal",
        ))?;
        Ok(Some((turn, message)))
    }

    pub async fn citation_refs(
        &self,
        owner_sub: &str,
        analysis_id: Uuid,
        message_id: Uuid,
    ) -> Result<Vec<(String, bool)>> {
        Ok(sqlx::query_as::<_, (String, bool)>(
            "SELECT citation_ref,resolved FROM citations WHERE message_id=$1 AND analysis_id=$2 \
             AND owner_sub=$3 ORDER BY citation_ref",
        )
        .bind(message_id)
        .bind(analysis_id)
        .bind(owner_sub)
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn delete_conversation(
        &self,
        owner_sub: &str,
        analysis_id: Uuid,
        conversation_id: Uuid,
        operation_id: Uuid,
        request_sha256: &str,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "SELECT id FROM conversations WHERE id=$1 AND analysis_id=$2 AND owner_sub=$3 FOR UPDATE",
        )
        .bind(conversation_id)
        .bind(analysis_id)
        .bind(owner_sub)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(AppError::not_found)?;
        claim_idempotency(
            &mut tx,
            owner_sub,
            "POST /api/analyses/:id/conversations/:cid/delete",
            operation_id,
            request_sha256,
        )
        .await?;
        let changed = sqlx::query(
            "DELETE FROM conversations WHERE id=$1 AND analysis_id=$2 AND owner_sub=$3",
        )
        .bind(conversation_id)
        .bind(analysis_id)
        .bind(owner_sub)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if changed == 0 {
            return Err(AppError::not_found());
        }
        sqlx::query(
            "UPDATE idempotency_operations SET state='completed',lease_token=NULL,leased_at=NULL,\
             lease_until=NULL,response_status=202,resource_location=$4,response_body=$5,updated_at=now() \
             WHERE owner_sub=$1 AND scope='POST /api/analyses/:id/conversations/:cid/delete' \
             AND operation_id=$2 AND request_sha256=$3",
        )
        .bind(owner_sub)
        .bind(operation_id)
        .bind(request_sha256)
        .bind(format!("/analyses/{analysis_id}/conversation"))
        .bind(json!({"conversation_id": conversation_id, "state": "deleted"}))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn recovery_chunks(&self) -> Result<Vec<RecoveryChunk>> {
        Ok(sqlx::query_as::<_, RecoveryChunk>(
            "SELECT c.upload_id,c.chunk_index,c.byte_size,c.sha256,c.storage_key \
             FROM upload_chunks c JOIN upload_sessions u ON u.id=c.upload_id \
             WHERE u.state NOT IN ('cancelled','expired') ORDER BY c.upload_id,c.chunk_index",
        )
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn invalidate_chunk(&self, upload_id: Uuid, chunk_index: i32) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT id FROM upload_sessions WHERE id=$1 FOR UPDATE")
            .bind(upload_id)
            .fetch_optional(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM upload_chunks WHERE upload_id=$1 AND chunk_index=$2")
            .bind(upload_id)
            .bind(chunk_index)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "UPDATE upload_sessions SET received_bytes=COALESCE(\
             (SELECT sum(byte_size) FROM upload_chunks WHERE upload_id=$1),0),\
             lease_token=NULL,leased_at=NULL,lease_until=NULL,updated_at=now() WHERE id=$1",
        )
        .bind(upload_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn uncertain_uploads(&self, limit: i64) -> Result<Vec<UploadSession>> {
        let query = format!(
            "SELECT {UPLOAD_COLUMNS} FROM upload_sessions WHERE state='upstream_uncertain' \
             AND (lease_until IS NULL OR lease_until<now()) ORDER BY updated_at,id LIMIT $1"
        );
        Ok(sqlx::query_as::<_, UploadSession>(&query)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?)
    }

    pub async fn expired_uploads(&self, limit: i64) -> Result<Vec<(Uuid, String)>> {
        Ok(sqlx::query_as::<_, (Uuid, String)>(
            "SELECT id,owner_sub FROM upload_sessions WHERE expires_at<=now() AND state IN \
             ('reserved','uploading','assembling') AND lease_token IS NULL \
             ORDER BY expires_at,id LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn begin_worker_operation(
        &self,
        analysis: &Analysis,
        kind: &str,
        operation_id: Uuid,
        request_sha256: &str,
    ) -> Result<()> {
        let scope = format!("worker:{kind}:{}", analysis.id);
        let mut tx = self.pool.begin().await?;
        claim_idempotency(
            &mut tx,
            &analysis.owner_sub,
            &scope,
            operation_id,
            request_sha256,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn has_unresolved_worker_operation(
        &self,
        analysis: &Analysis,
        kind: &str,
    ) -> Result<bool> {
        let scope = format!("worker:{kind}:{}", analysis.id);
        Ok(sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM idempotency_operations WHERE owner_sub=$1 AND scope=$2 \
             AND state IN ('leased','downstream_uncertain'))",
        )
        .bind(&analysis.owner_sub)
        .bind(scope)
        .fetch_one(&self.pool)
        .await?)
    }

    pub async fn recover_analysis_work(&self) -> Result<u64> {
        let mut tx = self.pool.begin().await?;
        let recovered_operations = sqlx::query(
            "UPDATE idempotency_operations SET state='downstream_uncertain',lease_token=NULL,\
             leased_at=NULL,lease_until=NULL,updated_at=now() WHERE scope LIKE 'worker:%' \
             AND state='leased' AND lease_until<now()",
        )
        .execute(&mut *tx)
        .await?
        .rows_affected();
        let recovered_starts = sqlx::query(
            "UPDATE analyses a SET state=CASE WHEN EXISTS(SELECT 1 FROM idempotency_operations i \
             WHERE i.owner_sub=a.owner_sub AND i.scope='worker:start:'||a.id::text \
             AND i.state='downstream_uncertain') THEN 'start_uncertain' ELSE 'uploaded' END,\
             poll_lease_token=NULL,poll_lease_until=NULL,updated_at=now() WHERE a.state='starting' \
             AND (a.poll_lease_until IS NULL OR a.poll_lease_until<now())",
        )
        .execute(&mut *tx)
        .await?
        .rows_affected();
        tx.commit().await?;
        Ok(recovered_operations + recovered_starts)
    }

    pub async fn finish_worker_operation(
        &self,
        analysis: &Analysis,
        kind: &str,
        operation_id: Uuid,
        uncertain: bool,
        response_body: Option<&serde_json::Value>,
    ) -> Result<()> {
        let scope = format!("worker:{kind}:{}", analysis.id);
        let state = if uncertain {
            "downstream_uncertain"
        } else {
            "completed"
        };
        let status = if uncertain { None } else { Some(200) };
        sqlx::query(
            "UPDATE idempotency_operations SET state=$5,lease_token=NULL,leased_at=NULL,lease_until=NULL,\
             response_status=$6,response_body=$7,resource_location=$4,updated_at=now() \
             WHERE owner_sub=$1 AND scope=$2 AND operation_id=$3",
        )
        .bind(&analysis.owner_sub)
        .bind(scope)
        .bind(operation_id)
        .bind(format!("/analyses/{}", analysis.id))
        .bind(state)
        .bind(status)
        .bind(response_body)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn fail_worker_operation(
        &self,
        analysis: &Analysis,
        kind: &str,
        operation_id: Uuid,
        error_code: &str,
    ) -> Result<()> {
        let scope = format!("worker:{kind}:{}", analysis.id);
        sqlx::query(
            "UPDATE idempotency_operations SET state='failed',lease_token=NULL,leased_at=NULL,\
             lease_until=NULL,response_status=NULL,response_body=jsonb_build_object('error_code',$4::text),\
             updated_at=now() WHERE owner_sub=$1 AND scope=$2 AND operation_id=$3 \
             AND state IN ('leased','downstream_uncertain')",
        )
        .bind(&analysis.owner_sub)
        .bind(scope)
        .bind(operation_id)
        .bind(error_code)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn request_analysis_delete(
        &self,
        owner_sub: &str,
        analysis_id: Uuid,
        operation_id: Uuid,
        request_sha256: &str,
    ) -> Result<DeletePlan> {
        let mut tx = self.pool.begin().await?;
        let analysis = sqlx::query_as::<_, Analysis>(&format!(
            "SELECT {ANALYSIS_COLUMNS} FROM analyses WHERE id=$1 AND owner_sub=$2 \
             AND deleted_at IS NULL FOR UPDATE"
        ))
        .bind(analysis_id)
        .bind(owner_sub)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(AppError::not_found)?;
        let upload = sqlx::query(&format!(
            "SELECT {UPLOAD_COLUMNS} FROM upload_sessions WHERE id=$1 AND owner_sub=$2 FOR UPDATE"
        ))
        .bind(analysis.upload_id)
        .bind(owner_sub)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(AppError::Invariant("analysis upload is missing"))?;
        let upload_id: Uuid = upload.get("id");
        let upload_state: String = upload.get("state");
        let total_bytes: i64 = upload.get("total_bytes");
        let staging_key: String = upload.get("staging_key");
        let sample_id: Option<String> = upload.get("sample_id");
        let assembled_sha256: Option<String> = upload.get("assembled_sha256");

        claim_idempotency(
            &mut tx,
            owner_sub,
            "POST /api/analyses/:id/delete",
            operation_id,
            request_sha256,
        )
        .await?;

        let chunks = sqlx::query(
            "SELECT chunk_index,byte_size,sha256,storage_key FROM upload_chunks \
             WHERE upload_id=$1 ORDER BY chunk_index",
        )
        .bind(upload_id)
        .fetch_all(&mut *tx)
        .await?;
        let chunk_manifest: Vec<serde_json::Value> = chunks
            .iter()
            .map(|row| {
                json!({
                    "type": "chunk",
                    "index": row.get::<i32, _>("chunk_index"),
                    "storage_key": row.get::<String, _>("storage_key"),
                    "byte_size": row.get::<i32, _>("byte_size"),
                    "sha256": row.get::<String, _>("sha256")
                })
            })
            .collect();
        let manifest = json!({
            "schema_version": 1,
            "staging_key": staging_key,
            "assembled": assembled_sha256.as_ref().map(|sha| json!({
                "type": "assembled",
                "storage_key": format!("{}/assembled.bin", staging_key),
                "byte_size": total_bytes,
                "sha256": sha
            })),
            "chunks": chunk_manifest,
            "sample_sha256": sample_id.as_deref().and_then(|value| value.strip_prefix("sha256:"))
        });
        let manifest_sha256 = stable_json_sha256(&manifest)?;
        let cleanup_job_id = Uuid::new_v4();

        let quota_changed = if upload_state == "finalized" {
            sqlx::query(
                "UPDATE owner_quotas SET used_bytes=used_bytes-$2,analysis_count=analysis_count-1,\
                 updated_at=now() WHERE owner_sub=$1 AND used_bytes >= $2 AND analysis_count > 0",
            )
            .bind(owner_sub)
            .bind(total_bytes)
            .execute(&mut *tx)
            .await?
            .rows_affected()
        } else if matches!(
            upload_state.as_str(),
            "reserved"
                | "uploading"
                | "assembling"
                | "forwarding"
                | "upstream_uncertain"
                | "cancel_pending"
        ) {
            sqlx::query(
                "UPDATE owner_quotas SET reserved_bytes=reserved_bytes-$2,analysis_count=analysis_count-1,\
                 updated_at=now() WHERE owner_sub=$1 AND reserved_bytes >= $2 AND analysis_count > 0",
            )
            .bind(owner_sub)
            .bind(total_bytes)
            .execute(&mut *tx)
            .await?
            .rows_affected()
        } else {
            sqlx::query(
                "UPDATE owner_quotas SET analysis_count=analysis_count-1,updated_at=now() \
                 WHERE owner_sub=$1 AND analysis_count > 0",
            )
            .bind(owner_sub)
            .execute(&mut *tx)
            .await?
            .rows_affected()
        };
        if quota_changed != 1 {
            return Err(AppError::Invariant("owner quota would underflow on delete"));
        }

        if let Some(sample_id) = sample_id.as_deref() {
            let sample = sqlx::query(
                "SELECT ref_count,lifecycle FROM sample_objects WHERE sample_id=$1 FOR UPDATE",
            )
            .bind(sample_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(AppError::Invariant("finalized sample object is missing"))?;
            let ref_count: i32 = sample.get("ref_count");
            if ref_count <= 0 {
                return Err(AppError::Invariant(
                    "sample reference count would underflow",
                ));
            }
            if ref_count == 1 {
                sqlx::query(
                    "UPDATE sample_objects SET ref_count=0,lifecycle='delete_pending',delete_after=now(),\
                     delete_operation_id=$2,updated_at=now() WHERE sample_id=$1",
                )
                .bind(sample_id)
                .bind(Uuid::new_v4())
                .execute(&mut *tx)
                .await?;
            } else {
                sqlx::query(
                    "UPDATE sample_objects SET ref_count=ref_count-1,updated_at=now() WHERE sample_id=$1",
                )
                .bind(sample_id)
                .execute(&mut *tx)
                .await?;
            }
        }

        sqlx::query("DELETE FROM conversations WHERE analysis_id=$1 AND owner_sub=$2")
            .bind(analysis_id)
            .bind(owner_sub)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM artifacts WHERE analysis_id=$1 AND owner_sub=$2")
            .bind(analysis_id)
            .bind(owner_sub)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "DELETE FROM event_deliveries WHERE outbox_id IN \
             (SELECT id FROM outbox WHERE aggregate_id=$1 AND owner_sub=$2)",
        )
        .bind(analysis_id)
        .bind(owner_sub)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM analysis_events WHERE analysis_id=$1 AND owner_sub=$2")
            .bind(analysis_id)
            .bind(owner_sub)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "UPDATE outbox SET payload=jsonb_build_object('analysis_id',$1::text,'state','deleted') \
             WHERE aggregate_id=$1 AND owner_sub=$2 AND state IN ('pending','leased')",
        )
        .bind(analysis_id)
        .bind(owner_sub)
        .execute(&mut *tx)
        .await?;
        let analysis_marker = format!("%{}%", analysis_id);
        let upload_marker = format!("%{}%", upload_id);
        sqlx::query(
            "UPDATE idempotency_operations SET response_body=NULL,resource_location=NULL,updated_at=now() \
             WHERE owner_sub=$1 AND operation_id<>$2 AND \
             (COALESCE(resource_location,'') LIKE $3 OR COALESCE(resource_location,'') LIKE $4 \
              OR COALESCE(response_body::text,'') LIKE $3 OR COALESCE(response_body::text,'') LIKE $4)",
        )
        .bind(owner_sub)
        .bind(operation_id)
        .bind(analysis_marker)
        .bind(upload_marker)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE upload_sessions SET state='cancelled',sample_id=NULL,filename='deleted',\
             frozen_body=NULL,frozen_location=NULL,lease_token=NULL,leased_at=NULL,lease_until=NULL,\
             error_code=NULL,updated_at=now() WHERE id=$1 AND owner_sub=$2",
        )
        .bind(upload_id)
        .bind(owner_sub)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE analyses SET sample_id=NULL,state='delete_pending',display_name='deleted',plan_id=NULL,\
             case_id=NULL,case_artifact_id=NULL,current_stage=NULL,latest_stage=NULL,deleted_at=now(),\
             updated_at=now() WHERE id=$1 AND owner_sub=$2",
        )
        .bind(analysis_id)
        .bind(owner_sub)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO cleanup_jobs(id,owner_sub,analysis_id,upload_id,manifest,manifest_sha256,\
             state,expires_at) VALUES($1,$2,$3,$4,$5,$6,'pending',now()+interval '100 years')",
        )
        .bind(cleanup_job_id)
        .bind(owner_sub)
        .bind(analysis_id)
        .bind(upload_id)
        .bind(&manifest)
        .bind(&manifest_sha256)
        .execute(&mut *tx)
        .await?;
        insert_outbox(
            &mut tx,
            analysis_id,
            owner_sub,
            "analysis.deleted",
            json!({"analysis_id": analysis_id, "state": "deleted"}),
        )
        .await?;
        let response = json!({"analysis_id": analysis_id, "state": "delete_pending"});
        sqlx::query(
            "UPDATE idempotency_operations SET state='completed',lease_token=NULL,leased_at=NULL,\
             lease_until=NULL,response_status=202,resource_location=$4,response_body=$5,updated_at=now() \
             WHERE owner_sub=$1 AND scope='POST /api/analyses/:id/delete' AND operation_id=$2 \
             AND request_sha256=$3",
        )
        .bind(owner_sub)
        .bind(operation_id)
        .bind(request_sha256)
        .bind(format!("/analyses/{analysis_id}"))
        .bind(response)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(DeletePlan {
            analysis_id,
            cleanup_job_id,
        })
    }

    pub async fn expired_analyses(&self, limit: i64) -> Result<Vec<(Uuid, String)>> {
        Ok(sqlx::query_as::<_, (Uuid, String)>(
            "SELECT id,owner_sub FROM analyses WHERE retention_until<=now() AND deleted_at IS NULL \
             ORDER BY retention_until,id LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn claim_cleanup(&self) -> Result<Option<CleanupJob>> {
        let lease_token = Uuid::new_v4();
        let mut tx = self.pool.begin().await?;
        let job = sqlx::query_as::<_, CleanupJob>(
            "WITH candidate AS (SELECT id FROM cleanup_jobs WHERE \
             (state='pending' OR (state='leased' AND lease_until<now())) \
             ORDER BY created_at,id FOR UPDATE SKIP LOCKED LIMIT 1) \
             UPDATE cleanup_jobs j SET state='leased',lease_token=$1,leased_at=now(),\
             lease_until=now()+interval '10 minutes',attempts=attempts+1,updated_at=now() \
             FROM candidate c WHERE j.id=c.id RETURNING j.id,j.owner_sub,j.analysis_id,j.upload_id,\
             j.manifest,j.manifest_sha256,j.lease_token,j.attempts",
        )
        .bind(lease_token)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(job) = &job {
            sqlx::query(
                "UPDATE analyses SET state='deleting',updated_at=now() \
                 WHERE id=$1 AND owner_sub=$2 AND state='delete_pending'",
            )
            .bind(job.analysis_id)
            .bind(&job.owner_sub)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(job)
    }

    pub async fn complete_cleanup(&self, job: &CleanupJob) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let owned = sqlx::query_scalar::<_, Uuid>(
            "SELECT lease_token FROM cleanup_jobs WHERE id=$1 AND state='leased' FOR UPDATE",
        )
        .bind(job.id)
        .fetch_optional(&mut *tx)
        .await?;
        if owned != Some(job.lease_token) {
            return Err(AppError::conflict(
                "state_conflict",
                "The cleanup lease changed.",
            ));
        }
        sqlx::query("DELETE FROM upload_chunks WHERE upload_id=$1")
            .bind(job.upload_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "UPDATE upload_sessions SET staging_key=$3,state='cancelled',sample_id=NULL,filename='deleted',\
             assembled_sha256=NULL,updated_at=now() WHERE id=$1 AND owner_sub=$2",
        )
        .bind(job.upload_id)
        .bind(&job.owner_sub)
        .bind(Uuid::new_v4().to_string())
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE analyses SET state='deleted',updated_at=now() WHERE id=$1 AND owner_sub=$2 \
             AND deleted_at IS NOT NULL",
        )
        .bind(job.analysis_id)
        .bind(&job.owner_sub)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE cleanup_jobs SET state='completed',lease_token=NULL,leased_at=NULL,lease_until=NULL,\
             completed_at=now(),expires_at=now()+interval '24 hours',updated_at=now() \
             WHERE id=$1 AND lease_token=$2",
        )
        .bind(job.id)
        .bind(job.lease_token)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn fail_cleanup(
        &self,
        job: &CleanupJob,
        error_code: &str,
        force_dead: bool,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE cleanup_jobs SET state=CASE WHEN $4 OR attempts>=20 THEN 'dead' ELSE 'pending' END,\
             lease_token=NULL,leased_at=NULL,lease_until=NULL,last_error_code=$3,updated_at=now() \
             WHERE id=$1 AND lease_token=$2",
        )
        .bind(job.id)
        .bind(job.lease_token)
        .bind(error_code)
        .bind(force_dead)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn claim_sample_delete(&self) -> Result<Option<SampleDeleteClaim>> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query_as::<_, SampleDeleteClaim>(
            "SELECT sample_id,sha256,delete_operation_id FROM sample_objects \
             WHERE ref_count=0 AND lifecycle IN ('delete_pending','delete_failed','deleting') \
             AND delete_after<=now() ORDER BY delete_after,sample_id FOR UPDATE SKIP LOCKED LIMIT 1",
        )
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(row) = &row {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
                .bind(&row.sample_id)
                .execute(&mut *tx)
                .await?;
            let still_eligible: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM sample_objects s WHERE s.sample_id=$1 \
                 AND s.delete_operation_id=$2 AND s.ref_count=0 \
                 AND s.lifecycle IN ('delete_pending','delete_failed','deleting') \
                 AND s.delete_after<=now() AND NOT EXISTS(SELECT 1 FROM upload_sessions u \
                 WHERE u.assembled_sha256=s.sha256 AND u.state IN \
                 ('assembling','forwarding','upstream_uncertain')))",
            )
            .bind(&row.sample_id)
            .bind(row.delete_operation_id)
            .fetch_one(&mut *tx)
            .await?;
            if !still_eligible {
                tx.commit().await?;
                return Ok(None);
            }
            sqlx::query(
                "UPDATE sample_objects SET lifecycle='deleting',delete_after=now()+interval '10 minutes',\
                 updated_at=now() WHERE sample_id=$1 \
                 AND delete_operation_id=$2 AND ref_count=0",
            )
            .bind(&row.sample_id)
            .bind(row.delete_operation_id)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(row)
    }

    pub async fn recover_sample_delete_leases(&self) -> Result<u64> {
        Ok(sqlx::query(
            "UPDATE sample_objects SET lifecycle='delete_failed',delete_after=now(),updated_at=now() \
             WHERE lifecycle='deleting' AND ref_count=0 \
             AND (delete_after IS NULL OR delete_after<now())",
        )
        .execute(&self.pool)
        .await?
        .rows_affected())
    }

    pub async fn finish_sample_delete(
        &self,
        claim: &SampleDeleteClaim,
        succeeded: bool,
        error_code: Option<&str>,
    ) -> Result<()> {
        let changed = if succeeded {
            sqlx::query(
                "UPDATE sample_objects SET lifecycle='deleted',delete_operation_id=NULL,delete_after=NULL,\
                 updated_at=now() WHERE sample_id=$1 AND ref_count=0 AND lifecycle='deleting' \
                 AND delete_operation_id=$2",
            )
            .bind(&claim.sample_id)
            .bind(claim.delete_operation_id)
            .execute(&self.pool)
            .await?
            .rows_affected()
        } else {
            sqlx::query(
                "UPDATE sample_objects SET lifecycle='delete_failed',\
                 delete_after=CASE WHEN $3='server_invariant_violation' THEN 'infinity'::timestamptz \
                 ELSE now()+interval '10 minutes' END,updated_at=now() \
                 WHERE sample_id=$1 AND ref_count=0 AND lifecycle='deleting' AND delete_operation_id=$2",
            )
            .bind(&claim.sample_id)
            .bind(claim.delete_operation_id)
            .bind(error_code)
            .execute(&self.pool)
            .await?
            .rows_affected()
        };
        if changed != 1 {
            return Err(AppError::conflict(
                "state_conflict",
                "The sample deletion claim changed.",
            ));
        }
        Ok(())
    }

    pub async fn run_bounded_reapers(&self) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM idempotency_operations WHERE expires_at<=now()")
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "DELETE FROM outbox WHERE state IN ('delivered','dead') AND \
             COALESCE(delivered_at,dead_at,created_at)<=now()-interval '7 days'",
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM notification_claims WHERE claimed_at<=now()-interval '32 days'")
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "DELETE FROM sample_objects WHERE lifecycle='deleted' AND updated_at<=now()-interval '30 days'",
        )
        .execute(&mut *tx)
        .await?;

        let purge = sqlx::query(
            "SELECT id,analysis_id,upload_id FROM cleanup_jobs j WHERE state='completed' \
             AND expires_at<=now() AND NOT EXISTS (SELECT 1 FROM sample_objects s \
             WHERE s.sha256=j.manifest->>'sample_sha256' AND s.lifecycle<>'deleted') \
             FOR UPDATE",
        )
        .fetch_all(&mut *tx)
        .await?;
        for row in purge {
            let cleanup_id: Uuid = row.get("id");
            let analysis_id: Uuid = row.get("analysis_id");
            let upload_id: Uuid = row.get("upload_id");
            sqlx::query("DELETE FROM outbox WHERE aggregate_id=$1")
                .bind(analysis_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM cleanup_jobs WHERE id=$1")
                .bind(cleanup_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM analyses WHERE id=$1 AND state='deleted'")
                .bind(analysis_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM upload_sessions WHERE id=$1 AND state='cancelled'")
                .bind(upload_id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }
}

async fn insert_outbox(
    tx: &mut Transaction<'_, Postgres>,
    analysis_id: Uuid,
    owner_sub: &str,
    event_type: &str,
    payload: serde_json::Value,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO outbox(id,aggregate_type,aggregate_id,owner_sub,event_type,payload,state) \
         VALUES($1,'analysis',$2,$3,$4,$5,'pending')",
    )
    .bind(Uuid::new_v4())
    .bind(analysis_id)
    .bind(owner_sub)
    .bind(event_type)
    .bind(payload)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn terminal_uncertain_upload(
    tx: &mut Transaction<'_, Postgres>,
    upload: &UploadSession,
    error_code: &'static str,
    quota_column: &'static str,
) -> Result<()> {
    let quota_sql = match quota_column {
        "reserved_bytes" => {
            "UPDATE owner_quotas SET reserved_bytes=reserved_bytes-$2,updated_at=now() \
             WHERE owner_sub=$1 AND reserved_bytes >= $2"
        }
        "used_bytes" => {
            "UPDATE owner_quotas SET used_bytes=used_bytes-$2,updated_at=now() \
             WHERE owner_sub=$1 AND used_bytes >= $2"
        }
        _ => return Err(AppError::Invariant("invalid upload disposition quota kind")),
    };
    let quota = sqlx::query(quota_sql)
        .bind(&upload.owner_sub)
        .bind(upload.total_bytes)
        .execute(&mut **tx)
        .await?
        .rows_affected();
    if quota != 1 {
        return Err(AppError::Invariant(
            "owner quota would underflow for upload disposition",
        ));
    }
    sqlx::query(
        "UPDATE upload_sessions SET state='failed',sample_id=NULL,error_code=$2,\
         lease_token=NULL,leased_at=NULL,lease_until=NULL,frozen_status=NULL,\
         frozen_location=NULL,frozen_body=NULL,updated_at=now() WHERE id=$1 AND owner_sub=$3",
    )
    .bind(upload.id)
    .bind(error_code)
    .bind(&upload.owner_sub)
    .execute(&mut **tx)
    .await?;
    let analysis_changed = sqlx::query(
        "UPDATE analyses SET state='failed',sample_id=NULL,updated_at=now() \
         WHERE id=$1 AND owner_sub=$2 AND state<>'failed'",
    )
    .bind(upload.analysis_id)
    .bind(&upload.owner_sub)
    .execute(&mut **tx)
    .await?
    .rows_affected();
    if analysis_changed == 1 {
        insert_outbox(
            tx,
            upload.analysis_id,
            &upload.owner_sub,
            "analysis.failed",
            json!({"analysis_id":upload.analysis_id,"state":"failed","error_code":error_code}),
        )
        .await?;
    }
    Ok(())
}

pub fn server_operation_id(purpose: &str, key: &str) -> Uuid {
    let digest = Sha256::digest([purpose.as_bytes(), b":", key.as_bytes()].concat());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    // RFC 9562 UUIDv8: application-defined payload with standard variant bits.
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

async fn claim_idempotency(
    tx: &mut Transaction<'_, Postgres>,
    owner_sub: &str,
    scope: &str,
    operation_id: Uuid,
    request_sha256: &str,
) -> Result<()> {
    let lease_token = Uuid::new_v4();
    let inserted = sqlx::query(
        "INSERT INTO idempotency_operations(owner_sub,scope,operation_id,request_sha256,state,\
         lease_token,leased_at,lease_until,expires_at) \
         VALUES($1,$2,$3,$4,'leased',$5,now(),now()+interval '5 minutes',now()+interval '24 hours') \
         ON CONFLICT(owner_sub,scope,operation_id) DO NOTHING",
    )
    .bind(owner_sub)
    .bind(scope)
    .bind(operation_id)
    .bind(request_sha256)
    .bind(lease_token)
    .execute(&mut **tx)
    .await?
    .rows_affected();
    if inserted == 1 {
        return Ok(());
    }
    let existing = sqlx::query(
        "SELECT request_sha256,state,lease_until FROM idempotency_operations \
         WHERE owner_sub=$1 AND scope=$2 AND operation_id=$3 FOR UPDATE",
    )
    .bind(owner_sub)
    .bind(scope)
    .bind(operation_id)
    .fetch_one(&mut **tx)
    .await?;
    let hash: String = existing.get("request_sha256");
    if hash != request_sha256 {
        return Err(AppError::conflict(
            "idempotency_mismatch",
            "The idempotency key is bound to a different request.",
        ));
    }
    let state: String = existing.get("state");
    let lease_until: Option<OffsetDateTime> = existing.get("lease_until");
    if state == "leased" && lease_until.is_some_and(|until| until <= OffsetDateTime::now_utc()) {
        let changed = sqlx::query(
            "UPDATE idempotency_operations SET lease_token=$5,leased_at=now(),\
             lease_until=now()+interval '5 minutes',attempt=attempt+1,updated_at=now() \
             WHERE owner_sub=$1 AND scope=$2 AND operation_id=$3 AND request_sha256=$4 \
             AND state='leased' AND lease_until<=now()",
        )
        .bind(owner_sub)
        .bind(scope)
        .bind(operation_id)
        .bind(request_sha256)
        .bind(lease_token)
        .execute(&mut **tx)
        .await?
        .rows_affected();
        if changed == 1 {
            return Ok(());
        }
    }
    Err(AppError::conflict(
        "state_conflict",
        "The operation was already accepted.",
    ))
}

fn validate_chunk_descriptor(
    session: &UploadSession,
    index: i32,
    start: i64,
    end: i64,
    byte_size: i32,
) -> Result<()> {
    if index < 0
        || index >= session.chunk_count
        || start != index as i64 * CHUNK_BYTES
        || end != start + byte_size as i64 - 1
        || end >= session.total_bytes
        || byte_size <= 0
        || byte_size as i64 > CHUNK_BYTES
        || (index < session.chunk_count - 1 && byte_size as i64 != CHUNK_BYTES)
        || (index == session.chunk_count - 1 && byte_size as i64 != session.total_bytes - start)
    {
        return Err(AppError::invalid(
            "invalid_upload",
            "Content-Range does not match the upload session.",
        ));
    }
    Ok(())
}

pub fn canonical_request_sha(method: &str, path: &str, owner: &str, body: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(method.as_bytes());
    hash.update(b"\n");
    hash.update(path.as_bytes());
    hash.update(b"\n");
    hash.update(owner.as_bytes());
    hash.update(b"\n");
    hash.update(body);
    hex::encode(hash.finalize())
}

fn stable_json_sha256(value: &serde_json::Value) -> Result<String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| AppError::Invariant("cleanup manifest is not serializable"))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(total: i64) -> UploadSession {
        UploadSession {
            id: Uuid::nil(),
            operation_id: Uuid::nil(),
            owner_sub: "user:a".into(),
            request_sha256: "a".repeat(64),
            filename: "x".into(),
            total_bytes: total,
            chunk_size: CHUNK_BYTES as i32,
            chunk_count: ((total + CHUNK_BYTES - 1) / CHUNK_BYTES) as i32,
            received_bytes: 0,
            state: "uploading".into(),
            staging_key: Uuid::nil().to_string(),
            lease_token: None,
            assembled_sha256: None,
            sample_id: None,
            analysis_id: Uuid::nil(),
            frozen_status: None,
            frozen_location: None,
            frozen_body: None,
            error_code: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
            expires_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn validates_full_and_tail_chunks_without_overlap() {
        let upload = session(CHUNK_BYTES + 7);
        assert!(
            validate_chunk_descriptor(&upload, 0, 0, CHUNK_BYTES - 1, CHUNK_BYTES as i32).is_ok()
        );
        assert!(validate_chunk_descriptor(&upload, 1, CHUNK_BYTES, CHUNK_BYTES + 6, 7).is_ok());
        assert!(
            validate_chunk_descriptor(&upload, 1, CHUNK_BYTES - 1, CHUNK_BYTES + 5, 7).is_err()
        );
    }

    #[test]
    fn canonical_request_hash_binds_owner_method_path_and_body() {
        let a = canonical_request_sha("POST", "/x", "user:a", b"{}");
        let b = canonical_request_sha("POST", "/x", "user:b", b"{}");
        assert_ne!(a, b);
        assert_eq!(a.len(), 64);
    }
}
