use std::{
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::{header, HeaderMap, Request, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use bytes::Bytes;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{Connection, Executor};
use strad::{
    analysis::AnalysisController,
    app::{router as strad_router, AppState},
    application_facade::{
        canonical_application_request_sha, AuthorizationAuditRequest, AuthorizationOutcome,
        ExecutionEnvelopeV1,
    },
    bridge::BridgeClient,
    chat::ChatEngine,
    config::{Config, APPLICATION_OWNER_BYTES, MAX_FILE_BYTES, OWNER_BYTES},
    migrations,
    newapi::{ChatMessage, FrozenChatRequest, NewApiClient, TokenBudgeter},
    store::{server_operation_id, ApplicationOperationClaim, SampleDeleteClaim, Store},
};
use tempfile::TempDir;
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt;
use uuid::Uuid;

#[tokio::test]
async fn application_conversation_turn_dispatches_once_and_retains_its_reservation() {
    let database_url = std::env::var("STRAD_TEST_DATABASE_URL")
        .expect("STRAD_TEST_DATABASE_URL is required; PostgreSQL contract tests never skip");
    migrations::run(&database_url).await.unwrap();
    let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
    let mut test_lock = pool.acquire().await.unwrap();
    sqlx::query("SELECT pg_advisory_lock(823202613)")
        .execute(&mut *test_lock)
        .await
        .unwrap();
    let root = TempDir::new().unwrap();
    let upstream_state = ContractUpstream::active();
    let (upstream, upstream_task) = spawn_contract_upstream(upstream_state.clone()).await;
    let mut config = app_contract_config(
        &database_url,
        &upstream,
        root.path(),
        Duration::from_secs(2),
    );
    config.newapi_model = "glm-5.2".into();
    let state = AppState::build(config).await.unwrap();
    let app = strad_router(state.clone());
    let owner = format!("application:chat_{}", Uuid::new_v4().simple());
    let created = state
        .store
        .create_upload(&owner, "chat.bin", 7, Uuid::new_v4(), &"e".repeat(64))
        .await
        .unwrap();
    let analysis_id = created.analysis.id;
    let sample_digest = hex::encode(Sha256::digest(Uuid::new_v4().as_bytes()));
    let sample_id = format!("sha256:{sample_digest}");
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("INSERT INTO sample_objects(sample_id,sha256,byte_size,file_type,ref_count,lifecycle) VALUES($1,$2,7,'elf',1,'active')")
        .bind(&sample_id).bind(&sample_digest)
        .execute(&mut *tx).await.unwrap();
    sqlx::query(
        "UPDATE upload_sessions SET state='finalized',sample_id=$2,assembled_sha256=$3 WHERE id=$1",
    )
    .bind(created.upload.id)
    .bind(&sample_id)
    .bind(&sample_digest)
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query("UPDATE analyses SET sample_id=$2,case_id='closed-case' WHERE id=$1")
        .bind(analysis_id)
        .bind(&sample_id)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let conversation = state
        .store
        .create_conversation(
            &owner,
            analysis_id,
            "Application chat",
            "binary-analyst",
            Uuid::new_v4(),
            &"d".repeat(64),
        )
        .await
        .unwrap();
    let operation_id = Uuid::new_v4();
    let ask = tool_payload(
        &owner,
        "analysis.conversation",
        &analysis_id.to_string(),
        json!({
            "analysis_id":analysis_id,"conversation_id":conversation.id,
            "client_seq":1,"message":"Explain the available evidence.","model":"glm-5.2"
        }),
        operation_id,
    );
    let path = "/internal/v1/facade/tools/analysis.conversation";
    let response = facade_post(&app, path, ask.clone(), &[]).await;
    let status = response.status();
    let accepted = response_json(response).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{accepted}");
    let turn_id = Uuid::parse_str(accepted["turn"]["id"].as_str().unwrap()).unwrap();
    assert_eq!(accepted["turn"]["model_alias"], "glm-5.2");
    assert_eq!(upstream_state.model_calls.load(Ordering::SeqCst), 0);
    let reserved: bool = sqlx::query_scalar(
        "SELECT reservation_active FROM application_operations WHERE application_sub=$1 AND operation_id=$2"
    ).bind(&owner).bind(operation_id).fetch_one(&pool).await.unwrap();
    assert!(
        reserved,
        "accepting a turn must not release its concurrency slot"
    );
    let replay = facade_post(&app, path, ask, &[]).await;
    assert_eq!(replay.status(), StatusCode::ACCEPTED);
    assert_eq!(response_json(replay).await, accepted);
    let turns: i64 = sqlx::query_scalar("SELECT count(*) FROM turns WHERE owner_sub=$1")
        .bind(&owner)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(turns, 1);
    assert!(state.chat.run_once().await.unwrap());
    assert_eq!(upstream_state.model_calls.load(Ordering::SeqCst), 1);
    let turn = state
        .store
        .get_turn(&owner, analysis_id, conversation.id, turn_id)
        .await
        .unwrap();
    assert_eq!(turn.state, "completed");
    assert!(
        upstream_state.fence_claims.load(Ordering::SeqCst) >= 3,
        "admission, grounding and generation each require the application fence"
    );
    let reserved: bool = sqlx::query_scalar(
        "SELECT reservation_active FROM application_operations WHERE application_sub=$1 AND operation_id=$2"
    ).bind(&owner).bind(operation_id).fetch_one(&pool).await.unwrap();
    assert!(
        !reserved,
        "a known terminal result must release its reservation"
    );
    let read_body = json!({"conversation_id":conversation.id,"turn_id":turn_id});
    let response = facade_post(
        &app,
        "/internal/v1/facade/tools/analysis.read",
        tool_payload(
            &owner,
            "analysis.read",
            &analysis_id.to_string(),
            read_body.clone(),
            Uuid::new_v4(),
        ),
        &[],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let result = response_json(response).await;
    assert_eq!(result["turn"]["state"], "completed");
    assert!(result["assistant"]["content"]
        .as_str()
        .unwrap()
        .contains("Closed test answer"));
    assert!(!result["assistant"]["content"]
        .as_str()
        .unwrap()
        .contains("Unsupported assertion"));
    assert_eq!(result["citations"], json!([["ref:closed-evidence", true]]));
    let other = format!("application:other_{}", Uuid::new_v4().simple());
    let response = facade_post(
        &app,
        "/internal/v1/facade/tools/analysis.read",
        tool_payload(
            &other,
            "analysis.read",
            &analysis_id.to_string(),
            read_body,
            Uuid::new_v4(),
        ),
        &[],
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let ask_next = |seq| {
        tool_payload(
            &owner,
            "analysis.conversation",
            &analysis_id.to_string(),
            json!({
                    "analysis_id":analysis_id,"conversation_id":conversation.id,"client_seq":seq,
            "message":"Explain the available evidence."
                }),
            Uuid::new_v4(),
        )
    };
    let mut queued = Vec::new();
    for seq in [2, 3] {
        let response = facade_post(&app, path, ask_next(seq), &[]).await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        queued.push(
            response_json(response).await["turn"]["id"]
                .as_str()
                .unwrap()
                .to_string(),
        );
    }
    let response = facade_post(&app, path, ask_next(4), &[]).await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response_error(response).await, "quota_exceeded");
    upstream_state.active.store(false, Ordering::SeqCst);
    for id in queued {
        assert!(state.chat.run_once().await.unwrap());
        assert_eq!(
            state
                .store
                .get_turn(
                    &owner,
                    analysis_id,
                    conversation.id,
                    Uuid::parse_str(&id).unwrap()
                )
                .await
                .unwrap()
                .state,
            "failed"
        );
    }
    assert_eq!(
        upstream_state.model_calls.load(Ordering::SeqCst),
        1,
        "revoked queued turns must not reach NewAPI"
    );
    let reserved: i64 = sqlx::query_scalar("SELECT count(*) FROM application_operations WHERE application_sub=$1 AND reservation_active")
        .bind(&owner).fetch_one(&pool).await.unwrap();
    assert_eq!(reserved, 0);
    upstream_state.active.store(true, Ordering::SeqCst);

    let expiry = facade_post(&app, path, ask_next(5), &[]).await;
    assert_eq!(expiry.status(), StatusCode::ACCEPTED);
    let expiry = response_json(expiry).await;
    let expiry_id = Uuid::parse_str(expiry["turn"]["id"].as_str().unwrap()).unwrap();
    sqlx::query("UPDATE application_turn_executions SET execution=jsonb_set(execution,'{expires_at}',to_jsonb($2::bigint)) WHERE turn_id=$1")
        .bind(expiry_id).bind(OffsetDateTime::now_utc().unix_timestamp()-1).execute(&pool).await.unwrap();
    assert!(state.chat.run_once().await.unwrap());
    assert_eq!(
        state
            .store
            .get_turn(&owner, analysis_id, conversation.id, expiry_id)
            .await
            .unwrap()
            .state,
        "failed"
    );
    assert_eq!(
        upstream_state.model_calls.load(Ordering::SeqCst),
        1,
        "expired admission must not be renewed by the worker"
    );

    let barrier = facade_post(&app, path, ask_next(6), &[]).await;
    assert_eq!(barrier.status(), StatusCode::ACCEPTED);
    upstream_state
        .revoke_during_ground
        .store(true, Ordering::SeqCst);
    assert!(state.chat.run_once().await.unwrap());
    assert_eq!(
        upstream_state.model_calls.load(Ordering::SeqCst),
        1,
        "revocation between grounding and model send must stop dispatch"
    );
    upstream_state
        .revoke_during_ground
        .store(false, Ordering::SeqCst);
    upstream_state.active.store(true, Ordering::SeqCst);

    let unknown = ask_next(7);
    let unknown_operation = Uuid::parse_str(unknown["operation_id"].as_str().unwrap()).unwrap();
    let response = facade_post(&app, path, unknown.clone(), &[]).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    upstream_state
        .model_interrupted
        .store(true, Ordering::SeqCst);
    assert!(state.chat.run_once().await.unwrap());
    assert_eq!(upstream_state.model_calls.load(Ordering::SeqCst), 2);
    assert!(
        !state.chat.run_once().await.unwrap(),
        "an uncertain model request must not auto-retry"
    );
    let journal: (String, bool) = sqlx::query_as("SELECT state,reservation_active FROM application_operations WHERE application_sub=$1 AND operation_id=$2")
        .bind(&owner).bind(unknown_operation).fetch_one(&pool).await.unwrap();
    assert_eq!(journal, ("downstream_uncertain".into(), true));
    let response = facade_post(&app, path, unknown, &[]).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(upstream_state.model_calls.load(Ordering::SeqCst), 2);
    let reconciliation =
        json!({"application_sub":owner,"reconciliation_id":Uuid::new_v4(),"completed":false});
    let reconcile_path = format!(
        "/internal/v1/facade/operations/analysis.conversation/{unknown_operation}/reconcile"
    );
    for _ in 0..2 {
        assert_eq!(
            facade_post(&app, &reconcile_path, reconciliation.clone(), &[])
                .await
                .status(),
            StatusCode::NO_CONTENT
        );
    }
    let audit_count: i64 = sqlx::query_scalar("SELECT count(*) FROM application_audit_events WHERE application_sub=$1 AND operation_id=$2 AND event_kind='reconciliation'")
        .bind(&owner).bind(unknown_operation).fetch_one(&pool).await.unwrap();
    assert_eq!(audit_count, 1);
    let reserved: i64 = sqlx::query_scalar("SELECT count(*) FROM application_operations WHERE application_sub=$1 AND reservation_active")
        .bind(&owner).fetch_one(&pool).await.unwrap();
    assert_eq!(reserved, 0);
    upstream_state
        .model_interrupted
        .store(false, Ordering::SeqCst);
    let crash = ask_next(8);
    let crash_operation = Uuid::parse_str(crash["operation_id"].as_str().unwrap()).unwrap();
    assert_eq!(
        facade_post(&app, path, crash, &[]).await.status(),
        StatusCode::ACCEPTED
    );
    let claimed = state.store.claim_turn().await.unwrap().unwrap();
    assert_eq!(claimed.operation_id, crash_operation);
    let frozen = json!({"model":"glm-5.2","messages":[],"max_tokens":2048,"stream":true,"user":"closed-test"});
    let frozen_sha = hex::encode(Sha256::digest(serde_json::to_vec(&frozen).unwrap()));
    state
        .store
        .freeze_turn_context(
            &claimed,
            "ctx:closed",
            &"a".repeat(64),
            &json!({}),
            &frozen,
            &frozen_sha,
        )
        .await
        .unwrap();
    state
        .store
        .begin_application_turn_dispatch(&claimed)
        .await
        .unwrap();
    sqlx::query("UPDATE turns SET generation_lease_until=now()-interval '1 second' WHERE id=$1")
        .bind(claimed.id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(state.chat.run_once().await.unwrap());
    assert_eq!(
        upstream_state.model_calls.load(Ordering::SeqCst),
        2,
        "recovering a dispatched lease must not resend even with no saved response"
    );
    let journal: (String, bool) = sqlx::query_as("SELECT state,reservation_active FROM application_operations WHERE application_sub=$1 AND operation_id=$2")
        .bind(&owner).bind(crash_operation).fetch_one(&pool).await.unwrap();
    assert_eq!(journal, ("downstream_uncertain".into(), true));
    let reconcile_path =
        format!("/internal/v1/facade/operations/analysis.conversation/{crash_operation}/reconcile");
    assert_eq!(
        facade_post(
            &app,
            &reconcile_path,
            json!({"application_sub":owner,"reconciliation_id":Uuid::new_v4(),"completed":false}),
            &[]
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
    let invalid_model = tool_payload(
        &owner,
        "analysis.conversation",
        &analysis_id.to_string(),
        json!({
            "analysis_id":analysis_id,"conversation_id":conversation.id,"client_seq":9,
            "message":"Explain.","model":"missing-model"
        }),
        Uuid::new_v4(),
    );
    let response = facade_post(&app, path, invalid_model, &[]).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response_error(response).await, "invalid_model");
    assert_eq!(upstream_state.model_calls.load(Ordering::SeqCst), 2);
    let invalid_turns: i64 =
        sqlx::query_scalar("SELECT count(*) FROM turns WHERE owner_sub=$1 AND client_seq=9")
            .bind(&owner)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(invalid_turns, 0);
    sqlx::query("SELECT pg_advisory_unlock(823202613)")
        .execute(&mut *test_lock)
        .await
        .unwrap();
    upstream_task.abort();
}

#[tokio::test]
async fn application_idempotency_key_excludes_digest_and_quota_headers_match() {
    let migration = include_str!("../migrations/0003_application_owner_operations.sql");
    assert!(migration.contains("UNIQUE(application_sub, canonical_tool, operation_id)"));
    assert!(!migration
        .contains("UNIQUE(application_sub, canonical_tool, operation_id, request_sha256)"));
    for column in ["rate_limit", "rate_remaining", "rate_reset"] {
        assert!(migration.contains(column), "missing {column}");
    }
    let database_url = std::env::var("STRAD_TEST_DATABASE_URL")
        .expect("STRAD_TEST_DATABASE_URL is required; PostgreSQL contract tests never skip");
    migrations::run(&database_url).await.unwrap();
    let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
    let mut test_lock = pool.acquire().await.unwrap();
    sqlx::query("SELECT pg_advisory_lock(823202613)")
        .execute(&mut *test_lock)
        .await
        .unwrap();
    let store = Store::from_pool(pool.clone());
    let application = format!("application:test_{}", Uuid::new_v4().simple());
    let operation_id = Uuid::new_v4();
    let digest = "a".repeat(64);
    let (lease, quota) = match store
        .claim_application_operation(
            &application,
            "analysis.read",
            operation_id,
            &digest,
            Uuid::new_v4(),
        )
        .await
        .unwrap()
    {
        ApplicationOperationClaim::Claimed { lease_token, quota } => (lease_token, quota),
        ApplicationOperationClaim::Replay(_) => panic!("new operation unexpectedly replayed"),
    };
    assert_eq!(quota.rate_limit, 120);
    assert_eq!(quota.rate_remaining, 119);
    assert!(quota.rate_reset > time::OffsetDateTime::now_utc().unix_timestamp());
    let frozen = serde_json::json!({"analysis":{"state":"created"}});
    store
        .complete_application_operation(
            &application,
            "analysis.read",
            operation_id,
            lease,
            200,
            &frozen,
        )
        .await
        .unwrap();
    let replay = store
        .claim_application_operation(
            &application,
            "analysis.read",
            operation_id,
            &digest,
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    let ApplicationOperationClaim::Replay(replay) = replay else {
        panic!("completed operation did not replay")
    };
    assert_eq!(replay.status, 200);
    assert_eq!(
        serde_json::to_vec(&replay.body).unwrap(),
        serde_json::to_vec(&frozen).unwrap()
    );
    assert_eq!(replay.quota.rate_limit, quota.rate_limit);
    assert_eq!(replay.quota.rate_remaining, quota.rate_remaining);
    assert_eq!(replay.quota.rate_reset, quota.rate_reset);
    assert_eq!(
        store
            .claim_application_operation(
                &application,
                "analysis.read",
                operation_id,
                &"b".repeat(64),
                Uuid::new_v4(),
            )
            .await
            .unwrap_err()
            .code(),
        "idempotency_mismatch"
    );
    let indexes: Vec<String> = sqlx::query_scalar(
        "SELECT indexdef FROM pg_indexes WHERE schemaname=current_schema() \
         AND tablename='application_operations' ORDER BY indexname",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(indexes.iter().any(|value| {
        value.contains("application_sub, canonical_tool, operation_id")
            && !value.contains("request_sha256")
    }));
}

#[tokio::test]
async fn application_owner_resources_are_isolated_and_malformed_owners_fail_closed() {
    let database_url = std::env::var("STRAD_TEST_DATABASE_URL")
        .expect("STRAD_TEST_DATABASE_URL is required; PostgreSQL contract tests never skip");
    migrations::run(&database_url).await.unwrap();
    let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
    let root = TempDir::new().unwrap();
    let upstream_state = ContractUpstream::active();
    let (upstream, upstream_task) = spawn_contract_upstream(upstream_state).await;
    let state = AppState::build(app_contract_config(
        &database_url,
        &upstream,
        root.path(),
        Duration::from_secs(2),
    ))
    .await
    .unwrap();
    let app = strad_router(state);
    let owner = format!("application:owner_{}", Uuid::new_v4().simple());
    let other = format!("application:other_{}", Uuid::new_v4().simple());
    let create = tool_payload(
        &owner,
        "analysis.create",
        "collection",
        json!({"filename":"owned.bin","total_bytes":7}),
        Uuid::new_v4(),
    );
    let response = facade_post(
        &app,
        "/internal/v1/facade/tools/analysis.create",
        create,
        &[],
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let created = response_json(response).await;
    let analysis_id = Uuid::parse_str(created["analysis_id"].as_str().unwrap()).unwrap();
    let upload_id = Uuid::parse_str(created["upload_id"].as_str().unwrap()).unwrap();

    let store = Store::from_pool(pool.clone());
    let quota = store.owner_quota(&owner).await.unwrap();
    assert_eq!(quota.byte_limit, APPLICATION_OWNER_BYTES);

    let owner_read = facade_post(
        &app,
        "/internal/v1/facade/tools/analysis.read",
        tool_payload(
            &owner,
            "analysis.read",
            &analysis_id.to_string(),
            json!({}),
            Uuid::new_v4(),
        ),
        &[],
    )
    .await;
    assert_eq!(owner_read.status(), StatusCode::OK);

    let conversation_body = json!({
        "analysis_id": analysis_id,
        "title": "Owned conversation",
        "persona_id": null
    });
    let owner_conversation = facade_post(
        &app,
        "/internal/v1/facade/tools/analysis.conversation",
        tool_payload(
            &owner,
            "analysis.conversation",
            &analysis_id.to_string(),
            conversation_body.clone(),
            Uuid::new_v4(),
        ),
        &[],
    )
    .await;
    assert_eq!(owner_conversation.status(), StatusCode::CREATED);

    for (tool, body) in [
        ("analysis.read", json!({})),
        ("analysis.conversation", conversation_body),
    ] {
        let operation_id = Uuid::new_v4();
        let response = facade_post(
            &app,
            &format!("/internal/v1/facade/tools/{tool}"),
            tool_payload(&other, tool, &analysis_id.to_string(), body, operation_id),
            &[],
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(response_error(response).await, "not_found");
        let denied: (i32, bool) = sqlx::query_as(
            "SELECT dispatch_count,reservation_active FROM application_operations \
             WHERE application_sub=$1 AND canonical_tool=$2 AND operation_id=$3",
        )
        .bind(&other)
        .bind(tool)
        .bind(operation_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            denied,
            (0, false),
            "foreign resources must be rejected before dispatch"
        );
    }

    let cross_chunk = facade_post(
        &app,
        &format!("/internal/v1/facade/uploads/{upload_id}/chunks/0"),
        json!({
            "application_sub": other,
            "request_sha256": "a".repeat(64),
            "correlation_id": Uuid::new_v4(),
            "content_range": "bytes 0-0/7",
            "chunk_sha256": hex::encode(Sha256::digest(b"0")),
            "content_base64": "MA==",
            "execution": execution_envelope(&other, &"a".repeat(64))
        }),
        &[],
    )
    .await;
    assert_eq!(cross_chunk.status(), StatusCode::NOT_FOUND);
    let cancel_id = server_operation_id("upload-cancel", &upload_id.to_string());
    let cross_cancel = facade_post(
        &app,
        &format!("/internal/v1/facade/uploads/{upload_id}/cancel"),
        upload_mutation_payload(
            &other,
            "analysis.upload.cancel",
            &upload_id.to_string(),
            cancel_id,
        ),
        &[],
    )
    .await;
    assert_eq!(cross_cancel.status(), StatusCode::NOT_FOUND);

    for (malformed, expected_status) in [
        ("user:user:bad", StatusCode::UNAUTHORIZED),
        ("application:", StatusCode::UNAUTHORIZED),
        ("application:bad/slash", StatusCode::UNAUTHORIZED),
    ] {
        for (tool, resource, body) in [
            (
                "analysis.create",
                "collection".to_string(),
                json!({"filename":"bad.bin","total_bytes":1}),
            ),
            ("analysis.read", analysis_id.to_string(), json!({})),
            (
                "analysis.conversation",
                analysis_id.to_string(),
                json!({
                    "analysis_id":analysis_id,
                    "title":"Malformed owner",
                    "persona_id":null
                }),
            ),
        ] {
            let response = facade_post(
                &app,
                &format!("/internal/v1/facade/tools/{tool}"),
                tool_payload(malformed, tool, &resource, body, Uuid::new_v4()),
                &[],
            )
            .await;
            assert_eq!(response.status(), expected_status);
        }
        let malformed_chunk = facade_post(
            &app,
            &format!("/internal/v1/facade/uploads/{upload_id}/chunks/0"),
            json!({
                "application_sub":malformed,
                "request_sha256":"a".repeat(64),
                "correlation_id":Uuid::new_v4(),
                "content_range":"bytes 0-0/7",
                "chunk_sha256":hex::encode(Sha256::digest(b"0")),
                "content_base64":"MA==",
                "execution":execution_envelope(malformed, &"a".repeat(64))
            }),
            &[],
        )
        .await;
        assert_eq!(malformed_chunk.status(), expected_status);
        let malformed_cancel = facade_post(
            &app,
            &format!("/internal/v1/facade/uploads/{upload_id}/cancel"),
            upload_mutation_payload(
                malformed,
                "analysis.upload.cancel",
                &upload_id.to_string(),
                cancel_id,
            ),
            &[],
        )
        .await;
        assert_eq!(malformed_cancel.status(), expected_status);
    }
    let owner_cancel = facade_post(
        &app,
        &format!("/internal/v1/facade/uploads/{upload_id}/cancel"),
        upload_mutation_payload(
            &owner,
            "analysis.upload.cancel",
            &upload_id.to_string(),
            cancel_id,
        ),
        &[],
    )
    .await;
    assert_eq!(owner_cancel.status(), StatusCode::ACCEPTED);
    let human = format!("user:legacy-{}", Uuid::new_v4());
    assert!(store
        .create_upload(&human, "human.bin", 1, Uuid::new_v4(), &"e".repeat(64))
        .await
        .is_ok());
    assert!(store
        .create_upload(
            &owner,
            "too-large.bin",
            MAX_FILE_BYTES + 1,
            Uuid::new_v4(),
            &"9".repeat(64),
        )
        .await
        .is_err());
    upstream_task.abort();
}

#[tokio::test]
async fn cached_application_result_requires_a_current_execution_fence() {
    let database_url = std::env::var("STRAD_TEST_DATABASE_URL")
        .expect("STRAD_TEST_DATABASE_URL is required; PostgreSQL contract tests never skip");
    migrations::run(&database_url).await.unwrap();
    let store = Store::connect(&database_url).await.unwrap();
    let owner = format!("application:replay_fence_{}", Uuid::new_v4().simple());
    let created = store
        .create_upload(&owner, "replay.bin", 1, Uuid::new_v4(), &"1".repeat(64))
        .await
        .unwrap();
    let upstream_state = ContractUpstream::active();
    let active = upstream_state.active.clone();
    let claims = upstream_state.fence_claims.clone();
    let (upstream, upstream_task) = spawn_contract_upstream(upstream_state).await;
    let root = TempDir::new().unwrap();
    let state = AppState::build(app_contract_config(
        &database_url,
        &upstream,
        root.path(),
        Duration::from_secs(2),
    ))
    .await
    .unwrap();
    let app = strad_router(state);
    let operation_id = Uuid::new_v4();
    let request = tool_payload(
        &owner,
        "analysis.read",
        &created.analysis.id.to_string(),
        json!({}),
        operation_id,
    );
    let path = "/internal/v1/facade/tools/analysis.read";
    let first = facade_post(&app, path, request.clone(), &[]).await;
    assert_eq!(first.status(), StatusCode::OK);
    let expected = response_json(first).await;
    let first_claims = claims.load(Ordering::SeqCst);
    let replay = facade_post(&app, path, request.clone(), &[]).await;
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(response_json(replay).await, expected);
    assert_eq!(claims.load(Ordering::SeqCst), first_claims + 1);
    active.store(false, Ordering::SeqCst);
    let revoked = facade_post(&app, path, request, &[]).await;
    assert_eq!(revoked.status(), StatusCode::UNAUTHORIZED);
    let dispatched: i32 = sqlx::query_scalar(
        "SELECT dispatch_count FROM application_operations WHERE application_sub=$1 AND operation_id=$2",
    ).bind(&owner).bind(operation_id).fetch_one(store.pool()).await.unwrap();
    assert_eq!(
        dispatched, 1,
        "the replay must never dispatch the operation again"
    );
    upstream_task.abort();
}

#[tokio::test]
async fn cached_upload_mutations_recheck_live_authority() {
    let database_url = std::env::var("STRAD_TEST_DATABASE_URL")
        .expect("STRAD_TEST_DATABASE_URL is required; PostgreSQL contract tests never skip");
    migrations::run(&database_url).await.unwrap();
    for cancel in [false, true] {
        let store = Store::connect(&database_url).await.unwrap();
        let owner = format!("application:upload_replay_{}", Uuid::new_v4().simple());
        let created = store
            .create_upload(&owner, "replay.bin", 1, Uuid::new_v4(), &"1".repeat(64))
            .await
            .unwrap();
        store
            .bind_application_upload(&owner, created.upload.id)
            .await
            .unwrap();
        let upstream_state = ContractUpstream::active();
        let active = upstream_state.active.clone();
        let (upstream, task) = spawn_contract_upstream(upstream_state).await;
        let root = TempDir::new().unwrap();
        let state = AppState::build(app_contract_config(
            &database_url,
            &upstream,
            root.path(),
            Duration::from_secs(2),
        ))
        .await
        .unwrap();
        if !cancel {
            state
                .upload
                .put_chunk(
                    &owner,
                    created.upload.id,
                    strad::upload::ContentRange {
                        start: 0,
                        end: 0,
                        total: 1,
                    },
                    &hex::encode(Sha256::digest(b"R")),
                    Bytes::from_static(b"R"),
                )
                .await
                .unwrap();
        }
        let app = strad_router(state);
        let action = if cancel { "cancel" } else { "finalize" };
        let tool = if cancel {
            "analysis.upload.cancel"
        } else {
            "analysis.create"
        };
        let operation =
            server_operation_id(&format!("upload-{action}"), &created.upload.id.to_string());
        let resource = if cancel {
            created.upload.id.to_string()
        } else {
            format!("{}/finalize", created.upload.id)
        };
        let body = upload_mutation_payload(&owner, tool, &resource, operation);
        let path = format!("/internal/v1/facade/uploads/{}/{action}", created.upload.id);
        let headers = if cancel {
            vec![]
        } else {
            vec![("idempotency-key", operation.to_string())]
        };
        let first = facade_post(&app, &path, body.clone(), &headers).await;
        assert_eq!(first.status(), StatusCode::ACCEPTED);
        let frozen = response_json(first).await;
        let replay = facade_post(&app, &path, body.clone(), &headers).await;
        assert_eq!(replay.status(), StatusCode::ACCEPTED);
        assert_eq!(response_json(replay).await, frozen);
        active.store(false, Ordering::SeqCst);
        let revoked = facade_post(&app, &path, body, &headers).await;
        assert_eq!(revoked.status(), StatusCode::UNAUTHORIZED);
        let count: i32 = sqlx::query_scalar("SELECT dispatch_count FROM application_operations WHERE application_sub=$1 AND operation_id=$2")
            .bind(&owner).bind(operation).fetch_one(store.pool()).await.unwrap();
        assert_eq!(count, 1);
        task.abort();
    }
}

#[tokio::test]
async fn strad_readiness_transitively_checks_access_fence_without_a_claim() {
    let database_url = std::env::var("STRAD_TEST_DATABASE_URL")
        .expect("STRAD_TEST_DATABASE_URL is required; PostgreSQL contract tests never skip");
    migrations::run(&database_url).await.unwrap();
    let root = TempDir::new().unwrap();
    let upstream_state = ContractUpstream::active();
    let fence_claims = upstream_state.fence_claims.clone();
    let fence_contract_ok = upstream_state.fence_contract_ok.clone();
    let (upstream, upstream_task) = spawn_contract_upstream(upstream_state).await;
    let state = AppState::build(app_contract_config(
        &database_url,
        &upstream,
        root.path(),
        Duration::from_secs(2),
    ))
    .await
    .unwrap();
    let response = strad_router(state)
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/readyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(fence_contract_ok.load(Ordering::SeqCst));
    assert_eq!(fence_claims.load(Ordering::SeqCst), 0);
    upstream_task.abort();
}

#[tokio::test]
async fn application_concurrency_never_exceeds_frozen_tool_or_system_reservations() {
    let database_url = std::env::var("STRAD_TEST_DATABASE_URL")
        .expect("STRAD_TEST_DATABASE_URL is required; PostgreSQL contract tests never skip");
    migrations::run(&database_url).await.unwrap();
    let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
    let store = Store::from_pool(pool.clone());
    let application = format!("application:load_{}", Uuid::new_v4().simple());
    let mut clients = Vec::new();
    for _ in 0..50 {
        let store = store.clone();
        let application = application.clone();
        clients.push(tokio::spawn(async move {
            let operation_id = Uuid::new_v4();
            let result = store
                .claim_application_operation(
                    &application,
                    "analysis.read",
                    operation_id,
                    &hex::encode(Sha256::digest(Uuid::new_v4().as_bytes())),
                    Uuid::new_v4(),
                )
                .await;
            (operation_id, result)
        }));
    }
    let mut accepted = 0;
    let mut claims = Vec::new();
    for client in clients {
        let (operation_id, result) = client.await.unwrap();
        match result {
            Ok(ApplicationOperationClaim::Claimed { lease_token, .. }) => {
                accepted += 1;
                claims.push((operation_id, lease_token));
            }
            Err(error) => assert_eq!(error.code(), "quota_exceeded"),
            Ok(ApplicationOperationClaim::Replay(_)) => panic!("random operation replayed"),
        }
    }
    assert_eq!(accepted, 8);
    let active: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM application_operations WHERE application_sub=$1 \
         AND canonical_tool='analysis.read' AND reservation_active=true",
    )
    .bind(&application)
    .fetch_one(&pool)
    .await
    .unwrap();
    let system: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM application_operations WHERE reservation_active=true",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(active, 8);
    assert!(system <= 32);
    for (operation_id, lease_token) in claims {
        store
            .fail_application_operation(
                &application,
                "analysis.read",
                operation_id,
                lease_token,
                "test_complete",
            )
            .await
            .unwrap();
    }
    let mut system_clients = Vec::new();
    for _ in 0..50 {
        let store = store.clone();
        system_clients.push(tokio::spawn(async move {
            let application = format!("application:system_{}", Uuid::new_v4().simple());
            let operation_id = Uuid::new_v4();
            let result = store
                .claim_application_operation(
                    &application,
                    "analysis.read",
                    operation_id,
                    &hex::encode(Sha256::digest(Uuid::new_v4().as_bytes())),
                    Uuid::new_v4(),
                )
                .await;
            (application, operation_id, result)
        }));
    }
    let mut system_claims = Vec::new();
    for client in system_clients {
        let (application, operation_id, result) = client.await.unwrap();
        match result {
            Ok(ApplicationOperationClaim::Claimed { lease_token, .. }) => {
                system_claims.push((application, operation_id, lease_token));
            }
            Err(error) => assert_eq!(error.code(), "quota_exceeded"),
            Ok(ApplicationOperationClaim::Replay(_)) => panic!("random operation replayed"),
        }
    }
    assert_eq!(system_claims.len(), 32);
    let active_system: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM application_operations WHERE reservation_active=true",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(active_system, 32);
    for (application, operation_id, lease_token) in system_claims {
        store
            .fail_application_operation(
                &application,
                "analysis.read",
                operation_id,
                lease_token,
                "test_complete",
            )
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn owner_and_support_audit_are_scoped_and_secondary() {
    let database_url = std::env::var("STRAD_TEST_DATABASE_URL")
        .expect("STRAD_TEST_DATABASE_URL is required; PostgreSQL contract tests never skip");
    migrations::run(&database_url).await.unwrap();
    let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
    let store = Store::from_pool(pool.clone());
    let owner = format!("application:audit_{}", Uuid::new_v4().simple());
    let other = format!("application:audit_other_{}", Uuid::new_v4().simple());
    for outcome in [
        AuthorizationOutcome::InsufficientScope,
        AuthorizationOutcome::Deny,
        AuthorizationOutcome::Indeterminate,
        AuthorizationOutcome::StaleDecision,
        AuthorizationOutcome::ExpiredDecision,
        AuthorizationOutcome::DecisionDigestMismatch,
        AuthorizationOutcome::AuthorizationUnavailable,
    ] {
        let event_id = Uuid::new_v4();
        let decision_digest = if matches!(outcome, AuthorizationOutcome::InsufficientScope) {
            None
        } else {
            Some("f".repeat(64))
        };
        let request = AuthorizationAuditRequest {
            application_sub: owner.clone(),
            authorization_event_id: event_id,
            outcome,
            canonical_tool: Some("analysis.read".into()),
            operation_id: Some(Uuid::new_v4()),
            decision_digest,
            correlation_id: Uuid::new_v4(),
        };
        assert!(store.record_authorization_audit(&request).await.unwrap());
        assert!(!store.record_authorization_audit(&request).await.unwrap());
    }
    assert_eq!(store.application_audit(&owner, 100).await.unwrap().len(), 7);
    assert!(store
        .application_audit(&other, 100)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        store
            .support_application_audit(&owner, Uuid::new_v4(), Uuid::new_v4(), false)
            .await
            .unwrap_err()
            .code(),
        "insufficient_scope"
    );
    let support_event = Uuid::new_v4();
    store
        .support_application_audit(&owner, support_event, Uuid::new_v4(), true)
        .await
        .unwrap();
    store
        .support_application_audit(&owner, support_event, Uuid::new_v4(), true)
        .await
        .unwrap();
    let second_order: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM application_audit_events WHERE application_sub=$1 \
         AND authorization_event_id=$2 AND event_kind='support_read'",
    )
    .bind(&owner)
    .bind(support_event)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(second_order, 1);
    let dispatch_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM application_operations WHERE application_sub=$1")
            .bind(&owner)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(dispatch_count, 0);
}

#[tokio::test]
async fn allow_then_revoke_before_release_dispatches_zero() {
    let database_url = std::env::var("STRAD_TEST_DATABASE_URL")
        .expect("STRAD_TEST_DATABASE_URL is required; PostgreSQL contract tests never skip");
    migrations::run(&database_url).await.unwrap();
    let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
    let store = Store::from_pool(pool.clone());
    let application = format!("application:barrier_{}", Uuid::new_v4().simple());
    let created = store
        .create_upload(
            &application,
            "barrier.bin",
            1,
            Uuid::new_v4(),
            &"1".repeat(64),
        )
        .await
        .unwrap();
    let operation_id = Uuid::new_v4();
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS test_access_execution_fence(\
         application_sub text PRIMARY KEY,active boolean NOT NULL,revocation_epoch bigint NOT NULL,\
         decision_digest text NOT NULL)",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "ALTER TABLE test_access_execution_fence ADD COLUMN IF NOT EXISTS decision_digest \
         text NOT NULL DEFAULT ''",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO test_access_execution_fence(application_sub,active,revocation_epoch,decision_digest) \
         VALUES($1,true,1,$2)",
    )
    .bind(&application)
    .bind("a2f92fb7e2eb50062013fffd0445bd489860039c2cea005cacedbd5e992adfb7")
    .execute(&pool)
    .await
    .unwrap();
    let upstream_state = ContractUpstream::barrier(pool.clone());
    let fence_entered = upstream_state.fence_entered.clone().unwrap();
    let fence_release = upstream_state.fence_release.clone().unwrap();
    let fence_contract_ok = upstream_state.fence_contract_ok.clone();
    let seen_decision_digest = upstream_state.seen_decision_digest.clone();
    let fence_response_mode = upstream_state.fence_response_mode.clone();
    let (upstream, upstream_task) = spawn_contract_upstream(upstream_state).await;
    let root = TempDir::new().unwrap();
    let state = AppState::build(app_contract_config(
        &database_url,
        &upstream,
        root.path(),
        Duration::from_secs(2),
    ))
    .await
    .unwrap();
    let app = strad_router(state);

    let active_operation_id = Uuid::new_v4();
    let active_request = tool_payload(
        &application,
        "analysis.read",
        &created.analysis.id.to_string(),
        json!({}),
        active_operation_id,
    );
    fence_release.notify_one();
    let active_response = facade_post(
        &app,
        "/internal/v1/facade/tools/analysis.read",
        active_request,
        &[],
    )
    .await;
    assert_eq!(active_response.status(), StatusCode::OK);
    fence_entered.notified().await;
    let active_dispatch_count: i32 = sqlx::query_scalar(
        "SELECT dispatch_count FROM application_operations WHERE application_sub=$1 \
         AND operation_id=$2",
    )
    .bind(&application)
    .bind(active_operation_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(active_dispatch_count, 1);

    let request = tool_payload(
        &application,
        "analysis.read",
        &created.analysis.id.to_string(),
        json!({}),
        operation_id,
    );
    let worker_app = app.clone();
    let worker = tokio::spawn(async move {
        facade_post(
            &worker_app,
            "/internal/v1/facade/tools/analysis.read",
            request,
            &[],
        )
        .await
    });
    fence_entered.notified().await;
    sqlx::query(
        "UPDATE test_access_execution_fence SET active=false,revocation_epoch=revocation_epoch+1 \
         WHERE application_sub=$1",
    )
    .bind(&application)
    .execute(&pool)
    .await
    .unwrap();
    fence_release.notify_one();
    let response = worker.await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(fence_contract_ok.load(Ordering::SeqCst));
    assert_eq!(
        seen_decision_digest.lock().await.as_deref(),
        Some("a2f92fb7e2eb50062013fffd0445bd489860039c2cea005cacedbd5e992adfb7")
    );
    let durable: (String, bool, i32) = sqlx::query_as(
        "SELECT state,reservation_active,dispatch_count FROM application_operations \
         WHERE application_sub=$1 AND canonical_tool='analysis.read' AND operation_id=$2",
    )
    .bind(&application)
    .bind(operation_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(durable, ("failed".into(), false, 0));
    let audit: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM application_audit_events WHERE application_sub=$1 \
         AND operation_id=$2 AND outcome='failed'",
    )
    .bind(&application)
    .bind(operation_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audit, 1);

    sqlx::query(
        "UPDATE test_access_execution_fence SET active=true,revocation_epoch=1 \
         WHERE application_sub=$1",
    )
    .bind(&application)
    .execute(&pool)
    .await
    .unwrap();
    let tampered_operation_id = Uuid::new_v4();
    let mut tampered = tool_payload(
        &application,
        "analysis.read",
        &created.analysis.id.to_string(),
        json!({}),
        tampered_operation_id,
    );
    let tampered_digest = format!(
        "{}0",
        &"a2f92fb7e2eb50062013fffd0445bd489860039c2cea005cacedbd5e992adfb7"[..63]
    );
    tampered["execution"]["decision_digest"] = Value::String(tampered_digest.clone());
    fence_release.notify_one();
    let tampered_response = facade_post(
        &app,
        "/internal/v1/facade/tools/analysis.read",
        tampered,
        &[],
    )
    .await;
    assert_eq!(tampered_response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        seen_decision_digest.lock().await.as_deref(),
        Some(tampered_digest.as_str())
    );
    let tampered_dispatch_count: i32 = sqlx::query_scalar(
        "SELECT dispatch_count FROM application_operations WHERE application_sub=$1 \
         AND operation_id=$2",
    )
    .bind(&application)
    .bind(tampered_operation_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(tampered_dispatch_count, 0);

    for (mode, expected_status, expected_code) in [
        (
            1,
            StatusCode::SERVICE_UNAVAILABLE,
            "authorization_unavailable",
        ),
        (2, StatusCode::UNAUTHORIZED, "unauthenticated"),
        (3, StatusCode::UNAUTHORIZED, "unauthenticated"),
        (
            4,
            StatusCode::SERVICE_UNAVAILABLE,
            "authorization_unavailable",
        ),
    ] {
        fence_response_mode.store(mode, Ordering::SeqCst);
        let malformed_operation_id = Uuid::new_v4();
        let malformed_response_request = tool_payload(
            &application,
            "analysis.read",
            &created.analysis.id.to_string(),
            json!({}),
            malformed_operation_id,
        );
        fence_release.notify_one();
        let malformed_response = facade_post(
            &app,
            "/internal/v1/facade/tools/analysis.read",
            malformed_response_request,
            &[],
        )
        .await;
        assert_eq!(malformed_response.status(), expected_status);
        assert_eq!(response_error(malformed_response).await, expected_code);
        let dispatch_count: i32 = sqlx::query_scalar(
            "SELECT dispatch_count FROM application_operations WHERE application_sub=$1 \
             AND operation_id=$2",
        )
        .bind(&application)
        .bind(malformed_operation_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(dispatch_count, 0);
    }
    upstream_task.abort();
}

#[tokio::test]
async fn dispatch_timeout_becomes_downstream_uncertain() {
    let database_url = std::env::var("STRAD_TEST_DATABASE_URL")
        .expect("STRAD_TEST_DATABASE_URL is required; PostgreSQL contract tests never skip");
    migrations::run(&database_url).await.unwrap();
    let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
    let store = Store::from_pool(pool.clone());
    let application = format!("application:timeout_{}", Uuid::new_v4().simple());
    let created = store
        .create_upload(
            &application,
            "timeout.bin",
            4,
            Uuid::new_v4(),
            &"2".repeat(64),
        )
        .await
        .unwrap();
    store
        .bind_application_upload(&application, created.upload.id)
        .await
        .unwrap();
    let upstream_state = ContractUpstream::with_bridge_delay(Duration::from_millis(300));
    let bridge_calls = upstream_state.bridge_calls.clone();
    let (upstream, upstream_task) = spawn_contract_upstream(upstream_state).await;
    let root = TempDir::new().unwrap();
    let state = AppState::build(app_contract_config(
        &database_url,
        &upstream,
        root.path(),
        Duration::from_millis(50),
    ))
    .await
    .unwrap();
    let bytes = Bytes::from_static(b"ELF!");
    let digest = hex::encode(Sha256::digest(&bytes));
    state
        .upload
        .put_chunk(
            &application,
            created.upload.id,
            strad::upload::ContentRange {
                start: 0,
                end: 3,
                total: 4,
            },
            &digest,
            bytes,
        )
        .await
        .unwrap();
    let app = strad_router(state);
    let operation_id = server_operation_id("upload-finalize", &created.upload.id.to_string());
    let request = upload_mutation_payload(
        &application,
        "analysis.create",
        &format!("{}/finalize", created.upload.id),
        operation_id,
    );
    let path = format!("/internal/v1/facade/uploads/{}/finalize", created.upload.id);
    let response = facade_post(
        &app,
        &path,
        request.clone(),
        &[("idempotency-key", operation_id.to_string())],
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response_error(response).await, "analyzer_unavailable");
    let durable: (String, bool, i32, String, String, String, i64, i64, i64) = sqlx::query_as(
        "SELECT o.state,o.reservation_active,o.dispatch_count,b.reservation_state,u.state,a.state,\
         q.used_bytes,q.reserved_bytes,(SELECT count(*) FROM application_audit_events \
         WHERE application_sub=$1 AND operation_id=$2 AND outcome='downstream_uncertain') \
         FROM application_operations o JOIN application_upload_bindings b \
         ON b.application_sub=o.application_sub AND b.finalize_operation_id=o.operation_id \
         JOIN upload_sessions u ON u.id=b.upload_id JOIN analyses a ON a.upload_id=u.id \
         JOIN owner_quotas q ON q.owner_sub=o.application_sub \
         WHERE o.application_sub=$1 AND o.operation_id=$2",
    )
    .bind(&application)
    .bind(operation_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        durable,
        (
            "downstream_uncertain".into(),
            true,
            1,
            "reserved".into(),
            "upstream_uncertain".into(),
            "created".into(),
            0,
            4,
            1,
        )
    );
    let retry = facade_post(
        &app,
        &path,
        request,
        &[("idempotency-key", operation_id.to_string())],
    )
    .await;
    assert_eq!(retry.status(), StatusCode::CONFLICT);
    assert_eq!(bridge_calls.load(Ordering::SeqCst), 1);
    let reconciliation_id = Uuid::new_v4();
    let route = format!("/internal/v1/facade/operations/analysis.create/{operation_id}/reconcile");
    let reconciliation = json!({
        "application_sub":application,
        "reconciliation_id":reconciliation_id,
        "completed":false,
        "response_status":null,
        "response_body":null
    });
    for _ in 0..2 {
        let reconciled = facade_post(&app, &route, reconciliation.clone(), &[]).await;
        assert_eq!(reconciled.status(), StatusCode::NO_CONTENT);
    }
    let terminal: (String, bool, i32, String, String, String, i64, i64, i64) = sqlx::query_as(
        "SELECT o.state,o.reservation_active,o.dispatch_count,b.reservation_state,u.state,a.state,\
         q.used_bytes,q.reserved_bytes,(SELECT count(*) FROM application_audit_events \
         WHERE application_sub=$1 AND operation_id=$2 AND event_kind='reconciliation') \
         FROM application_operations o JOIN application_upload_bindings b \
         ON b.application_sub=o.application_sub AND b.finalize_operation_id=o.operation_id \
         JOIN upload_sessions u ON u.id=b.upload_id JOIN analyses a ON a.upload_id=u.id \
         JOIN owner_quotas q ON q.owner_sub=o.application_sub \
         WHERE o.application_sub=$1 AND o.operation_id=$2",
    )
    .bind(&application)
    .bind(operation_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        terminal,
        (
            "failed".into(),
            false,
            1,
            "released".into(),
            "failed".into(),
            "failed".into(),
            0,
            0,
            1,
        )
    );
    assert_eq!(bridge_calls.load(Ordering::SeqCst), 1);
    upstream_task.abort();
}

#[tokio::test]
async fn response_before_crash_reconciles_without_resend() {
    let database_url = std::env::var("STRAD_TEST_DATABASE_URL")
        .expect("STRAD_TEST_DATABASE_URL is required; PostgreSQL contract tests never skip");
    migrations::run(&database_url).await.unwrap();
    let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
    let store = Store::from_pool(pool.clone());
    let application = format!("application:response_{}", Uuid::new_v4().simple());
    let created = store
        .create_upload(
            &application,
            "response.bin",
            1,
            Uuid::new_v4(),
            &"3".repeat(64),
        )
        .await
        .unwrap();
    store
        .bind_application_upload(&application, created.upload.id)
        .await
        .unwrap();
    let operation_id = server_operation_id("upload-finalize", &created.upload.id.to_string());
    sqlx::query(&format!(
        "CREATE OR REPLACE FUNCTION test_fail_application_completion() RETURNS trigger \
         LANGUAGE plpgsql AS $$ BEGIN IF NEW.application_sub='{}' AND NEW.operation_id='{}' \
         AND OLD.state='leased' AND NEW.state='completed' THEN RAISE EXCEPTION 'injected commit crash'; \
         END IF; RETURN NEW; END $$",
        application, operation_id
    ))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER test_fail_application_completion_trigger BEFORE UPDATE ON application_operations \
         FOR EACH ROW EXECUTE FUNCTION test_fail_application_completion()",
    )
    .execute(&pool)
    .await
    .unwrap();
    let upstream_state = ContractUpstream::active();
    let bridge_calls = upstream_state.bridge_calls.clone();
    let (upstream, upstream_task) = spawn_contract_upstream(upstream_state).await;
    let root = TempDir::new().unwrap();
    let state = AppState::build(app_contract_config(
        &database_url,
        &upstream,
        root.path(),
        Duration::from_secs(2),
    ))
    .await
    .unwrap();
    let bytes = Bytes::from_static(b"R");
    let content_sha256 = hex::encode(Sha256::digest(&bytes));
    state
        .upload
        .put_chunk(
            &application,
            created.upload.id,
            strad::upload::ContentRange {
                start: 0,
                end: 0,
                total: 1,
            },
            &content_sha256,
            bytes,
        )
        .await
        .unwrap();
    let app = strad_router(state);
    let request = upload_mutation_payload(
        &application,
        "analysis.create",
        &format!("{}/finalize", created.upload.id),
        operation_id,
    );
    let finalize_path = format!("/internal/v1/facade/uploads/{}/finalize", created.upload.id);
    let first = facade_post(
        &app,
        &finalize_path,
        request.clone(),
        &[("idempotency-key", operation_id.to_string())],
    )
    .await;
    assert_eq!(first.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response_error(first).await, "dependency_unavailable");
    let uncertain: (String, bool, i32, String, String, String, i64, i64) = sqlx::query_as(
        "SELECT o.state,o.reservation_active,o.dispatch_count,b.reservation_state,u.state,a.state,\
         q.used_bytes,q.reserved_bytes FROM application_operations o \
         JOIN application_upload_bindings b ON b.application_sub=o.application_sub \
         AND b.finalize_operation_id=o.operation_id JOIN upload_sessions u ON u.id=b.upload_id \
         JOIN analyses a ON a.upload_id=u.id JOIN owner_quotas q ON q.owner_sub=o.application_sub \
         WHERE o.application_sub=$1 AND o.operation_id=$2",
    )
    .bind(&application)
    .bind(operation_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        uncertain,
        (
            "downstream_uncertain".into(),
            true,
            1,
            "committed".into(),
            "finalized".into(),
            "uploaded".into(),
            1,
            0,
        )
    );
    let retry = facade_post(
        &app,
        &finalize_path,
        request.clone(),
        &[("idempotency-key", operation_id.to_string())],
    )
    .await;
    assert_eq!(retry.status(), StatusCode::CONFLICT);
    assert_eq!(bridge_calls.load(Ordering::SeqCst), 1);
    sqlx::query("DROP TRIGGER test_fail_application_completion_trigger ON application_operations")
        .execute(&pool)
        .await
        .unwrap();
    let reconciliation_id = Uuid::new_v4();
    let analysis = store
        .get_analysis(&application, created.analysis.id)
        .await
        .unwrap();
    let frozen = json!({"analysis_id":analysis.id,"state":analysis.state});
    let route = format!("/internal/v1/facade/operations/analysis.create/{operation_id}/reconcile");
    let reconciliation = json!({
        "application_sub":application,
        "reconciliation_id":reconciliation_id,
        "completed":true,
        "response_status":202,
        "response_body":frozen
    });
    for _ in 0..2 {
        let response = facade_post(&app, &route, reconciliation.clone(), &[]).await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }
    let replay = facade_post(
        &app,
        &finalize_path,
        request,
        &[("idempotency-key", operation_id.to_string())],
    )
    .await;
    assert_eq!(replay.status(), StatusCode::ACCEPTED);
    assert_eq!(response_json(replay).await, frozen);
    let terminal: (String, bool, i32, String, String, String, i64, i64, i64) = sqlx::query_as(
        "SELECT o.state,o.reservation_active,o.dispatch_count,b.reservation_state,u.state,a.state,\
         q.used_bytes,q.reserved_bytes,(SELECT count(*) FROM application_audit_events \
         WHERE application_sub=$1 AND operation_id=$2 AND event_kind='reconciliation') \
         FROM application_operations o JOIN application_upload_bindings b \
         ON b.application_sub=o.application_sub AND b.finalize_operation_id=o.operation_id \
         JOIN upload_sessions u ON u.id=b.upload_id JOIN analyses a ON a.upload_id=u.id \
         JOIN owner_quotas q ON q.owner_sub=o.application_sub \
         WHERE o.application_sub=$1 AND o.operation_id=$2",
    )
    .bind(&application)
    .bind(operation_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        terminal,
        (
            "completed".into(),
            false,
            1,
            "committed".into(),
            "finalized".into(),
            "uploaded".into(),
            1,
            0,
            1,
        )
    );
    assert_eq!(bridge_calls.load(Ordering::SeqCst), 1);
    upstream_task.abort();
}

#[tokio::test]
async fn cleanup_crash_retains_reservation_until_audited_resolution() {
    let database_url = std::env::var("STRAD_TEST_DATABASE_URL")
        .expect("STRAD_TEST_DATABASE_URL is required; PostgreSQL contract tests never skip");
    migrations::run(&database_url).await.unwrap();
    let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
    let store = Store::from_pool(pool.clone());
    let application = format!("application:cleanup_{}", Uuid::new_v4().simple());
    let upload = store
        .create_upload(
            &application,
            "cleanup.bin",
            9,
            Uuid::new_v4(),
            &"4".repeat(64),
        )
        .await
        .unwrap();
    store
        .bind_application_upload(&application, upload.upload.id)
        .await
        .unwrap();
    let operation_id = server_operation_id("upload-cancel", &upload.upload.id.to_string());
    sqlx::query(&format!(
        "CREATE OR REPLACE FUNCTION test_fail_application_cleanup() RETURNS trigger \
         LANGUAGE plpgsql AS $$ BEGIN IF OLD.owner_sub='{}' THEN \
         RAISE EXCEPTION 'injected cleanup transaction crash'; END IF; RETURN NEW; END $$",
        application
    ))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER test_fail_application_cleanup_trigger BEFORE UPDATE ON owner_quotas \
         FOR EACH ROW EXECUTE FUNCTION test_fail_application_cleanup()",
    )
    .execute(&pool)
    .await
    .unwrap();
    let upstream_state = ContractUpstream::active();
    let (upstream, upstream_task) = spawn_contract_upstream(upstream_state).await;
    let root = TempDir::new().unwrap();
    let state = AppState::build(app_contract_config(
        &database_url,
        &upstream,
        root.path(),
        Duration::from_secs(2),
    ))
    .await
    .unwrap();
    let app = strad_router(state);
    let request = upload_mutation_payload(
        &application,
        "analysis.upload.cancel",
        &upload.upload.id.to_string(),
        operation_id,
    );
    let path = format!("/internal/v1/facade/uploads/{}/cancel", upload.upload.id);
    let first = facade_post(&app, &path, request.clone(), &[]).await;
    assert_eq!(first.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response_error(first).await, "database_unavailable");
    let retained: (i64, i64, bool, String, i32, String, String, String) = sqlx::query_as(
        "SELECT q.used_bytes,q.reserved_bytes,o.reservation_active,o.state,o.dispatch_count,\
         b.reservation_state,u.state,a.state FROM owner_quotas q \
         JOIN application_operations o ON o.application_sub=q.owner_sub \
         JOIN application_upload_bindings b ON b.application_sub=o.application_sub \
         AND b.cancel_operation_id=o.operation_id JOIN upload_sessions u ON u.id=b.upload_id \
         JOIN analyses a ON a.upload_id=u.id \
         WHERE o.application_sub=$1 AND o.operation_id=$2",
    )
    .bind(&application)
    .bind(operation_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        retained,
        (
            0,
            9,
            true,
            "downstream_uncertain".into(),
            1,
            "reserved".into(),
            "cancel_pending".into(),
            "created".into(),
        )
    );
    let retry = facade_post(&app, &path, request, &[]).await;
    assert_eq!(retry.status(), StatusCode::CONFLICT);
    sqlx::query("DROP TRIGGER test_fail_application_cleanup_trigger ON owner_quotas")
        .execute(&pool)
        .await
        .unwrap();
    let reconciliation_id = Uuid::new_v4();
    let reconciliation = json!({
        "application_sub":application,
        "reconciliation_id":reconciliation_id,
        "completed":false,
        "response_status":null,
        "response_body":null
    });
    let route =
        format!("/internal/v1/facade/operations/analysis.upload.cancel/{operation_id}/reconcile");
    for _ in 0..2 {
        let response = facade_post(&app, &route, reconciliation.clone(), &[]).await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }
    let terminal: (i64, i64, bool, String, i32, String, String, String, i64) = sqlx::query_as(
        "SELECT q.used_bytes,q.reserved_bytes,o.reservation_active,o.state,o.dispatch_count,\
         b.reservation_state,u.state,a.state,\
         (SELECT count(*) FROM application_audit_events WHERE application_sub=$1 \
          AND operation_id=$2 AND event_kind='reconciliation') FROM owner_quotas q \
         JOIN application_operations o ON o.application_sub=q.owner_sub \
         JOIN application_upload_bindings b ON b.application_sub=o.application_sub \
         AND b.cancel_operation_id=o.operation_id JOIN upload_sessions u ON u.id=b.upload_id \
         JOIN analyses a ON a.upload_id=u.id WHERE o.application_sub=$1 AND o.operation_id=$2",
    )
    .bind(&application)
    .bind(operation_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        terminal,
        (
            0,
            0,
            false,
            "failed".into(),
            1,
            "released".into(),
            "cancelled".into(),
            "failed".into(),
            1,
        )
    );
    upstream_task.abort();
}

#[tokio::test]
async fn postgres_owner_delete_and_sample_lifecycle_are_transactional() {
    let database_url = std::env::var("STRAD_TEST_DATABASE_URL")
        .expect("STRAD_TEST_DATABASE_URL is required; PostgreSQL contract tests never skip");
    migrations::run(&database_url).await.unwrap();
    let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
    let mut _test_lock = pool.acquire().await.unwrap();
    sqlx::query("SELECT pg_advisory_lock(823202613)")
        .execute(&mut *_test_lock)
        .await
        .unwrap();
    let store = Store::from_pool(pool.clone());

    let owner = format!("user:test-{}", Uuid::new_v4());
    let operation_id = Uuid::new_v4();
    let request_sha = "a".repeat(64);
    let created = store
        .create_upload(&owner, "cancel.bin", 7, operation_id, &request_sha)
        .await
        .unwrap();
    let replay = store
        .idempotency_replay(&owner, "POST /api/analyses", operation_id, &request_sha)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(replay.status, 201);
    store.begin_cancel(&owner, created.upload.id).await.unwrap();
    store
        .complete_cancel(&owner, created.upload.id)
        .await
        .unwrap();
    let quota: (i64, i32) =
        sqlx::query_as("SELECT reserved_bytes,analysis_count FROM owner_quotas WHERE owner_sub=$1")
            .bind(&owner)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(quota, (0, 1));

    let delete_operation = Uuid::new_v4();
    store
        .request_analysis_delete(
            &owner,
            created.analysis.id,
            delete_operation,
            &"b".repeat(64),
        )
        .await
        .unwrap();
    assert!(store
        .get_analysis(&owner, created.analysis.id)
        .await
        .is_err());
    let quota: i32 =
        sqlx::query_scalar("SELECT analysis_count FROM owner_quotas WHERE owner_sub=$1")
            .bind(&owner)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(quota, 0);
    let cleanup = store.claim_cleanup().await.unwrap().unwrap();
    store.complete_cleanup(&cleanup).await.unwrap();

    let owner = format!("user:test-{}", Uuid::new_v4());
    let created = store
        .create_upload(&owner, "shared.bin", 1, Uuid::new_v4(), &"c".repeat(64))
        .await
        .unwrap();
    let digest = hex::encode(Sha256::digest(Uuid::new_v4().as_bytes()));
    let sample_id = format!("sha256:{digest}");
    let mut tx = pool.begin().await.unwrap();
    tx.execute(
        sqlx::query(
            "INSERT INTO sample_objects(sample_id,sha256,byte_size,file_type,ref_count,lifecycle) \
             VALUES($1,$2,1,'elf',1,'active')",
        )
        .bind(&sample_id)
        .bind(&digest),
    )
    .await
    .unwrap();
    tx.execute(
        sqlx::query(
            "UPDATE upload_sessions SET state='finalized',sample_id=$2,assembled_sha256=$3 \
             WHERE id=$1",
        )
        .bind(created.upload.id)
        .bind(&sample_id)
        .bind(&digest),
    )
    .await
    .unwrap();
    tx.execute(
        sqlx::query("UPDATE analyses SET state='uploaded',sample_id=$2 WHERE id=$1")
            .bind(created.analysis.id)
            .bind(&sample_id),
    )
    .await
    .unwrap();
    tx.execute(
        sqlx::query(
            "UPDATE owner_quotas SET reserved_bytes=reserved_bytes-1,used_bytes=used_bytes+1 \
             WHERE owner_sub=$1",
        )
        .bind(&owner),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    store
        .request_analysis_delete(&owner, created.analysis.id, Uuid::new_v4(), &"e".repeat(64))
        .await
        .unwrap();
    let lifecycle: (i32, String) =
        sqlx::query_as("SELECT ref_count,lifecycle FROM sample_objects WHERE sample_id=$1")
            .bind(&sample_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(lifecycle, (0, "delete_pending".into()));
    let claim = store.claim_sample_delete().await.unwrap().unwrap();
    assert_eq!(claim.sample_id, sample_id);
    store
        .finish_sample_delete(&claim, true, None)
        .await
        .unwrap();
    let lifecycle: String =
        sqlx::query_scalar("SELECT lifecycle FROM sample_objects WHERE sample_id=$1")
            .bind(&sample_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(lifecycle, "deleted");

    // A crashed analysis start is recovered without minting a new downstream operation ID.
    let recovery_owner = format!("user:test-{}", Uuid::new_v4());
    let recovery = store
        .create_upload(
            &recovery_owner,
            "recovery.bin",
            1,
            Uuid::new_v4(),
            &"1".repeat(64),
        )
        .await
        .unwrap();
    sqlx::query("UPDATE analyses SET state='uploaded' WHERE id=$1")
        .bind(recovery.analysis.id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE analyses SET state='degraded' WHERE state='uploaded' AND id<>$1")
        .bind(recovery.analysis.id)
        .execute(&pool)
        .await
        .unwrap();
    let starting = store.claim_start().await.unwrap().unwrap();
    assert_eq!(starting.id, recovery.analysis.id);
    let worker_operation = Uuid::new_v4();
    store
        .begin_worker_operation(&starting, "start", worker_operation, &"2".repeat(64))
        .await
        .unwrap();
    sqlx::query("UPDATE analyses SET poll_lease_until=now()-interval '1 second' WHERE id=$1")
        .bind(starting.id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE idempotency_operations SET lease_until=now()-interval '1 second' \
         WHERE owner_sub=$1 AND scope='worker:start:'||$2::text AND operation_id=$3",
    )
    .bind(&recovery_owner)
    .bind(starting.id)
    .bind(worker_operation)
    .execute(&pool)
    .await
    .unwrap();
    assert!(store.recover_analysis_work().await.unwrap() >= 2);
    let recovered_state: String = sqlx::query_scalar("SELECT state FROM analyses WHERE id=$1")
        .bind(starting.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    let recovered_operation: (String, Uuid) = sqlx::query_as(
        "SELECT state,operation_id FROM idempotency_operations WHERE owner_sub=$1 \
         AND scope='worker:start:'||$2::text",
    )
    .bind(&recovery_owner)
    .bind(starting.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(recovered_state, "start_uncertain");
    assert_eq!(
        recovered_operation,
        ("downstream_uncertain".into(), worker_operation)
    );
    store
        .fail_worker_operation(&starting, "start", worker_operation, "test_fixture_closed")
        .await
        .unwrap();

    let orphan = store
        .create_upload(
            &format!("user:test-{}", Uuid::new_v4()),
            "orphan.bin",
            1,
            Uuid::new_v4(),
            &"3".repeat(64),
        )
        .await
        .unwrap();
    sqlx::query(
        "UPDATE analyses SET state='starting',poll_lease_token=$2,\
         poll_lease_until=now()-interval '1 second' WHERE id=$1",
    )
    .bind(orphan.analysis.id)
    .bind(Uuid::new_v4())
    .execute(&pool)
    .await
    .unwrap();
    store.recover_analysis_work().await.unwrap();
    let orphan_state: String = sqlx::query_scalar("SELECT state FROM analyses WHERE id=$1")
        .bind(orphan.analysis.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(orphan_state, "uploaded");

    // Leased outbox rows are reclaimed after a worker crash.
    sqlx::query(
        "UPDATE outbox SET state='delivered',lease_token=NULL,leased_at=NULL,lease_until=NULL,\
         delivered_at=now() WHERE state IN ('pending','leased')",
    )
    .execute(&pool)
    .await
    .unwrap();
    let outbox_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO outbox(id,aggregate_type,aggregate_id,owner_sub,event_type,payload,state) \
         VALUES($1,'analysis',$2,$3,'test.crash','{}','pending')",
    )
    .bind(outbox_id)
    .bind(orphan.analysis.id)
    .bind(&orphan.analysis.owner_sub)
    .execute(&pool)
    .await
    .unwrap();
    let first_claim = store.claim_outbox().await.unwrap().unwrap();
    assert_eq!(first_claim.id, outbox_id);
    sqlx::query("UPDATE outbox SET lease_until=now()-interval '1 second' WHERE id=$1")
        .bind(outbox_id)
        .execute(&pool)
        .await
        .unwrap();
    let reclaimed = store.claim_outbox().await.unwrap().unwrap();
    assert_eq!(reclaimed.id, outbox_id);
    assert_ne!(reclaimed.lease_token, first_claim.lease_token);

    // PostgreSQL permits the replacement event-retention lock query and it advances the floor.
    sqlx::query("UPDATE analyses SET next_event_seq=101 WHERE id=$1")
        .bind(orphan.analysis.id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO analysis_events(analysis_id,owner_sub,seq,event_type,payload,expires_at) \
         VALUES($1,$2,99,'test.expired','{}',now()-interval '1 second')",
    )
    .bind(orphan.analysis.id)
    .bind(&orphan.analysis.owner_sub)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO analysis_events(analysis_id,owner_sub,seq,event_type,payload,expires_at) \
         VALUES($1,$2,100,'test.replay','{}',now()+interval '1 day')",
    )
    .bind(orphan.analysis.id)
    .bind(&orphan.analysis.owner_sub)
    .execute(&pool)
    .await
    .unwrap();
    let replayed = store
        .events_after(&orphan.analysis.owner_sub, orphan.analysis.id, 99, 256)
        .await
        .unwrap();
    assert_eq!(replayed.len(), 1);
    assert_eq!(replayed[0].seq, 100);
    assert_eq!(store.reap_events().await.unwrap(), 1);
    let retained: i64 = sqlx::query_scalar("SELECT retained_from_seq FROM analyses WHERE id=$1")
        .bind(orphan.analysis.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(retained, 100);

    // Forwarding cancellation records intent but preserves spool authority and reservation.
    let cancel_owner = format!("user:test-{}", Uuid::new_v4());
    let cancel = store
        .create_upload(
            &cancel_owner,
            "cancel-forwarding.bin",
            1,
            Uuid::new_v4(),
            &"4".repeat(64),
        )
        .await
        .unwrap();
    sqlx::query(
        "UPDATE upload_sessions SET state='forwarding',assembled_sha256=$2,lease_token=$3,\
         leased_at=now(),lease_until=now()+interval '5 minutes' WHERE id=$1",
    )
    .bind(cancel.upload.id)
    .bind("4".repeat(64))
    .bind(Uuid::new_v4())
    .execute(&pool)
    .await
    .unwrap();
    store
        .begin_cancel(&cancel_owner, cancel.upload.id)
        .await
        .unwrap();
    let cancel_state: (String, Option<String>, i64) = sqlx::query_as(
        "SELECT u.state,u.error_code,q.reserved_bytes FROM upload_sessions u \
         JOIN owner_quotas q ON q.owner_sub=u.owner_sub WHERE u.id=$1",
    )
    .bind(cancel.upload.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        cancel_state,
        ("forwarding".into(), Some("cancel_requested".into()), 1)
    );

    // A succeeded unknown upload becomes non-analyzable in the finalize transaction, then
    // remains durably discoverable for disposition after a crash.
    let unknown_owner = format!("user:test-{}", Uuid::new_v4());
    let unknown = store
        .create_upload(
            &unknown_owner,
            "unknown.bin",
            1,
            Uuid::new_v4(),
            &"5".repeat(64),
        )
        .await
        .unwrap();
    let unknown_digest = hex::encode(Sha256::digest(Uuid::new_v4().as_bytes()));
    let unknown_lease = Uuid::new_v4();
    sqlx::query(
        "UPDATE upload_sessions SET state='forwarding',assembled_sha256=$2,lease_token=$3,\
         leased_at=now(),lease_until=now()+interval '5 minutes' WHERE id=$1",
    )
    .bind(unknown.upload.id)
    .bind(&unknown_digest)
    .bind(unknown_lease)
    .execute(&pool)
    .await
    .unwrap();
    store
        .complete_finalize(
            &unknown_owner,
            unknown.upload.id,
            Some(unknown_lease),
            &unknown_digest,
            "unknown",
        )
        .await
        .unwrap();
    let crash_safe_unknown: (String, Option<String>, String, Option<String>) = sqlx::query_as(
        "SELECT u.state,u.error_code,a.state,a.sample_id FROM upload_sessions u JOIN analyses a \
         ON a.id=u.analysis_id WHERE u.id=$1",
    )
    .bind(unknown.upload.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        crash_safe_unknown,
        (
            "finalized".into(),
            Some("unknown_file_disposition_waiting".into()),
            "failed".into(),
            Some(format!("sha256:{unknown_digest}")),
        )
    );
    assert!(store
        .disposition_uploads(100)
        .await
        .unwrap()
        .iter()
        .any(|upload| upload.id == unknown.upload.id));
    sqlx::query("UPDATE analyses SET state='degraded' WHERE state='uploaded' AND id<>$1")
        .bind(unknown.analysis.id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(store.claim_start().await.unwrap().is_none());
    assert!(!store
        .dispose_finalized_unknown(&unknown_owner, unknown.upload.id, &unknown_digest)
        .await
        .unwrap());
    let unknown_pending: (String, Option<String>, String, i64) = sqlx::query_as(
        "SELECT u.state,u.sample_id,a.state,q.used_bytes FROM upload_sessions u JOIN analyses a \
         ON a.id=u.analysis_id JOIN owner_quotas q ON q.owner_sub=u.owner_sub WHERE u.id=$1",
    )
    .bind(unknown.upload.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        unknown_pending,
        ("expired".into(), None, "failed".into(), 1)
    );
    let unknown_delete = store.claim_sample_delete().await.unwrap().unwrap();
    assert_eq!(unknown_delete.sample_id, format!("sha256:{unknown_digest}"));
    assert_ne!(
        unknown_delete.delete_operation_id,
        unknown.upload.operation_id
    );
    store
        .finish_sample_delete(&unknown_delete, true, None)
        .await
        .unwrap();
    let disposition = store
        .get_upload(&unknown_owner, unknown.upload.id)
        .await
        .unwrap();
    assert!(store
        .complete_unknown_disposition(&disposition)
        .await
        .unwrap());
    let unknown_state: (String, Option<String>, String, i64) = sqlx::query_as(
        "SELECT u.state,u.sample_id,a.state,q.used_bytes FROM upload_sessions u JOIN analyses a \
         ON a.id=u.analysis_id JOIN owner_quotas q ON q.owner_sub=u.owner_sub WHERE u.id=$1",
    )
    .bind(unknown.upload.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let unknown_sample: (i32, String) =
        sqlx::query_as("SELECT ref_count,lifecycle FROM sample_objects WHERE sample_id=$1")
            .bind(format!("sha256:{unknown_digest}"))
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(unknown_state, ("failed".into(), None, "failed".into(), 0));
    assert_eq!(unknown_sample, (0, "deleted".into()));

    // Re-uploading identical content starts a fresh physical-delete operation. Reusing a
    // digest-derived operation ID would make the bridge journal replay the first deletion.
    let reuploaded = store
        .create_upload(
            &unknown_owner,
            "unknown-reuploaded.bin",
            1,
            Uuid::new_v4(),
            &"d".repeat(64),
        )
        .await
        .unwrap();
    let reuploaded_lease = Uuid::new_v4();
    sqlx::query(
        "UPDATE upload_sessions SET state='forwarding',assembled_sha256=$2,lease_token=$3,\
         leased_at=now(),lease_until=now()+interval '5 minutes' WHERE id=$1",
    )
    .bind(reuploaded.upload.id)
    .bind(&unknown_digest)
    .bind(reuploaded_lease)
    .execute(&pool)
    .await
    .unwrap();
    store
        .complete_finalize(
            &unknown_owner,
            reuploaded.upload.id,
            Some(reuploaded_lease),
            &unknown_digest,
            "unknown",
        )
        .await
        .unwrap();
    assert!(!store
        .dispose_finalized_unknown(&unknown_owner, reuploaded.upload.id, &unknown_digest)
        .await
        .unwrap());
    let reuploaded_delete = store.claim_sample_delete().await.unwrap().unwrap();
    assert_eq!(reuploaded_delete.sample_id, unknown_delete.sample_id);
    assert_ne!(
        reuploaded_delete.delete_operation_id,
        unknown_delete.delete_operation_id
    );
    store
        .finish_sample_delete(&reuploaded_delete, true, None)
        .await
        .unwrap();
    let reuploaded_disposition = store
        .get_upload(&unknown_owner, reuploaded.upload.id)
        .await
        .unwrap();
    assert!(store
        .complete_unknown_disposition(&reuploaded_disposition)
        .await
        .unwrap());

    // A pending same-digest session gates deletion; a stale deleting lease is recoverable.
    let gated_digest = hex::encode(Sha256::digest(Uuid::new_v4().as_bytes()));
    let gated_sample = format!("sha256:{gated_digest}");
    let gated_delete_operation = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO sample_objects(sample_id,sha256,byte_size,file_type,ref_count,lifecycle,\
         delete_after,delete_operation_id) VALUES($1,$2,1,'unknown',0,'delete_pending',now(),$3)",
    )
    .bind(&gated_sample)
    .bind(&gated_digest)
    .bind(gated_delete_operation)
    .execute(&pool)
    .await
    .unwrap();
    let gate_owner = format!("user:test-{}", Uuid::new_v4());
    let gate_upload = store
        .create_upload(&gate_owner, "gate.bin", 1, Uuid::new_v4(), &"6".repeat(64))
        .await
        .unwrap();
    sqlx::query(
        "UPDATE upload_sessions SET state='upstream_uncertain',assembled_sha256=$2,\
         updated_at=now()-interval '25 hours' WHERE id=$1",
    )
    .bind(gate_upload.upload.id)
    .bind(&gated_digest)
    .execute(&pool)
    .await
    .unwrap();
    assert!(store.claim_sample_delete().await.unwrap().is_none());
    sqlx::query("UPDATE upload_sessions SET state='failed' WHERE id=$1")
        .bind(gate_upload.upload.id)
        .execute(&pool)
        .await
        .unwrap();
    let gated_claim = store.claim_sample_delete().await.unwrap().unwrap();
    assert_eq!(gated_claim.sample_id, gated_sample);
    sqlx::query(
        "UPDATE sample_objects SET delete_after=now()-interval '1 second' WHERE sample_id=$1",
    )
    .bind(&gated_sample)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(store.recover_sample_delete_leases().await.unwrap(), 1);
    let reclaimed_delete = store.claim_sample_delete().await.unwrap().unwrap();
    assert_eq!(reclaimed_delete.delete_operation_id, gated_delete_operation);
    store
        .finish_sample_delete(&reclaimed_delete, true, None)
        .await
        .unwrap();
}

#[tokio::test]
async fn postgres_24h_disposition_preserves_spool_authority_until_physical_delete() {
    let database_url = std::env::var("STRAD_TEST_DATABASE_URL")
        .expect("STRAD_TEST_DATABASE_URL is required; PostgreSQL contract tests never skip");
    migrations::run(&database_url).await.unwrap();
    let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
    let mut _test_lock = pool.acquire().await.unwrap();
    sqlx::query("SELECT pg_advisory_lock(823202613)")
        .execute(&mut *_test_lock)
        .await
        .unwrap();
    let store = Store::from_pool(pool.clone());

    let owner = format!("user:test-{}", Uuid::new_v4());
    let created = store
        .create_upload(&owner, "ambiguous.bin", 7, Uuid::new_v4(), &"7".repeat(64))
        .await
        .unwrap();
    let digest = hex::encode(Sha256::digest(Uuid::new_v4().as_bytes()));
    sqlx::query(
        "UPDATE upload_sessions SET state='upstream_uncertain',assembled_sha256=$2,\
         updated_at=now()-interval '25 hours' WHERE id=$1",
    )
    .bind(created.upload.id)
    .bind(&digest)
    .execute(&pool)
    .await
    .unwrap();
    let uncertain = store.get_upload(&owner, created.upload.id).await.unwrap();
    assert!(!store
        .expire_uncertain_upload(&uncertain, false)
        .await
        .unwrap());
    let pending: (String, Option<String>, i64, String, Uuid) = sqlx::query_as(
        "SELECT u.state,u.error_code,q.reserved_bytes,s.lifecycle,s.delete_operation_id \
         FROM upload_sessions u JOIN owner_quotas q ON q.owner_sub=u.owner_sub \
         JOIN sample_objects s ON s.sha256=u.assembled_sha256 WHERE u.id=$1",
    )
    .bind(created.upload.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(pending.0, "expired");
    assert_eq!(pending.1.as_deref(), Some("analyzer_unknown_disposition"));
    assert_eq!(pending.2, 7);
    assert_eq!(pending.3, "delete_pending");
    assert_ne!(pending.4, created.upload.operation_id);

    sqlx::query(
        "UPDATE sample_objects SET lifecycle='deleting',delete_after=now()+interval '10 minutes' \
         WHERE sha256=$1 AND delete_operation_id=$2",
    )
    .bind(&digest)
    .bind(pending.4)
    .execute(&pool)
    .await
    .unwrap();
    let claim = SampleDeleteClaim {
        sample_id: format!("sha256:{digest}"),
        sha256: digest.clone(),
        delete_operation_id: pending.4,
    };
    store
        .finish_sample_delete(&claim, true, None)
        .await
        .unwrap();
    let disposition = store.get_upload(&owner, created.upload.id).await.unwrap();
    assert!(store
        .complete_unknown_disposition(&disposition)
        .await
        .unwrap());
    let terminal: (String, i64, String) = sqlx::query_as(
        "SELECT u.state,q.reserved_bytes,s.lifecycle FROM upload_sessions u \
         JOIN owner_quotas q ON q.owner_sub=u.owner_sub \
         JOIN sample_objects s ON s.sha256=u.assembled_sha256 WHERE u.id=$1",
    )
    .bind(created.upload.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(terminal, ("failed".into(), 0, "deleted".into()));

    // Once the retained sample tombstone is reaped, the uncertain-upload disposition path
    // must also mint a fresh operation ID for identical content.
    sqlx::query("DELETE FROM sample_objects WHERE sha256=$1")
        .bind(&digest)
        .execute(&pool)
        .await
        .unwrap();
    let replay_owner = format!("user:test-{}", Uuid::new_v4());
    let replay = store
        .create_upload(
            &replay_owner,
            "ambiguous-reuploaded.bin",
            7,
            Uuid::new_v4(),
            &"f".repeat(64),
        )
        .await
        .unwrap();
    sqlx::query(
        "UPDATE upload_sessions SET state='upstream_uncertain',assembled_sha256=$2,\
         updated_at=now()-interval '25 hours' WHERE id=$1",
    )
    .bind(replay.upload.id)
    .bind(&digest)
    .execute(&pool)
    .await
    .unwrap();
    let replay_upload = store
        .get_upload(&replay_owner, replay.upload.id)
        .await
        .unwrap();
    assert!(!store
        .expire_uncertain_upload(&replay_upload, false)
        .await
        .unwrap());
    let replay_delete_operation: Uuid =
        sqlx::query_scalar("SELECT delete_operation_id FROM sample_objects WHERE sha256=$1")
            .bind(&digest)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_ne!(replay_delete_operation, pending.4);
    sqlx::query(
        "UPDATE sample_objects SET lifecycle='deleting',delete_after=now()+interval '10 minutes' \
         WHERE sha256=$1 AND delete_operation_id=$2",
    )
    .bind(&digest)
    .bind(replay_delete_operation)
    .execute(&pool)
    .await
    .unwrap();
    let replay_claim = SampleDeleteClaim {
        sample_id: format!("sha256:{digest}"),
        sha256: digest.clone(),
        delete_operation_id: replay_delete_operation,
    };
    store
        .finish_sample_delete(&replay_claim, true, None)
        .await
        .unwrap();
    let replay_disposition = store
        .get_upload(&replay_owner, replay.upload.id)
        .await
        .unwrap();
    assert!(store
        .complete_unknown_disposition(&replay_disposition)
        .await
        .unwrap());

    let dead_owner = format!("user:test-{}", Uuid::new_v4());
    let dead = store
        .create_upload(
            &dead_owner,
            "dead-letter.bin",
            9,
            Uuid::new_v4(),
            &"8".repeat(64),
        )
        .await
        .unwrap();
    let dead_digest = hex::encode(Sha256::digest(Uuid::new_v4().as_bytes()));
    sqlx::query(
        "UPDATE upload_sessions SET state='upstream_uncertain',assembled_sha256=$2,\
         updated_at=now()-interval '25 hours' WHERE id=$1",
    )
    .bind(dead.upload.id)
    .bind(&dead_digest)
    .execute(&pool)
    .await
    .unwrap();
    let dead_upload = store.get_upload(&dead_owner, dead.upload.id).await.unwrap();
    assert!(!store
        .expire_uncertain_upload(&dead_upload, false)
        .await
        .unwrap());
    let dead_operation: Uuid = sqlx::query_scalar(
        "UPDATE sample_objects SET lifecycle='deleting',delete_after=now()+interval '10 minutes' \
         WHERE sha256=$1 RETURNING delete_operation_id",
    )
    .bind(&dead_digest)
    .fetch_one(&pool)
    .await
    .unwrap();
    let dead_claim = SampleDeleteClaim {
        sample_id: format!("sha256:{dead_digest}"),
        sha256: dead_digest.clone(),
        delete_operation_id: dead_operation,
    };
    store
        .finish_sample_delete(&dead_claim, false, Some("server_invariant_violation"))
        .await
        .unwrap();
    let dead_state: (String, bool, i64) = sqlx::query_as(
        "SELECT s.lifecycle,s.delete_after='infinity'::timestamptz,q.reserved_bytes \
         FROM sample_objects s JOIN upload_sessions u ON u.assembled_sha256=s.sha256 \
         JOIN owner_quotas q ON q.owner_sub=u.owner_sub WHERE u.id=$1",
    )
    .bind(dead.upload.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(dead_state, ("delete_failed".into(), true, 9));

    let cancel_owner = format!("user:test-{}", Uuid::new_v4());
    let cancel = store
        .create_upload(
            &cancel_owner,
            "cancel-recovery.bin",
            1,
            Uuid::new_v4(),
            &"9".repeat(64),
        )
        .await
        .unwrap();
    store
        .begin_cancel(&cancel_owner, cancel.upload.id)
        .await
        .unwrap();
    assert!(store
        .cancellable_requested_uploads(100)
        .await
        .unwrap()
        .contains(&(cancel_owner, cancel.upload.id)));
}

#[tokio::test]
async fn postgres_quota_warning_claims_once_per_owner_and_utc_day() {
    let database_url = std::env::var("STRAD_TEST_DATABASE_URL")
        .expect("STRAD_TEST_DATABASE_URL is required; PostgreSQL contract tests never skip");
    migrations::run(&database_url).await.unwrap();
    let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
    let mut _test_lock = pool.acquire().await.unwrap();
    sqlx::query("SELECT pg_advisory_lock(823202613)")
        .execute(&mut *_test_lock)
        .await
        .unwrap();
    let store = Store::from_pool(pool.clone());
    let owner = format!("user:test-{}", Uuid::new_v4());
    let first = store
        .create_upload(&owner, "quota-one.bin", 1, Uuid::new_v4(), &"a".repeat(64))
        .await
        .unwrap();
    let second = store
        .create_upload(&owner, "quota-two.bin", 1, Uuid::new_v4(), &"b".repeat(64))
        .await
        .unwrap();
    sqlx::query("UPDATE owner_quotas SET used_bytes=$2 WHERE owner_sub=$1")
        .bind(&owner)
        .bind(OWNER_BYTES * 80 / 100)
        .execute(&pool)
        .await
        .unwrap();
    for created in [&first, &second] {
        let digest = hex::encode(Sha256::digest(created.upload.id.as_bytes()));
        let lease = Uuid::new_v4();
        sqlx::query(
            "UPDATE upload_sessions SET state='forwarding',assembled_sha256=$2,lease_token=$3,\
             leased_at=now(),lease_until=now()+interval '5 minutes' WHERE id=$1",
        )
        .bind(created.upload.id)
        .bind(&digest)
        .bind(lease)
        .execute(&pool)
        .await
        .unwrap();
        store
            .complete_finalize(&owner, created.upload.id, Some(lease), &digest, "elf")
            .await
            .unwrap();
    }
    let claim_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM notification_claims WHERE owner_sub=$1 AND kind='storage_80pct'",
    )
    .bind(&owner)
    .fetch_one(&pool)
    .await
    .unwrap();
    let warning_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM outbox WHERE owner_sub=$1 AND event_type='quota.storage_80pct'",
    )
    .bind(&owner)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(claim_count, 1);
    assert_eq!(warning_count, 1);
}

#[tokio::test]
async fn postgres_promote_and_checkpoint_uncertain_reconcile_the_original_operations() {
    let database_url = std::env::var("STRAD_TEST_DATABASE_URL")
        .expect("STRAD_TEST_DATABASE_URL is required; PostgreSQL contract tests never skip");
    migrations::run(&database_url).await.unwrap();
    let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
    let mut _test_lock = pool.acquire().await.unwrap();
    sqlx::query("SELECT pg_advisory_lock(823202613)")
        .execute(&mut *_test_lock)
        .await
        .unwrap();
    let store = Store::from_pool(pool.clone());

    let start_owner = format!("user:test-{}", Uuid::new_v4());
    let start_created = store
        .create_upload(
            &start_owner,
            "start.bin",
            1,
            Uuid::new_v4(),
            &"0".repeat(64),
        )
        .await
        .unwrap();
    sqlx::query("UPDATE analyses SET state='start_uncertain' WHERE id=$1")
        .bind(start_created.analysis.id)
        .execute(&pool)
        .await
        .unwrap();
    let start_analysis = store
        .get_analysis(&start_owner, start_created.analysis.id)
        .await
        .unwrap();
    let start_operation = Uuid::new_v4();
    store
        .begin_worker_operation(&start_analysis, "start", start_operation, &"1".repeat(64))
        .await
        .unwrap();
    store
        .finish_worker_operation(&start_analysis, "start", start_operation, true, None)
        .await
        .unwrap();

    let promote_owner = format!("user:test-{}", Uuid::new_v4());
    let promote_created = store
        .create_upload(
            &promote_owner,
            "promote.bin",
            1,
            Uuid::new_v4(),
            &"c".repeat(64),
        )
        .await
        .unwrap();
    sqlx::query(
        "UPDATE analyses SET state='degraded',plan_id='plan-promote',\
         current_stage='enrich_static',latest_stage='enrich_static' WHERE id=$1",
    )
    .bind(promote_created.analysis.id)
    .execute(&pool)
    .await
    .unwrap();
    let promote_analysis = store
        .get_analysis(&promote_owner, promote_created.analysis.id)
        .await
        .unwrap();
    let promote_operation = Uuid::new_v4();
    store
        .begin_worker_operation(
            &promote_analysis,
            "promote",
            promote_operation,
            &"d".repeat(64),
        )
        .await
        .unwrap();
    store
        .finish_worker_operation(&promote_analysis, "promote", promote_operation, true, None)
        .await
        .unwrap();

    let checkpoint_owner = format!("user:test-{}", Uuid::new_v4());
    let checkpoint_created = store
        .create_upload(
            &checkpoint_owner,
            "checkpoint.bin",
            1,
            Uuid::new_v4(),
            &"e".repeat(64),
        )
        .await
        .unwrap();
    sqlx::query(
        "UPDATE analyses SET state='degraded',plan_id='plan-checkpoint',\
         current_stage='function_map',latest_stage='function_map' WHERE id=$1",
    )
    .bind(checkpoint_created.analysis.id)
    .execute(&pool)
    .await
    .unwrap();
    let checkpoint_analysis = store
        .get_analysis(&checkpoint_owner, checkpoint_created.analysis.id)
        .await
        .unwrap();
    let checkpoint_operation = Uuid::new_v4();
    store
        .begin_worker_operation(
            &checkpoint_analysis,
            "checkpoint",
            checkpoint_operation,
            &"f".repeat(64),
        )
        .await
        .unwrap();
    store
        .finish_worker_operation(
            &checkpoint_analysis,
            "checkpoint",
            checkpoint_operation,
            true,
            None,
        )
        .await
        .unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mock = tokio::spawn(async move {
        for _ in 0..3 {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                let mut chunk = [0u8; 2048];
                let count = socket.read(&mut chunk).await.unwrap();
                assert!(count > 0);
                request.extend_from_slice(&chunk[..count]);
                if request.windows(4).any(|part| part == b"\r\n\r\n") {
                    break;
                }
            }
            let first_line = std::str::from_utf8(&request)
                .unwrap()
                .lines()
                .next()
                .unwrap();
            let operation = first_line
                .split_whitespace()
                .nth(1)
                .and_then(|path| path.rsplit('/').next())
                .and_then(|id| Uuid::parse_str(id).ok())
                .unwrap();
            let result = if operation == start_operation {
                serde_json::json!({
                    "plan_id":"plan-start",
                    "stage_statuses":[],
                    "function_index_ready":false,
                    "current_stage":null,
                    "latest_stage":null,
                    "artifact_selectors":[],
                    "artifact_selector_summary":null
                })
            } else if operation == promote_operation {
                serde_json::json!({
                    "plan_id":"plan-promote",
                    "stage_statuses":[],
                    "function_index_ready":false,
                    "current_stage":"enrich_static",
                    "latest_stage":"enrich_static",
                    "artifact_selectors":[],
                    "artifact_selector_summary":null
                })
            } else {
                assert_eq!(operation, checkpoint_operation);
                serde_json::json!({
                    "case_id":"case-original-operation",
                    "checkpoint_artifact_id":"artifact-original-operation"
                })
            };
            let body = serde_json::to_vec(&serde_json::json!({
                "ok":true,
                "data":{
                    "operation_id":operation,
                    "state":"succeeded",
                    "result":result
                }
            }))
            .unwrap();
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            socket.write_all(headers.as_bytes()).await.unwrap();
            socket.write_all(&body).await.unwrap();
        }
    });
    let temporary = tempfile::tempdir().unwrap();
    let config = bridge_test_config(
        &database_url,
        &format!("http://{address}"),
        temporary.path(),
    );
    let bridge = BridgeClient::new(&config).unwrap();
    let controller = AnalysisController::new(store.clone(), bridge);
    assert_eq!(controller.reconcile_uncertain().await.unwrap(), 3);
    mock.await.unwrap();

    let start_result: (String, Option<String>, String, Uuid) = sqlx::query_as(
        "SELECT a.state,a.plan_id,i.state,i.operation_id FROM analyses a JOIN idempotency_operations i \
         ON i.owner_sub=a.owner_sub AND i.scope='worker:start:'||a.id::text WHERE a.id=$1",
    )
    .bind(start_created.analysis.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        start_result,
        (
            "analyzing".into(),
            Some("plan-start".into()),
            "completed".into(),
            start_operation,
        )
    );

    let promote_result: (String, String, Uuid) = sqlx::query_as(
        "SELECT a.state,i.state,i.operation_id FROM analyses a JOIN idempotency_operations i \
         ON i.owner_sub=a.owner_sub AND i.scope='worker:promote:'||a.id::text WHERE a.id=$1",
    )
    .bind(promote_created.analysis.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        promote_result,
        ("analyzing".into(), "completed".into(), promote_operation)
    );
    let checkpoint_result: (String, Option<String>, Option<String>, String, Uuid) = sqlx::query_as(
        "SELECT a.state,a.case_id,a.case_artifact_id,i.state,i.operation_id FROM analyses a \
             JOIN idempotency_operations i ON i.owner_sub=a.owner_sub \
             AND i.scope='worker:checkpoint:'||a.id::text WHERE a.id=$1",
    )
    .bind(checkpoint_created.analysis.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        checkpoint_result,
        (
            "analyzed".into(),
            Some("case-original-operation".into()),
            Some("artifact-original-operation".into()),
            "completed".into(),
            checkpoint_operation,
        )
    );
}

#[tokio::test]
async fn postgres_chat_terminal_citation_retry_delete_replay_and_promote_order() {
    let database_url = std::env::var("STRAD_TEST_DATABASE_URL")
        .expect("STRAD_TEST_DATABASE_URL is required; PostgreSQL contract tests never skip");
    migrations::run(&database_url).await.unwrap();
    let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
    let mut _test_lock = pool.acquire().await.unwrap();
    sqlx::query("SELECT pg_advisory_lock(823202613)")
        .execute(&mut *_test_lock)
        .await
        .unwrap();
    let store = Store::from_pool(pool.clone());
    let owner = format!("user:test-{}", Uuid::new_v4());
    let created = store
        .create_upload(&owner, "chat.bin", 1, Uuid::new_v4(), &"2".repeat(64))
        .await
        .unwrap();
    sqlx::query("UPDATE analyses SET state='degraded',plan_id='plan-order' WHERE id=$1")
        .bind(created.analysis.id)
        .execute(&pool)
        .await
        .unwrap();
    let promote_operation = Uuid::new_v4();
    store
        .begin_promote(
            &owner,
            created.analysis.id,
            promote_operation,
            &"3".repeat(64),
        )
        .await
        .unwrap();
    let promoting: (String, String) = sqlx::query_as(
        "SELECT a.state,o.event_type FROM analyses a JOIN LATERAL \
         (SELECT event_type FROM outbox WHERE aggregate_id=a.id ORDER BY created_at DESC,id DESC LIMIT 1) o \
         ON true WHERE a.id=$1",
    )
    .bind(created.analysis.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(promoting, ("promoting".into(), "analysis.promoting".into()));
    store
        .complete_promote(&owner, created.analysis.id, promote_operation, true)
        .await
        .unwrap();

    let conversation = store
        .create_conversation(
            &owner,
            created.analysis.id,
            "Durable chat",
            "binary-analyst",
            Uuid::new_v4(),
            &"4".repeat(64),
        )
        .await
        .unwrap();
    let mismatched = store
        .create_turn(
            &owner,
            created.analysis.id,
            conversation.id,
            Uuid::new_v4(),
            1,
            &"5".repeat(64),
            "test-model",
            "Explain the binary.",
        )
        .await
        .unwrap();
    let frozen = serde_json::json!({
        "model":"test-model",
        "messages":[{"role":"user","content":"bounded"}],
        "max_tokens":2048,
        "stream":true,
        "user":"a".repeat(64)
    });
    sqlx::query("UPDATE turns SET frozen_request=$2,frozen_prompt_sha256=$3 WHERE id=$1")
        .bind(mismatched.id)
        .bind(&frozen)
        .bind("0".repeat(64))
        .execute(&pool)
        .await
        .unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let config = bridge_test_config(&database_url, "http://127.0.0.1:9", temporary.path());
    let budgeter = TokenBudgeter::load().unwrap();
    let engine = ChatEngine::new(
        store.clone(),
        BridgeClient::new(&config).unwrap(),
        NewApiClient::new(&config).unwrap(),
        budgeter,
    );
    assert!(engine.run_once().await.unwrap());
    let terminal: (String, Option<String>, String) = sqlx::query_as(
        "SELECT t.state,t.error_code,m.status FROM turns t JOIN messages m ON m.turn_id=t.id \
         AND m.role='assistant' WHERE t.id=$1",
    )
    .bind(mismatched.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        terminal,
        (
            "failed".into(),
            Some("frozen_prompt_mismatch".into()),
            "failed".into()
        )
    );

    let frozen_model_mismatch = store
        .create_turn(
            &owner,
            created.analysis.id,
            conversation.id,
            Uuid::new_v4(),
            2,
            &"6".repeat(64),
            "glm-5.2",
            "Keep the selected model.",
        )
        .await
        .unwrap();
    let other_model_request = FrozenChatRequest {
        model: "other-model".into(),
        messages: vec![ChatMessage {
            role: "user".into(),
            content: "bounded".into(),
        }],
        max_tokens: 2048,
        stream: true,
        user: "b".repeat(64),
    };
    let other_model_value = serde_json::to_value(&other_model_request).unwrap();
    let other_model_sha = hex::encode(Sha256::digest(
        serde_json::to_vec(&other_model_request).unwrap(),
    ));
    sqlx::query("UPDATE turns SET frozen_request=$2,frozen_prompt_sha256=$3 WHERE id=$1")
        .bind(frozen_model_mismatch.id)
        .bind(other_model_value)
        .bind(other_model_sha)
        .execute(&pool)
        .await
        .unwrap();
    assert!(engine.run_once().await.unwrap());
    let frozen_failure: (String, Option<String>) =
        sqlx::query_as("SELECT state,error_code FROM turns WHERE id=$1")
            .bind(frozen_model_mismatch.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        frozen_failure,
        ("failed".into(), Some("frozen_model_mismatch".into()))
    );

    let selected_model = "glm-5.2";
    let audited_operation = Uuid::new_v4();
    let audited = store
        .create_turn(
            &owner,
            created.analysis.id,
            conversation.id,
            audited_operation,
            3,
            &"7".repeat(64),
            selected_model,
            "Audit the selected model.",
        )
        .await
        .unwrap();
    assert_eq!(audited.model_alias, selected_model);
    let replay = store
        .idempotency_replay(
            &owner,
            "POST /api/analyses/:id/conversations/:cid/turns",
            audited_operation,
            &"7".repeat(64),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(replay.body.unwrap()["model_alias"], selected_model);
    let first_claim = store.claim_turn().await.unwrap().unwrap();
    assert_eq!(first_claim.id, audited.id);
    assert_eq!(first_claim.model_alias, selected_model);
    store
        .release_turn_for_retry(&first_claim, "test_retry")
        .await
        .unwrap();
    let retry_claim = store.claim_turn().await.unwrap().unwrap();
    assert_eq!(retry_claim.id, audited.id);
    assert_eq!(retry_claim.model_alias, selected_model);
    store
        .finish_turn(
            &retry_claim,
            "completed",
            "complete",
            None,
            7,
            3,
            selected_model,
        )
        .await
        .unwrap();
    let usage_model: String =
        sqlx::query_scalar("SELECT model_alias FROM ai_usage WHERE turn_id=$1")
            .bind(audited.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(usage_model, selected_model);

    let cited = store
        .create_turn(
            &owner,
            created.analysis.id,
            conversation.id,
            Uuid::new_v4(),
            4,
            &"8".repeat(64),
            "test-model",
            "Give one fact.",
        )
        .await
        .unwrap();
    sqlx::query("UPDATE turns SET state='completed',terminal_at=now() WHERE id=$1")
        .bind(cited.id)
        .execute(&pool)
        .await
        .unwrap();
    let assistant_id: Uuid = sqlx::query_scalar(
        "UPDATE messages SET status='complete',content='Fact [ref:missing].',\
         updated_at=now()-interval '31 seconds' WHERE turn_id=$1 AND role='assistant' RETURNING id",
    )
    .bind(cited.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let first_retry = store.unresolved_citation_work().await.unwrap().unwrap();
    assert_eq!(first_retry.0.id, cited.id);
    store
        .save_citation(
            assistant_id,
            created.analysis.id,
            &owner,
            "ref:missing",
            None,
            None,
        )
        .await
        .unwrap();
    assert!(store.unresolved_citation_work().await.unwrap().is_none());
    sqlx::query("UPDATE citations SET created_at=now()-interval '31 seconds' WHERE message_id=$1")
        .bind(assistant_id)
        .execute(&pool)
        .await
        .unwrap();
    let durable_retry = store.unresolved_citation_work().await.unwrap().unwrap();
    assert_eq!(durable_retry.0.id, cited.id);

    let delete_operation = Uuid::new_v4();
    let delete_sha = "7".repeat(64);
    store
        .delete_conversation(
            &owner,
            created.analysis.id,
            conversation.id,
            delete_operation,
            &delete_sha,
        )
        .await
        .unwrap();
    assert!(store
        .get_conversation(&owner, created.analysis.id, conversation.id)
        .await
        .is_err());
    let replay = store
        .idempotency_replay(
            &owner,
            "POST /api/analyses/:id/conversations/:cid/delete",
            delete_operation,
            &delete_sha,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(replay.status, 202);
}

#[tokio::test]
async fn postgres_ssr_projection_and_server_operation_claims_are_owner_scoped() {
    let database_url = std::env::var("STRAD_TEST_DATABASE_URL")
        .expect("STRAD_TEST_DATABASE_URL is required; PostgreSQL contract tests never skip");
    migrations::run(&database_url).await.unwrap();
    let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
    let mut _test_lock = pool.acquire().await.unwrap();
    sqlx::query("SELECT pg_advisory_lock(823202613)")
        .execute(&mut *_test_lock)
        .await
        .unwrap();
    let store = Store::from_pool(pool.clone());
    let owner = format!("user:ssr-{}", Uuid::new_v4());
    let other = format!("user:ssr-other-{}", Uuid::new_v4());
    let created = store
        .create_upload(
            &owner,
            "projection.bin",
            17,
            Uuid::new_v4(),
            &"8".repeat(64),
        )
        .await
        .unwrap();
    let quota = store.owner_quota(&owner).await.unwrap();
    assert_eq!(quota.used_bytes, 0);
    assert_eq!(quota.reserved_bytes, 17);
    assert_eq!(quota.analysis_count, 1);
    let upload_status = store
        .upload_status(&owner, created.upload.id)
        .await
        .unwrap();
    assert_eq!(
        upload_status.finalize_operation_id,
        strad::store::server_operation_id("upload-finalize", &created.upload.id.to_string())
    );
    assert_ne!(
        upload_status.finalize_operation_id,
        upload_status.cancel_operation_id
    );

    let conversation = store
        .create_conversation(
            &owner,
            created.analysis.id,
            "Projection",
            "binary-analyst",
            Uuid::new_v4(),
            &"9".repeat(64),
        )
        .await
        .unwrap();
    let turn = store
        .create_turn(
            &owner,
            created.analysis.id,
            conversation.id,
            Uuid::new_v4(),
            1,
            &"a".repeat(64),
            "test-model",
            "Question",
        )
        .await
        .unwrap();
    let assistant_id: Uuid = sqlx::query_scalar(
        "UPDATE messages SET status='complete',content='Fact [ref:projection].' \
         WHERE turn_id=$1 AND role='assistant' RETURNING id",
    )
    .bind(turn.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let artifact_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO artifacts(id,analysis_id,owner_sub,upstream_artifact_id,artifact_type,\
         artifact_ref,path,sha256,mime,metadata) VALUES($1,$2,$3,'upstream-projection',\
         'summary','ref:projection','projection.json',$4,'application/json',$5)",
    )
    .bind(artifact_id)
    .bind(created.analysis.id)
    .bind(&owner)
    .bind("b".repeat(64))
    .bind(serde_json::json!({"summary":"bounded"}))
    .execute(&pool)
    .await
    .unwrap();
    let artifact = store
        .artifacts(&owner, created.analysis.id)
        .await
        .unwrap()
        .pop()
        .unwrap();
    store
        .save_citation(
            assistant_id,
            created.analysis.id,
            &owner,
            "ref:projection",
            Some(&artifact),
            Some(("bounded", 0, 7, &"c".repeat(64))),
        )
        .await
        .unwrap();
    let (messages, next_client_seq) = store
        .conversation_projection(&owner, created.analysis.id, conversation.id)
        .await
        .unwrap();
    assert_eq!(next_client_seq, 2);
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0]["role"], "user");
    assert_eq!(
        messages[1]["citations"][0]["citation_ref"],
        "ref:projection"
    );
    assert_eq!(messages[1]["citations"][0]["resolved"], true);
    assert!(store
        .conversation_projection(&other, created.analysis.id, conversation.id)
        .await
        .is_err());

    let operation_id =
        strad::store::server_operation_id("upload-finalize", &created.upload.id.to_string());
    let scope = "POST /api/uploads/:id/finalize";
    let request_sha = "d".repeat(64);
    store
        .claim_http_operation(&owner, scope, operation_id, &request_sha)
        .await
        .unwrap();
    assert!(store
        .claim_http_operation(&owner, scope, operation_id, &request_sha)
        .await
        .is_err());
    sqlx::query(
        "UPDATE idempotency_operations SET lease_until=now()-interval '1 second' \
         WHERE owner_sub=$1 AND scope=$2 AND operation_id=$3",
    )
    .bind(&owner)
    .bind(scope)
    .bind(operation_id)
    .execute(&pool)
    .await
    .unwrap();
    assert!(store
        .idempotency_replay(&owner, scope, operation_id, &request_sha)
        .await
        .unwrap()
        .is_none());
    store
        .claim_http_operation(&owner, scope, operation_id, &request_sha)
        .await
        .unwrap();
    store
        .complete_http_operation(
            &owner,
            scope,
            operation_id,
            &request_sha,
            202,
            &format!("/analyses/{}", created.analysis.id),
            &serde_json::json!({"state":"accepted"}),
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .idempotency_replay(&owner, scope, operation_id, &request_sha)
            .await
            .unwrap()
            .unwrap()
            .status,
        202
    );
}

#[tokio::test]
async fn postgres_artifact_lookup_binds_owner_analysis_and_artifact() {
    let database_url = std::env::var("STRAD_TEST_DATABASE_URL")
        .expect("STRAD_TEST_DATABASE_URL is required; PostgreSQL contract tests never skip");
    migrations::run(&database_url).await.unwrap();
    let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
    let mut _test_lock = pool.acquire().await.unwrap();
    sqlx::query("SELECT pg_advisory_lock(823202613)")
        .execute(&mut *_test_lock)
        .await
        .unwrap();
    let store = Store::from_pool(pool.clone());
    let owner = format!("user:artifact-{}", Uuid::new_v4());
    let created = store
        .create_upload(&owner, "artifact.bin", 1, Uuid::new_v4(), &"d".repeat(64))
        .await
        .unwrap();
    let artifact_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO artifacts(id,analysis_id,owner_sub,upstream_artifact_id,artifact_type,\
         artifact_ref,path,sha256,mime,metadata) VALUES($1,$2,$3,'upstream-owned',\
         'summary','ref:owned','owned.json',$4,'application/json','{}'::jsonb)",
    )
    .bind(artifact_id)
    .bind(created.analysis.id)
    .bind(&owner)
    .bind("e".repeat(64))
    .execute(&pool)
    .await
    .unwrap();

    let artifact = store
        .get_artifact(&owner, created.analysis.id, artifact_id)
        .await
        .unwrap();
    assert_eq!(artifact.upstream_artifact_id, "upstream-owned");
    for (candidate_owner, candidate_analysis) in [
        (
            format!("user:other-{}", Uuid::new_v4()),
            created.analysis.id,
        ),
        (owner.clone(), Uuid::new_v4()),
    ] {
        let error = store
            .get_artifact(&candidate_owner, candidate_analysis, artifact_id)
            .await
            .unwrap_err();
        assert_eq!(error.code(), "not_found");
    }
}

#[tokio::test]
async fn postgres_schema_v1_turn_models_upgrade_and_ledger_are_fail_closed() {
    let base_database_url = std::env::var("STRAD_TEST_DATABASE_URL")
        .expect("STRAD_TEST_DATABASE_URL is required; PostgreSQL contract tests never skip");
    let schema = format!("upgrade_{}", Uuid::new_v4().simple());
    let admin_pool = sqlx::PgPool::connect(&base_database_url).await.unwrap();
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin_pool)
        .await
        .unwrap();
    let separator = if base_database_url.contains('?') {
        '&'
    } else {
        '?'
    };
    let database_url = format!("{base_database_url}{separator}options=-csearch_path%3D{schema}");
    let mut connection = sqlx::PgConnection::connect(&database_url).await.unwrap();
    connection
        .execute(
            "CREATE TABLE strad_schema_migrations(\
             version bigint PRIMARY KEY,\
             name text NOT NULL,\
             sha256 char(64) NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),\
             applied_at timestamptz NOT NULL)",
        )
        .await
        .unwrap();
    let v1_sql = include_str!("../migrations/0001_strad_core.sql");
    connection.execute(v1_sql).await.unwrap();
    sqlx::query(
        "INSERT INTO strad_schema_migrations(version,name,sha256,applied_at) \
         VALUES(1,'strad_core',$1,now())",
    )
    .bind(hex::encode(Sha256::digest(v1_sql.as_bytes())))
    .execute(&mut connection)
    .await
    .unwrap();

    let owner = format!("user:test-{}", Uuid::new_v4());
    let upload_id = Uuid::new_v4();
    let analysis_id = Uuid::new_v4();
    let conversation_id = Uuid::new_v4();
    let frozen_turn_id = Uuid::new_v4();
    let usage_turn_id = Uuid::new_v4();
    let legacy_turn_id = Uuid::new_v4();
    let mut tx = connection.begin().await.unwrap();
    sqlx::query("INSERT INTO owner_quotas(owner_sub) VALUES($1)")
        .bind(&owner)
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO upload_sessions(\
           id,operation_id,owner_sub,request_sha256,filename,total_bytes,chunk_count,\
           reserved_bytes,state,staging_key,analysis_id,expires_at) \
         VALUES($1,$2,$3,$4,'legacy.bin',1,1,1,'reserved',$5,$6,now()+interval '1 hour')",
    )
    .bind(upload_id)
    .bind(Uuid::new_v4())
    .bind(&owner)
    .bind("a".repeat(64))
    .bind(upload_id.to_string())
    .bind(analysis_id)
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO analyses(id,owner_sub,upload_id,display_name,state,retention_until) \
         VALUES($1,$2,$3,'legacy.bin','created',now()+interval '1 day')",
    )
    .bind(analysis_id)
    .bind(&owner)
    .bind(upload_id)
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO conversations(id,analysis_id,owner_sub,title,persona_id) \
         VALUES($1,$2,$3,'Legacy','binary-analyst')",
    )
    .bind(conversation_id)
    .bind(analysis_id)
    .bind(&owner)
    .execute(&mut *tx)
    .await
    .unwrap();
    for (client_seq, turn_id, frozen_request) in [
        (
            1_i64,
            frozen_turn_id,
            Some(serde_json::json!({"model":"frozen-model"})),
        ),
        (2_i64, usage_turn_id, None),
        (3_i64, legacy_turn_id, None),
    ] {
        sqlx::query(
            "INSERT INTO turns(\
               id,conversation_id,analysis_id,owner_sub,client_seq,operation_id,\
               request_sha256,state,frozen_request) \
             VALUES($1,$2,$3,$4,$5,$6,$7,'accepted',$8)",
        )
        .bind(turn_id)
        .bind(conversation_id)
        .bind(analysis_id)
        .bind(&owner)
        .bind(client_seq)
        .bind(Uuid::new_v4())
        .bind(format!("{client_seq:x}").repeat(64))
        .bind(frozen_request)
        .execute(&mut *tx)
        .await
        .unwrap();
    }
    sqlx::query(
        "INSERT INTO ai_usage(\
           owner_sub,analysis_id,turn_id,prompt_tokens,completion_tokens,model_alias) \
         VALUES($1,$2,$3,1,1,'usage-model')",
    )
    .bind(&owner)
    .bind(analysis_id)
    .bind(usage_turn_id)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    drop(connection);

    migrations::run(&database_url).await.unwrap();
    let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
    let migrated: Vec<(i64, String)> =
        sqlx::query_as("SELECT client_seq,model_alias FROM turns ORDER BY client_seq")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        migrated,
        vec![
            (1, "frozen-model".into()),
            (2, "usage-model".into()),
            (3, "openai/gpt-5.6-luna".into()),
        ]
    );
    assert!(migrations::schema_compatible(&pool).await);
    assert!(
        sqlx::query("UPDATE turns SET model_alias='bad model' WHERE id=$1")
            .bind(legacy_turn_id)
            .execute(&pool)
            .await
            .is_err()
    );
    migrations::run(&database_url).await.unwrap();
    let ledger: Vec<(i64, String, String)> =
        sqlx::query_as("SELECT version,name,sha256 FROM strad_schema_migrations ORDER BY version")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(ledger.len(), 4);
    assert_eq!(ledger[0].0, 1);
    assert_eq!(ledger[0].1, "strad_core");
    assert_eq!(ledger[1].0, 2);
    assert_eq!(ledger[1].1, "turn_model_alias");
    assert_eq!(
        ledger[1].2,
        hex::encode(Sha256::digest(
            include_str!("../migrations/0002_turn_model_alias.sql").as_bytes()
        ))
    );
    assert_eq!(ledger[2].0, 3);
    assert_eq!(ledger[2].1, "application_owner_operations");
    assert_eq!(
        ledger[2].2,
        hex::encode(Sha256::digest(
            include_str!("../migrations/0003_application_owner_operations.sql").as_bytes()
        ))
    );
    assert_eq!(ledger[3].0, 4);
    assert_eq!(ledger[3].1, "application_turn_executions");
    assert_eq!(
        ledger[3].2,
        hex::encode(Sha256::digest(
            include_str!("../migrations/0004_application_turn_executions.sql").as_bytes()
        ))
    );

    sqlx::query("DELETE FROM strad_schema_migrations WHERE version=1")
        .execute(&pool)
        .await
        .unwrap();
    assert!(!migrations::schema_compatible(&pool).await);
    assert!(migrations::run(&database_url)
        .await
        .unwrap_err()
        .contains("contiguous prefix"));
}

fn bridge_test_config(database_url: &str, bridge_url: &str, root: &std::path::Path) -> Config {
    Config {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        database_url: database_url.into(),
        gateway_hmac_key: vec![b'i'; 32],
        gateway_zone_hmac_key: vec![b'z'; 32],
        verdict_decision_token: "v".repeat(32),
        verdict_url: "http://verdict:9140/api/v2/check".into(),
        bridge_token: "b".repeat(32),
        bridge_url: bridge_url.into(),
        bridge_upload_timeout: std::time::Duration::from_secs(900),
        newapi_key: "n".repeat(32),
        newapi_url: "http://newapi:9080/v1/chat/completions".into(),
        newapi_model: "test-model".into(),
        newapi_context_tokens: 32_768,
        rikune_file_server_api_key: "f".repeat(32),
        facade_token: "q".repeat(32),
        governance_reporting_token: "r".repeat(32),
        access_execution_fence_token: "x".repeat(32),
        access_execution_fence_url:
            "https://access.w33d.xyz/internal/v1/application-execution-fence/check".into(),
        upload_root: root.join("uploads"),
        template_root: root.join("templates"),
        canonical_host: "rikune.w33d.xyz".into(),
        canonical_route: "rikune-root".into(),
        expected_zone: "external".into(),
        session_lease: std::time::Duration::from_secs(1800),
        session_ttl: std::time::Duration::from_secs(86400),
    }
}

#[derive(Clone)]
struct ContractUpstream {
    active: Arc<AtomicBool>,
    fence_claims: Arc<AtomicUsize>,
    durable_fence: Option<sqlx::PgPool>,
    fence_entered: Option<Arc<tokio::sync::Notify>>,
    fence_release: Option<Arc<tokio::sync::Notify>>,
    fence_contract_ok: Arc<AtomicBool>,
    seen_decision_digest: Arc<tokio::sync::Mutex<Option<String>>>,
    fence_response_mode: Arc<AtomicUsize>,
    bridge_delay: Duration,
    bridge_calls: Arc<AtomicUsize>,
    model_calls: Arc<AtomicUsize>,
    model_interrupted: Arc<AtomicBool>,
    revoke_during_ground: Arc<AtomicBool>,
}

impl ContractUpstream {
    fn active() -> Self {
        Self {
            active: Arc::new(AtomicBool::new(true)),
            fence_claims: Arc::new(AtomicUsize::new(0)),
            durable_fence: None,
            fence_entered: None,
            fence_release: None,
            fence_contract_ok: Arc::new(AtomicBool::new(true)),
            seen_decision_digest: Arc::new(tokio::sync::Mutex::new(None)),
            fence_response_mode: Arc::new(AtomicUsize::new(0)),
            bridge_delay: Duration::ZERO,
            bridge_calls: Arc::new(AtomicUsize::new(0)),
            model_calls: Arc::new(AtomicUsize::new(0)),
            model_interrupted: Arc::new(AtomicBool::new(false)),
            revoke_during_ground: Arc::new(AtomicBool::new(false)),
        }
    }

    fn with_bridge_delay(bridge_delay: Duration) -> Self {
        Self {
            bridge_delay,
            ..Self::active()
        }
    }

    fn barrier(pool: sqlx::PgPool) -> Self {
        Self {
            durable_fence: Some(pool),
            fence_entered: Some(Arc::new(tokio::sync::Notify::new())),
            fence_release: Some(Arc::new(tokio::sync::Notify::new())),
            ..Self::active()
        }
    }
}

async fn contract_fence(
    State(state): State<ContractUpstream>,
    headers: HeaderMap,
    Json(envelope): Json<ExecutionEnvelopeV1>,
) -> Json<Value> {
    let contract_ok = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        == Some(&format!("Bearer {}", "x".repeat(32)))
        && headers
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok())
            == Some("no-store")
        && headers
            .get(header::PRAGMA)
            .and_then(|value| value.to_str().ok())
            == Some("no-cache");
    state.fence_contract_ok.store(contract_ok, Ordering::SeqCst);
    if envelope.subject_version <= 0 {
        return Json(json!({"active":false}));
    }
    state.fence_claims.fetch_add(1, Ordering::SeqCst);
    *state.seen_decision_digest.lock().await = Some(envelope.decision_digest.clone());
    if let Some(entered) = &state.fence_entered {
        entered.notify_one();
    }
    if let Some(release) = &state.fence_release {
        release.notified().await;
    }
    let active = match &state.durable_fence {
        Some(pool) => sqlx::query_scalar(
            "SELECT active FROM test_access_execution_fence WHERE application_sub=$1 \
             AND decision_digest=$2",
        )
        .bind(&envelope.application_sub)
        .bind(&envelope.decision_digest)
        .fetch_optional(pool)
        .await
        .unwrap()
        .unwrap_or(false),
        None => state.active.load(Ordering::SeqCst),
    };
    if !active {
        return Json(json!({"active":false}));
    }
    let mut response = json!({
        "active":true,
        "subject_version":envelope.subject_version,
        "policy_epoch":envelope.policy_epoch,
        "revocation_epoch":envelope.revocation_epoch,
        "checked_at":OffsetDateTime::now_utc().unix_timestamp()
    });
    match state.fence_response_mode.load(Ordering::SeqCst) {
        1 => {
            response
                .as_object_mut()
                .unwrap()
                .insert("unknown".into(), json!(true));
        }
        2 => response["subject_version"] = json!(envelope.subject_version + 1),
        3 => {
            response["checked_at"] = json!(OffsetDateTime::now_utc()
                .unix_timestamp()
                .saturating_sub(60))
        }
        4 => {
            response.as_object_mut().unwrap().remove("checked_at");
        }
        _ => {}
    }
    Json(response)
}

async fn contract_bridge_upload(
    State(state): State<ContractUpstream>,
    headers: HeaderMap,
) -> impl IntoResponse {
    state.bridge_calls.fetch_add(1, Ordering::SeqCst);
    if !state.bridge_delay.is_zero() {
        tokio::time::sleep(state.bridge_delay).await;
    }
    let digest = headers
        .get("x-content-sha256")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .unwrap_or_else(|| "0".repeat(64));
    Json(json!({
        "ok":true,
        "data":{"sample_id":format!("sha256:{digest}"),"file_type":"elf"},
        "error":null
    }))
}

async fn contract_verdict(headers: HeaderMap) -> impl IntoResponse {
    if headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        != Some(format!("Bearer {}", "v".repeat(32)).as_str())
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    Json(json!({
        "decision":"Deny",
        "reason":"readiness sentinel",
        "epoch":1,
        "evaluated_at":OffsetDateTime::now_utc().unix_timestamp(),
        "evidence":[]
    }))
    .into_response()
}

async fn spawn_contract_upstream(state: ContractUpstream) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/readyz", get(|| async { StatusCode::OK }))
        .route("/verdict", post(contract_verdict))
        .route("/fence", post(contract_fence))
        .route("/internal/v1/samples/upload", post(contract_bridge_upload))
        .route("/internal/v1/context/pack", post(|State(state): State<ContractUpstream>| async move {
            if state.revoke_during_ground.load(Ordering::SeqCst) {
                state.active.store(false, Ordering::SeqCst);
            }
            Json(json!({"ok":true,"data":{"evidence":[{
                "id":"closed-evidence","type":"report","path":"report.md",
                "sha256":hex::encode(Sha256::digest(b"Closed evidence."))
            }],"claims":[]},"error":null}))
        }))
        .route("/internal/v1/artifacts/read", post(|| async {
            Json(json!({"ok":true,"data":{"content":"Closed evidence."},"error":null}))
        }))
        .route("/v1/models", get(|| async {
            Json(json!({"success":true,"object":"list","data":[{"id":"glm-5.2","object":"model","supported_endpoint_types":["openai"]}]}))
        }))
        .route("/v1/chat/completions", post(|State(state): State<ContractUpstream>, Json(body): Json<Value>| async move {
            assert_eq!(body["model"], "glm-5.2");
            assert_eq!(body["stream"], true);
            state.model_calls.fetch_add(1, Ordering::SeqCst);
            if state.model_interrupted.load(Ordering::SeqCst) {
                return ([(header::CONTENT_TYPE,"text/event-stream")], ": interrupted\n\n");
            }
            ([(header::CONTENT_TYPE,"text/event-stream")],
                "data: {\"choices\":[{\"delta\":{\"content\":\"Closed test answer [ref:closed-evidence].\\n\\nUnsupported assertion.\"}}]}\n\ndata: [DONE]\n\n")
        }))
        .with_state(state);
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{address}"), task)
}

fn app_contract_config(
    database_url: &str,
    upstream: &str,
    root: &Path,
    upload_timeout: Duration,
) -> Config {
    let mut config = bridge_test_config(database_url, upstream, root);
    config.bridge_upload_timeout = upload_timeout;
    config.verdict_url = format!("{upstream}/verdict");
    config.newapi_url = format!("{upstream}/v1/chat/completions");
    config.access_execution_fence_url = format!("{upstream}/fence");
    config.template_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("templates");
    config
}

fn execution_envelope(application_sub: &str, request_sha256: &str) -> ExecutionEnvelopeV1 {
    let now = OffsetDateTime::now_utc();
    ExecutionEnvelopeV1 {
        version: 1,
        decision_id: "dec_a2f92fb7e2eb50062013fffd0445bd48".into(),
        decision_digest: "a2f92fb7e2eb50062013fffd0445bd489860039c2cea005cacedbd5e992adfb7".into(),
        subject_version: 1,
        application_sub: application_sub.into(),
        credential_id: format!("acr_{}", Uuid::new_v4().simple()),
        credential_version: 1,
        policy_epoch: 1,
        revocation_epoch: 1,
        request_sha256: request_sha256.into(),
        mcp_session_digest: "a".repeat(64),
        issued_at: now.unix_timestamp(),
        expires_at: now.unix_timestamp() + 30,
    }
}

fn tool_payload(
    application_sub: &str,
    canonical_tool: &str,
    resource: &str,
    body: Value,
    operation_id: Uuid,
) -> Value {
    let request_sha256 =
        canonical_application_request_sha(application_sub, canonical_tool, resource, &body)
            .unwrap();
    json!({
        "application_sub":application_sub,
        "operation_id":operation_id,
        "request_sha256":request_sha256,
        "correlation_id":Uuid::new_v4(),
        "resource":resource,
        "body":body,
        "execution":execution_envelope(application_sub, &request_sha256)
    })
}

fn upload_mutation_payload(
    application_sub: &str,
    canonical_tool: &str,
    resource: &str,
    operation_id: Uuid,
) -> Value {
    let request_sha256 =
        canonical_application_request_sha(application_sub, canonical_tool, resource, &json!({}))
            .unwrap();
    json!({
        "application_sub":application_sub,
        "operation_id":operation_id,
        "request_sha256":request_sha256,
        "correlation_id":Uuid::new_v4(),
        "execution":execution_envelope(application_sub, &request_sha256)
    })
}

async fn facade_post(
    app: &Router,
    path: &str,
    body: Value,
    extra_headers: &[(&str, String)],
) -> axum::response::Response {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {}", "q".repeat(32)))
        .header(header::CONTENT_TYPE, "application/json");
    for (name, value) in extra_headers {
        builder = builder.header(*name, value);
    }
    app.clone()
        .oneshot(builder.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap()
}

async fn response_json(response: axum::response::Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap()).unwrap()
}

async fn response_error(response: axum::response::Response) -> String {
    response_json(response).await["error"]["code"]
        .as_str()
        .unwrap()
        .to_string()
}
