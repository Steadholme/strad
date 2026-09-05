use std::{
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering},
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
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use strad::{
    app::{router as strad_router, AppState},
    application_facade::{canonical_application_request_sha, ExecutionEnvelopeV1},
    config::Config,
    migrations,
    store::{server_operation_id, ChunkClaim, Store},
    upload::ContentRange,
};
use tempfile::TempDir;
use time::OffsetDateTime;
use tower::ServiceExt;
use uuid::Uuid;

#[tokio::test]
async fn disconnected_finalize_recovers_from_journal_without_restart_or_redispatch() {
    let database_url = std::env::var("STRAD_TEST_DATABASE_URL")
        .expect("STRAD_TEST_DATABASE_URL is required; PostgreSQL contract tests never skip");
    migrations::run(&database_url).await.unwrap();
    let root = TempDir::new().unwrap();
    let bytes = bytes::Bytes::from_static(b"interrupted upload");
    let digest = hex::encode(Sha256::digest(&bytes));
    let bridge_id = Uuid::new_v4();
    let dispatches = Arc::new(AtomicUsize::new(0));
    let entered = Arc::new(tokio::sync::Notify::new());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let bridge = Router::new()
        .route("/readyz", get(|| async { StatusCode::OK }))
        .route(
            "/internal/v1/samples/upload",
            post({
                let dispatches = dispatches.clone();
                let entered = entered.clone();
                move || {
                    let dispatches = dispatches.clone();
                    let entered = entered.clone();
                    async move {
                        dispatches.fetch_add(1, Ordering::SeqCst);
                        entered.notify_one();
                        std::future::pending::<StatusCode>().await
                    }
                }
            }),
        )
        .route(
            &format!("/internal/v1/operations/{bridge_id}"),
            get({
                let digest = digest.clone();
                move || {
                    let digest = digest.clone();
                    async move {
                        Json(json!({"ok":true,"error":null,"data":{
                            "operation_id":bridge_id,"state":"succeeded",
                            "result":{"sample_id":format!("sha256:{digest}"),"file_type":"elf"},
                            "error":null
                        }}))
                    }
                }
            }),
        );
    let server = tokio::spawn(async move { axum::serve(listener, bridge).await.unwrap() });
    let state = AppState::build(contract_config(&database_url, &origin, root.path()))
        .await
        .unwrap();
    let owner = format!("application:interrupted_{}", Uuid::new_v4().simple());
    let created = state
        .store
        .create_upload(
            &owner,
            "interrupted.bin",
            bytes.len() as i64,
            bridge_id,
            &"c".repeat(64),
        )
        .await
        .unwrap();
    state
        .store
        .bind_application_upload(&owner, created.upload.id)
        .await
        .unwrap();
    state
        .upload
        .put_chunk(
            &owner,
            created.upload.id,
            ContentRange {
                start: 0,
                end: bytes.len() as i64 - 1,
                total: bytes.len() as i64,
            },
            &digest,
            bytes.clone(),
        )
        .await
        .unwrap();
    let finalize = tokio::spawn({
        let upload = state.upload.clone();
        let owner = owner.clone();
        async move { upload.finalize(&owner, created.upload.id).await }
    });
    tokio::time::timeout(Duration::from_secs(5), entered.notified())
        .await
        .unwrap();
    finalize.abort();
    assert!(finalize.await.unwrap_err().is_cancelled());
    // Still-live leases must not be stolen even when the journal has a result.
    assert_eq!(state.upload.reconcile_uncertain().await.unwrap(), 0);
    let pool = state.store.pool();
    let pending: (String, String) = sqlx::query_as(
        "SELECT u.state,b.reservation_state FROM upload_sessions u JOIN application_upload_bindings b ON b.upload_id=u.id WHERE u.id=$1"
    ).bind(created.upload.id).fetch_one(pool).await.unwrap();
    assert_eq!(pending, ("forwarding".into(), "reserved".into()));
    // Unit-only clock fixture; the L2 test uses the unchanged real lease.
    sqlx::query("UPDATE upload_sessions SET lease_until=now()-interval '1 second' WHERE id=$1")
        .bind(created.upload.id)
        .execute(pool)
        .await
        .unwrap();
    assert_eq!(state.upload.reconcile_uncertain().await.unwrap(), 1);
    assert_eq!(state.upload.reconcile_uncertain().await.unwrap(), 0);
    let settled: (String, String, i64, i64) = sqlx::query_as(
        "SELECT u.state,b.reservation_state,q.reserved_bytes,q.used_bytes FROM upload_sessions u JOIN application_upload_bindings b ON b.upload_id=u.id JOIN owner_quotas q ON q.owner_sub=u.owner_sub WHERE u.id=$1"
    ).bind(created.upload.id).fetch_one(pool).await.unwrap();
    assert_eq!(
        settled,
        (
            "finalized".into(),
            "committed".into(),
            0,
            bytes.len() as i64
        )
    );
    assert_eq!(dispatches.load(Ordering::SeqCst), 1);
    server.abort();
}

#[test]
fn private_finalize_requires_single_http_idempotency_key() {
    let source = include_str!("../src/app.rs");
    assert!(source.contains("required_idempotency_key(&headers)?"));
}

#[tokio::test]
async fn private_upload_handlers_enforce_headers_ranges_digests_and_finalize() {
    let database_url = std::env::var("STRAD_TEST_DATABASE_URL")
        .expect("STRAD_TEST_DATABASE_URL is required; PostgreSQL contract tests never skip");
    migrations::run(&database_url).await.unwrap();
    let root = TempDir::new().unwrap();
    let (upstream, upstream_task) = spawn_upload_upstream().await;
    let state = AppState::build(contract_config(&database_url, &upstream, root.path()))
        .await
        .unwrap();
    let app = strad_router(state);
    let application = format!("application:handler_{}", Uuid::new_v4().simple());
    let create_body = json!({"filename":"handler.bin","total_bytes":10});
    let create_hash = canonical_application_request_sha(
        &application,
        "analysis.create",
        "collection",
        &create_body,
    )
    .unwrap();
    let create = json!({
        "application_sub": application,
        "operation_id": Uuid::new_v4(),
        "request_sha256": create_hash,
        "correlation_id": Uuid::new_v4(),
        "resource": "collection",
        "body": create_body,
        "execution": execution_envelope(&application, &create_hash)
    });
    let response = json_request(
        &app,
        "/internal/v1/facade/tools/analysis.create",
        create,
        &[],
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let created: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap()).unwrap();
    let upload_id = Uuid::parse_str(created["upload_id"].as_str().unwrap()).unwrap();
    let finalize_id = Uuid::parse_str(created["finalize_operation_id"].as_str().unwrap()).unwrap();

    let bytes = b"0123456789";
    let content_base64 = BASE64_STANDARD.encode(bytes);
    let valid_digest = hex::encode(Sha256::digest(bytes));
    let other = format!("application:other_{}", Uuid::new_v4().simple());
    let cross_body = json!({
        "content_range": "bytes 0-9/10",
        "chunk_sha256": valid_digest,
        "content_base64": content_base64
    });
    let cross_hash = canonical_application_request_sha(
        &other,
        "analysis.create",
        &format!("{upload_id}/0"),
        &cross_body,
    )
    .unwrap();
    let cross_owner = json_request(
        &app,
        &format!("/internal/v1/facade/uploads/{upload_id}/chunks/0"),
        json!({
            "application_sub": other,
            "request_sha256": cross_hash,
            "correlation_id": Uuid::new_v4(),
            "content_range": "bytes 0-9/10",
            "chunk_sha256": valid_digest,
            "content_base64": content_base64,
            "execution": execution_envelope(&other, &cross_hash)
        }),
        &[],
    )
    .await;
    assert_eq!(cross_owner.status(), StatusCode::NOT_FOUND);
    for (content_range, chunk_digest, expected) in [
        ("bytes 1-10/11", valid_digest.as_str(), "invalid_upload"),
        ("bytes 0-9/10", &"f".repeat(64), "invalid_upload"),
    ] {
        let digest_body = json!({
            "content_range": content_range,
            "chunk_sha256": chunk_digest,
            "content_base64": content_base64
        });
        let request_hash = canonical_application_request_sha(
            &application,
            "analysis.create",
            &format!("{upload_id}/0"),
            &digest_body,
        )
        .unwrap();
        let response = json_request(
            &app,
            &format!("/internal/v1/facade/uploads/{upload_id}/chunks/0"),
            json!({
                "application_sub": application,
                "request_sha256": request_hash,
                "correlation_id": Uuid::new_v4(),
                "content_range": content_range,
                "chunk_sha256": chunk_digest,
                "content_base64": content_base64,
                "execution": execution_envelope(&application, &request_hash)
            }),
            &[],
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response_error_code(response).await, expected);
    }

    let digest_body = json!({
        "content_range": "bytes 0-9/10",
        "chunk_sha256": valid_digest,
        "content_base64": content_base64
    });
    let chunk_hash = canonical_application_request_sha(
        &application,
        "analysis.create",
        &format!("{upload_id}/0"),
        &digest_body,
    )
    .unwrap();
    let response = json_request(
        &app,
        &format!("/internal/v1/facade/uploads/{upload_id}/chunks/0"),
        json!({
            "application_sub": application,
            "request_sha256": chunk_hash,
            "correlation_id": Uuid::new_v4(),
            "content_range": "bytes 0-9/10",
            "chunk_sha256": valid_digest,
            "content_base64": content_base64,
            "execution": execution_envelope(&application, &chunk_hash)
        }),
        &[],
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let empty = json!({});
    let finalize_hash = canonical_application_request_sha(
        &application,
        "analysis.create",
        &format!("{upload_id}/finalize"),
        &empty,
    )
    .unwrap();
    let finalize = json!({
        "application_sub": application,
        "operation_id": finalize_id,
        "request_sha256": finalize_hash,
        "correlation_id": Uuid::new_v4(),
        "execution": execution_envelope(&application, &finalize_hash)
    });
    let path = format!("/internal/v1/facade/uploads/{upload_id}/finalize");
    let missing = json_request(&app, &path, finalize.clone(), &[]).await;
    assert_eq!(missing.status(), StatusCode::BAD_REQUEST);
    let duplicate = json_request(
        &app,
        &path,
        finalize.clone(),
        &[
            ("idempotency-key", finalize_id.to_string()),
            ("idempotency-key", finalize_id.to_string()),
        ],
    )
    .await;
    assert_eq!(duplicate.status(), StatusCode::BAD_REQUEST);
    let mismatch = json_request(
        &app,
        &path,
        finalize.clone(),
        &[("idempotency-key", Uuid::new_v4().to_string())],
    )
    .await;
    assert_eq!(mismatch.status(), StatusCode::BAD_REQUEST);
    let completed = json_request(
        &app,
        &path,
        finalize.clone(),
        &[("idempotency-key", finalize_id.to_string())],
    )
    .await;
    assert_eq!(completed.status(), StatusCode::ACCEPTED);
    let replay = json_request(
        &app,
        &path,
        finalize,
        &[("idempotency-key", finalize_id.to_string())],
    )
    .await;
    assert_eq!(replay.status(), StatusCode::ACCEPTED);

    let cancel_create_body = json!({"filename":"cancel.bin","total_bytes":3});
    let cancel_create_hash = canonical_application_request_sha(
        &application,
        "analysis.create",
        "collection",
        &cancel_create_body,
    )
    .unwrap();
    let cancel_created = json_request(
        &app,
        "/internal/v1/facade/tools/analysis.create",
        json!({
            "application_sub": application,
            "operation_id": Uuid::new_v4(),
            "request_sha256": cancel_create_hash,
            "correlation_id": Uuid::new_v4(),
            "resource": "collection",
            "body": cancel_create_body,
            "execution": execution_envelope(&application, &cancel_create_hash)
        }),
        &[],
    )
    .await;
    assert_eq!(cancel_created.status(), StatusCode::CREATED);
    let cancel_created: Value = serde_json::from_slice(
        &to_bytes(cancel_created.into_body(), 64 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    let cancel_upload = Uuid::parse_str(cancel_created["upload_id"].as_str().unwrap()).unwrap();
    let cancel_id = server_operation_id("upload-cancel", &cancel_upload.to_string());
    let cancel_hash = canonical_application_request_sha(
        &application,
        "analysis.upload.cancel",
        &cancel_upload.to_string(),
        &json!({}),
    )
    .unwrap();
    let cancel_request = json!({
        "application_sub":application,
        "operation_id":cancel_id,
        "request_sha256":cancel_hash,
        "correlation_id":Uuid::new_v4(),
        "execution":execution_envelope(&application, &cancel_hash)
    });
    let cancel_path = format!("/internal/v1/facade/uploads/{cancel_upload}/cancel");
    for _ in 0..2 {
        let cancelled = json_request(&app, &cancel_path, cancel_request.clone(), &[]).await;
        assert_eq!(cancelled.status(), StatusCode::ACCEPTED);
    }
    let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
    let quota: (i64, i64) =
        sqlx::query_as("SELECT reserved_bytes,used_bytes FROM owner_quotas WHERE owner_sub=$1")
            .bind(&application)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(quota, (0, 10));
    let states: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT upload_id,reservation_state FROM application_upload_bindings \
         WHERE application_sub=$1 ORDER BY upload_id",
    )
    .bind(&application)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(states.contains(&(upload_id, "committed".into())));
    assert!(states.contains(&(cancel_upload, "released".into())));
    upstream_task.abort();
}

#[tokio::test]
async fn upload_reservation_chunk_finalize_cancel_contract() {
    let migration = include_str!("../migrations/0003_application_owner_operations.sql");
    assert!(migration.contains("application_operations"));
    assert!(migration.contains("application_upload_chunks"));
    assert!(migration.contains("finalize_operation_id"));
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
    let application = format!("application:upload_{}", Uuid::new_v4().simple());
    let other = format!("application:other_{}", Uuid::new_v4().simple());
    let created = store
        .create_upload(
            &application,
            "sample.bin",
            10,
            Uuid::new_v4(),
            &"1".repeat(64),
        )
        .await
        .unwrap();
    store
        .bind_application_upload(&application, created.upload.id)
        .await
        .unwrap();
    assert_eq!(
        store
            .assert_application_upload(&other, created.upload.id)
            .await
            .unwrap_err()
            .code(),
        "not_found"
    );
    let bytes = b"0123456789";
    let digest = hex::encode(Sha256::digest(bytes));
    let ChunkClaim::Claimed { lease_token, .. } = store
        .claim_chunk(&application, created.upload.id, 0, 0, 9, 10, &digest)
        .await
        .unwrap()
    else {
        panic!("first chunk unexpectedly replayed")
    };
    store
        .commit_chunk(
            &application,
            created.upload.id,
            lease_token,
            0,
            0,
            9,
            10,
            &digest,
            &format!("{}/parts/00.part", created.upload.id),
        )
        .await
        .unwrap();
    assert!(matches!(
        store
            .claim_chunk(&application, created.upload.id, 0, 0, 9, 10, &digest)
            .await
            .unwrap(),
        ChunkClaim::Replay
    ));
    assert_eq!(
        store
            .claim_chunk(
                &application,
                created.upload.id,
                0,
                0,
                9,
                10,
                &"f".repeat(64),
            )
            .await
            .unwrap_err()
            .code(),
        "chunk_conflict"
    );
    let claim = store
        .claim_finalize(&application, created.upload.id)
        .await
        .unwrap();
    assert_eq!(claim.chunks.len(), 1);
    assert_eq!(claim.chunks[0].sha256, digest);
    let bound_finalize: Uuid = sqlx::query_scalar(
        "SELECT finalize_operation_id FROM application_upload_bindings \
         WHERE upload_id=$1 AND application_sub=$2",
    )
    .bind(created.upload.id)
    .bind(&application)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        bound_finalize,
        server_operation_id("upload-finalize", &created.upload.id.to_string())
    );
    store
        .mark_forwarding(&application, created.upload.id, claim.lease_token, &digest)
        .await
        .unwrap();
    store
        .complete_finalize(
            &application,
            created.upload.id,
            Some(claim.lease_token),
            &digest,
            "elf",
        )
        .await
        .unwrap();
    let quota: (i64, i64) =
        sqlx::query_as("SELECT reserved_bytes,used_bytes FROM owner_quotas WHERE owner_sub=$1")
            .bind(&application)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(quota, (0, 10));
    let committed: String = sqlx::query_scalar(
        "SELECT reservation_state FROM application_upload_bindings WHERE upload_id=$1",
    )
    .bind(created.upload.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(committed, "committed");
    assert!(store
        .begin_cancel(&application, created.upload.id)
        .await
        .is_err());

    let cancelled = store
        .create_upload(
            &application,
            "cancel.bin",
            7,
            Uuid::new_v4(),
            &"2".repeat(64),
        )
        .await
        .unwrap();
    store
        .bind_application_upload(&application, cancelled.upload.id)
        .await
        .unwrap();
    store
        .begin_cancel(&application, cancelled.upload.id)
        .await
        .unwrap();
    store
        .complete_cancel(&application, cancelled.upload.id)
        .await
        .unwrap();
    store
        .complete_cancel(&application, cancelled.upload.id)
        .await
        .unwrap();
    assert!(store
        .claim_finalize(&application, cancelled.upload.id)
        .await
        .is_err());
    let reserved: i64 =
        sqlx::query_scalar("SELECT reserved_bytes FROM owner_quotas WHERE owner_sub=$1")
            .bind(&application)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(reserved, 0);
    let released: String = sqlx::query_scalar(
        "SELECT reservation_state FROM application_upload_bindings WHERE upload_id=$1",
    )
    .bind(cancelled.upload.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(released, "released");
}

async fn json_request(
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

async fn response_error_code(response: axum::response::Response) -> String {
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap()).unwrap();
    body["error"]["code"].as_str().unwrap().to_string()
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

fn contract_config(database_url: &str, upstream: &str, root: &Path) -> Config {
    Config {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        database_url: database_url.into(),
        gateway_hmac_key: vec![b'i'; 32],
        gateway_zone_hmac_key: vec![b'z'; 32],
        verdict_decision_token: "v".repeat(32),
        verdict_url: format!("{upstream}/verdict"),
        bridge_token: "b".repeat(32),
        bridge_url: upstream.into(),
        bridge_upload_timeout: Duration::from_secs(2),
        newapi_key: "n".repeat(32),
        newapi_url: format!("{upstream}/v1/chat/completions"),
        newapi_model: "test-model".into(),
        newapi_context_tokens: 32_768,
        rikune_file_server_api_key: "f".repeat(32),
        facade_token: "q".repeat(32),
        governance_reporting_token: "r".repeat(32),
        access_execution_fence_token: "x".repeat(32),
        access_execution_fence_url: format!("{upstream}/fence"),
        upload_root: root.join("uploads"),
        template_root: Path::new(env!("CARGO_MANIFEST_DIR")).join("templates"),
        canonical_host: "rikune.w33d.xyz".into(),
        canonical_route: "rikune-root".into(),
        expected_zone: "external".into(),
        session_lease: Duration::from_secs(1800),
        session_ttl: Duration::from_secs(86400),
    }
}

async fn spawn_upload_upstream() -> (String, tokio::task::JoinHandle<()>) {
    async fn bridge_upload(headers: HeaderMap) -> impl IntoResponse {
        let digest = headers.get("x-content-sha256").unwrap().to_str().unwrap();
        Json(json!({
            "ok": true,
            "data": {"sample_id":format!("sha256:{digest}"),"file_type":"elf"},
            "error": null
        }))
    }
    async fn fence(
        State(active): State<Arc<bool>>,
        Json(envelope): Json<ExecutionEnvelopeV1>,
    ) -> Json<Value> {
        if !*active {
            return Json(json!({"active":false}));
        }
        Json(json!({
            "active":true,
            "subject_version":envelope.subject_version,
            "policy_epoch":envelope.policy_epoch,
            "revocation_epoch":envelope.revocation_epoch,
            "checked_at":OffsetDateTime::now_utc().unix_timestamp()
        }))
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/readyz", get(|| async { StatusCode::OK }))
        .route("/fence", post(fence))
        .route("/internal/v1/samples/upload", post(bridge_upload))
        .with_state(Arc::new(true));
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{address}"), task)
}
