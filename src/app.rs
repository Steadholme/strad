use std::{path::Component, sync::Arc};

use axum::{
    body::to_bytes,
    extract::{DefaultBodyLimit, Extension, FromRequest, Multipart, Path, Query, Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use bytes::Bytes;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    analysis::AnalysisController,
    auth::{
        csrf_cookie, csrf_from_headers, existing_or_new_csrf, identity_middleware,
        security_headers, verify_csrf, AuthVerifier, Identity,
    },
    bridge::{ArtifactReadRequest, ArtifactReadResult, BridgeClient},
    chat::ChatEngine,
    cleanup::CleanupService,
    config::{Config, CHUNK_BYTES, MAX_FILE_BYTES},
    error::{AppError, Result},
    events, migrations,
    models::{
        Artifact, CreateAnalysisInput, CreateAnalysisOutput, CreateConversationInput,
        CreateTurnInput, UpdatePersonaInput,
    },
    newapi::{NewApiClient, TokenBudgeter},
    store::{canonical_request_sha, server_operation_id, CreatedUpload, IdempotencyReplay, Store},
    templates::{TemplateName, TemplateRenderer},
    upload::{ContentRange, FinalizeOutcome, UploadService},
    verdict::{Risk, VerdictClient},
};

const JSON_LIMIT: usize = 1024 * 1024;
const MULTIPART_LIMIT: usize = 536_870_912;
const ARTIFACT_READ_MAX_BYTES: u64 = 256 * 1024;
const ANALYSIS_MODELS_ROUTE: &str = "/api/analyses/{id}/models";
const ANALYSIS_ARTIFACT_CONTENT_ROUTE: &str = "/api/analyses/{id}/artifacts/{artifact_id}/content";
const ANALYSIS_RESOURCE_TYPE: &str = "rikune-analysis";
const CONVERSATION_RESOURCE_TYPE: &str = "rikune-conversation";
const TURN_RESOURCE_TYPE: &str = "rikune-turn";

fn analysis_resource(analysis_id: Uuid) -> (&'static str, String) {
    (ANALYSIS_RESOURCE_TYPE, analysis_id.to_string())
}

fn conversation_resource(conversation_id: Uuid) -> (&'static str, String) {
    (CONVERSATION_RESOURCE_TYPE, conversation_id.to_string())
}

fn turn_resource(turn_id: Uuid) -> (&'static str, String) {
    (TURN_RESOURCE_TYPE, turn_id.to_string())
}

#[derive(Clone, Debug)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Store,
    pub upload: UploadService,
    pub analysis: AnalysisController,
    pub chat: ChatEngine,
    pub cleanup: CleanupService,
    pub verdict: VerdictClient,
    pub bridge: BridgeClient,
    pub newapi: NewApiClient,
    pub templates: TemplateRenderer,
}

impl AppState {
    pub async fn build(config: Config) -> std::result::Result<Self, String> {
        let store = Store::connect(&config.database_url)
            .await
            .map_err(|_| "failed to connect Strad store".to_string())?;
        let bridge = BridgeClient::new(&config)?;
        let verdict = VerdictClient::new(&config)?;
        let budgeter = TokenBudgeter::load()?;
        let newapi = NewApiClient::new(&config)?;
        let templates = TemplateRenderer::new(config.template_root.clone())
            .map_err(|_| "failed to initialize SSR renderer".to_string())?;
        let upload = UploadService::new(&config, store.clone(), bridge.clone())
            .await
            .map_err(|_| "failed to initialize upload storage".to_string())?;
        store
            .recover_expired_upload_leases()
            .await
            .map_err(|_| "upload lease recovery failed".to_string())?;
        store
            .recover_analysis_work()
            .await
            .map_err(|_| "analysis lease recovery failed".to_string())?;
        store
            .recover_sample_delete_leases()
            .await
            .map_err(|_| "sample deletion lease recovery failed".to_string())?;
        upload
            .recover_filesystem()
            .await
            .map_err(|_| "upload recovery failed".to_string())?;
        newapi
            .readiness_probe()
            .await
            .map_err(|_| "NewAPI startup probe failed".to_string())?;
        let analysis = AnalysisController::new(store.clone(), bridge.clone());
        let chat = ChatEngine::new(store.clone(), bridge.clone(), newapi.clone(), budgeter);
        let cleanup = CleanupService::new(&config, store.clone(), bridge.clone())
            .map_err(|_| "failed to anchor cleanup storage".to_string())?;
        Ok(Self {
            config: Arc::new(config),
            store,
            upload,
            analysis,
            chat,
            cleanup,
            verdict,
            bridge,
            newapi,
            templates,
        })
    }
}

pub fn router(state: AppState) -> Router {
    let verifier = AuthVerifier::new(&state.config);
    let error_state = state.clone();
    let private = Router::new()
        .route("/", get(workbench))
        .route("/analyses", get(analysis_list))
        .route("/api/analyses", post(create_analysis))
        .route("/api/uploads/{rid}", get(upload_status))
        .route("/api/uploads/{rid}/chunks", post(upload_chunk))
        .route("/api/uploads/{rid}/finalize", post(upload_finalize))
        .route("/api/uploads/{rid}/cancel", post(upload_cancel))
        .route("/analyses/{id}", get(analysis_detail))
        .route("/analyses/{id}/summary", get(analysis_summary))
        .route("/analyses/{id}/evidence", get(analysis_evidence))
        .route("/analyses/{id}/stages", get(analysis_stages))
        .route("/analyses/{id}/conversation", get(analysis_conversation))
        .route("/api/analyses/{id}/context-preview", get(context_preview))
        .route(ANALYSIS_MODELS_ROUTE, get(analysis_models))
        .route(
            ANALYSIS_ARTIFACT_CONTENT_ROUTE,
            get(analysis_artifact_content),
        )
        .route("/api/analyses/{id}/events", get(analysis_events))
        .route("/api/analyses/{id}/promote", post(promote_analysis))
        .route("/api/analyses/{id}/delete", post(delete_analysis))
        .route(
            "/api/analyses/{id}/conversations",
            post(create_conversation),
        )
        .route(
            "/api/analyses/{id}/conversations/{cid}/persona",
            post(update_persona),
        )
        .route(
            "/api/analyses/{id}/conversations/{cid}/turns",
            post(create_turn),
        )
        .route(
            "/api/analyses/{id}/conversations/{cid}/turns/{tid}",
            get(turn_status),
        )
        .route(
            "/api/analyses/{id}/conversations/{cid}/delete",
            post(delete_conversation),
        )
        .route_layer(middleware::from_fn_with_state(
            verifier,
            identity_middleware,
        ));
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/static/{*path}", get(static_asset))
        .merge(private)
        .layer(middleware::from_fn_with_state(
            error_state,
            html_error_middleware,
        ))
        .layer(DefaultBodyLimit::max(MULTIPART_LIMIT))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

async fn html_error_middleware(
    State(state): State<AppState>,
    request: Request,
    next: middleware::Next,
) -> Response {
    let html_requested = wants_html(request.headers());
    let response = next.run(request).await;
    if !html_requested
        || !(response.status().is_client_error() || response.status().is_server_error())
    {
        return response;
    }
    let status = response.status();
    let retry_after = response.headers().get(header::RETRY_AFTER).cloned();
    match state
        .templates
        .render(TemplateName::Error, &json!({}))
        .await
    {
        Ok(body) => {
            let mut rendered = (status, Html(body)).into_response();
            if let Some(retry_after) = retry_after {
                rendered
                    .headers_mut()
                    .insert(header::RETRY_AFTER, retry_after);
            }
            rendered
        }
        Err(error) => error.into_response(),
    }
}

async fn healthz() -> StatusCode {
    StatusCode::OK
}

async fn readyz(State(state): State<AppState>) -> Result<StatusCode> {
    state.store.ping().await?;
    if !migrations::schema_compatible(state.store.pool()).await {
        return Err(AppError::unavailable(
            "database_unavailable",
            "The database schema is incompatible.",
        ));
    }
    state.verdict.readiness_probe().await?;
    state.bridge.ready().await?;
    state.newapi.readiness_probe().await?;
    Ok(StatusCode::OK)
}

async fn static_asset(State(state): State<AppState>, Path(path): Path<String>) -> Result<Response> {
    let relative = std::path::Path::new(&path);
    if relative.is_absolute()
        || relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(AppError::not_found());
    }
    let root = state
        .config
        .template_root
        .parent()
        .ok_or(AppError::Invariant("template root has no parent"))?
        .join("static");
    let target = root.join(relative);
    let metadata = tokio::fs::symlink_metadata(&target)
        .await
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => AppError::not_found(),
            _ => AppError::Io(error),
        })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || !target.starts_with(&root) {
        return Err(AppError::not_found());
    }
    let body = tokio::fs::read(&target).await?;
    if body.len() > 4 * 1024 * 1024 {
        return Err(AppError::not_found());
    }
    let mime = match target.extension().and_then(|value| value.to_str()) {
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    };
    Ok(([(header::CONTENT_TYPE, mime)], body).into_response())
}

async fn workbench(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    headers: HeaderMap,
) -> Result<Response> {
    state
        .verdict
        .authorize(
            &identity,
            "rikune.console.enter",
            "route",
            "rikune-root",
            Risk::Critical,
        )
        .await?;
    let csrf = existing_or_new_csrf(&headers);
    let upload_create_operation_id = Uuid::new_v4();
    let html = state
        .templates
        .render(
            TemplateName::Workbench,
            &json!({
                "title": "Rikune analysis workbench",
                "csrf_token": csrf,
                "owner": identity.subject,
                "operation_id": upload_create_operation_id,
                "upload_create_operation_id": upload_create_operation_id
            }),
        )
        .await?;
    html_with_csrf(html, &csrf)
}

async fn analysis_list(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    headers: HeaderMap,
) -> Result<Response> {
    state
        .verdict
        .authorize(
            &identity,
            "rikune.analysis.read",
            "rikune-analysis",
            "collection",
            Risk::Medium,
        )
        .await?;
    let analyses = state.store.list_analyses(&identity.subject).await?;
    let quota = state.store.owner_quota(&identity.subject).await?;
    let csrf = existing_or_new_csrf(&headers);
    let html = state
        .templates
        .render(
            TemplateName::List,
            &json!({
                "title": "Analyses",
                "csrf_token": csrf,
                "owner": identity.subject,
                "analyses": analyses,
                "analyses_json": analyses,
                "quota": quota,
                "quota_json": quota,
                "used_bytes": quota.used_bytes
            }),
        )
        .await?;
    html_with_csrf(html, &csrf)
}

async fn create_analysis(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    request: Request,
) -> Result<Response> {
    state
        .verdict
        .authorize(
            &identity,
            "rikune.analysis.create",
            "rikune-analysis",
            "collection",
            Risk::High,
        )
        .await?;
    let content_type = content_type(request.headers())?.to_string();
    if content_type.starts_with("multipart/form-data;") {
        return create_analysis_multipart(state, identity, request).await;
    }
    let headers = request.headers().clone();
    verify_header_csrf(&headers)?;
    let body = collect_body(request, JSON_LIMIT).await?;
    let input: CreateAnalysisInput = decode_body(&content_type, &body)?;
    validate_filename_and_size(&input.filename, input.total_bytes)?;
    let operation_id = required_operation_id(&headers)?;
    let request_sha = canonical_request_sha("POST", "/api/analyses", &identity.subject, &body);
    if let Some(replay) = state
        .store
        .idempotency_replay(
            &identity.subject,
            "POST /api/analyses",
            operation_id,
            &request_sha,
        )
        .await?
    {
        return replay_response(replay, &headers);
    }
    let created = state
        .store
        .create_upload(
            &identity.subject,
            &input.filename,
            input.total_bytes,
            operation_id,
            &request_sha,
        )
        .await?;
    created_upload_response(created)
}

async fn create_analysis_multipart(
    state: AppState,
    identity: Identity,
    request: Request,
) -> Result<Response> {
    let headers = request.headers().clone();
    let mut multipart = Multipart::from_request(request, &state)
        .await
        .map_err(|_| AppError::invalid("invalid_request", "Multipart form is invalid."))?;
    let mut csrf = None;
    let mut saw_declared_bytes = false;
    let mut hidden_operation = None;
    let mut created: Option<CreatedUpload> = None;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|_| AppError::invalid("invalid_request", "Multipart form is invalid."))?
    {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "csrf_token" if created.is_none() => {
                csrf = Some(read_small_field(&mut field, 128).await?);
            }
            "total_bytes" if created.is_none() && !saw_declared_bytes => {
                // Compatibility-only field. The reservation size is derived from the
                // durably streamed file and this untrusted browser value is ignored.
                let _ = read_small_field(&mut field, 32).await?;
                saw_declared_bytes = true;
            }
            "operation_id" if created.is_none() && hidden_operation.is_none() => {
                let value = read_small_field(&mut field, 64).await?;
                hidden_operation = Some(Uuid::parse_str(&value).map_err(|_| {
                    AppError::invalid("invalid_request", "Operation ID is invalid.")
                })?);
            }
            "file" if created.is_none() => {
                let csrf = csrf.as_deref().ok_or_else(|| {
                    AppError::invalid("invalid_request", "CSRF field must precede the file.")
                })?;
                verify_csrf(&headers, csrf)?;
                let filename = field.file_name().map(str::to_string).ok_or_else(|| {
                    AppError::invalid("invalid_upload", "A file name is required.")
                })?;
                let operation_id = hidden_operation.ok_or_else(|| {
                    AppError::invalid(
                        "invalid_request",
                        "The server-issued operation ID must precede the file.",
                    )
                })?;
                let spool = state
                    .upload
                    .spool_multipart(operation_id, &mut field)
                    .await?;
                let total_bytes = spool.total_bytes;
                validate_filename_and_size(&filename, total_bytes)?;
                let semantic_body = serde_json::to_vec(&json!({
                    "filename": filename,
                    "total_bytes": total_bytes,
                    "operation_id": operation_id
                }))
                .map_err(|_| AppError::Invariant("multipart reservation is not serializable"))?;
                let request_sha = canonical_request_sha(
                    "POST",
                    "/api/analyses",
                    &identity.subject,
                    &semantic_body,
                );
                let replay = state
                    .store
                    .idempotency_replay(
                        &identity.subject,
                        "POST /api/analyses",
                        operation_id,
                        &request_sha,
                    )
                    .await?;
                if let Some(replay) = replay {
                    let upload_id = replay
                        .body
                        .as_ref()
                        .and_then(|body| body.get("upload_id"))
                        .and_then(Value::as_str)
                        .and_then(|value| Uuid::parse_str(value).ok())
                        .ok_or(AppError::Invariant(
                            "multipart replay omitted its upload ID",
                        ))?;
                    let upload = state.store.get_upload(&identity.subject, upload_id).await?;
                    if upload.filename != filename || upload.total_bytes != total_bytes {
                        let _ = state.upload.discard_multipart_spool(&spool).await;
                        return Err(AppError::conflict(
                            "idempotency_mismatch",
                            "The idempotency key is bound to a different multipart file.",
                        ));
                    }
                    if matches!(upload.state.as_str(), "reserved" | "uploading") {
                        let result = state
                            .upload
                            .ingest_multipart_spool(&identity.subject, upload_id, &spool)
                            .await;
                        let discard = state.upload.discard_multipart_spool(&spool).await;
                        result?;
                        discard?;
                        return finalize_multipart_upload(
                            &state,
                            &identity.subject,
                            upload_id,
                            upload.analysis_id,
                        )
                        .await;
                    }
                    state.upload.discard_multipart_spool(&spool).await?;
                    return match upload.state.as_str() {
                        "finalized" | "forwarding" | "upstream_uncertain" => {
                            redirect(&format!("/analyses/{}", upload.analysis_id))
                        }
                        "failed"
                            if upload
                                .error_code
                                .as_deref()
                                .is_some_and(|code| code.starts_with("unknown_file")) =>
                        {
                            Err(AppError::api(
                                StatusCode::UNPROCESSABLE_ENTITY,
                                "unknown_file_type",
                                "The uploaded file type is not supported.",
                                false,
                            ))
                        }
                        _ => replay_response(replay, &headers),
                    };
                }
                let reservation = match state
                    .store
                    .create_upload(
                        &identity.subject,
                        &filename,
                        total_bytes,
                        operation_id,
                        &request_sha,
                    )
                    .await
                {
                    Ok(reservation) => reservation,
                    Err(error) => {
                        let _ = state.upload.discard_multipart_spool(&spool).await;
                        return Err(error);
                    }
                };
                let upload_id = reservation.upload.id;
                let upload_result = state
                    .upload
                    .ingest_multipart_spool(&identity.subject, upload_id, &spool)
                    .await;
                let discard_result = state.upload.discard_multipart_spool(&spool).await;
                if let Err(error) = upload_result {
                    let _ = state.upload.cancel(&identity.subject, upload_id).await;
                    return Err(error);
                }
                discard_result?;
                created = Some(reservation);
            }
            _ => {
                return Err(AppError::invalid(
                    "invalid_request",
                    "Multipart fields are invalid or out of order.",
                ));
            }
        }
    }
    let created =
        created.ok_or_else(|| AppError::invalid("invalid_upload", "A file is required."))?;
    finalize_multipart_upload(
        &state,
        &identity.subject,
        created.upload.id,
        created.analysis.id,
    )
    .await
}

async fn finalize_multipart_upload(
    state: &AppState,
    owner_sub: &str,
    upload_id: Uuid,
    analysis_id: Uuid,
) -> Result<Response> {
    match state.upload.finalize(owner_sub, upload_id).await? {
        FinalizeOutcome::Complete(analysis) => redirect(&format!("/analyses/{}", analysis.id)),
        FinalizeOutcome::Pending => redirect(&format!("/analyses/{analysis_id}")),
        FinalizeOutcome::UnknownFile => Err(AppError::api(
            StatusCode::UNPROCESSABLE_ENTITY,
            "unknown_file_type",
            "The uploaded file type is not supported.",
            false,
        )),
    }
}

async fn upload_status(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Path(upload_id): Path<Uuid>,
) -> Result<Json<Value>> {
    let status = state
        .store
        .upload_status(&identity.subject, upload_id)
        .await?;
    state
        .verdict
        .authorize(
            &identity,
            "rikune.analysis.create",
            "rikune-upload",
            &upload_id.to_string(),
            Risk::High,
        )
        .await?;
    Ok(Json(serde_json::to_value(status).map_err(|_| {
        AppError::Invariant("upload status is not serializable")
    })?))
}

async fn upload_chunk(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Path(upload_id): Path<Uuid>,
    request: Request,
) -> Result<StatusCode> {
    state.store.get_upload(&identity.subject, upload_id).await?;
    state
        .verdict
        .authorize(
            &identity,
            "rikune.analysis.create",
            "rikune-upload",
            &upload_id.to_string(),
            Risk::High,
        )
        .await?;
    let headers = request.headers().clone();
    verify_header_csrf(&headers)?;
    let range = ContentRange::parse(required_header(&headers, header::CONTENT_RANGE.as_str())?)?;
    let digest = required_header(&headers, "x-chunk-sha256")?.to_string();
    let body = collect_body(request, CHUNK_BYTES as usize).await?;
    state
        .upload
        .put_chunk(&identity.subject, upload_id, range, &digest, body)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn upload_finalize(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Path(upload_id): Path<Uuid>,
    request: Request,
) -> Result<Response> {
    let upload = state.store.get_upload(&identity.subject, upload_id).await?;
    state
        .verdict
        .authorize(
            &identity,
            "rikune.analysis.create",
            "rikune-upload",
            &upload_id.to_string(),
            Risk::High,
        )
        .await?;
    let parsed = parse_empty_mutation(request).await?;
    verify_mutation_csrf(&parsed)?;
    let operation_id = parsed.operation_id()?;
    let expected = server_operation_id("upload-finalize", &upload_id.to_string());
    if operation_id != expected {
        return Err(AppError::invalid(
            "invalid_request",
            "Idempotency-Key is not the server-issued finalize operation ID.",
        ));
    }
    let scope = "POST /api/uploads/:id/finalize";
    let request_sha = canonical_request_sha(
        "POST",
        &format!("/api/uploads/{upload_id}/finalize"),
        &identity.subject,
        &parsed.body,
    );
    if let Some(replay) = state
        .store
        .idempotency_replay(&identity.subject, scope, operation_id, &request_sha)
        .await?
    {
        return replay_response(replay, &parsed.headers);
    }
    state
        .store
        .claim_http_operation(&identity.subject, scope, operation_id, &request_sha)
        .await?;
    let location = format!("/analyses/{}", upload.analysis_id);
    if matches!(
        upload.error_code.as_deref(),
        Some("unknown_file_type" | "unknown_file_disposition" | "unknown_file_disposition_waiting")
    ) {
        let body = mutation_error_body(
            operation_id,
            "unknown_file_type",
            "The uploaded file type is not supported.",
            false,
        );
        state
            .store
            .complete_http_operation(
                &identity.subject,
                scope,
                operation_id,
                &request_sha,
                StatusCode::UNPROCESSABLE_ENTITY.as_u16().into(),
                &location,
                &body,
            )
            .await?;
        return Ok((StatusCode::UNPROCESSABLE_ENTITY, Json(body)).into_response());
    }
    let (status, body) = if upload.state == "finalized" {
        (
            StatusCode::ACCEPTED,
            upload
                .frozen_body
                .unwrap_or_else(|| json!({"analysis_id": upload.analysis_id, "state": "uploaded"})),
        )
    } else {
        match state.upload.finalize(&identity.subject, upload_id).await? {
            FinalizeOutcome::Complete(analysis) => (
                StatusCode::ACCEPTED,
                json!({"analysis_id": analysis.id, "state": analysis.state}),
            ),
            FinalizeOutcome::Pending => (
                StatusCode::ACCEPTED,
                json!({"analysis_id": upload.analysis_id, "state": "upstream_uncertain"}),
            ),
            FinalizeOutcome::UnknownFile => (
                StatusCode::UNPROCESSABLE_ENTITY,
                mutation_error_body(
                    operation_id,
                    "unknown_file_type",
                    "The uploaded file type is not supported.",
                    false,
                ),
            ),
        }
    };
    state
        .store
        .complete_http_operation(
            &identity.subject,
            scope,
            operation_id,
            &request_sha,
            status.as_u16().into(),
            &location,
            &body,
        )
        .await?;
    if status.is_success() {
        mutation_success(&parsed.headers, status, &location, body)
    } else {
        Ok((status, Json(body)).into_response())
    }
}

async fn upload_cancel(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Path(upload_id): Path<Uuid>,
    request: Request,
) -> Result<Response> {
    let upload = state.store.get_upload(&identity.subject, upload_id).await?;
    state
        .verdict
        .authorize(
            &identity,
            "rikune.upload.cancel",
            "rikune-upload",
            &upload_id.to_string(),
            Risk::Medium,
        )
        .await?;
    let parsed = parse_empty_mutation(request).await?;
    verify_mutation_csrf(&parsed)?;
    let operation_id = parsed.operation_id()?;
    let expected = server_operation_id("upload-cancel", &upload_id.to_string());
    if operation_id != expected {
        return Err(AppError::invalid(
            "invalid_request",
            "Idempotency-Key is not the server-issued cancel operation ID.",
        ));
    }
    let scope = "POST /api/uploads/:id/cancel";
    let request_sha = canonical_request_sha(
        "POST",
        &format!("/api/uploads/{upload_id}/cancel"),
        &identity.subject,
        &parsed.body,
    );
    if let Some(replay) = state
        .store
        .idempotency_replay(&identity.subject, scope, operation_id, &request_sha)
        .await?
    {
        return replay_response(replay, &parsed.headers);
    }
    state
        .store
        .claim_http_operation(&identity.subject, scope, operation_id, &request_sha)
        .await?;
    if upload.state != "cancelled" {
        state.upload.cancel(&identity.subject, upload_id).await?;
    }
    let current = state.store.get_upload(&identity.subject, upload_id).await?;
    let body = json!({"upload_id": upload_id, "state": current.state});
    state
        .store
        .complete_http_operation(
            &identity.subject,
            scope,
            operation_id,
            &request_sha,
            StatusCode::ACCEPTED.as_u16().into(),
            "/analyses",
            &body,
        )
        .await?;
    mutation_success(&parsed.headers, StatusCode::ACCEPTED, "/analyses", body)
}

async fn analysis_detail(
    state: State<AppState>,
    identity: Extension<Identity>,
    headers: HeaderMap,
    Path(analysis_id): Path<Uuid>,
) -> Result<Response> {
    render_analysis_section(state.0, identity.0, headers, analysis_id, "detail").await
}

async fn analysis_summary(
    state: State<AppState>,
    identity: Extension<Identity>,
    headers: HeaderMap,
    Path(analysis_id): Path<Uuid>,
) -> Result<Response> {
    render_analysis_section(state.0, identity.0, headers, analysis_id, "summary").await
}

async fn analysis_evidence(
    state: State<AppState>,
    identity: Extension<Identity>,
    headers: HeaderMap,
    Path(analysis_id): Path<Uuid>,
) -> Result<Response> {
    render_analysis_section(state.0, identity.0, headers, analysis_id, "evidence").await
}

async fn analysis_stages(
    state: State<AppState>,
    identity: Extension<Identity>,
    headers: HeaderMap,
    Path(analysis_id): Path<Uuid>,
) -> Result<Response> {
    render_analysis_section(state.0, identity.0, headers, analysis_id, "stages").await
}

async fn render_analysis_section(
    state: AppState,
    identity: Identity,
    headers: HeaderMap,
    analysis_id: Uuid,
    section: &'static str,
) -> Result<Response> {
    let analysis = state
        .store
        .get_analysis(&identity.subject, analysis_id)
        .await?;
    state
        .verdict
        .authorize(
            &identity,
            "rikune.analysis.read",
            "rikune-analysis",
            &analysis_id.to_string(),
            Risk::Medium,
        )
        .await?;
    let artifacts = state
        .store
        .artifacts(&identity.subject, analysis_id)
        .await?;
    let summary = artifacts
        .iter()
        .find(|artifact| artifact.artifact_type.to_ascii_lowercase().contains("summ"))
        .map(|artifact| json!({"artifact": artifact}));
    let csrf = existing_or_new_csrf(&headers);
    let promote_operation_id = Uuid::new_v4();
    let delete_operation_id = Uuid::new_v4();
    let html = state
        .templates
        .render(
            TemplateName::Detail,
            &json!({
                "title": analysis.display_name,
                "csrf_token": csrf,
                "operation_id": promote_operation_id,
                "promote_operation_id": promote_operation_id,
                "delete_operation_id": delete_operation_id,
                "section": section,
                "analysis_id": analysis_id,
                "analysis": analysis,
                "analysis_json": analysis,
                "summary": summary,
                "summary_json": summary,
                "artifacts": artifacts,
                "artifacts_json": artifacts
            }),
        )
        .await?;
    html_with_csrf(html, &csrf)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConversationQuery {
    conversation_id: Option<Uuid>,
}

async fn analysis_conversation(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    headers: HeaderMap,
    Path(analysis_id): Path<Uuid>,
    Query(query): Query<ConversationQuery>,
) -> Result<Response> {
    let analysis = state
        .store
        .get_analysis(&identity.subject, analysis_id)
        .await?;
    let (resource_type, resource_id) = analysis_resource(analysis_id);
    state
        .verdict
        .authorize(
            &identity,
            "rikune.conversation.use",
            resource_type,
            &resource_id,
            Risk::Medium,
        )
        .await?;
    let conversations = state
        .store
        .conversations(&identity.subject, analysis_id)
        .await?;
    let selected_conversation = if let Some(conversation_id) = query.conversation_id {
        Some(
            state
                .store
                .get_conversation(&identity.subject, analysis_id, conversation_id)
                .await?,
        )
    } else {
        conversations.first().cloned()
    };
    let (messages, next_client_seq) = if let Some(conversation) = selected_conversation.as_ref() {
        state
            .store
            .conversation_projection(&identity.subject, analysis_id, conversation.id)
            .await?
    } else {
        (Vec::new(), 1)
    };
    let selected_conversation_id = selected_conversation
        .as_ref()
        .map(|conversation| conversation.id.to_string())
        .unwrap_or_default();
    let csrf = existing_or_new_csrf(&headers);
    let create_conversation_operation_id = Uuid::new_v4();
    let persona_operation_id = Uuid::new_v4();
    let turn_operation_id = Uuid::new_v4();
    let delete_conversation_operation_id = Uuid::new_v4();
    let html = state
        .templates
        .render(
            TemplateName::Conversation,
            &json!({
                "title": format!("{} conversation", analysis.display_name),
                "csrf_token": csrf,
                "operation_id": create_conversation_operation_id,
                "create_conversation_operation_id": create_conversation_operation_id,
                "persona_operation_id": persona_operation_id,
                "turn_operation_id": turn_operation_id,
                "delete_conversation_operation_id": delete_conversation_operation_id,
                "analysis_id": analysis_id,
                "analysis": analysis,
                "analysis_json": analysis,
                "conversations": conversations,
                "conversations_json": conversations,
                "selected_conversation": selected_conversation,
                "selected_conversation_id": selected_conversation_id,
                "default_model": state.newapi.model(),
                "next_client_seq": next_client_seq,
                "messages": messages,
                "messages_json": messages
            }),
        )
        .await?;
    html_with_csrf(html, &csrf)
}

async fn analysis_models(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Path(analysis_id): Path<Uuid>,
) -> Result<Json<Value>> {
    state
        .store
        .get_analysis(&identity.subject, analysis_id)
        .await?;
    let (resource_type, resource_id) = analysis_resource(analysis_id);
    state
        .verdict
        .authorize(
            &identity,
            "rikune.conversation.use",
            resource_type,
            &resource_id,
            Risk::Medium,
        )
        .await?;
    let models = state.newapi.available_models().await?;
    Ok(Json(json!({
        "default_model": state.newapi.model(),
        "models": models,
    })))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ArtifactContentState {
    InlineText,
    Binary,
    TooLarge,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum ArtifactContentEncoding {
    Utf8,
    Base64,
}

#[derive(Debug, Serialize)]
struct VerifiedArtifactContent {
    content: Option<String>,
    content_state: ArtifactContentState,
    content_encoding: ArtifactContentEncoding,
    truncated: bool,
    bytes_read: u64,
    total_size: u64,
}

#[derive(Debug, Serialize)]
struct ArtifactContentResponse {
    artifact: Artifact,
    #[serde(flatten)]
    verified: VerifiedArtifactContent,
}

async fn analysis_artifact_content(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Path((analysis_id, artifact_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<ArtifactContentResponse>> {
    let analysis = state
        .store
        .get_analysis(&identity.subject, analysis_id)
        .await?;
    let (resource_type, resource_id) = analysis_resource(analysis_id);
    state
        .verdict
        .authorize(
            &identity,
            "rikune.analysis.read",
            resource_type,
            &resource_id,
            Risk::Medium,
        )
        .await?;
    let artifact = state
        .store
        .get_artifact(&identity.subject, analysis_id, artifact_id)
        .await?;
    let sample_id = analysis.sample_id.ok_or(AppError::Invariant(
        "owned analysis omitted sample id for artifact read",
    ))?;
    if artifact.upstream_artifact_id.is_empty() {
        return Err(AppError::Invariant(
            "stored artifact omitted upstream artifact id",
        ));
    }
    let response = state
        .bridge
        .artifact_read(&ArtifactReadRequest {
            sample_id: &sample_id,
            artifact_id: Some(&artifact.upstream_artifact_id),
            artifact_type: None,
            path: None,
            read_mode: "content",
        })
        .await?;
    let verified = verified_artifact_content(response, &sample_id, &artifact)?;
    Ok(Json(ArtifactContentResponse { artifact, verified }))
}

fn verified_artifact_content(
    response: ArtifactReadResult,
    expected_sample_id: &str,
    expected_artifact: &Artifact,
) -> Result<VerifiedArtifactContent> {
    fn required_string<'a>(
        object: &'a serde_json::Map<String, Value>,
        key: &'static str,
    ) -> Result<&'a str> {
        object
            .get(key)
            .and_then(Value::as_str)
            .ok_or(AppError::Invariant(key))
    }
    if required_string(&response.value, "sample_id")? != expected_sample_id {
        return Err(AppError::Invariant("bridge artifact sample id mismatch"));
    }
    if required_string(&response.value, "read_mode")? != "content" {
        return Err(AppError::Invariant("bridge artifact read mode mismatch"));
    }
    let upstream_artifact = response
        .value
        .get("artifact")
        .and_then(Value::as_object)
        .ok_or(AppError::Invariant(
            "bridge artifact response omitted artifact identity",
        ))?;
    for (key, expected) in [
        ("id", expected_artifact.upstream_artifact_id.as_str()),
        ("type", expected_artifact.artifact_type.as_str()),
        ("path", expected_artifact.path.as_str()),
        ("sha256", expected_artifact.sha256.as_str()),
    ] {
        if required_string(upstream_artifact, key)? != expected {
            return Err(AppError::Invariant("bridge artifact identity mismatch"));
        }
    }

    let content = response
        .value
        .get("content")
        .and_then(Value::as_str)
        .ok_or(AppError::Invariant(
            "bridge artifact response omitted string content",
        ))?;
    let content_encoding = match required_string(&response.value, "content_encoding")? {
        "utf8" => ArtifactContentEncoding::Utf8,
        "base64" => ArtifactContentEncoding::Base64,
        _ => return Err(AppError::Invariant("unsupported artifact content encoding")),
    };
    let bytes_read = response
        .value
        .get("bytes_read")
        .and_then(Value::as_u64)
        .ok_or(AppError::Invariant(
            "bridge artifact response omitted byte count",
        ))?;
    let total_size = response
        .value
        .get("total_size")
        .and_then(Value::as_u64)
        .ok_or(AppError::Invariant(
            "bridge artifact response omitted total size",
        ))?;
    let truncated = response
        .value
        .get("truncated")
        .and_then(Value::as_bool)
        .ok_or(AppError::Invariant(
            "bridge artifact response omitted truncation state",
        ))?;
    if bytes_read > ARTIFACT_READ_MAX_BYTES
        || bytes_read > total_size
        || truncated != (bytes_read < total_size)
    {
        return Err(AppError::Invariant(
            "bridge artifact byte counts are inconsistent",
        ));
    }

    let raw_content = match content_encoding {
        ArtifactContentEncoding::Utf8 => content.as_bytes().to_vec(),
        ArtifactContentEncoding::Base64 => BASE64_STANDARD
            .decode(content)
            .map_err(|_| AppError::Invariant("bridge artifact base64 is invalid"))?,
    };
    if u64::try_from(raw_content.len()).ok() != Some(bytes_read) {
        return Err(AppError::Invariant(
            "bridge artifact decoded length mismatch",
        ));
    }

    if truncated {
        return Ok(VerifiedArtifactContent {
            content: None,
            content_state: ArtifactContentState::TooLarge,
            content_encoding,
            truncated,
            bytes_read,
            total_size,
        });
    }
    if hex::encode(Sha256::digest(&raw_content)) != expected_artifact.sha256 {
        return Err(AppError::Invariant("artifact content sha256 mismatch"));
    }
    let (content_state, content) = match content_encoding {
        ArtifactContentEncoding::Utf8 => {
            (ArtifactContentState::InlineText, Some(content.to_owned()))
        }
        ArtifactContentEncoding::Base64 => (ArtifactContentState::Binary, None),
    };
    Ok(VerifiedArtifactContent {
        content,
        content_state,
        content_encoding,
        truncated,
        bytes_read,
        total_size,
    })
}

async fn context_preview(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    headers: HeaderMap,
    Path(analysis_id): Path<Uuid>,
) -> Result<Response> {
    let analysis = state
        .store
        .get_analysis(&identity.subject, analysis_id)
        .await?;
    state
        .verdict
        .authorize(
            &identity,
            "rikune.analysis.read",
            "rikune-analysis",
            &analysis_id.to_string(),
            Risk::Medium,
        )
        .await?;
    let context = state
        .store
        .latest_context_preview(&identity.subject, analysis_id)
        .await?;
    let value = json!({"analysis_id": analysis_id, "context": context});
    if !wants_html(&headers) {
        return Ok(Json(value).into_response());
    }
    let csrf = existing_or_new_csrf(&headers);
    let html = state
        .templates
        .render(
            TemplateName::ContextPreview,
            &json!({
                "title": format!("{} context preview", analysis.display_name),
                "csrf_token": csrf,
                "analysis_id": analysis_id,
                "analysis": analysis,
                "context": context,
                "context_json": context
            }),
        )
        .await?;
    html_with_csrf(html, &csrf)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EventQuery {
    last_event_id: Option<String>,
}

async fn analysis_events(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    headers: HeaderMap,
    Path(analysis_id): Path<Uuid>,
    Query(query): Query<EventQuery>,
) -> Result<Response> {
    let analysis = state
        .store
        .get_analysis(&identity.subject, analysis_id)
        .await?;
    state
        .verdict
        .authorize(
            &identity,
            "rikune.analysis.read",
            "rikune-analysis",
            &analysis_id.to_string(),
            Risk::Medium,
        )
        .await?;
    let header = optional_header(&headers, "last-event-id")?;
    let last = events::parse_last_event_id(header, query.last_event_id.as_deref())?;
    Ok(events::stream(state.store, identity.subject, analysis, last).into_response())
}

async fn promote_analysis(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Path(analysis_id): Path<Uuid>,
    request: Request,
) -> Result<Response> {
    let analysis = state
        .store
        .get_analysis(&identity.subject, analysis_id)
        .await?;
    state
        .verdict
        .authorize(
            &identity,
            "rikune.analysis.promote",
            "rikune-analysis",
            &analysis_id.to_string(),
            Risk::High,
        )
        .await?;
    let parsed = parse_empty_mutation(request).await?;
    verify_mutation_csrf(&parsed)?;
    let operation_id = parsed.operation_id()?;
    let request_sha = canonical_request_sha(
        "POST",
        &format!("/api/analyses/{analysis_id}/promote"),
        &identity.subject,
        &parsed.body,
    );
    if let Some(replay) = state
        .store
        .idempotency_replay(
            &identity.subject,
            "POST /api/analyses/:id/promote",
            operation_id,
            &request_sha,
        )
        .await?
    {
        return replay_response(replay, &parsed.headers);
    }
    state
        .store
        .begin_promote(&identity.subject, analysis_id, operation_id, &request_sha)
        .await?;
    let completed = state.analysis.promote(&analysis, operation_id).await?;
    state
        .store
        .complete_promote(&identity.subject, analysis_id, operation_id, !completed)
        .await?;
    mutation_success(
        &parsed.headers,
        StatusCode::ACCEPTED,
        &format!("/analyses/{analysis_id}"),
        json!({"analysis_id": analysis_id, "state": if completed {"analyzing"} else {"degraded"}}),
    )
}

async fn delete_analysis(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Path(analysis_id): Path<Uuid>,
    request: Request,
) -> Result<Response> {
    let parsed = parse_empty_mutation(request).await?;
    verify_mutation_csrf(&parsed)?;
    let operation_id = parsed.operation_id()?;
    let request_sha = canonical_request_sha(
        "POST",
        &format!("/api/analyses/{analysis_id}/delete"),
        &identity.subject,
        &parsed.body,
    );
    state
        .store
        .assert_analysis_owner(&identity.subject, analysis_id)
        .await?;
    state
        .verdict
        .authorize(
            &identity,
            "rikune.analysis.delete",
            "rikune-analysis",
            &analysis_id.to_string(),
            Risk::High,
        )
        .await?;
    if let Some(replay) = state
        .store
        .idempotency_replay(
            &identity.subject,
            "POST /api/analyses/:id/delete",
            operation_id,
            &request_sha,
        )
        .await?
    {
        return replay_response(replay, &parsed.headers);
    }
    state
        .store
        .get_analysis(&identity.subject, analysis_id)
        .await?;
    state
        .store
        .request_analysis_delete(&identity.subject, analysis_id, operation_id, &request_sha)
        .await?;
    mutation_success(
        &parsed.headers,
        StatusCode::ACCEPTED,
        "/analyses",
        json!({"analysis_id": analysis_id, "state": "delete_pending"}),
    )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConversationForm {
    title: String,
    persona_id: Option<String>,
    csrf_token: String,
    operation_id: Uuid,
}

async fn create_conversation(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Path(analysis_id): Path<Uuid>,
    request: Request,
) -> Result<Response> {
    state
        .store
        .get_analysis(&identity.subject, analysis_id)
        .await?;
    let (resource_type, resource_id) = analysis_resource(analysis_id);
    state
        .verdict
        .authorize(
            &identity,
            "rikune.conversation.use",
            resource_type,
            &resource_id,
            Risk::Medium,
        )
        .await?;
    let headers = request.headers().clone();
    let kind = content_type(&headers)?.to_string();
    let body = collect_body(request, JSON_LIMIT).await?;
    let (input, operation_id) = if kind.starts_with("application/x-www-form-urlencoded") {
        let form: ConversationForm = serde_urlencoded::from_bytes(&body)
            .map_err(|_| AppError::invalid("invalid_request", "Form body is invalid."))?;
        verify_csrf(&headers, &form.csrf_token)?;
        (
            CreateConversationInput {
                title: form.title,
                persona_id: form.persona_id,
            },
            form.operation_id,
        )
    } else if kind.starts_with("application/json") {
        verify_header_csrf(&headers)?;
        (
            serde_json::from_slice::<CreateConversationInput>(&body).map_err(|_| {
                AppError::invalid("invalid_request", "JSON body does not match the contract.")
            })?,
            required_operation_id(&headers)?,
        )
    } else {
        return Err(AppError::invalid(
            "invalid_request",
            "Content-Type is not supported.",
        ));
    };
    validate_conversation(
        &input.title,
        input.persona_id.as_deref().unwrap_or("binary-analyst"),
    )?;
    let request_sha = canonical_request_sha(
        "POST",
        &format!("/api/analyses/{analysis_id}/conversations"),
        &identity.subject,
        &body,
    );
    if let Some(replay) = state
        .store
        .idempotency_replay(
            &identity.subject,
            "POST /api/analyses/:id/conversations",
            operation_id,
            &request_sha,
        )
        .await?
    {
        return replay_response(replay, &headers);
    }
    let conversation = state
        .store
        .create_conversation(
            &identity.subject,
            analysis_id,
            &input.title,
            input.persona_id.as_deref().unwrap_or("binary-analyst"),
            operation_id,
            &request_sha,
        )
        .await?;
    let location = format!(
        "/analyses/{analysis_id}/conversation?conversation_id={}",
        conversation.id
    );
    mutation_success(
        &headers,
        StatusCode::CREATED,
        &location,
        json!({"conversation": conversation}),
    )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersonaForm {
    persona_id: String,
    custom_persona: Option<String>,
    csrf_token: String,
    operation_id: Uuid,
}

async fn update_persona(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Path((analysis_id, conversation_id)): Path<(Uuid, Uuid)>,
    request: Request,
) -> Result<Response> {
    state
        .store
        .get_conversation(&identity.subject, analysis_id, conversation_id)
        .await?;
    let (resource_type, resource_id) = conversation_resource(conversation_id);
    state
        .verdict
        .authorize(
            &identity,
            "rikune.conversation.use",
            resource_type,
            &resource_id,
            Risk::Medium,
        )
        .await?;
    let headers = request.headers().clone();
    let kind = content_type(&headers)?.to_string();
    let body = collect_body(request, JSON_LIMIT).await?;
    let (input, operation_id) = if kind.starts_with("application/x-www-form-urlencoded") {
        let form: PersonaForm = serde_urlencoded::from_bytes(&body)
            .map_err(|_| AppError::invalid("invalid_request", "Form body is invalid."))?;
        verify_csrf(&headers, &form.csrf_token)?;
        (
            UpdatePersonaInput {
                persona_id: form.persona_id,
                custom_persona: form.custom_persona,
            },
            form.operation_id,
        )
    } else if kind.starts_with("application/json") {
        verify_header_csrf(&headers)?;
        (
            serde_json::from_slice::<UpdatePersonaInput>(&body).map_err(|_| {
                AppError::invalid("invalid_request", "JSON body does not match the contract.")
            })?,
            required_operation_id(&headers)?,
        )
    } else {
        return Err(AppError::invalid(
            "invalid_request",
            "Content-Type is not supported.",
        ));
    };
    validate_persona(&input.persona_id, input.custom_persona.as_deref())?;
    let request_sha = canonical_request_sha(
        "POST",
        &format!("/api/analyses/{analysis_id}/conversations/{conversation_id}/persona"),
        &identity.subject,
        &body,
    );
    if let Some(replay) = state
        .store
        .idempotency_replay(
            &identity.subject,
            "POST /api/analyses/:id/conversations/:cid/persona",
            operation_id,
            &request_sha,
        )
        .await?
    {
        return replay_response(replay, &headers);
    }
    let conversation = state
        .store
        .update_persona(
            &identity.subject,
            analysis_id,
            conversation_id,
            &input.persona_id,
            input.custom_persona.as_deref(),
            operation_id,
            &request_sha,
        )
        .await?;
    mutation_success(
        &headers,
        StatusCode::OK,
        &format!("/analyses/{analysis_id}/conversation"),
        json!({"conversation": conversation}),
    )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TurnForm {
    client_seq: i64,
    message: String,
    model: Option<String>,
    csrf_token: String,
    operation_id: Uuid,
}

async fn create_turn(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Path((analysis_id, conversation_id)): Path<(Uuid, Uuid)>,
    request: Request,
) -> Result<Response> {
    state
        .store
        .get_conversation(&identity.subject, analysis_id, conversation_id)
        .await?;
    let (resource_type, resource_id) = conversation_resource(conversation_id);
    state
        .verdict
        .authorize(
            &identity,
            "rikune.conversation.use",
            resource_type,
            &resource_id,
            Risk::Medium,
        )
        .await?;
    let headers = request.headers().clone();
    let kind = content_type(&headers)?.to_string();
    let body = collect_body(request, JSON_LIMIT).await?;
    let (input, operation_id) = if kind.starts_with("application/x-www-form-urlencoded") {
        let form: TurnForm = serde_urlencoded::from_bytes(&body)
            .map_err(|_| AppError::invalid("invalid_request", "Form body is invalid."))?;
        verify_csrf(&headers, &form.csrf_token)?;
        (
            CreateTurnInput {
                client_seq: form.client_seq,
                message: form.message,
                model: form.model,
            },
            form.operation_id,
        )
    } else if kind.starts_with("application/json") {
        verify_header_csrf(&headers)?;
        (
            serde_json::from_slice::<CreateTurnInput>(&body).map_err(|_| {
                AppError::invalid("invalid_request", "JSON body does not match the contract.")
            })?,
            required_operation_id(&headers)?,
        )
    } else {
        return Err(AppError::invalid(
            "invalid_request",
            "Content-Type is not supported.",
        ));
    };
    if input.client_seq < 1
        || input.message.is_empty()
        || input.message.len() > 8 * 1024
        || input.message.chars().any(|value| value == '\0')
    {
        return Err(AppError::invalid(
            "invalid_request",
            "The conversation turn is invalid or exceeds 8 KiB.",
        ));
    }
    let request_sha = canonical_request_sha(
        "POST",
        &format!("/api/analyses/{analysis_id}/conversations/{conversation_id}/turns"),
        &identity.subject,
        &body,
    );
    if let Some(replay) = state
        .store
        .idempotency_replay(
            &identity.subject,
            "POST /api/analyses/:id/conversations/:cid/turns",
            operation_id,
            &request_sha,
        )
        .await?
    {
        if wants_html(&headers) {
            return redirect(&format!(
                "/analyses/{analysis_id}/conversation?conversation_id={conversation_id}"
            ));
        }
        return replay_response(replay, &headers);
    }
    let selected_model = input
        .model
        .as_deref()
        .unwrap_or_else(|| state.newapi.model());
    state.newapi.validate_model(selected_model).await?;
    let turn = state
        .store
        .create_turn(
            &identity.subject,
            analysis_id,
            conversation_id,
            operation_id,
            input.client_seq,
            &request_sha,
            selected_model,
            &input.message,
        )
        .await?;
    let location = if wants_html(&headers) {
        format!("/analyses/{analysis_id}/conversation?conversation_id={conversation_id}")
    } else {
        format!(
            "/api/analyses/{analysis_id}/conversations/{conversation_id}/turns/{}",
            turn.id
        )
    };
    mutation_success(
        &headers,
        StatusCode::ACCEPTED,
        &location,
        json!({"turn": turn}),
    )
}

async fn turn_status(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Path((analysis_id, conversation_id, turn_id)): Path<(Uuid, Uuid, Uuid)>,
) -> Result<Json<Value>> {
    let turn = state
        .store
        .get_turn(&identity.subject, analysis_id, conversation_id, turn_id)
        .await?;
    let (resource_type, resource_id) = turn_resource(turn_id);
    state
        .verdict
        .authorize(
            &identity,
            "rikune.conversation.use",
            resource_type,
            &resource_id,
            Risk::Medium,
        )
        .await?;
    let mut assistant = state.store.assistant_message(turn_id).await?;
    let citations = state
        .store
        .citation_refs(&identity.subject, analysis_id, assistant.id)
        .await?;
    let resolved: Vec<String> = citations
        .iter()
        .filter(|(_, resolved)| *resolved)
        .map(|(citation_ref, _)| citation_ref.clone())
        .collect();
    assistant.content = crate::citation::annotate_uncited_markdown(&assistant.content, &resolved);
    Ok(Json(
        json!({"turn": turn, "assistant": assistant, "citations": citations}),
    ))
}

async fn delete_conversation(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Path((analysis_id, conversation_id)): Path<(Uuid, Uuid)>,
    request: Request,
) -> Result<Response> {
    let parsed = parse_empty_mutation(request).await?;
    verify_mutation_csrf(&parsed)?;
    let operation_id = parsed.operation_id()?;
    let request_sha = canonical_request_sha(
        "POST",
        &format!("/api/analyses/{analysis_id}/conversations/{conversation_id}/delete"),
        &identity.subject,
        &parsed.body,
    );
    state
        .store
        .assert_analysis_owner(&identity.subject, analysis_id)
        .await?;
    let (resource_type, resource_id) = conversation_resource(conversation_id);
    state
        .verdict
        .authorize(
            &identity,
            "rikune.conversation.use",
            resource_type,
            &resource_id,
            Risk::Medium,
        )
        .await?;
    if let Some(replay) = state
        .store
        .idempotency_replay(
            &identity.subject,
            "POST /api/analyses/:id/conversations/:cid/delete",
            operation_id,
            &request_sha,
        )
        .await?
    {
        return replay_response(replay, &parsed.headers);
    }
    state
        .store
        .get_conversation(&identity.subject, analysis_id, conversation_id)
        .await?;
    state
        .store
        .delete_conversation(
            &identity.subject,
            analysis_id,
            conversation_id,
            operation_id,
            &request_sha,
        )
        .await?;
    mutation_success(
        &parsed.headers,
        StatusCode::ACCEPTED,
        &format!("/analyses/{analysis_id}/conversation"),
        json!({"conversation_id": conversation_id, "state": "deleted"}),
    )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyMutationJson {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyMutationForm {
    csrf_token: String,
    operation_id: Uuid,
}

struct ParsedMutation {
    headers: HeaderMap,
    body: Bytes,
    csrf_token: Option<String>,
    form_operation_id: Option<Uuid>,
    is_form: bool,
}

impl ParsedMutation {
    fn operation_id(&self) -> Result<Uuid> {
        if self.is_form {
            self.form_operation_id
                .ok_or_else(|| AppError::invalid("invalid_request", "Operation ID is required."))
        } else {
            required_operation_id(&self.headers)
        }
    }
}

async fn parse_empty_mutation(request: Request) -> Result<ParsedMutation> {
    let headers = request.headers().clone();
    let kind = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("application/json")
        .to_string();
    let body = collect_body(request, JSON_LIMIT).await?;
    if kind.starts_with("application/x-www-form-urlencoded") {
        let form: EmptyMutationForm = serde_urlencoded::from_bytes(&body)
            .map_err(|_| AppError::invalid("invalid_request", "Form body is invalid."))?;
        Ok(ParsedMutation {
            headers,
            body,
            csrf_token: Some(form.csrf_token),
            form_operation_id: Some(form.operation_id),
            is_form: true,
        })
    } else if kind.starts_with("application/json") {
        if !body.is_empty() {
            serde_json::from_slice::<EmptyMutationJson>(&body).map_err(|_| {
                AppError::invalid("invalid_request", "JSON body does not match the contract.")
            })?;
        }
        Ok(ParsedMutation {
            headers,
            body,
            csrf_token: None,
            form_operation_id: None,
            is_form: false,
        })
    } else {
        Err(AppError::invalid(
            "invalid_request",
            "Content-Type is not supported.",
        ))
    }
}

fn verify_mutation_csrf(parsed: &ParsedMutation) -> Result<()> {
    if let Some(token) = parsed.csrf_token.as_deref() {
        verify_csrf(&parsed.headers, token)
    } else {
        verify_header_csrf(&parsed.headers)
    }
}

async fn read_small_field(
    field: &mut axum::extract::multipart::Field<'_>,
    limit: usize,
) -> Result<String> {
    let mut bytes = Vec::new();
    while let Some(chunk) = field
        .chunk()
        .await
        .map_err(|_| AppError::invalid("invalid_request", "Multipart field is unreadable."))?
    {
        if bytes.len().saturating_add(chunk.len()) > limit {
            return Err(AppError::invalid(
                "invalid_request",
                "Multipart field exceeds its limit.",
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    String::from_utf8(bytes)
        .map_err(|_| AppError::invalid("invalid_request", "Multipart field is not UTF-8."))
}

async fn collect_body(request: Request, limit: usize) -> Result<Bytes> {
    to_bytes(request.into_body(), limit).await.map_err(|_| {
        AppError::api(
            StatusCode::PAYLOAD_TOO_LARGE,
            "file_too_large",
            "The request body exceeds its limit.",
            false,
        )
    })
}

fn decode_body<T: DeserializeOwned>(content_type: &str, body: &[u8]) -> Result<T> {
    if !content_type.starts_with("application/json") {
        return Err(AppError::invalid(
            "invalid_request",
            "Content-Type is not supported.",
        ));
    }
    serde_json::from_slice(body)
        .map_err(|_| AppError::invalid("invalid_request", "JSON body does not match the contract."))
}

fn content_type(headers: &HeaderMap) -> Result<&str> {
    required_header(headers, header::CONTENT_TYPE.as_str())
}

fn required_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str> {
    let mut values = headers.get_all(name).iter();
    let first = values.next().ok_or_else(|| {
        AppError::invalid("invalid_request", "A required request header is missing.")
    })?;
    if values.next().is_some() {
        return Err(AppError::invalid(
            "invalid_request",
            "A request header was repeated.",
        ));
    }
    first
        .to_str()
        .map_err(|_| AppError::invalid("invalid_request", "A request header is invalid."))
}

fn optional_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>> {
    let mut values = headers.get_all(name).iter();
    let Some(first) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(AppError::invalid(
            "invalid_request",
            "A request header was repeated.",
        ));
    }
    Ok(Some(first.to_str().map_err(|_| {
        AppError::invalid("invalid_request", "A request header is invalid.")
    })?))
}

fn verify_header_csrf(headers: &HeaderMap) -> Result<()> {
    verify_csrf(headers, csrf_from_headers(headers)?)
}

fn required_operation_id(headers: &HeaderMap) -> Result<Uuid> {
    Uuid::parse_str(required_header(headers, "idempotency-key")?)
        .map_err(|_| AppError::invalid("invalid_request", "Idempotency-Key must be a UUID."))
}

fn validate_filename_and_size(filename: &str, total_bytes: i64) -> Result<()> {
    if filename.is_empty() || filename.len() > 512 || filename.chars().any(char::is_control) {
        return Err(AppError::invalid("invalid_upload", "File name is invalid."));
    }
    if total_bytes <= 0 {
        return Err(AppError::invalid("invalid_upload", "File size is invalid."));
    }
    if total_bytes > MAX_FILE_BYTES {
        return Err(AppError::api(
            StatusCode::PAYLOAD_TOO_LARGE,
            "file_too_large",
            "The file exceeds 500 MiB.",
            false,
        ));
    }
    Ok(())
}

fn validate_conversation(title: &str, persona_id: &str) -> Result<()> {
    if title.is_empty() || title.len() > 240 || title.chars().any(char::is_control) {
        return Err(AppError::invalid(
            "invalid_request",
            "Conversation title is invalid.",
        ));
    }
    validate_persona(persona_id, None)
}

fn validate_persona(persona_id: &str, custom: Option<&str>) -> Result<()> {
    let valid = matches!(
        persona_id,
        "binary-analyst" | "malware-analyst" | "reverse-engineer" | "incident-responder" | "custom"
    );
    if !valid
        || custom.is_some_and(|value| value.len() > 8000 || value.contains('\0'))
        || (persona_id == "custom" && custom.is_none_or(str::is_empty))
        || (persona_id != "custom" && custom.is_some())
    {
        return Err(AppError::invalid(
            "invalid_request",
            "Persona selection is invalid.",
        ));
    }
    Ok(())
}

fn created_upload_response(created: CreatedUpload) -> Result<Response> {
    let finalize_operation_id =
        server_operation_id("upload-finalize", &created.upload.id.to_string());
    let cancel_operation_id = server_operation_id("upload-cancel", &created.upload.id.to_string());
    let output = CreateAnalysisOutput {
        analysis_id: created.analysis.id,
        upload_id: created.upload.id,
        operation_id: created.upload.operation_id,
        finalize_operation_id,
        cancel_operation_id,
        chunk_size: CHUNK_BYTES,
        chunk_count: created.upload.chunk_count,
        upload_location: format!("/api/uploads/{}", created.upload.id),
        analysis_location: format!("/analyses/{}", created.analysis.id),
    };
    let location = output.upload_location.clone();
    let mut response = (StatusCode::CREATED, Json(output)).into_response();
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(&location)
            .map_err(|_| AppError::Invariant("upload Location is invalid"))?,
    );
    Ok(response)
}

fn replay_response(replay: IdempotencyReplay, headers: &HeaderMap) -> Result<Response> {
    if replay.status >= 400 {
        let status = StatusCode::from_u16(replay.status as u16)
            .map_err(|_| AppError::Invariant("frozen HTTP status is invalid"))?;
        let body = replay.body.ok_or(AppError::Invariant(
            "frozen error representation was scrubbed",
        ))?;
        return Ok((status, Json(body)).into_response());
    }
    let representation = optional_header(headers, "prefer")?.is_some_and(|value| {
        value
            .split(',')
            .any(|item| item.trim() == "return=representation")
    });
    if representation {
        let status = StatusCode::from_u16(replay.status as u16)
            .map_err(|_| AppError::Invariant("frozen HTTP status is invalid"))?;
        let body = replay
            .body
            .ok_or(AppError::Invariant("frozen representation was scrubbed"))?;
        let mut response = (status, Json(body)).into_response();
        if let Some(location) = replay.location {
            response.headers_mut().insert(
                header::LOCATION,
                HeaderValue::from_str(&location)
                    .map_err(|_| AppError::Invariant("frozen Location is invalid"))?,
            );
        }
        return Ok(response);
    }
    redirect(
        replay
            .location
            .as_deref()
            .ok_or(AppError::Invariant("frozen redirect Location was scrubbed"))?,
    )
}

fn mutation_error_body(
    operation_id: Uuid,
    code: &'static str,
    message: &'static str,
    retryable: bool,
) -> Value {
    json!({
        "error": {
            "code": code,
            "message": message,
            "request_id": operation_id,
            "retryable": retryable
        }
    })
}

fn mutation_success(
    headers: &HeaderMap,
    status: StatusCode,
    location: &str,
    body: Value,
) -> Result<Response> {
    if wants_html(headers) {
        return redirect(location);
    }
    let mut response = (status, Json(body)).into_response();
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(location)
            .map_err(|_| AppError::Invariant("response Location is invalid"))?,
    );
    Ok(response)
}

fn redirect(location: &str) -> Result<Response> {
    let mut response = StatusCode::SEE_OTHER.into_response();
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(location)
            .map_err(|_| AppError::Invariant("redirect Location is invalid"))?,
    );
    Ok(response)
}

fn html_with_csrf(html: String, csrf: &str) -> Result<Response> {
    let mut response = Html(html).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&csrf_cookie(csrf))
            .map_err(|_| AppError::Invariant("CSRF cookie is invalid"))?,
    );
    Ok(response)
}

fn wants_html(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|item| item.trim().starts_with("text/html"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filename_and_persona_validation_is_bounded() {
        assert!(validate_filename_and_size("sample.exe", 1).is_ok());
        assert!(validate_filename_and_size("sample\n.exe", 1).is_err());
        assert!(validate_filename_and_size("sample", MAX_FILE_BYTES + 1).is_err());
        assert!(validate_persona("binary-analyst", None).is_ok());
        assert!(validate_persona("custom", Some("Focus on imports")).is_ok());
        assert!(validate_persona("custom", None).is_err());
        assert!(validate_persona("arbitrary", None).is_err());
    }

    #[test]
    fn html_mutations_redirect_instead_of_returning_json() {
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, HeaderValue::from_static("text/html"));
        let response = mutation_success(
            &headers,
            StatusCode::ACCEPTED,
            "/analyses/00000000-0000-0000-0000-000000000001",
            json!({"state":"accepted"}),
        )
        .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "/analyses/00000000-0000-0000-0000-000000000001"
        );
    }

    const TEST_SAMPLE_ID: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn artifact_fixture(raw_content: &[u8]) -> Artifact {
        Artifact {
            id: Uuid::nil(),
            analysis_id: Uuid::nil(),
            owner_sub: "user:test".into(),
            upstream_artifact_id: "upstream-artifact".into(),
            artifact_type: "summary".into(),
            artifact_ref: "ref:summary".into(),
            path: "summary.json".into(),
            sha256: hex::encode(Sha256::digest(raw_content)),
            mime: Some("application/json".into()),
            metadata: json!({}),
            created_at: time::OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn artifact_read_result(
        artifact: &Artifact,
        content: &str,
        content_encoding: &str,
        bytes_read: u64,
        total_size: u64,
        truncated: bool,
    ) -> ArtifactReadResult {
        ArtifactReadResult {
            value: json!({
                "sample_id": TEST_SAMPLE_ID,
                "read_mode": "content",
                "artifact": {
                    "id": artifact.upstream_artifact_id,
                    "type": artifact.artifact_type,
                    "path": artifact.path,
                    "sha256": artifact.sha256,
                },
                "content": content,
                "content_encoding": content_encoding,
                "bytes_read": bytes_read,
                "total_size": total_size,
                "truncated": truncated,
            })
            .as_object()
            .unwrap()
            .clone(),
        }
    }

    fn assert_artifact_invariant(error: AppError) {
        assert_eq!(error.code(), "server_invariant_violation");
    }

    #[test]
    fn complete_utf8_artifact_is_verified_and_inlined() {
        let content = "verified artifact content ☃";
        let artifact = artifact_fixture(content.as_bytes());
        let verified = verified_artifact_content(
            artifact_read_result(
                &artifact,
                content,
                "utf8",
                content.len() as u64,
                content.len() as u64,
                false,
            ),
            TEST_SAMPLE_ID,
            &artifact,
        )
        .unwrap();

        assert_eq!(verified.content.as_deref(), Some(content));
        assert_eq!(verified.content_state, ArtifactContentState::InlineText);
        assert_eq!(verified.content_encoding, ArtifactContentEncoding::Utf8);
        assert!(!verified.truncated);
        assert_eq!(verified.bytes_read, content.len() as u64);
        assert_eq!(verified.total_size, content.len() as u64);
    }

    #[test]
    fn complete_base64_artifact_is_verified_without_exposing_binary() {
        let raw_content = [0, 159, 146, 150, 255];
        let content = BASE64_STANDARD.encode(raw_content);
        let artifact = artifact_fixture(&raw_content);
        let verified = verified_artifact_content(
            artifact_read_result(
                &artifact,
                &content,
                "base64",
                raw_content.len() as u64,
                raw_content.len() as u64,
                false,
            ),
            TEST_SAMPLE_ID,
            &artifact,
        )
        .unwrap();

        assert_eq!(verified.content, None);
        assert_eq!(verified.content_state, ArtifactContentState::Binary);
        assert_eq!(verified.content_encoding, ArtifactContentEncoding::Base64);
        assert!(!verified.truncated);
        assert_eq!(verified.bytes_read, raw_content.len() as u64);
        assert_eq!(verified.total_size, raw_content.len() as u64);
    }

    #[test]
    fn truncated_utf8_and_base64_artifacts_are_not_exposed() {
        let full_utf8 = b"prefix and omitted suffix";
        let utf8_prefix = "prefix";
        let utf8_artifact = artifact_fixture(full_utf8);
        let utf8 = verified_artifact_content(
            artifact_read_result(
                &utf8_artifact,
                utf8_prefix,
                "utf8",
                utf8_prefix.len() as u64,
                full_utf8.len() as u64,
                true,
            ),
            TEST_SAMPLE_ID,
            &utf8_artifact,
        )
        .unwrap();

        let full_binary = [0, 1, 2, 3, 4, 5, 6];
        let binary_prefix = [0, 1, 2];
        let binary_artifact = artifact_fixture(&full_binary);
        let base64 = verified_artifact_content(
            artifact_read_result(
                &binary_artifact,
                &BASE64_STANDARD.encode(binary_prefix),
                "base64",
                binary_prefix.len() as u64,
                full_binary.len() as u64,
                true,
            ),
            TEST_SAMPLE_ID,
            &binary_artifact,
        )
        .unwrap();

        for verified in [utf8, base64] {
            assert_eq!(verified.content, None);
            assert_eq!(verified.content_state, ArtifactContentState::TooLarge);
            assert!(verified.truncated);
            assert!(verified.bytes_read < verified.total_size);
        }
    }

    #[test]
    fn artifact_identity_drift_fails_closed() {
        let content = "verified artifact content";
        let artifact = artifact_fixture(content.as_bytes());
        for (field, replacement) in [
            ("id", "other-artifact"),
            ("type", "other-type"),
            ("path", "other/path"),
            (
                "sha256",
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            ),
        ] {
            let mut response = artifact_read_result(
                &artifact,
                content,
                "utf8",
                content.len() as u64,
                content.len() as u64,
                false,
            );
            response.value.get_mut("artifact").unwrap()[field] = json!(replacement);
            assert_artifact_invariant(
                verified_artifact_content(response, TEST_SAMPLE_ID, &artifact).unwrap_err(),
            );
        }
    }

    #[test]
    fn malformed_base64_fails_closed() {
        let artifact = artifact_fixture(b"binary");
        let response = artifact_read_result(&artifact, "%%%", "base64", 2, 2, false);
        assert_artifact_invariant(
            verified_artifact_content(response, TEST_SAMPLE_ID, &artifact).unwrap_err(),
        );
    }

    #[test]
    fn artifact_length_truncation_encoding_and_digest_drift_fail_closed() {
        let content = "abc";
        let artifact = artifact_fixture(content.as_bytes());
        for response in [
            artifact_read_result(&artifact, content, "utf8", 2, 2, false),
            artifact_read_result(&artifact, content, "utf8", 3, 4, false),
            artifact_read_result(&artifact, content, "utf8", 3, 3, true),
            artifact_read_result(
                &artifact,
                content,
                "utf8",
                ARTIFACT_READ_MAX_BYTES + 1,
                ARTIFACT_READ_MAX_BYTES + 1,
                false,
            ),
            artifact_read_result(&artifact, content, "hex", 3, 3, false),
        ] {
            assert_artifact_invariant(
                verified_artifact_content(response, TEST_SAMPLE_ID, &artifact).unwrap_err(),
            );
        }

        let mut digest_drift = artifact_fixture(content.as_bytes());
        digest_drift.sha256 = "0".repeat(64);
        let response = artifact_read_result(&digest_drift, content, "utf8", 3, 3, false);
        assert_artifact_invariant(
            verified_artifact_content(response, TEST_SAMPLE_ID, &digest_drift).unwrap_err(),
        );
    }

    #[test]
    fn artifact_content_response_has_exact_top_level_contract() {
        let artifact = artifact_fixture(b"content");
        let response = serde_json::to_value(ArtifactContentResponse {
            artifact,
            verified: VerifiedArtifactContent {
                content: Some("content".into()),
                content_state: ArtifactContentState::InlineText,
                content_encoding: ArtifactContentEncoding::Utf8,
                truncated: false,
                bytes_read: 7,
                total_size: 7,
            },
        })
        .unwrap();
        let object = response.as_object().unwrap();
        let keys: std::collections::BTreeSet<&str> = object.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            std::collections::BTreeSet::from([
                "artifact",
                "bytes_read",
                "content",
                "content_encoding",
                "content_state",
                "total_size",
                "truncated",
            ])
        );
        assert_eq!(object["content_state"], "inline_text");
        assert_eq!(object["content_encoding"], "utf8");
    }

    #[test]
    fn authz_manifest_matches_runtime_resource_contracts() {
        let manifest: Value =
            serde_json::from_str(include_str!("../ops/holdfast/assets/rikune-authz-v1.json"))
                .unwrap();
        let functions = manifest["functions"].as_array().unwrap();
        let permissions = manifest["permissions"].as_array().unwrap();
        for (method, router_path, handler, permission, resource_type, resource_field) in [
            (
                "GET",
                "/analyses/{id}/conversation",
                "conversation-page",
                "rikune.conversation.use",
                ANALYSIS_RESOURCE_TYPE,
                "id",
            ),
            (
                "GET",
                ANALYSIS_MODELS_ROUTE,
                "analysis-models",
                "rikune.conversation.use",
                ANALYSIS_RESOURCE_TYPE,
                "id",
            ),
            (
                "GET",
                ANALYSIS_ARTIFACT_CONTENT_ROUTE,
                "analysis-artifact-content",
                "rikune.analysis.read",
                ANALYSIS_RESOURCE_TYPE,
                "id",
            ),
            (
                "POST",
                "/api/analyses/{id}/conversations",
                "conversation-create",
                "rikune.conversation.use",
                ANALYSIS_RESOURCE_TYPE,
                "id",
            ),
            (
                "POST",
                "/api/analyses/{id}/conversations/{cid}/persona",
                "conversation-persona",
                "rikune.conversation.use",
                CONVERSATION_RESOURCE_TYPE,
                "cid",
            ),
            (
                "POST",
                "/api/analyses/{id}/conversations/{cid}/turns",
                "turn-create",
                "rikune.conversation.use",
                CONVERSATION_RESOURCE_TYPE,
                "cid",
            ),
            (
                "GET",
                "/api/analyses/{id}/conversations/{cid}/turns/{tid}",
                "turn-status",
                "rikune.conversation.use",
                TURN_RESOURCE_TYPE,
                "tid",
            ),
            (
                "POST",
                "/api/analyses/{id}/conversations/{cid}/delete",
                "conversation-delete",
                "rikune.conversation.use",
                CONVERSATION_RESOURCE_TYPE,
                "cid",
            ),
        ] {
            let manifest_path = router_path.replace('{', ":").replace('}', "");
            let matching: Vec<&Value> = functions
                .iter()
                .filter(|entry| {
                    entry["method"] == method && entry["path"] == manifest_path.as_str()
                })
                .collect();
            assert_eq!(matching.len(), 1, "manifest route {manifest_path}");
            let entry = matching[0];
            assert_eq!(entry["handler"], handler);
            assert_eq!(entry["action"], permission);
            assert_eq!(entry["permission"], permission);
            assert_eq!(entry["resource"]["type"], resource_type);
            assert_eq!(entry["resource"]["source"], "path");
            assert_eq!(entry["resource"]["field"], resource_field);

            let permission_entry = permissions
                .iter()
                .find(|entry| entry["key"] == permission)
                .unwrap();
            assert_eq!(permission_entry["risk"], "medium");
        }

        let analysis_id = Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap();
        let conversation_id = Uuid::parse_str("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").unwrap();
        let turn_id = Uuid::parse_str("cccccccc-cccc-4ccc-8ccc-cccccccccccc").unwrap();
        assert_eq!(
            analysis_resource(analysis_id),
            (ANALYSIS_RESOURCE_TYPE, analysis_id.to_string())
        );
        assert_eq!(
            conversation_resource(conversation_id),
            (CONVERSATION_RESOURCE_TYPE, conversation_id.to_string())
        );
        assert_eq!(
            turn_resource(turn_id),
            (TURN_RESOURCE_TYPE, turn_id.to_string())
        );
    }
}
