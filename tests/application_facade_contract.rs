use std::collections::BTreeSet;

use axum::response::IntoResponse;
use sha2::{Digest, Sha256};
use strad::application_facade::{is_public_tool, ExecutionEnvelopeV1, PUBLIC_TOOLS};
use strad::error::AppError;

const VERDICT_KNOWN_DIGEST: &str =
    "a2f92fb7e2eb50062013fffd0445bd489860039c2cea005cacedbd5e992adfb7";
const VERDICT_KNOWN_DECISION_ID: &str = "dec_a2f92fb7e2eb50062013fffd0445bd48";
const VERDICT_KNOWN_CANONICAL_JSON: &str = r#"{"domain":"w33d.verdict.application-decision.v2","request":{"v":2,"application_sub":"application:knownvector0001","client_id":"client_known","credential_id":"11111111-1111-4111-8111-111111111111","credential_version":3,"grant_id":"grant_known","package_id":"pkg_analyze_mcp_client","package_revision_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","scopes":["analysis.read"],"canonical_tool":"analysis.read","resource":{"type":"analysis","id":"22222222-2222-4222-8222-222222222222"},"session_id":"session_known","request_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","policy_epoch":11,"revocation_epoch":13,"correlation_id":"33333333-3333-4333-8333-333333333333"},"subject":"application:knownvector0001","resource":{"type":"analysis","id":"22222222-2222-4222-8222-222222222222"},"permission":"rikune.analysis.read","decision":"Allow","reason":"matching application projection","evidence":[],"policy_version":5,"subject_version":7,"policy_epoch":11,"issued_at":1788307200,"expires_at":1788307230}"#;

#[test]
fn private_adapter_allows_exact_four_and_no_raw_authorization() {
    let source = include_str!("../src/application_facade.rs");
    for tool in [
        "analysis.create",
        "analysis.read",
        "analysis.conversation",
        "analysis.upload.cancel",
    ] {
        assert!(source.contains(tool), "missing public tool {tool}");
    }
    assert!(source.contains("ExecutionEnvelopeV1"));
    assert!(!source.contains("raw_authorization"));
    assert_eq!(
        PUBLIC_TOOLS,
        [
            "analysis.create",
            "analysis.read",
            "analysis.conversation",
            "analysis.upload.cancel",
        ]
    );
    for forbidden in [
        "analysis.promote",
        "analysis.delete",
        "console.enter",
        "tools.call",
        "rikune.analysis.create",
    ] {
        assert!(!is_public_tool(forbidden));
    }
    let envelope = ExecutionEnvelopeV1 {
        version: 1,
        decision_id: VERDICT_KNOWN_DECISION_ID.into(),
        decision_digest: VERDICT_KNOWN_DIGEST.into(),
        subject_version: 1,
        application_sub: "application:test_client".into(),
        credential_id: "acr_task001_contract".into(),
        credential_version: 1,
        policy_epoch: 2,
        revocation_epoch: 3,
        request_sha256: "b".repeat(64),
        mcp_session_digest: "c".repeat(64),
        issued_at: 1_788_307_200,
        expires_at: 1_788_307_230,
    };
    let value = serde_json::to_value(envelope).unwrap();
    let keys: BTreeSet<&str> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let task001: serde_json::Value =
        serde_json::from_str(include_str!("../ops/analyze/analyze-public-v1.json")).unwrap();
    let authoritative_keys: BTreeSet<&str> = task001["execution"]["envelope_fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| field.as_str().unwrap())
        .collect();
    assert_eq!(keys, authoritative_keys);
    assert_eq!(value["credential_id"], "acr_task001_contract");
    assert_eq!(value["issued_at"], 1_788_307_200_i64);
    assert_eq!(value["expires_at"], 1_788_307_230_i64);
    let mut legacy = value.clone();
    legacy
        .as_object_mut()
        .unwrap()
        .insert("grant_id".into(), serde_json::json!("grt_forbidden"));
    assert!(serde_json::from_value::<ExecutionEnvelopeV1>(legacy).is_err());
    let serialized = serde_json::to_string(&value).unwrap();
    for forbidden in ["authorization", "credential_token", "app_v1_"] {
        assert!(!serialized.contains(forbidden));
    }
}

#[test]
fn quota_errors_emit_frozen_integer_headers_and_retry_after() {
    let response = AppError::quota("quota", 120, 7, 1_788_000_000, 5).into_response();
    assert_eq!(response.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);
    for (name, expected) in [
        ("x-ratelimit-limit", "120"),
        ("x-ratelimit-remaining", "7"),
        ("x-ratelimit-reset", "1788000000"),
        ("retry-after", "5"),
    ] {
        assert_eq!(response.headers().get(name).unwrap(), expected);
    }
}

#[test]
fn execution_envelope_preserves_verdict_known_vector_and_rejects_tamper() {
    assert_eq!(
        hex::encode(Sha256::digest(VERDICT_KNOWN_CANONICAL_JSON.as_bytes())),
        VERDICT_KNOWN_DIGEST
    );
    let now = time::OffsetDateTime::now_utc();
    let now_unix = now.unix_timestamp();
    let envelope = ExecutionEnvelopeV1 {
        version: 1,
        decision_id: VERDICT_KNOWN_DECISION_ID.into(),
        decision_digest: VERDICT_KNOWN_DIGEST.into(),
        subject_version: 7,
        application_sub: "application:knownvector0001".into(),
        credential_id: "acr_task002_known_vector".into(),
        credential_version: 3,
        policy_epoch: 11,
        revocation_epoch: 13,
        request_sha256: "b".repeat(64),
        mcp_session_digest: "c".repeat(64),
        issued_at: now_unix,
        expires_at: now_unix + 30,
    };
    envelope
        .validate_binding(&envelope.application_sub, &envelope.request_sha256, now)
        .unwrap();
    let expected_application = envelope.application_sub.clone();
    let expected_request = envelope.request_sha256.clone();
    let mut mutations = Vec::new();
    let mut malformed_digest = envelope.clone();
    malformed_digest.decision_digest = "not-a-digest".into();
    mutations.push(malformed_digest);
    let mut changed_id = envelope.clone();
    changed_id.decision_id.clear();
    mutations.push(changed_id);
    let mut zero_subject_version = envelope.clone();
    zero_subject_version.subject_version = 0;
    mutations.push(zero_subject_version);
    let mut zero_credential_version = envelope.clone();
    zero_credential_version.credential_version = 0;
    mutations.push(zero_credential_version);
    let mut malformed_credential = envelope.clone();
    malformed_credential.credential_id = "not-an-access-credential".into();
    mutations.push(malformed_credential);
    let mut zero_policy_epoch = envelope.clone();
    zero_policy_epoch.policy_epoch = 0;
    mutations.push(zero_policy_epoch);
    let mut zero_revocation_epoch = envelope.clone();
    zero_revocation_epoch.revocation_epoch = 0;
    mutations.push(zero_revocation_epoch);
    let mut malformed_session = envelope.clone();
    malformed_session.mcp_session_digest = "not-a-digest".into();
    mutations.push(malformed_session);
    let mut changed_application = envelope.clone();
    changed_application.application_sub = "application:different".into();
    mutations.push(changed_application);
    let mut changed_request = envelope.clone();
    changed_request.request_sha256 = "f".repeat(64);
    mutations.push(changed_request);
    let mut expired = envelope.clone();
    expired.expires_at = now_unix - 1;
    mutations.push(expired);
    for mutation in mutations {
        assert_eq!(
            mutation
                .validate_binding(&expected_application, &expected_request, now)
                .unwrap_err()
                .code(),
            "invalid_request"
        );
    }
}
