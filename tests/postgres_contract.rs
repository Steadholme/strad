use sha2::{Digest, Sha256};
use sqlx::{Connection, Executor};
use strad::{
    analysis::AnalysisController,
    bridge::BridgeClient,
    chat::ChatEngine,
    config::{Config, OWNER_BYTES},
    migrations,
    newapi::{ChatMessage, FrozenChatRequest, NewApiClient, TokenBudgeter},
    store::{SampleDeleteClaim, Store},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

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
    let database_url = std::env::var("STRAD_TEST_DATABASE_URL")
        .expect("STRAD_TEST_DATABASE_URL is required; PostgreSQL contract tests never skip");
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
    assert_eq!(ledger.len(), 2);
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
        newapi_key: "n".repeat(32),
        newapi_url: "http://newapi:9080/v1/chat/completions".into(),
        newapi_model: "test-model".into(),
        newapi_context_tokens: 32_768,
        rikune_file_server_api_key: "f".repeat(32),
        upload_root: root.join("uploads"),
        template_root: root.join("templates"),
        canonical_host: "analyze.w33d.xyz".into(),
        canonical_route: "rikune-root".into(),
        expected_zone: "external".into(),
        session_lease: std::time::Duration::from_secs(1800),
        session_ttl: std::time::Duration::from_secs(86400),
    }
}
