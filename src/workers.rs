use std::time::Duration;

use sqlx::{pool::PoolConnection, PgPool, Postgres};
use tokio::{task::JoinHandle, time::MissedTickBehavior};

use crate::app::AppState;

pub fn spawn(state: AppState) -> Vec<JoinHandle<()>> {
    vec![
        tokio::spawn(run_analysis(state.clone())),
        tokio::spawn(run_outbox(state.clone())),
        tokio::spawn(run_retention(state.clone())),
        tokio::spawn(run_chat(state.clone())),
        tokio::spawn(run_upload_reconciliation(state)),
    ]
}

async fn run_analysis(state: AppState) {
    let _guard = acquire_worker_lock(state.store.pool(), "strad:worker:analysis").await;
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        if let Err(error) = state.store.recover_analysis_work().await {
            tracing::warn!(
                code = error.code(),
                "analysis lease recovery iteration failed"
            );
        }
        if let Err(error) = state.analysis.start_one().await {
            tracing::warn!(code = error.code(), "analysis starter iteration failed");
        }
        if let Err(error) = state.analysis.reconcile_uncertain().await {
            tracing::warn!(code = error.code(), "analysis reconciler iteration failed");
        }
        if let Err(error) = state.analysis.poll_batch().await {
            tracing::warn!(code = error.code(), "analysis poller iteration failed");
        }
    }
}

async fn run_outbox(state: AppState) {
    let _guard = acquire_worker_lock(state.store.pool(), "strad:worker:outbox").await;
    let mut tick = tokio::time::interval(Duration::from_millis(500));
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        match state.store.claim_outbox().await {
            Ok(Some(claim)) => {
                if let Err(error) = state.store.deliver_outbox(&claim).await {
                    tracing::warn!(outbox_id = %claim.id, code = error.code(), "outbox delivery failed");
                    if let Err(failure) = state.store.fail_outbox(&claim, error.code()).await {
                        tracing::error!(outbox_id = %claim.id, code = failure.code(), "outbox failure transition failed");
                    }
                }
            }
            Ok(None) => {}
            Err(error) => tracing::warn!(code = error.code(), "outbox claim failed"),
        }
    }
}

async fn run_retention(state: AppState) {
    let _guard = acquire_worker_lock(state.store.pool(), "strad:worker:retention").await;
    let mut tick = tokio::time::interval(Duration::from_secs(10));
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        if let Err(error) = state.store.recover_sample_delete_leases().await {
            tracing::warn!(code = error.code(), "sample deletion lease recovery failed");
        }
        if let Err(error) = state.cleanup.run_retention_once().await {
            tracing::warn!(code = error.code(), "retention claim iteration failed");
        }
        for _ in 0..16 {
            match state.cleanup.run_cleanup_once().await {
                Ok(true) => {}
                Ok(false) => break,
                Err(error) => {
                    tracing::warn!(code = error.code(), "cleanup iteration failed");
                    break;
                }
            }
        }
        for _ in 0..16 {
            match state.cleanup.run_sample_delete_once().await {
                Ok(true) => {}
                Ok(false) => break,
                Err(error) => {
                    tracing::warn!(code = error.code(), "sample deletion iteration failed");
                    break;
                }
            }
        }
        if let Err(error) = state.store.reap_events().await {
            tracing::warn!(code = error.code(), "event retention iteration failed");
        }
        if let Err(error) = state.store.run_bounded_reapers().await {
            tracing::warn!(code = error.code(), "bounded tombstone reaper failed");
        }
    }
}

async fn run_chat(state: AppState) {
    let _guard = acquire_worker_lock(state.store.pool(), "strad:worker:chat").await;
    let mut tick = tokio::time::interval(Duration::from_millis(500));
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        match state.chat.run_once().await {
            Ok(_) => {}
            Err(error) => tracing::warn!(code = error.code(), "chat worker iteration failed"),
        }
    }
}

async fn run_upload_reconciliation(state: AppState) {
    let _guard = acquire_worker_lock(state.store.pool(), "strad:worker:upload-reconcile").await;
    let mut tick = tokio::time::interval(Duration::from_secs(30));
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        match state.store.expired_uploads(16).await {
            Ok(expired) => {
                for (upload_id, owner_sub) in expired {
                    if let Err(error) = state.upload.cancel(&owner_sub, upload_id).await {
                        tracing::warn!(upload_id = %upload_id, code = error.code(), "expired upload cleanup failed");
                    }
                }
            }
            Err(error) => tracing::warn!(code = error.code(), "expired upload scan failed"),
        }
        if let Err(error) = state.upload.reconcile_uncertain().await {
            tracing::warn!(
                code = error.code(),
                "upload reconciliation iteration failed"
            );
        }
        if let Err(error) = state.upload.sweep_cancellations().await {
            tracing::warn!(code = error.code(), "upload cancellation sweep failed");
        }
    }
}

async fn acquire_worker_lock(pool: &PgPool, key: &'static str) -> PoolConnection<Postgres> {
    loop {
        match pool.acquire().await {
            Ok(mut connection) => {
                let locked = sqlx::query_scalar::<_, bool>(
                    "SELECT pg_try_advisory_lock(hashtextextended($1,0))",
                )
                .bind(key)
                .fetch_one(&mut *connection)
                .await;
                match locked {
                    Ok(true) => {
                        tracing::info!(worker_lock = key, "worker leadership acquired");
                        return connection;
                    }
                    Ok(false) => {}
                    Err(error) => {
                        tracing::warn!(worker_lock = key, error = %error, "worker lock probe failed")
                    }
                }
            }
            Err(error) => {
                tracing::warn!(worker_lock = key, error = %error, "worker lock connection failed")
            }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}
