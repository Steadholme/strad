use std::time::Duration;

use tokio::time::{interval, MissedTickBehavior};

use crate::{error::Result, store::Store};

pub async fn dispatch_once(store: &Store) -> Result<bool> {
    let Some(claimed) = store.claim_outbox().await? else {
        return Ok(false);
    };
    match store.deliver_outbox(&claimed).await {
        Ok(_) => Ok(true),
        Err(error) => {
            tracing::warn!(outbox_id = %claimed.id, code = error.code(), "outbox delivery failed");
            store.fail_outbox(&claimed, error.code()).await?;
            Ok(false)
        }
    }
}

pub async fn run(store: Store) {
    let mut ticker = interval(Duration::from_secs(1));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        for _ in 0..64 {
            match dispatch_once(&store).await {
                Ok(true) => continue,
                Ok(false) => break,
                Err(error) => {
                    tracing::error!(code = error.code(), "outbox worker failed");
                    break;
                }
            }
        }
    }
}

pub async fn run_event_reaper(store: Store) {
    let mut ticker = interval(Duration::from_secs(60));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        if let Err(error) = store.reap_events().await {
            tracing::error!(code = error.code(), "event reaper failed");
        }
    }
}
