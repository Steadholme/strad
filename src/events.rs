use std::{convert::Infallible, time::Duration};

use axum::response::sse::{Event, KeepAlive, Sse};
use futures_util::Stream;
use serde_json::json;
use tokio::time::{interval, MissedTickBehavior};
use uuid::Uuid;

use crate::{error::Result, models::Analysis, store::Store};

pub fn parse_last_event_id(header: Option<&str>, query: Option<&str>) -> Result<i64> {
    if header.is_some() && query.is_some() && header != query {
        return Err(crate::error::AppError::invalid(
            "invalid_request",
            "Last-Event-ID header and query value conflict.",
        ));
    }
    let raw = header.or(query).unwrap_or("0");
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(crate::error::AppError::invalid(
            "invalid_request",
            "Last-Event-ID is invalid.",
        ));
    }
    let parsed: i64 = raw.parse().map_err(|_| {
        crate::error::AppError::invalid("invalid_request", "Last-Event-ID is invalid.")
    })?;
    Ok(parsed)
}

pub fn stream(
    store: Store,
    owner_sub: String,
    analysis: Analysis,
    last_event_id: i64,
) -> Sse<impl Stream<Item = std::result::Result<Event, Infallible>>> {
    let output = async_stream::stream! {
        let mut cursor = last_event_id;
        if cursor.saturating_add(1) < analysis.retained_from_seq {
            yield Ok(resync_event(&analysis));
            return;
        }
        let mut poll = interval(Duration::from_secs(1));
        poll.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut heartbeat = interval(Duration::from_secs(15));
        heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
        // Consume the immediate heartbeat tick; real heartbeat cadence starts in 15 seconds.
        heartbeat.tick().await;
        loop {
            tokio::select! {
                _ = poll.tick() => {
                    let events = match store.events_after(&owner_sub, analysis.id, cursor, 257).await {
                        Ok(events) => events,
                        Err(error) => {
                            tracing::warn!(analysis_id = %analysis.id, code = error.code(), "SSE replay failed");
                            yield Ok(resync_event(&analysis));
                            return;
                        }
                    };
                    if events.len() > 256 {
                        yield Ok(resync_event(&analysis));
                        return;
                    }
                    for event in events {
                        cursor = event.seq;
                        let data = json!({
                            "seq": event.seq,
                            "analysis_id": event.analysis_id,
                            "type": event.event_type,
                            "payload": event.payload,
                            "created_at": event.created_at,
                        });
                        yield Ok(Event::default()
                            .id(event.seq.to_string())
                            .event(event.event_type)
                            .data(data.to_string()));
                    }
                }
                _ = heartbeat.tick() => {
                    yield Ok(Event::default().comment("heartbeat"));
                }
            }
        }
    };
    Sse::new(output).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("heartbeat"),
    )
}

fn resync_event(analysis: &Analysis) -> Event {
    Event::default().event("resync").data(
        json!({
            "analysis_id": analysis.id,
            "status_url": format!("/analyses/{}", analysis.id),
            "stream_head": analysis.next_event_seq.saturating_sub(1),
            "retained_from_seq": analysis.retained_from_seq,
        })
        .to_string(),
    )
}

pub fn canonical_status_url(analysis_id: Uuid) -> String {
    format!("/analyses/{analysis_id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_event_id_sources_must_match() {
        assert_eq!(parse_last_event_id(Some("41"), None).unwrap(), 41);
        assert_eq!(parse_last_event_id(Some("41"), Some("41")).unwrap(), 41);
        assert!(parse_last_event_id(Some("41"), Some("42")).is_err());
        assert!(parse_last_event_id(Some("-1"), None).is_err());
    }

    #[tokio::test]
    async fn retention_gap_emits_one_resync_event_and_closes() {
        use axum::{body::to_bytes, response::IntoResponse};
        use time::OffsetDateTime;

        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgresql://unused:unused@127.0.0.1:1/unused")
            .unwrap();
        let analysis_id = Uuid::new_v4();
        let analysis = Analysis {
            id: analysis_id,
            owner_sub: "user:test".into(),
            upload_id: Uuid::new_v4(),
            sample_id: None,
            display_name: "sample.bin".into(),
            state: "analyzing".into(),
            plan_id: None,
            case_id: None,
            case_artifact_id: None,
            current_stage: None,
            latest_stage: None,
            retained_from_seq: 8,
            next_event_seq: 12,
            retention_until: OffsetDateTime::now_utc(),
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        };
        let response =
            stream(Store::from_pool(pool), "user:test".into(), analysis, 1).into_response();
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.contains("event: resync"));
        assert!(text.contains(&analysis_id.to_string()));
        assert!(text.contains("retained_from_seq"));
    }
}
