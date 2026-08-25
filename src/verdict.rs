use std::time::Duration;

use futures_util::StreamExt;
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{auth::Identity, config::Config, error::AppError};

const MAX_BODY: usize = 64 * 1024;

#[derive(Clone)]
pub struct VerdictClient {
    http: reqwest::Client,
    endpoint: String,
    token: String,
}

impl std::fmt::Debug for VerdictClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerdictClient")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Risk {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct CheckRequest<'a> {
    subject: &'a str,
    permission: &'a str,
    resource: Resource<'a>,
    context: DecisionContext<'a>,
    risk: Risk,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct Resource<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    id: &'a str,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct DecisionContext<'a> {
    zone: &'a str,
    mfa: bool,
    ip: Option<&'a str>,
    request_id: String,
    break_glass: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckResponse {
    decision: Decision,
    reason: String,
    epoch: i64,
    evaluated_at: i64,
    evidence: Vec<Evidence>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    edge_id: String,
    source_grant_id: String,
    effect: Effect,
    path: Vec<String>,
    condition_result: String,
}

#[derive(Debug, Deserialize)]
enum Decision {
    Allow,
    Deny,
    Indeterminate,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Effect {
    Allow,
    Deny,
}

impl VerdictClient {
    pub fn new(config: &Config) -> std::result::Result<Self, String> {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(2))
            .redirect(Policy::none())
            .build()
            .map_err(|_| "failed to build Verdict client".to_string())?;
        Ok(Self {
            http,
            endpoint: config.verdict_url.clone(),
            token: config.verdict_decision_token.clone(),
        })
    }

    pub async fn authorize(
        &self,
        identity: &Identity,
        permission: &str,
        resource_type: &str,
        resource_id: &str,
        risk: Risk,
    ) -> Result<(), AppError> {
        let body = CheckRequest {
            subject: &identity.subject,
            permission,
            resource: Resource {
                kind: resource_type,
                id: resource_id,
            },
            context: DecisionContext {
                zone: &identity.zone,
                mfa: false,
                ip: None,
                request_id: identity.request_id.to_string(),
                break_glass: false,
            },
            risk,
        };
        let response = self
            .http
            .post(&self.endpoint)
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .map_err(|_| authz_unavailable())?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(authz_unavailable());
        }
        let mut collected = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| authz_unavailable())?;
            if collected.len().saturating_add(chunk.len()) > MAX_BODY {
                return Err(authz_unavailable());
            }
            collected.extend_from_slice(&chunk);
        }
        let response: CheckResponse =
            serde_json::from_slice(&collected).map_err(|_| authz_unavailable())?;
        let _strictly_consumed = (
            &response.reason,
            response.epoch,
            response.evaluated_at,
            response.evidence.iter().map(|e| {
                (
                    &e.edge_id,
                    &e.source_grant_id,
                    &e.effect,
                    &e.path,
                    &e.condition_result,
                )
            }),
        );
        match response.decision {
            Decision::Allow => Ok(()),
            Decision::Deny => Err(AppError::api(
                axum::http::StatusCode::FORBIDDEN,
                "forbidden",
                "Access was denied.",
                false,
            )),
            Decision::Indeterminate => Err(authz_unavailable()),
        }
    }

    pub async fn readiness_probe(&self) -> Result<(), AppError> {
        let identity = Identity {
            subject: "user:strad-readiness".to_string(),
            email: None,
            zone: "external".to_string(),
            request_id: Uuid::new_v4(),
        };
        match self
            .authorize(
                &identity,
                "rikune.console.enter",
                "route",
                "rikune-root",
                Risk::Critical,
            )
            .await
        {
            Ok(()) => Ok(()),
            Err(AppError::Api { status, .. }) if status == axum::http::StatusCode::FORBIDDEN => {
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
}

fn authz_unavailable() -> AppError {
    AppError::unavailable(
        "authorization_unavailable",
        "Authorization is temporarily unavailable.",
    )
}
