use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    bridge::{
        BridgeClient, CaseCheckpointRequest, CaseCheckpointResult, CaseProducer, CaseState,
        MutationOutcome, OperationState, StageStatus, WorkflowPromoteRequest, WorkflowResult,
        WorkflowStartRequest,
    },
    error::{AppError, Result},
    models::Analysis,
    store::Store,
};

#[derive(Clone, Debug)]
pub struct AnalysisController {
    store: Store,
    bridge: BridgeClient,
}

impl AnalysisController {
    pub fn new(store: Store, bridge: BridgeClient) -> Self {
        Self { store, bridge }
    }

    pub async fn start_one(&self) -> Result<bool> {
        let Some(analysis) = self.store.claim_start().await? else {
            return Ok(false);
        };
        let sample_id = analysis
            .sample_id
            .as_deref()
            .ok_or(AppError::Invariant("uploaded analysis has no sample"))?;
        let request = WorkflowStartRequest::static_balanced(sample_id);
        let operation_id = Uuid::new_v4();
        let request_sha = json_sha(&request)?;
        self.store
            .begin_worker_operation(&analysis, "start", operation_id, &request_sha)
            .await?;
        match self.bridge.workflow_start(operation_id, &request).await {
            Ok(MutationOutcome::Complete(result)) => {
                self.materialize_artifacts(&analysis, &result).await?;
                let body = serde_json::to_value(&result)
                    .map_err(|_| AppError::Invariant("workflow result is not serializable"))?;
                self.store
                    .finish_worker_operation(&analysis, "start", operation_id, false, Some(&body))
                    .await?;
                self.store
                    .finish_start(&analysis, Some(&result.plan_id), false)
                    .await?;
            }
            Ok(MutationOutcome::Pending) | Err(_) => {
                self.store
                    .finish_worker_operation(&analysis, "start", operation_id, true, None)
                    .await?;
                self.store.finish_start(&analysis, None, true).await?;
            }
        }
        Ok(true)
    }

    pub async fn poll_batch(&self) -> Result<u64> {
        let analyses = self.store.analyses_for_poll(32).await?;
        let mut progressed = 0;
        for analysis in analyses {
            let Some(plan_id) = analysis.plan_id.as_deref() else {
                continue;
            };
            let status = match self.bridge.workflow_status(plan_id).await {
                Ok(status) => status,
                Err(error) => {
                    tracing::warn!(analysis_id = %analysis.id, code = error.code(), "workflow poll failed");
                    continue;
                }
            };
            self.materialize_artifacts(&analysis, &status).await?;
            self.apply_status(&analysis, &status).await?;
            progressed += 1;
        }
        Ok(progressed)
    }

    pub async fn promote(&self, analysis: &Analysis, operation_id: Uuid) -> Result<bool> {
        let plan_id = analysis
            .plan_id
            .as_deref()
            .ok_or_else(|| AppError::conflict("state_conflict", "The analysis has no plan."))?;
        let request = WorkflowPromoteRequest::function_map(plan_id);
        let request_sha = json_sha(&request)?;
        self.store
            .begin_worker_operation(analysis, "promote", operation_id, &request_sha)
            .await?;
        match self.bridge.workflow_promote(operation_id, &request).await {
            Ok(MutationOutcome::Complete(result)) => {
                self.materialize_artifacts(analysis, &result).await?;
                let value = serde_json::to_value(&result)
                    .map_err(|_| AppError::Invariant("workflow result is not serializable"))?;
                self.store
                    .finish_worker_operation(analysis, "promote", operation_id, false, Some(&value))
                    .await?;
                self.store
                    .apply_workflow_status(
                        analysis,
                        "analyzing",
                        result.current_stage.as_deref(),
                        result.latest_stage.as_deref(),
                        "analysis.promoted",
                        workflow_event(analysis.id, "analyzing", &result),
                    )
                    .await?;
                Ok(true)
            }
            Ok(MutationOutcome::Pending) | Err(_) => {
                self.store
                    .finish_worker_operation(analysis, "promote", operation_id, true, None)
                    .await?;
                self.store
                    .apply_workflow_status(
                        analysis,
                        "degraded",
                        analysis.current_stage.as_deref(),
                        analysis.latest_stage.as_deref(),
                        "analysis.downstream_uncertain",
                        json!({"analysis_id":analysis.id,"state":"degraded"}),
                    )
                    .await?;
                Ok(false)
            }
        }
    }

    pub async fn reconcile_uncertain(&self) -> Result<u64> {
        let rows = sqlx::query(
            "SELECT i.owner_sub,i.scope,i.operation_id,a.id AS analysis_id \
             FROM idempotency_operations i JOIN analyses a ON a.owner_sub=i.owner_sub \
             AND i.scope IN ('worker:start:'||a.id::text,'worker:promote:'||a.id::text,'worker:checkpoint:'||a.id::text) \
             WHERE i.state='downstream_uncertain' ORDER BY i.updated_at LIMIT 32",
        )
        .fetch_all(self.store.pool())
        .await?;
        let mut progressed = 0;
        for row in rows {
            use sqlx::Row;
            let owner_sub: String = row.get("owner_sub");
            let scope: String = row.get("scope");
            let operation_id: Uuid = row.get("operation_id");
            let analysis_id: Uuid = row.get("analysis_id");
            let analysis = match self.store.get_analysis(&owner_sub, analysis_id).await {
                Ok(analysis) => analysis,
                Err(_) => continue,
            };
            let operation = match self.bridge.operation(operation_id).await {
                Ok(operation) => operation,
                Err(_) => continue,
            };
            match operation.state {
                OperationState::Pending | OperationState::Unknown => continue,
                OperationState::Failed => {
                    let code = operation
                        .error
                        .as_ref()
                        .map(|error| error.code.as_str())
                        .unwrap_or("analyzer_operation_failed");
                    let kind = operation_kind(&scope)?;
                    self.store
                        .fail_worker_operation(&analysis, kind, operation_id, code)
                        .await?;
                    let (state, event) = if kind == "start" {
                        ("failed", "analysis.failed")
                    } else {
                        ("degraded", "analysis.downstream_failed")
                    };
                    self.store
                        .apply_workflow_status(
                            &analysis,
                            state,
                            analysis.current_stage.as_deref(),
                            analysis.latest_stage.as_deref(),
                            event,
                            json!({"analysis_id":analysis.id,"state":state,"operation":kind}),
                        )
                        .await?;
                    progressed += 1;
                }
                OperationState::Succeeded => {
                    let result = operation.result.ok_or(AppError::Invariant(
                        "succeeded analyzer operation omitted result",
                    ))?;
                    let kind = operation_kind(&scope)?;
                    match kind {
                        "start" => {
                            let result: WorkflowResult =
                                serde_json::from_value(result).map_err(|_| {
                                    AppError::Invariant("reconciled start schema drift")
                                })?;
                            self.materialize_artifacts(&analysis, &result).await?;
                            self.complete_reconciled_workflow(
                                &analysis,
                                kind,
                                operation_id,
                                &result,
                            )
                            .await?;
                            self.store
                                .finish_start(&analysis, Some(&result.plan_id), false)
                                .await?;
                        }
                        "promote" => {
                            let result: WorkflowResult =
                                serde_json::from_value(result).map_err(|_| {
                                    AppError::Invariant("reconciled promote schema drift")
                                })?;
                            self.materialize_artifacts(&analysis, &result).await?;
                            self.complete_reconciled_workflow(
                                &analysis,
                                kind,
                                operation_id,
                                &result,
                            )
                            .await?;
                            self.store
                                .apply_workflow_status(
                                    &analysis,
                                    "analyzing",
                                    result.current_stage.as_deref(),
                                    result.latest_stage.as_deref(),
                                    "analysis.promoted",
                                    workflow_event(analysis.id, "analyzing", &result),
                                )
                                .await?;
                        }
                        "checkpoint" => {
                            let result: CaseCheckpointResult = serde_json::from_value(result)
                                .map_err(|_| {
                                    AppError::Invariant("reconciled checkpoint schema drift")
                                })?;
                            let value = serde_json::to_value(&result).map_err(|_| {
                                AppError::Invariant("checkpoint result is not serializable")
                            })?;
                            self.store
                                .finish_worker_operation(
                                    &analysis,
                                    kind,
                                    operation_id,
                                    false,
                                    Some(&value),
                                )
                                .await?;
                            self.store
                                .save_case(
                                    &analysis,
                                    &result.case_id,
                                    &result.checkpoint_artifact_id,
                                )
                                .await?;
                            self.store
                                .apply_workflow_status(
                                    &analysis,
                                    "analyzed",
                                    analysis.current_stage.as_deref(),
                                    analysis.latest_stage.as_deref(),
                                    "analysis.completed",
                                    json!({"analysis_id":analysis.id,"state":"analyzed"}),
                                )
                                .await?;
                        }
                        _ => unreachable!("operation_kind returns a closed set"),
                    }
                    progressed += 1;
                }
            }
        }
        Ok(progressed)
    }

    async fn complete_reconciled_workflow(
        &self,
        analysis: &Analysis,
        kind: &str,
        operation_id: Uuid,
        result: &WorkflowResult,
    ) -> Result<()> {
        let value = serde_json::to_value(result)
            .map_err(|_| AppError::Invariant("workflow result is not serializable"))?;
        self.store
            .finish_worker_operation(analysis, kind, operation_id, false, Some(&value))
            .await
    }

    async fn apply_status(&self, analysis: &Analysis, status: &WorkflowResult) -> Result<()> {
        if status
            .stage_statuses
            .iter()
            .any(|stage| stage.status == "failed")
        {
            self.store
                .apply_workflow_status(
                    analysis,
                    "failed",
                    status.current_stage.as_deref(),
                    status.latest_stage.as_deref(),
                    "analysis.failed",
                    workflow_event(analysis.id, "failed", status),
                )
                .await?;
            return Ok(());
        }
        if status.stage_statuses.iter().any(recovery_blocked) {
            self.store
                .apply_workflow_status(
                    analysis,
                    "degraded",
                    status.current_stage.as_deref(),
                    status.latest_stage.as_deref(),
                    "analysis.degraded",
                    workflow_event(analysis.id, "degraded", status),
                )
                .await?;
            return Ok(());
        }
        let function_complete = status
            .stage_statuses
            .iter()
            .any(|stage| stage.stage == "function_map" && stage.status == "completed")
            && status.function_index_ready;
        if function_complete {
            if analysis.case_id.is_none() && !self.create_case(analysis).await? {
                return Ok(());
            }
            self.store
                .apply_workflow_status(
                    analysis,
                    "analyzed",
                    status.current_stage.as_deref(),
                    status.latest_stage.as_deref(),
                    "analysis.completed",
                    workflow_event(analysis.id, "analyzed", status),
                )
                .await?;
            return Ok(());
        }
        if status.stage_statuses.iter().any(active) {
            self.store
                .apply_workflow_status(
                    analysis,
                    "analyzing",
                    status.current_stage.as_deref(),
                    status.latest_stage.as_deref(),
                    "analysis.stage",
                    workflow_event(analysis.id, "analyzing", status),
                )
                .await?;
            return Ok(());
        }
        // No active/deferred job: the target-stage controller may safely request the next bounded
        // static promotion. Each mutation has a distinct durable operation identity.
        if !self
            .store
            .has_unresolved_worker_operation(analysis, "promote")
            .await?
        {
            self.promote(analysis, Uuid::new_v4()).await?;
        }
        Ok(())
    }

    async fn materialize_artifacts(
        &self,
        analysis: &Analysis,
        status: &WorkflowResult,
    ) -> Result<()> {
        for selector in &status.artifact_selectors {
            if selector.sample_id != analysis.sample_id.as_deref().unwrap_or("")
                || selector.read_args.sample_id != selector.sample_id
                || selector.read_args.artifact_id != selector.artifact_id
                || !matches!(
                    selector.read_args.read_mode.as_str(),
                    "profile" | "summary" | "content"
                )
                || selector.read_args.read_mode != selector.suggested_read_mode
                || selector.artifact_id.is_empty()
                // `artifact_ref` is persisted as `ref:<artifact_id>` and the frozen
                // database constraint caps that complete value at 240 bytes.
                || selector.artifact_id.len() > 236
                || !selector.artifact_id.bytes().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_-".contains(&byte)
                })
                || selector.artifact_type.is_empty()
                || selector.path.is_empty()
                || selector.path.len() > 2048
            {
                return Err(AppError::Invariant(
                    "workflow artifact selector violates the frozen contract",
                ));
            }
            let Some(sha256) = selector.sha256.as_deref() else {
                continue;
            };
            if sha256.len() != 64
                || !sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(AppError::Invariant(
                    "workflow artifact selector has an invalid digest",
                ));
            }
            self.store
                .upsert_context_artifact(
                    &analysis.owner_sub,
                    analysis.id,
                    &selector.artifact_id,
                    &selector.artifact_type,
                    &format!("ref:{}", selector.artifact_id),
                    &selector.path,
                    sha256,
                    selector.mime.as_deref(),
                    "workflow.status",
                )
                .await?;
        }
        Ok(())
    }

    async fn create_case(&self, analysis: &Analysis) -> Result<bool> {
        if self
            .store
            .has_unresolved_worker_operation(analysis, "checkpoint")
            .await?
        {
            return Ok(false);
        }
        let sample_id = analysis
            .sample_id
            .as_deref()
            .ok_or(AppError::Invariant("analyzed record has no sample"))?;
        let request = CaseCheckpointRequest {
            sample_id,
            parent_artifact_id: None,
            session_tag: format!("strad:{}", analysis.id),
            producer: CaseProducer {
                kind: "external_agent",
                agent_name: "strad",
            },
            state: CaseState {
                objective: format!("Static analysis for {}", analysis.display_name),
                decisions: vec![],
                open_questions: vec![],
                attempted_actions: vec![],
                active_claim_ids: vec![],
                pinned_artifact_ids: vec![],
                next_actions: vec!["Answer owner questions from current evidence".into()],
            },
        };
        let operation_id = Uuid::new_v4();
        let request_sha = json_sha(&request)?;
        self.store
            .begin_worker_operation(analysis, "checkpoint", operation_id, &request_sha)
            .await?;
        match self.bridge.checkpoint(operation_id, &request).await {
            Ok(MutationOutcome::Complete(result)) => {
                let value = serde_json::to_value(&result)
                    .map_err(|_| AppError::Invariant("case result is not serializable"))?;
                self.store
                    .finish_worker_operation(
                        analysis,
                        "checkpoint",
                        operation_id,
                        false,
                        Some(&value),
                    )
                    .await?;
                self.store
                    .save_case(analysis, &result.case_id, &result.checkpoint_artifact_id)
                    .await?;
                Ok(true)
            }
            Ok(MutationOutcome::Pending) | Err(_) => {
                self.store
                    .finish_worker_operation(analysis, "checkpoint", operation_id, true, None)
                    .await?;
                self.store
                    .apply_workflow_status(
                        analysis,
                        "degraded",
                        analysis.current_stage.as_deref(),
                        analysis.latest_stage.as_deref(),
                        "analysis.checkpoint_uncertain",
                        json!({"analysis_id":analysis.id,"state":"degraded"}),
                    )
                    .await?;
                Ok(false)
            }
        }
    }
}

fn operation_kind(scope: &str) -> Result<&'static str> {
    for kind in ["start", "promote", "checkpoint"] {
        if scope.starts_with(&format!("worker:{kind}:")) {
            return Ok(kind);
        }
    }
    Err(AppError::Invariant("unknown worker operation scope"))
}

fn active(stage: &StageStatus) -> bool {
    matches!(stage.status.as_str(), "queued" | "running")
        || stage
            .execution_state
            .as_deref()
            .is_some_and(|state| matches!(state, "queued" | "running" | "deferred"))
}

fn recovery_blocked(stage: &StageStatus) -> bool {
    stage
        .recovery_state
        .as_deref()
        .is_some_and(|state| matches!(state, "recoverable" | "interrupted"))
}

fn workflow_event(analysis_id: Uuid, state: &str, workflow: &WorkflowResult) -> serde_json::Value {
    json!({
        "analysis_id": analysis_id,
        "state": state,
        "current_stage": workflow.current_stage,
        "latest_stage": workflow.latest_stage,
        "stage_statuses": workflow.stage_statuses,
        "function_index_ready": workflow.function_index_ready
    })
}

fn json_sha<T: Serialize>(value: &T) -> Result<String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| AppError::Invariant("failed to serialize analyzer request"))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controller_never_promotes_while_a_job_is_active() {
        let running = StageStatus {
            stage: "enrich_static".into(),
            status: "partial".into(),
            execution_state: Some("running".into()),
            recovery_state: None,
            job_id: Some("job".into()),
        };
        assert!(active(&running));
        let terminated_partial = StageStatus {
            execution_state: Some("completed".into()),
            ..running
        };
        assert!(!active(&terminated_partial));
    }
}
