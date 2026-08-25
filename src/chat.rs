use std::time::Duration;

use futures_util::StreamExt;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::time::timeout;

use crate::{
    bridge::{BridgeClient, ContextPackRequest},
    citation,
    error::{AppError, Result},
    models::{Conversation, Turn},
    newapi::{response_limits, FrozenChatRequest, NewApiClient, TokenBudgeter},
    store::Store,
};

#[derive(Clone, Debug)]
pub struct ChatEngine {
    store: Store,
    bridge: BridgeClient,
    newapi: NewApiClient,
    budgeter: TokenBudgeter,
}

impl ChatEngine {
    pub fn new(
        store: Store,
        bridge: BridgeClient,
        newapi: NewApiClient,
        budgeter: TokenBudgeter,
    ) -> Self {
        Self {
            store,
            bridge,
            newapi,
            budgeter,
        }
    }

    pub async fn run_once(&self) -> Result<bool> {
        let Some(turn) = self.store.claim_turn().await? else {
            let Some((turn, assistant)) = self.store.unresolved_citation_work().await? else {
                return Ok(false);
            };
            citation::resolve(&self.store, &self.bridge, &turn, &assistant).await?;
            return Ok(true);
        };
        let assistant = self.store.assistant_message(turn.id).await?;
        if !assistant.content.is_empty() {
            self.store
                .finish_turn(
                    &turn,
                    "partial",
                    "partial",
                    Some("generation_interrupted"),
                    0,
                    assistant.token_count,
                    self.newapi.model(),
                )
                .await?;
            let _ = citation::resolve(&self.store, &self.bridge, &turn, &assistant).await;
            return Ok(true);
        }

        let (request, prompt_tokens, effective_attempt) = if let Some(frozen) = &turn.frozen_request
        {
            if turn.provider_attempt > 2 {
                self.store
                    .finish_turn(
                        &turn,
                        "failed",
                        "failed",
                        Some("assistant_unavailable"),
                        0,
                        0,
                        self.newapi.model(),
                    )
                    .await?;
                return Ok(true);
            }
            let request: FrozenChatRequest = match serde_json::from_value(frozen.clone()) {
                Ok(request) => request,
                Err(_) => {
                    self.fail_claimed_turn(&turn, "frozen_prompt_invalid", 0)
                        .await?;
                    return Ok(true);
                }
            };
            let encoded = serde_json::to_vec(&request)
                .map_err(|_| AppError::Invariant("frozen chat request is not serializable"))?;
            let recomputed = hex::encode(Sha256::digest(encoded));
            if turn.frozen_prompt_sha256.as_deref() != Some(&recomputed) {
                self.fail_claimed_turn(&turn, "frozen_prompt_mismatch", 0)
                    .await?;
                return Ok(true);
            }
            let prompt_tokens = self.budgeter.serialized_message_tokens(&request.messages)?;
            (request, prompt_tokens, turn.provider_attempt)
        } else {
            let built = match self.ground(&turn).await {
                Ok(built) => built,
                Err(error) if error.retryable() && turn.provider_attempt < 2 => {
                    self.store
                        .release_turn_for_retry(&turn, error.code())
                        .await?;
                    return Ok(true);
                }
                Err(error) => {
                    self.fail_claimed_turn(&turn, error.code(), 0).await?;
                    return Ok(true);
                }
            };
            self.store
                .freeze_turn_context(
                    &turn,
                    &built.context_marker,
                    &built.context_sha256,
                    &built.context_record,
                    &serde_json::to_value(&built.request)
                        .map_err(|_| AppError::Invariant("chat request is not serializable"))?,
                    &built.prompt_sha256,
                )
                .await?;
            (built.request, built.prompt_tokens, turn.provider_attempt)
        };

        self.stream_and_persist(&turn, &request, prompt_tokens, effective_attempt)
            .await?;
        Ok(true)
    }

    async fn fail_claimed_turn(
        &self,
        turn: &Turn,
        error_code: &str,
        prompt_tokens: i32,
    ) -> Result<()> {
        self.store
            .finish_turn(
                turn,
                "failed",
                "failed",
                Some(error_code),
                prompt_tokens,
                0,
                self.newapi.model(),
            )
            .await
    }

    async fn ground(&self, turn: &Turn) -> Result<crate::newapi::BudgetedPrompt> {
        let analysis = self
            .store
            .get_analysis(&turn.owner_sub, turn.analysis_id)
            .await?;
        let conversation = self
            .store
            .get_conversation(&turn.owner_sub, turn.analysis_id, turn.conversation_id)
            .await?;
        let history = self
            .store
            .messages(&turn.owner_sub, turn.conversation_id)
            .await?;
        let user_message = history
            .iter()
            .find(|message| message.turn_id == turn.id && message.role == "user")
            .ok_or(AppError::Invariant("turn is missing its user message"))?;
        let sample_id = analysis
            .sample_id
            .as_deref()
            .ok_or(AppError::Invariant("conversation analysis has no sample"))?;
        let case_id = analysis.case_id.as_deref().ok_or_else(|| {
            AppError::conflict("state_conflict", "Analysis context is not ready.")
        })?;
        let goal = truncate_unicode(&user_message.content, 1000);
        let context = self
            .bridge
            .context_pack(&ContextPackRequest {
                sample_id,
                goal,
                token_budget: 8192,
                evidence_scope: "latest",
                claim_scope: "latest",
                include_case: true,
                case_id,
            })
            .await?;
        let context = Value::Object(context.value);
        self.materialize_context_artifacts(&turn.owner_sub, turn.analysis_id, &context)
            .await?;
        self.budgeter.build(
            self.newapi.model(),
            &turn.owner_sub,
            &persona(&conversation),
            &user_message.content,
            &context,
            &history,
        )
    }

    async fn materialize_context_artifacts(
        &self,
        owner_sub: &str,
        analysis_id: uuid::Uuid,
        context: &Value,
    ) -> Result<()> {
        let mut pointers = Vec::new();
        collect_artifact_pointers(context, &mut pointers);
        pointers.sort();
        pointers.dedup();
        for (id, artifact_type, path, sha256) in pointers {
            if id.is_empty()
                // The persisted `ref:` prefix is part of the 240-byte contract.
                || id.len() > 236
                || !id.bytes().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_-".contains(&byte)
                })
                || artifact_type.is_empty()
                || path.is_empty()
                || path.len() > 2048
                || sha256.len() != 64
                || !sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                continue;
            }
            self.store
                .upsert_context_artifact(
                    owner_sub,
                    analysis_id,
                    &id,
                    &artifact_type,
                    &format!("ref:{id}"),
                    &path,
                    &sha256,
                    None,
                    "analysis.context.pack",
                )
                .await?;
        }
        Ok(())
    }

    async fn stream_and_persist(
        &self,
        turn: &Turn,
        request: &FrozenChatRequest,
        prompt_tokens: usize,
        effective_attempt: i32,
    ) -> Result<()> {
        let response = match self.newapi.send_stream(request).await {
            Ok(response) => response,
            Err(_) if effective_attempt < 2 => {
                self.store
                    .release_turn_for_retry(turn, "assistant_unavailable")
                    .await?;
                return Ok(());
            }
            Err(_) => {
                self.store
                    .finish_turn(
                        turn,
                        "failed",
                        "failed",
                        Some("assistant_unavailable"),
                        prompt_tokens as i32,
                        0,
                        self.newapi.model(),
                    )
                    .await?;
                return Ok(());
            }
        };
        let (max_body, max_line) = response_limits();
        let mut stream = response.bytes_stream();
        let mut pending = Vec::new();
        let mut received = 0usize;
        let mut content = String::new();
        let mut done = false;
        'provider: loop {
            let item = if received == 0 {
                match timeout(Duration::from_secs(30), stream.next()).await {
                    Ok(item) => item,
                    Err(_) => break 'provider,
                }
            } else {
                stream.next().await
            };
            let Some(item) = item else { break };
            let chunk = match item {
                Ok(chunk) => chunk,
                Err(_) => break 'provider,
            };
            received = received.saturating_add(chunk.len());
            if received > max_body {
                break 'provider;
            }
            pending.extend_from_slice(&chunk);
            while let Some(newline) = pending.iter().position(|byte| *byte == b'\n') {
                if newline > max_line {
                    break 'provider;
                }
                let mut line = pending.drain(..=newline).collect::<Vec<_>>();
                while matches!(line.last(), Some(b'\n' | b'\r')) {
                    line.pop();
                }
                let line = match std::str::from_utf8(&line) {
                    Ok(line) => line,
                    Err(_) => break 'provider,
                };
                let Some(data) = line.strip_prefix("data: ") else {
                    continue;
                };
                if data == "[DONE]" {
                    done = true;
                    break;
                }
                let delta = match parse_delta(data) {
                    Ok(delta) => delta,
                    Err(_) => break 'provider,
                };
                if !delta.is_empty() {
                    content.push_str(&delta);
                    if content.len() > 262_144 {
                        break 'provider;
                    }
                    self.store
                        .append_assistant(turn, &delta, self.budgeter.count(&content) as i32)
                        .await?;
                }
            }
            if done {
                break;
            }
            if pending.len() > max_line {
                break 'provider;
            }
        }
        if content.is_empty() && !done && effective_attempt < 2 {
            self.store
                .release_turn_for_retry(turn, "assistant_interrupted")
                .await?;
            return Ok(());
        }
        let (turn_state, message_state, error) = if done {
            ("completed", "complete", None)
        } else if !content.is_empty() {
            ("partial", "partial", Some("generation_interrupted"))
        } else {
            ("failed", "failed", Some("assistant_unavailable"))
        };
        self.store
            .finish_turn(
                turn,
                turn_state,
                message_state,
                error,
                prompt_tokens as i32,
                self.budgeter.count(&content) as i32,
                self.newapi.model(),
            )
            .await?;
        let assistant = self.store.assistant_message(turn.id).await?;
        if !assistant.content.is_empty() {
            if let Err(error) = citation::resolve(&self.store, &self.bridge, turn, &assistant).await
            {
                tracing::warn!(turn_id = %turn.id, code = error.code(), "citation resolution failed");
            }
        }
        Ok(())
    }
}

fn parse_delta(line: &str) -> Result<String> {
    let value: Value = serde_json::from_str(line).map_err(|_| {
        AppError::unavailable(
            "assistant_unavailable",
            "The assistant response was invalid.",
        )
    })?;
    let choices = value
        .get("choices")
        .and_then(Value::as_array)
        .ok_or_else(|| AppError::Invariant("NewAPI response omitted choices"))?;
    let Some(choice) = choices.first() else {
        return Ok(String::new());
    };
    match choice.get("delta").and_then(|delta| delta.get("content")) {
        Some(Value::String(content)) => Ok(content.clone()),
        Some(Value::Null) | None => Ok(String::new()),
        _ => Err(AppError::Invariant("NewAPI delta content is not text")),
    }
}

fn persona(conversation: &Conversation) -> String {
    match conversation.persona_id.as_str() {
        "malware-analyst" => "Malware analyst: prioritize behaviors, capabilities, IOCs, and uncertainty.".into(),
        "reverse-engineer" => "Reverse engineer: prioritize functions, control flow, data structures, and call relationships.".into(),
        "incident-responder" => "Incident responder: prioritize containment-relevant evidence and safe next steps.".into(),
        "custom" => conversation
            .custom_persona
            .clone()
            .unwrap_or_else(|| "Binary analyst".into()),
        _ => "Binary analyst: answer precisely from the supplied static evidence.".into(),
    }
}

fn truncate_unicode(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

fn collect_artifact_pointers(value: &Value, output: &mut Vec<(String, String, String, String)>) {
    match value {
        Value::Object(object) => {
            let id = object
                .get("id")
                .or_else(|| object.get("artifact_id"))
                .and_then(Value::as_str);
            let artifact_type = object
                .get("type")
                .or_else(|| object.get("artifact_type"))
                .and_then(Value::as_str);
            let path = object.get("path").and_then(Value::as_str);
            let sha256 = object.get("sha256").and_then(Value::as_str);
            if let (Some(id), Some(artifact_type), Some(path), Some(sha256)) =
                (id, artifact_type, path, sha256)
            {
                output.push((
                    id.to_string(),
                    artifact_type.to_string(),
                    path.to_string(),
                    sha256.to_string(),
                ));
            }
            for nested in object.values() {
                collect_artifact_pointers(nested, output);
            }
        }
        Value::Array(values) => {
            for nested in values {
                collect_artifact_pointers(nested, output);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_accepts_only_text_delta() {
        assert_eq!(
            parse_delta(r#"{"choices":[{"delta":{"content":"abc"}}]}"#).unwrap(),
            "abc".to_string()
        );
        assert!(parse_delta(r#"{"choices":[{"delta":{"content":7}}]}"#).is_err());
    }

    #[test]
    fn goal_truncation_is_unicode_safe() {
        let value = truncate_unicode(&"界".repeat(1001), 1000);
        assert_eq!(value.chars().count(), 1000);
    }

    #[test]
    fn artifact_pointers_are_discovered_from_context_pack() {
        let mut pointers = Vec::new();
        collect_artifact_pointers(
            &serde_json::json!({"primary_evidence":[{"artifact_refs":[{
                "id":"abc-1","type":"report","path":"reports/a.json","sha256":"a".repeat(64)
            }]}]}),
            &mut pointers,
        );
        assert_eq!(pointers.len(), 1);
        assert_eq!(pointers[0].0, "abc-1");
    }
}
