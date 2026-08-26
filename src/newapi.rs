use std::{
    panic::AssertUnwindSafe,
    sync::Arc,
    time::{Duration, Instant},
};

use futures_util::StreamExt;
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tiktoken_rs::CoreBPE;

use crate::{config::Config, error::AppError, models::Message};

pub const INPUT_BUDGET: usize = 16_384;
pub const OUTPUT_BUDGET: u32 = 2_048;
const SYSTEM_BUDGET: usize = 1_024;
const PERSONA_BUDGET: usize = 512;
const USER_BUDGET: usize = 2_048;
const CONTEXT_BUDGET: usize = 8_192;
const HISTORY_BUDGET: usize = 4_608;
const MAX_HISTORY_MESSAGES: usize = 32;
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_RESPONSE_LINE_BYTES: usize = 64 * 1024;
const READINESS_INPUT_TOKENS: usize = 32_700;
const READINESS_BODY_LIMIT: usize = 256 * 1024;
const MODEL_CATALOG_BODY_LIMIT: usize = 256 * 1024;
const MODEL_CATALOG_TTL: Duration = Duration::from_secs(60);
const MODEL_CATALOG_FAILURE_TTL: Duration = Duration::from_secs(5);
const MODEL_CATALOG_TIMEOUT: Duration = Duration::from_secs(15);
const CHAT_COMPLETIONS_PATH: &str = "/v1/chat/completions";
const MODELS_PATH: &str = "/v1/models";

pub const SYSTEM_INSTRUCTION: &str = "You are Strad, a security-focused binary-analysis assistant. Answer only from the supplied Rikune evidence. Cite every factual claim with [ref:<id>]. Never invent an artifact, address, symbol, behavior, or finding. Clearly label hypotheses and uncertainty. Do not request, expose, or infer secrets, internal paths, raw binaries, memory dumps, credentials, or data from another analysis. Dynamic execution and transformations are prohibited.";

#[derive(Clone)]
pub struct TokenBudgeter {
    tokenizer: Arc<CoreBPE>,
}

impl std::fmt::Debug for TokenBudgeter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenBudgeter")
            .field("tokenizer", &"cl100k_base")
            .finish()
    }
}

#[derive(Clone)]
pub struct NewApiClient {
    http: reqwest::Client,
    endpoint: String,
    models_endpoint: String,
    api_key: String,
    model: String,
    catalog: Arc<tokio::sync::Mutex<ModelCatalogCache>>,
    readiness_request: Arc<FrozenChatRequest>,
}

impl std::fmt::Debug for NewApiClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewApiClient")
            .field("endpoint", &self.endpoint)
            .field("models_endpoint", &self.models_endpoint)
            .field("model", &self.model)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Default)]
struct ModelCatalogCache {
    fetched_at: Option<Instant>,
    failed_at: Option<Instant>,
    models: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenChatRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    pub max_tokens: u32,
    pub stream: bool,
    pub user: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct TruncationManifest {
    pub tokenizer: &'static str,
    pub system_tokens: usize,
    pub persona_tokens: usize,
    pub user_tokens: usize,
    pub context_tokens: usize,
    pub history_tokens: usize,
    pub serialized_input_tokens: usize,
    pub history_messages_included: usize,
    pub history_messages_omitted: usize,
    pub context_truncated: bool,
}

#[derive(Clone, Debug)]
pub struct BudgetedPrompt {
    pub request: FrozenChatRequest,
    pub prompt_tokens: usize,
    pub context_record: serde_json::Value,
    pub context_marker: String,
    pub context_sha256: String,
    pub prompt_sha256: String,
}

impl TokenBudgeter {
    pub fn load() -> std::result::Result<Self, String> {
        let tokenizer = tiktoken_rs::cl100k_base()
            .map_err(|_| "failed to load pinned cl100k_base tokenizer".to_string())?;
        Ok(Self {
            tokenizer: Arc::new(tokenizer),
        })
    }

    pub fn count(&self, value: &str) -> usize {
        // The pinned tokenizer's regex can become super-linear on very large low-entropy
        // strings. UTF-8 bytes are a safe upper bound and keep request admission bounded.
        if value.len() > 8 * 1024 {
            return value.len();
        }
        std::panic::catch_unwind(AssertUnwindSafe(|| {
            self.tokenizer.encode_with_special_tokens(value).len()
        }))
        // UTF-8 bytes are a safe, deliberately pessimistic runtime upper bound.
        .unwrap_or(value.len())
    }

    fn readiness_content(&self, target_tokens: usize) -> std::result::Result<String, String> {
        let mut source = String::with_capacity(target_tokens.saturating_mul(5));
        for counter in 0u32..4096 {
            let digest = Sha256::digest(
                [
                    b"strad-newapi-readiness-v1:".as_slice(),
                    &counter.to_be_bytes(),
                ]
                .concat(),
            );
            source.push_str(&hex::encode(digest));
            source.push('\n');
        }
        let tokens = self.tokenizer.encode_with_special_tokens(&source);
        if tokens.len() < target_tokens {
            return Err("failed to construct the 32k NewAPI readiness probe".into());
        }
        let content = self
            .tokenizer
            .decode(tokens[..target_tokens].to_vec())
            .map_err(|_| "failed to decode the 32k NewAPI readiness probe".to_string())?;
        let verified = self.tokenizer.encode_with_special_tokens(&content).len();
        if !(target_tokens.saturating_sub(8)..=target_tokens).contains(&verified) {
            return Err("the 32k NewAPI readiness probe is not tokenizer-stable".into());
        }
        Ok(content)
    }

    pub fn truncate(&self, value: &str, limit: usize) -> (String, bool) {
        if self.count(value) <= limit {
            return (value.to_string(), false);
        }
        let boundaries: Vec<usize> = value
            .char_indices()
            .map(|(index, _)| index)
            .chain(std::iter::once(value.len()))
            .collect();
        let mut low = 0usize;
        let mut high = boundaries.len() - 1;
        while low < high {
            let middle = (low + high).div_ceil(2);
            if self.count(&value[..boundaries[middle]]) <= limit {
                low = middle;
            } else {
                high = middle - 1;
            }
        }
        (value[..boundaries[low]].to_string(), true)
    }

    pub fn build(
        &self,
        model: &str,
        owner_sub: &str,
        persona: &str,
        user: &str,
        context_pack: &serde_json::Value,
        history: &[Message],
    ) -> Result<BudgetedPrompt, AppError> {
        if user.len() > 8 * 1024 || self.count(user) > USER_BUDGET {
            return Err(AppError::invalid(
                "invalid_request",
                "The question exceeds the 8 KiB or 2,048-token limit.",
            ));
        }
        if self.count(SYSTEM_INSTRUCTION) > SYSTEM_BUDGET {
            return Err(AppError::Invariant("system instruction exceeds its budget"));
        }
        let (persona, _) = self.truncate(persona, PERSONA_BUDGET);
        let (mut selected_context, mut context_truncated) =
            self.select_context_units(context_pack, CONTEXT_BUDGET)?;
        let mut context = serde_json::to_string(&selected_context)
            .map_err(|_| AppError::Invariant("selected context is not serializable"))?;

        let mut pairs = complete_history_pairs(history, MAX_HISTORY_MESSAGES);
        while history_tokens(self, &pairs) > HISTORY_BUDGET {
            if pairs.is_empty() {
                break;
            }
            pairs.remove(0);
        }
        let total_history = history
            .iter()
            .filter(|message| matches!(message.role.as_str(), "user" | "assistant"))
            .count();
        let mut messages = assemble_messages(&persona, user, &context, &pairs);
        let mut serialized = self.serialized_message_tokens(&messages)?;
        while serialized > INPUT_BUDGET && !pairs.is_empty() {
            pairs.remove(0);
            messages = assemble_messages(&persona, user, &context, &pairs);
            serialized = self.serialized_message_tokens(&messages)?;
        }
        if serialized > INPUT_BUDGET {
            let over = serialized - INPUT_BUDGET;
            let target = self.count(&context).saturating_sub(over + 16);
            (selected_context, _) = self.select_context_units(context_pack, target)?;
            context = serde_json::to_string(&selected_context)
                .map_err(|_| AppError::Invariant("selected context is not serializable"))?;
            context_truncated = true;
            messages = assemble_messages(&persona, user, &context, &pairs);
            serialized = self.serialized_message_tokens(&messages)?;
        }
        while serialized > INPUT_BUDGET && context != "{}" {
            let next_limit = self.count(&context).saturating_sub(64);
            (selected_context, _) = self.select_context_units(context_pack, next_limit)?;
            context = serde_json::to_string(&selected_context)
                .map_err(|_| AppError::Invariant("selected context is not serializable"))?;
            context_truncated = true;
            messages = assemble_messages(&persona, user, &context, &pairs);
            serialized = self.serialized_message_tokens(&messages)?;
        }
        if serialized > INPUT_BUDGET {
            return Err(AppError::invalid(
                "invalid_request",
                "The grounded prompt cannot fit the model input budget.",
            ));
        }
        let context_sha256 = hex::encode(Sha256::digest(context.as_bytes()));
        let context_marker = format!("ctx:{}", &context_sha256[..16]);
        let manifest = TruncationManifest {
            tokenizer: "cl100k_base:tiktoken-rs@0.7",
            system_tokens: self.count(SYSTEM_INSTRUCTION),
            persona_tokens: self.count(&persona),
            user_tokens: self.count(user),
            context_tokens: self.count(&context),
            history_tokens: history_tokens(self, &pairs),
            serialized_input_tokens: serialized,
            history_messages_included: pairs.len() * 2,
            history_messages_omitted: total_history.saturating_sub(pairs.len() * 2),
            context_truncated,
        };
        let request = FrozenChatRequest {
            model: model.to_string(),
            messages,
            max_tokens: OUTPUT_BUDGET,
            stream: true,
            user: pseudonymous_user(owner_sub),
        };
        let encoded = serde_json::to_vec(&request)
            .map_err(|_| AppError::Invariant("chat request is not serializable"))?;
        let prompt_sha256 = hex::encode(Sha256::digest(&encoded));
        Ok(BudgetedPrompt {
            request,
            prompt_tokens: serialized,
            context_record: json!({
                "pack": context_pack,
                "selected_context": selected_context,
                "selected_context_json": context,
                "marker": context_marker,
                "sha256": context_sha256,
                "truncation": manifest,
                "citations": extract_context_refs(context_pack),
            }),
            context_marker,
            context_sha256,
            prompt_sha256,
        })
    }

    pub fn serialized_message_tokens(&self, messages: &[ChatMessage]) -> Result<usize, AppError> {
        let serialized = serde_json::to_string(messages)
            .map_err(|_| AppError::Invariant("chat messages are not serializable"))?;
        // Exact JSON escaping plus a pinned assistant-priming framing constant.
        Ok(self.count(&serialized) + 3)
    }

    fn select_context_units(
        &self,
        context_pack: &serde_json::Value,
        token_budget: usize,
    ) -> Result<(serde_json::Value, bool), AppError> {
        let serde_json::Value::Object(source) = context_pack else {
            let encoded = serde_json::to_string(context_pack)
                .map_err(|_| AppError::Invariant("context pack is not serializable"))?;
            return if self.count(&encoded) <= token_budget {
                Ok((context_pack.clone(), false))
            } else {
                Ok((json!({}), true))
            };
        };
        let mut selected = serde_json::Map::new();
        let mut truncated = false;
        for (key, value) in source {
            match value {
                serde_json::Value::Array(units) => {
                    let mut accepted = Vec::new();
                    for unit in units {
                        let mut candidate = selected.clone();
                        let mut with_unit = accepted.clone();
                        with_unit.push(unit.clone());
                        candidate.insert(key.clone(), serde_json::Value::Array(with_unit.clone()));
                        let encoded = serde_json::to_string(&candidate).map_err(|_| {
                            AppError::Invariant("selected context is not serializable")
                        })?;
                        if self.count(&encoded) <= token_budget {
                            accepted = with_unit;
                        } else {
                            truncated = true;
                        }
                    }
                    if !accepted.is_empty() || units.is_empty() {
                        selected.insert(key.clone(), serde_json::Value::Array(accepted));
                    }
                }
                _ => {
                    let mut candidate = selected.clone();
                    candidate.insert(key.clone(), value.clone());
                    let encoded = serde_json::to_string(&candidate)
                        .map_err(|_| AppError::Invariant("selected context is not serializable"))?;
                    if self.count(&encoded) <= token_budget {
                        selected = candidate;
                    } else {
                        truncated = true;
                    }
                }
            }
        }
        Ok((serde_json::Value::Object(selected), truncated))
    }
}

impl NewApiClient {
    pub fn new(config: &Config, budgeter: &TokenBudgeter) -> std::result::Result<Self, String> {
        if !valid_model_id(&config.newapi_model) {
            return Err("STRAD_NEWAPI_MODEL is invalid".to_string());
        }
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(180))
            .redirect(Policy::none())
            .build()
            .map_err(|_| "failed to build NewAPI client".to_string())?;
        let models_endpoint = derive_models_endpoint(&config.newapi_url)?;
        let readiness_request = FrozenChatRequest {
            model: config.newapi_model.clone(),
            messages: vec![ChatMessage {
                role: "user".into(),
                content: budgeter.readiness_content(READINESS_INPUT_TOKENS)?,
            }],
            max_tokens: 1,
            stream: true,
            user: hex::encode(Sha256::digest(b"strad-readiness")),
        };
        Ok(Self {
            http,
            endpoint: config.newapi_url.clone(),
            models_endpoint,
            api_key: config.newapi_key.clone(),
            model: config.newapi_model.clone(),
            catalog: Arc::new(tokio::sync::Mutex::new(ModelCatalogCache::default())),
            readiness_request: Arc::new(readiness_request),
        })
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    pub async fn available_models(&self) -> Result<Vec<String>, AppError> {
        self.models().await
    }

    pub async fn validate_model(&self, model: &str) -> Result<(), AppError> {
        if !valid_model_id(model) {
            return Err(invalid_model());
        }
        let models = self.available_models().await?;
        if models
            .binary_search_by(|available| available.as_str().cmp(model))
            .is_err()
        {
            return Err(invalid_model());
        }
        Ok(())
    }

    pub async fn send_stream(
        &self,
        frozen: &FrozenChatRequest,
    ) -> Result<reqwest::Response, AppError> {
        if frozen.max_tokens != OUTPUT_BUDGET || !frozen.stream {
            return Err(AppError::Invariant(
                "frozen chat request violates response policy",
            ));
        }
        self.validate_model(&frozen.model).await?;
        self.send(frozen).await
    }

    async fn models(&self) -> Result<Vec<String>, AppError> {
        let mut catalog = self.catalog.lock().await;
        if let Some(fetched_at) = catalog.fetched_at {
            if fetched_at.elapsed() < MODEL_CATALOG_TTL {
                return Ok(catalog.models.clone());
            }
        }
        if catalog
            .failed_at
            .is_some_and(|failed_at| failed_at.elapsed() < MODEL_CATALOG_FAILURE_TTL)
        {
            return Err(assistant_unavailable());
        }

        match self.fetch_models().await {
            Ok(models) => {
                catalog.models = models.clone();
                catalog.fetched_at = Some(Instant::now());
                catalog.failed_at = None;
                Ok(models)
            }
            Err(error) => {
                // An expired catalog must never authorize a model after refresh failure.
                catalog.models.clear();
                catalog.fetched_at = None;
                catalog.failed_at = Some(Instant::now());
                Err(error)
            }
        }
    }

    async fn fetch_models(&self) -> Result<Vec<String>, AppError> {
        let response = self
            .http
            .get(&self.models_endpoint)
            .bearer_auth(&self.api_key)
            .timeout(MODEL_CATALOG_TIMEOUT)
            .send()
            .await
            .map_err(|_| assistant_unavailable())?;
        if response.status() != reqwest::StatusCode::OK {
            // Raw provider error bodies are deliberately not read, stored, or logged.
            return Err(assistant_unavailable());
        }
        if !response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(';')
                    .next()
                    .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"))
            })
        {
            return Err(assistant_unavailable());
        }
        if response
            .content_length()
            .is_some_and(|length| length > MODEL_CATALOG_BODY_LIMIT as u64)
        {
            return Err(assistant_unavailable());
        }

        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| assistant_unavailable())?;
            if body.len().saturating_add(chunk.len()) > MODEL_CATALOG_BODY_LIMIT {
                return Err(assistant_unavailable());
            }
            body.extend_from_slice(&chunk);
        }
        parse_model_catalog(&body)
    }

    async fn send(&self, request: &FrozenChatRequest) -> Result<reqwest::Response, AppError> {
        let response = self
            .http
            .post(&self.endpoint)
            .bearer_auth(&self.api_key)
            .json(request)
            .send()
            .await
            .map_err(|_| assistant_unavailable())?;
        if response.status() != reqwest::StatusCode::OK {
            // Raw provider body is deliberately not read, stored, or logged.
            return Err(assistant_unavailable());
        }
        Ok(response)
    }

    pub async fn readiness_probe(&self) -> Result<(), AppError> {
        // Startup reaches this method with an empty cache and therefore refreshes.
        // Routine /readyz probes share the bounded cache instead of queueing forced
        // catalog fetches ahead of conversation traffic.
        let models = self.models().await?;
        if models
            .binary_search_by(|available| available.as_str().cmp(self.model()))
            .is_err()
        {
            return Err(assistant_unavailable());
        }
        let response = self.send(&self.readiness_request).await?;
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        if !content_type.starts_with("text/event-stream") {
            return Err(assistant_unavailable());
        }
        let mut stream = response.bytes_stream();
        let mut buffered = Vec::new();
        let mut total = 0usize;
        let mut saw_choice = false;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| assistant_unavailable())?;
            total = total.saturating_add(chunk.len());
            if total > READINESS_BODY_LIMIT {
                return Err(assistant_unavailable());
            }
            buffered.extend_from_slice(&chunk);
            while let Some(end) = buffered.iter().position(|byte| *byte == b'\n') {
                let line: Vec<u8> = buffered.drain(..=end).collect();
                let line = std::str::from_utf8(&line)
                    .map_err(|_| assistant_unavailable())?
                    .trim();
                let Some(data) = line.strip_prefix("data:").map(str::trim) else {
                    continue;
                };
                if data == "[DONE]" {
                    return saw_choice.then_some(()).ok_or_else(assistant_unavailable);
                }
                let event: serde_json::Value =
                    serde_json::from_str(data).map_err(|_| assistant_unavailable())?;
                if event.get("error").is_some() {
                    return Err(assistant_unavailable());
                }
                saw_choice |= event
                    .get("choices")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|choices| !choices.is_empty());
            }
        }
        Err(assistant_unavailable())
    }
}

fn derive_models_endpoint(endpoint: &str) -> std::result::Result<String, String> {
    let base = endpoint
        .strip_suffix(CHAT_COMPLETIONS_PATH)
        .filter(|base| !base.is_empty())
        .ok_or_else(|| "STRAD_NEWAPI_URL must end with /v1/chat/completions".to_string())?;
    Ok(format!("{base}{MODELS_PATH}"))
}

fn valid_model_id(model: &str) -> bool {
    crate::config::valid_model_alias(model)
}

fn parse_model_catalog(body: &[u8]) -> Result<Vec<String>, AppError> {
    let payload: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| assistant_unavailable())?;
    let object = payload.as_object().ok_or_else(assistant_unavailable)?;
    if object.get("success") != Some(&serde_json::Value::Bool(true))
        || object.get("object").and_then(serde_json::Value::as_str) != Some("list")
    {
        return Err(assistant_unavailable());
    }
    let data = object
        .get("data")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(assistant_unavailable)?;

    let mut models = Vec::new();
    for entry in data {
        let id = entry.as_object().and_then(|model| {
            supports_chat_completions(model)
                .then(|| model.get("id").and_then(serde_json::Value::as_str))
                .flatten()
        });
        if let Some(id) = id.filter(|id| valid_model_id(id)) {
            models.push(id.to_string());
        }
    }
    models.sort_unstable();
    models.dedup();
    Ok(models)
}

fn supports_chat_completions(model: &serde_json::Map<String, serde_json::Value>) -> bool {
    model
        .get("supported_endpoint_types")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|types| types.iter().any(|value| value.as_str() == Some("openai")))
}

pub fn response_limits() -> (usize, usize) {
    (MAX_RESPONSE_BYTES, MAX_RESPONSE_LINE_BYTES)
}

fn complete_history_pairs(history: &[Message], max_messages: usize) -> Vec<(Message, Message)> {
    let mut ordered: Vec<Message> = history
        .iter()
        .filter(|message| {
            (message.role == "user" && message.status == "committed")
                || (message.role == "assistant"
                    && matches!(message.status.as_str(), "complete" | "partial"))
        })
        .cloned()
        .collect();
    ordered.sort_by_key(|message| message.seq);
    let mut pairs = Vec::new();
    for window in ordered.windows(2) {
        if window[0].role == "user"
            && window[1].role == "assistant"
            && window[0].turn_id == window[1].turn_id
        {
            pairs.push((window[0].clone(), window[1].clone()));
        }
    }
    let max_pairs = max_messages / 2;
    if pairs.len() > max_pairs {
        pairs.drain(0..pairs.len() - max_pairs);
    }
    pairs
}

fn history_tokens(budgeter: &TokenBudgeter, pairs: &[(Message, Message)]) -> usize {
    pairs
        .iter()
        .map(|(user, assistant)| budgeter.count(&user.content) + budgeter.count(&assistant.content))
        .sum()
}

fn assemble_messages(
    persona: &str,
    user: &str,
    context: &str,
    history: &[(Message, Message)],
) -> Vec<ChatMessage> {
    let mut messages = vec![
        ChatMessage {
            role: "system".into(),
            content: SYSTEM_INSTRUCTION.into(),
        },
        ChatMessage {
            role: "system".into(),
            content: format!("Server-selected persona:\n{persona}"),
        },
        ChatMessage {
            role: "system".into(),
            content: format!("Current immutable Rikune context pack:\n{context}"),
        },
    ];
    for (previous_user, assistant) in history {
        messages.push(ChatMessage {
            role: "user".into(),
            content: previous_user.content.clone(),
        });
        messages.push(ChatMessage {
            role: "assistant".into(),
            content: assistant.content.clone(),
        });
    }
    messages.push(ChatMessage {
        role: "user".into(),
        content: user.to_string(),
    });
    messages
}

fn extract_context_refs(context_pack: &serde_json::Value) -> Vec<String> {
    let text = context_pack.to_string();
    let matcher = regex::Regex::new(r"ref:[a-z0-9_-]{1,240}").expect("static regex");
    let mut refs: Vec<String> = matcher
        .find_iter(&text)
        .map(|found| found.as_str().to_string())
        .collect();
    refs.sort();
    refs.dedup();
    refs
}

pub fn pseudonymous_user(owner_sub: &str) -> String {
    hex::encode(Sha256::digest(owner_sub.as_bytes()))
}

fn assistant_unavailable() -> AppError {
    AppError::unavailable(
        "assistant_unavailable",
        "The analysis assistant is temporarily unavailable.",
    )
}

fn invalid_model() -> AppError {
    AppError::invalid(
        "invalid_model",
        "The selected model is not available for this analysis.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use uuid::Uuid;

    fn message(seq: i64, role: &str, content: &str, turn: Uuid) -> Message {
        Message {
            id: Uuid::new_v4(),
            turn_id: turn,
            conversation_id: Uuid::nil(),
            analysis_id: Uuid::nil(),
            owner_sub: "user:a".into(),
            seq,
            role: role.into(),
            client_seq: (role == "user").then_some(seq),
            status: if role == "user" {
                "committed"
            } else {
                "complete"
            }
            .into(),
            content: content.into(),
            token_count: 0,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    async fn read_request(socket: &mut tokio::net::TcpStream) -> (String, Vec<u8>) {
        let mut request = Vec::new();
        let header_end = loop {
            let mut chunk = [0u8; 8192];
            let count = socket.read(&mut chunk).await.unwrap();
            assert!(count > 0);
            request.extend_from_slice(&chunk[..count]);
            if let Some(index) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                break index + 4;
            }
        };
        let headers = std::str::from_utf8(&request[..header_end])
            .unwrap()
            .to_string();
        let content_length = headers
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .map(str::trim)
                    .and_then(|value| value.parse::<usize>().ok())
            })
            .unwrap_or(0);
        while request.len() - header_end < content_length {
            let mut chunk = [0u8; 8192];
            let count = socket.read(&mut chunk).await.unwrap();
            assert!(count > 0);
            request.extend_from_slice(&chunk[..count]);
        }
        (
            headers,
            request[header_end..header_end + content_length].to_vec(),
        )
    }

    async fn write_json_response(socket: &mut tokio::net::TcpStream, status: &str, body: &[u8]) {
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        socket.write_all(response.as_bytes()).await.unwrap();
        socket.write_all(body).await.unwrap();
    }

    fn client_for(address: std::net::SocketAddr, model: &str) -> NewApiClient {
        let temporary = tempfile::tempdir().unwrap();
        let mut config = crate::config::Config::for_tests(temporary.path().to_path_buf());
        config.newapi_url = format!("http://{address}/v1/chat/completions");
        config.newapi_model = model.to_string();
        NewApiClient::new(&config, &TokenBudgeter::load().unwrap()).unwrap()
    }

    #[test]
    fn final_serialized_prompt_is_bounded_and_history_is_pairwise() {
        let budgeter = TokenBudgeter::load().unwrap();
        let mut history = Vec::new();
        for index in 0..40 {
            let turn = Uuid::new_v4();
            history.push(message(index * 2, "user", &"question ".repeat(200), turn));
            history.push(message(
                index * 2 + 1,
                "assistant",
                &"answer ".repeat(200),
                turn,
            ));
        }
        let prompt = budgeter
            .build(
                "model",
                "user:alice",
                "analyst",
                "What is the entry point?",
                &json!({"evidence": "x".repeat(100_000)}),
                &history,
            )
            .unwrap();
        assert!(prompt.prompt_tokens <= INPUT_BUDGET);
        assert_eq!(prompt.request.max_tokens, OUTPUT_BUDGET);
        assert_eq!(prompt.request.user.len(), 64);
        assert!(!prompt
            .request
            .messages
            .iter()
            .any(|m| m.content.contains("user:alice")));
    }

    #[test]
    fn fallback_bound_is_bytes_not_divided_bytes() {
        let budgeter = TokenBudgeter::load().unwrap();
        let (truncated, did_truncate) = budgeter.truncate(&"界".repeat(5000), 32);
        assert!(did_truncate);
        assert!(budgeter.count(&truncated) <= 32);
    }

    #[test]
    fn readiness_probe_contains_a_real_32k_token_prompt() {
        let budgeter = TokenBudgeter::load().unwrap();
        let content = budgeter.readiness_content(READINESS_INPUT_TOKENS).unwrap();
        let exact = budgeter
            .tokenizer
            .encode_with_special_tokens(&content)
            .len();
        assert!((READINESS_INPUT_TOKENS - 8..=READINESS_INPUT_TOKENS).contains(&exact));
    }

    #[test]
    fn model_ids_and_models_endpoint_are_strictly_bounded() {
        assert!(valid_model_id("glm-5.2"));
        assert!(valid_model_id("vendor/model_name:v1"));
        assert!(valid_model_id(&"a".repeat(128)));
        assert!(!valid_model_id(""));
        assert!(!valid_model_id(&"a".repeat(129)));
        assert!(!valid_model_id("bad model"));
        assert!(!valid_model_id("模型"));
        assert!(!valid_model_id("model?variant=1"));
        assert_eq!(
            derive_models_endpoint("http://newapi:9080/v1/chat/completions").unwrap(),
            "http://newapi:9080/v1/models"
        );
        assert!(derive_models_endpoint("http://newapi:9080/v1/responses").is_err());
    }

    #[test]
    fn catalog_parser_filters_sorts_and_deduplicates_models() {
        let payload = json!({
            "success": true,
            "object": "list",
            "data": [
                {"id":"z-model","supported_endpoint_types":["openai"]},
                {"id":"response-only","supported_endpoint_types":["openai-response"]},
                {"id":"a/model","supported_endpoint_types":["anthropic", "openai"]},
                {"id":"legacy-model"},
                {"id":"null-metadata","supported_endpoint_types":null},
                {"id":"empty-metadata","supported_endpoint_types":[]},
                {"id":"wrong-metadata","supported_endpoint_types":"openai"},
                {"id":"bad model","supported_endpoint_types":["openai"]},
                {"id":"z-model","supported_endpoint_types":["openai"]},
                "string-model"
            ]
        });
        let models = parse_model_catalog(&serde_json::to_vec(&payload).unwrap()).unwrap();
        assert_eq!(models, vec!["a/model", "z-model"]);
        assert!(!models.iter().any(|model| model == "response-only"));
        assert!(!models.iter().any(|model| model == "bad model"));
        assert_eq!(
            parse_model_catalog(br#"{"success":false,"data":[]}"#)
                .unwrap_err()
                .code(),
            "assistant_unavailable"
        );
        assert_eq!(
            parse_model_catalog(br#"{"data":"not-an-array"}"#)
                .unwrap_err()
                .code(),
            "assistant_unavailable"
        );
    }

    #[tokio::test]
    async fn catalog_uses_bearer_get_and_shared_fresh_cache() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let (headers, body) = read_request(&mut socket).await;
            assert!(headers.starts_with("GET /v1/models HTTP/1.1\r\n"));
            assert!(headers
                .to_ascii_lowercase()
                .contains("authorization: bearer nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn"));
            assert!(body.is_empty());
            write_json_response(
                &mut socket,
                "200 OK",
                br#"{"success":true,"object":"list","data":[{"id":"glm-5.2","supported_endpoint_types":["openai"]}]}"#,
            )
            .await;
        });
        let client = client_for(address, "glm-5.2");
        let cloned = client.clone();
        assert_eq!(client.available_models().await.unwrap(), vec!["glm-5.2"]);
        assert_eq!(cloned.available_models().await.unwrap(), vec!["glm-5.2"]);
        client.validate_model("glm-5.2").await.unwrap();
        assert_eq!(
            client
                .validate_model("missing-model")
                .await
                .unwrap_err()
                .code(),
            "invalid_model"
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn catalog_rejects_non_json_and_declared_oversize_responses() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut wrong_type, _) = listener.accept().await.unwrap();
            let _ = read_request(&mut wrong_type).await;
            wrong_type
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                )
                .await
                .unwrap();

            let (mut oversized, _) = listener.accept().await.unwrap();
            let _ = read_request(&mut oversized).await;
            oversized
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 262145\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
        });
        let client = client_for(address, "glm-5.2");
        assert_eq!(
            client.available_models().await.unwrap_err().code(),
            "assistant_unavailable"
        );
        client.catalog.lock().await.failed_at = None;
        assert_eq!(
            client.available_models().await.unwrap_err().code(),
            "assistant_unavailable"
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn stream_posts_the_selected_catalog_model_without_failover() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut catalog_socket, _) = listener.accept().await.unwrap();
            let _ = read_request(&mut catalog_socket).await;
            write_json_response(
                &mut catalog_socket,
                "200 OK",
                br#"{"success":true,"object":"list","data":[{"id":"alternate-model","supported_endpoint_types":["openai"]}]}"#,
            )
            .await;

            let (mut chat_socket, _) = listener.accept().await.unwrap();
            let (headers, body) = read_request(&mut chat_socket).await;
            assert!(headers.starts_with("POST /v1/chat/completions HTTP/1.1\r\n"));
            let request: FrozenChatRequest = serde_json::from_slice(&body).unwrap();
            assert_eq!(request.model, "alternate-model");
            assert_eq!(request.max_tokens, OUTPUT_BUDGET);
            assert!(request.stream);
            write_json_response(&mut chat_socket, "200 OK", br#"{}"#).await;
        });
        let client = client_for(address, "glm-5.2");
        let selected = FrozenChatRequest {
            model: "alternate-model".into(),
            messages: vec![ChatMessage {
                role: "user".into(),
                content: "hello".into(),
            }],
            max_tokens: OUTPUT_BUDGET,
            stream: true,
            user: "pseudonymous".into(),
        };
        client.send_stream(&selected).await.unwrap();

        let mut unlisted = selected;
        unlisted.model = "unlisted-model".into();
        assert_eq!(
            client.send_stream(&unlisted).await.unwrap_err().code(),
            "invalid_model"
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn expired_catalog_is_cleared_when_refresh_fails() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.unwrap();
            let _ = read_request(&mut first).await;
            write_json_response(
                &mut first,
                "200 OK",
                br#"{"success":true,"object":"list","data":[{"id":"glm-5.2","supported_endpoint_types":["openai"]}]}"#,
            )
            .await;
            let (mut second, _) = listener.accept().await.unwrap();
            let _ = read_request(&mut second).await;
            write_json_response(&mut second, "503 Service Unavailable", b"upstream error").await;
        });
        let client = client_for(address, "glm-5.2");
        assert_eq!(client.available_models().await.unwrap(), vec!["glm-5.2"]);
        {
            let mut catalog = client.catalog.lock().await;
            catalog.fetched_at = Some(Instant::now() - MODEL_CATALOG_TTL - Duration::from_secs(1));
        }
        assert_eq!(
            client.available_models().await.unwrap_err().code(),
            "assistant_unavailable"
        );
        assert_eq!(
            client.available_models().await.unwrap_err().code(),
            "assistant_unavailable"
        );
        let catalog = client.catalog.lock().await;
        assert!(catalog.models.is_empty());
        assert!(catalog.fetched_at.is_none());
        assert!(catalog.failed_at.is_some());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn readiness_posts_the_full_32k_probe_with_one_output_token() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let budgeter = TokenBudgeter::load().unwrap();
        let expected_content = budgeter.readiness_content(READINESS_INPUT_TOKENS).unwrap();
        let server_expected = expected_content.clone();
        let server = tokio::spawn(async move {
            let (mut catalog_socket, _) = listener.accept().await.unwrap();
            let (catalog_headers, catalog_body) = read_request(&mut catalog_socket).await;
            assert!(catalog_headers.starts_with("GET /v1/models HTTP/1.1\r\n"));
            assert!(catalog_headers
                .to_ascii_lowercase()
                .contains("authorization: bearer nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn"));
            assert!(catalog_body.is_empty());
            write_json_response(
                &mut catalog_socket,
                "200 OK",
                br#"{"success":true,"object":"list","data":[{"id":"test-model","supported_endpoint_types":["openai"]}]}"#,
            )
            .await;

            let (mut socket, _) = listener.accept().await.unwrap();
            let (headers, request_body) = read_request(&mut socket).await;
            assert!(headers.starts_with("POST /v1/chat/completions HTTP/1.1\r\n"));
            assert!(headers
                .to_ascii_lowercase()
                .contains("authorization: bearer nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn"));
            let body: serde_json::Value = serde_json::from_slice(&request_body).unwrap();
            assert_eq!(body["max_tokens"], 1);
            assert_eq!(body["stream"], true);
            assert_eq!(body["model"], "test-model");
            assert_eq!(body["messages"][0]["content"], server_expected);
            let events =
                b"data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\ndata: [DONE]\n\n";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                events.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
            socket.write_all(events).await.unwrap();
        });
        let temporary = tempfile::tempdir().unwrap();
        let mut config = crate::config::Config::for_tests(temporary.path().to_path_buf());
        config.newapi_url = format!("http://{address}/v1/chat/completions");
        let client = NewApiClient::new(&config, &budgeter).unwrap();
        client.readiness_probe().await.unwrap();
        server.await.unwrap();
    }

    #[test]
    fn context_truncation_keeps_complete_deterministic_units() {
        let budgeter = TokenBudgeter::load().unwrap();
        let pack = json!({
            "primary_evidence": [
                {"id":"one","content":"a".repeat(200)},
                {"id":"two","content":"b".repeat(200)},
                {"id":"three","content":"c".repeat(200)}
            ],
            "summary": "stable"
        });
        let (selected, truncated) = budgeter.select_context_units(&pack, 120).unwrap();
        assert!(truncated);
        let encoded = serde_json::to_string(&selected).unwrap();
        assert!(serde_json::from_str::<serde_json::Value>(&encoded).is_ok());
        for unit in selected
            .get("primary_evidence")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            assert!(unit.get("id").is_some());
            assert!(unit.get("content").is_some());
        }
        assert_eq!(
            budgeter.select_context_units(&pack, 120).unwrap().0,
            selected
        );
    }
}
