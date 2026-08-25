use std::{collections::BTreeMap, path::PathBuf, sync::Arc};

use regex::Regex;
use serde_json::Value;

use crate::error::{AppError, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TemplateName {
    Workbench,
    List,
    Detail,
    Conversation,
    ContextPreview,
    Error,
    Confirm,
}

impl TemplateName {
    fn candidates(self) -> &'static [&'static str] {
        match self {
            Self::Workbench => &["workbench.html", "index.html"],
            Self::List => &["list.html", "analyses.html"],
            Self::Detail => &["detail.html", "analysis-detail.html"],
            Self::Conversation => &["conversation.html"],
            Self::ContextPreview => &["context-preview.html"],
            Self::Error => &["error.html"],
            Self::Confirm => &["confirm.html"],
        }
    }
}

#[derive(Clone, Debug)]
pub struct TemplateRenderer {
    root: Arc<PathBuf>,
    placeholder: Arc<Regex>,
}

impl TemplateRenderer {
    pub fn new(root: PathBuf) -> Result<Self> {
        if !root.is_absolute() {
            return Err(AppError::Invariant("template root must be absolute"));
        }
        let placeholder = Regex::new(r"\{\{\s*([a-zA-Z0-9_.-]+)\s*\}\}")
            .map_err(|_| AppError::Invariant("template placeholder regex is invalid"))?;
        Ok(Self {
            root: Arc::new(root),
            placeholder: Arc::new(placeholder),
        })
    }

    pub async fn render(&self, name: TemplateName, context: &Value) -> Result<String> {
        let path = self.resolve(name).await?;
        let source =
            tokio::fs::read_to_string(&path)
                .await
                .map_err(|error| match error.kind() {
                    std::io::ErrorKind::NotFound => {
                        AppError::Invariant("required SSR template is missing")
                    }
                    _ => AppError::Io(error),
                })?;
        let values = flatten_context(context)?;
        let mut missing = false;
        let rendered = self
            .placeholder
            .replace_all(&source, |captures: &regex::Captures<'_>| {
                let key = captures.get(1).map(|value| value.as_str()).unwrap_or("");
                match values.get(key) {
                    Some(value) => escape_html(value),
                    None => {
                        missing = true;
                        String::new()
                    }
                }
            });
        if missing {
            return Err(AppError::Invariant(
                "SSR template referenced an unknown placeholder",
            ));
        }
        enrich_ssr(name, context, rendered.into_owned())
    }

    async fn resolve(&self, name: TemplateName) -> Result<PathBuf> {
        for candidate in name.candidates() {
            let path = self.root.join(candidate);
            match tokio::fs::symlink_metadata(&path).await {
                Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                    return Ok(path);
                }
                Ok(_) => return Err(AppError::Invariant("SSR template is not a regular file")),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(AppError::Invariant("required SSR template is missing"))
    }
}

fn flatten_context(context: &Value) -> Result<BTreeMap<String, String>> {
    let object = context
        .as_object()
        .ok_or(AppError::Invariant("SSR context must be an object"))?;
    let mut flattened = BTreeMap::new();
    for (key, value) in object {
        let rendered = match value {
            Value::Null => String::new(),
            Value::String(value) => value.clone(),
            Value::Bool(value) => value.to_string(),
            Value::Number(value) => value.to_string(),
            Value::Array(_) | Value::Object(_) => serde_json::to_string(value)
                .map_err(|_| AppError::Invariant("SSR context is not serializable"))?,
        };
        flattened.insert(key.clone(), rendered);
    }
    Ok(flattened)
}

fn escape_html(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#x27;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

fn enrich_ssr(name: TemplateName, context: &Value, rendered: String) -> Result<String> {
    match name {
        TemplateName::List => enrich_list(context, rendered),
        TemplateName::Detail => enrich_detail(context, rendered),
        TemplateName::Conversation => enrich_conversation(context, rendered),
        _ => Ok(rendered),
    }
}

fn enrich_list(context: &Value, mut rendered: String) -> Result<String> {
    let analyses = context
        .get("analyses")
        .and_then(Value::as_array)
        .ok_or(AppError::Invariant("SSR analysis collection is missing"))?;
    if analyses.is_empty() {
        rendered = rendered.replacen(
            "class=\"empty\" data-wb-analyses-empty hidden",
            "class=\"empty\" data-wb-analyses-empty",
            1,
        );
    } else {
        let mut rows = String::from("<ul class=\"wb-alist\">");
        for analysis in analyses {
            let Some(id) = json_uuid(analysis, "id") else {
                return Err(AppError::Invariant("SSR analysis ID is invalid"));
            };
            let title = json_text(analysis, "display_name").unwrap_or(id.as_str());
            let state = json_text(analysis, "state").unwrap_or("unknown");
            let sample = json_text(analysis, "sample_id").unwrap_or("—");
            let sample_short: String = sample.chars().take(24).collect();
            rows.push_str(
                "<li class=\"wb-alist__row\"><a class=\"wb-alist__main\" href=\"/analyses/",
            );
            rows.push_str(&id);
            rows.push_str("\"><span class=\"wb-alist__name mono\">");
            rows.push_str(&escape_html(title));
            rows.push_str("</span><span class=\"wb-alist__meta\">");
            rows.push_str(&escape_html(status_label(state)));
            rows.push_str(" · ");
            rows.push_str(&escape_html(&sample_short));
            rows.push_str("</span></a><span class=\"pill pill-neutral\">");
            rows.push_str(&escape_html(status_label(state)));
            rows.push_str("</span></li>");
        }
        rows.push_str("</ul>");
        rendered = replace_required(
            rendered,
            "<div data-wb-analyses hidden></div>",
            &format!("<div data-wb-analyses>{rows}</div>"),
            "SSR analysis mount is missing",
        )?;
    }
    rendered = rendered.replacen(
        "<span data-wb-analysis-count>—</span>",
        &format!("<span data-wb-analysis-count>{}</span>", analyses.len()),
        1,
    );
    if let Some(quota) = context.get("quota") {
        let used = quota.get("used_bytes").and_then(Value::as_i64).unwrap_or(0);
        let reserved = quota
            .get("reserved_bytes")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let limit = quota.get("byte_limit").and_then(Value::as_i64).unwrap_or(0);
        rendered = rendered.replacen(
            "<div class=\"stat__value num\" data-wb-storage-value>10 GiB</div>",
            &format!(
                "<div class=\"stat__value num\" data-wb-storage-value>{}</div>",
                escape_html(&format_bytes(used.saturating_add(reserved)))
            ),
            1,
        );
        rendered = rendered.replacen(
            "<div class=\"stat__meta\" data-wb-storage-meta>Total available per person</div>",
            &format!(
                "<div class=\"stat__meta\" data-wb-storage-meta>{} used · {} reserved · {} limit</div>",
                escape_html(&format_bytes(used)),
                escape_html(&format_bytes(reserved)),
                escape_html(&format_bytes(limit))
            ),
            1,
        );
    }
    Ok(rendered)
}

fn enrich_detail(context: &Value, mut rendered: String) -> Result<String> {
    let analysis = context
        .get("analysis")
        .and_then(Value::as_object)
        .ok_or(AppError::Invariant("SSR analysis projection is missing"))?;
    for (field, value) in [
        (
            "state",
            analysis
                .get("state")
                .and_then(Value::as_str)
                .map(status_label)
                .unwrap_or("Unknown"),
        ),
        (
            "sample_id",
            analysis
                .get("sample_id")
                .and_then(Value::as_str)
                .unwrap_or("—"),
        ),
        (
            "created_at",
            analysis
                .get("created_at")
                .and_then(Value::as_str)
                .unwrap_or("—"),
        ),
        (
            "retention_until",
            analysis
                .get("retention_until")
                .and_then(Value::as_str)
                .unwrap_or("—"),
        ),
    ] {
        rendered = replace_data_field(rendered, field, value)?;
    }
    if let Some(state) = analysis.get("state").and_then(Value::as_str) {
        rendered = rendered.replacen(
            "<span data-wb-status-label>Loading…</span>",
            &format!(
                "<span data-wb-status-label>{}</span>",
                escape_html(status_label(state))
            ),
            1,
        );
    }

    if let Some(summary) = context.get("summary").filter(|value| !value.is_null()) {
        let artifact = summary.get("artifact").unwrap_or(summary);
        let artifact_type = json_text(artifact, "artifact_type").unwrap_or("Analysis summary");
        let artifact_ref = json_text(artifact, "artifact_ref").unwrap_or("");
        let metadata = artifact.get("metadata").unwrap_or(&Value::Null);
        let metadata = serde_json::to_string_pretty(metadata)
            .map_err(|_| AppError::Invariant("SSR summary is not serializable"))?;
        let html = format!(
            "<div data-wb-summary><article class=\"wb-evi__item\"><h3>{}</h3><p class=\"mono\">{}</p><pre class=\"wb-datapre\">{}</pre></article></div>",
            escape_html(artifact_type),
            escape_html(artifact_ref),
            escape_html(&metadata)
        );
        rendered = replace_required(
            rendered,
            "<div data-wb-summary hidden></div>",
            &html,
            "SSR summary mount is missing",
        )?;
    } else {
        rendered = rendered.replacen(
            "class=\"empty\" data-wb-summary-empty hidden",
            "class=\"empty\" data-wb-summary-empty",
            1,
        );
    }

    let artifacts = context
        .get("artifacts")
        .and_then(Value::as_array)
        .ok_or(AppError::Invariant("SSR artifact collection is missing"))?;
    if artifacts.is_empty() {
        rendered = rendered.replacen(
            "class=\"empty\" data-wb-evidence-empty hidden",
            "class=\"empty\" data-wb-evidence-empty",
            1,
        );
    } else {
        let mut items = String::from("<ul class=\"wb-evi\">");
        for artifact in artifacts {
            let artifact_ref = json_text(artifact, "artifact_ref").unwrap_or("unknown");
            let artifact_type = json_text(artifact, "artifact_type").unwrap_or("artifact");
            let mime = json_text(artifact, "mime").unwrap_or("application/octet-stream");
            items.push_str("<li class=\"wb-evi__item\" id=\"");
            items.push_str(&escape_html(artifact_ref));
            items.push_str("\"><div class=\"wb-evi__ref mono\">");
            items.push_str(&escape_html(artifact_ref));
            items.push_str("</div><div class=\"wb-evi__meta\">");
            items.push_str(&escape_html(artifact_type));
            items.push_str(" · ");
            items.push_str(&escape_html(mime));
            items.push_str("</div></li>");
        }
        items.push_str("</ul>");
        rendered = replace_required(
            rendered,
            "<div data-wb-evidence hidden></div>",
            &format!("<div data-wb-evidence>{items}</div>"),
            "SSR evidence mount is missing",
        )?;
    }

    let stage_rows = [
        ("State", analysis.get("state").and_then(Value::as_str)),
        (
            "Current stage",
            analysis.get("current_stage").and_then(Value::as_str),
        ),
        (
            "Latest stage",
            analysis.get("latest_stage").and_then(Value::as_str),
        ),
        ("Plan", analysis.get("plan_id").and_then(Value::as_str)),
    ];
    let mut stages = String::from("<dl class=\"desc\">");
    for (label, value) in stage_rows {
        stages.push_str("<dt class=\"desc__term\">");
        stages.push_str(label);
        stages.push_str("</dt><dd class=\"desc__val mono\">");
        stages.push_str(&escape_html(value.unwrap_or("—")));
        stages.push_str("</dd>");
    }
    stages.push_str("</dl>");
    rendered = replace_required(
        rendered,
        "<div data-wb-stages hidden></div>",
        &format!("<div data-wb-stages>{stages}</div>"),
        "SSR stages mount is missing",
    )?;
    Ok(rendered)
}

fn enrich_conversation(context: &Value, mut rendered: String) -> Result<String> {
    let analysis_id = context
        .get("analysis_id")
        .and_then(Value::as_str)
        .and_then(|value| uuid::Uuid::parse_str(value).ok())
        .ok_or(AppError::Invariant(
            "SSR conversation analysis ID is invalid",
        ))?
        .to_string();
    let selected = context
        .get("selected_conversation_id")
        .and_then(Value::as_str)
        .and_then(|value| uuid::Uuid::parse_str(value).ok())
        .map(|value| value.to_string());
    let conversations = context
        .get("conversations")
        .and_then(Value::as_array)
        .ok_or(AppError::Invariant(
            "SSR conversation collection is missing",
        ))?;
    if conversations.is_empty() {
        rendered = rendered.replacen(
            "class=\"empty\" data-wb-sessions-empty hidden",
            "class=\"empty\" data-wb-sessions-empty",
            1,
        );
    } else {
        let csrf = context
            .get("csrf_token")
            .and_then(Value::as_str)
            .unwrap_or("");
        let delete_operation = context
            .get("delete_conversation_operation_id")
            .and_then(Value::as_str)
            .unwrap_or("");
        let mut items = String::from("<ul class=\"wb-convlist\">");
        for conversation in conversations {
            let Some(id) = json_uuid(conversation, "id") else {
                return Err(AppError::Invariant("SSR conversation ID is invalid"));
            };
            let title = json_text(conversation, "title").unwrap_or("Session");
            let persona = json_text(conversation, "persona_id").unwrap_or("binary-analyst");
            let active = selected.as_deref() == Some(id.as_str());
            items.push_str("<li><a href=\"/analyses/");
            items.push_str(&analysis_id);
            items.push_str("/conversation?conversation_id=");
            items.push_str(&id);
            if active {
                items.push_str("\" class=\"is-active\" aria-current=\"page");
            }
            items.push_str("\">");
            items.push_str(&escape_html(title));
            items.push_str("<span class=\"muted\">");
            items.push_str(&escape_html(persona_label(persona)));
            items.push_str("</span></a>");
            if active {
                items.push_str("<form method=\"post\" action=\"/api/analyses/");
                items.push_str(&analysis_id);
                items.push_str("/conversations/");
                items.push_str(&id);
                items.push_str("/delete\"><input type=\"hidden\" name=\"csrf_token\" value=\"");
                items.push_str(&escape_html(csrf));
                items.push_str("\"><input type=\"hidden\" name=\"operation_id\" value=\"");
                items.push_str(&escape_html(delete_operation));
                items.push_str("\"><button class=\"btn btn-danger btn-sm\" type=\"submit\">Delete session</button></form>");
            }
            items.push_str("</li>");
        }
        items.push_str("</ul>");
        rendered = replace_required(
            rendered,
            "<div data-wb-sessions hidden></div>",
            &format!("<div data-wb-sessions>{items}</div>"),
            "SSR session mount is missing",
        )?;
    }

    let messages = context
        .get("messages")
        .and_then(Value::as_array)
        .ok_or(AppError::Invariant("SSR message collection is missing"))?;
    if messages.is_empty() {
        rendered = rendered.replacen(
            "class=\"empty\" data-wb-thread-empty hidden",
            "class=\"empty\" data-wb-thread-empty",
            1,
        );
    } else {
        let mut thread = String::new();
        for message in messages {
            let role = json_text(message, "role").unwrap_or("assistant");
            let role_class = if role == "user" { "user" } else { "assistant" };
            let content = json_text(message, "content").unwrap_or("");
            let status = json_text(message, "status").unwrap_or("");
            thread.push_str("<article class=\"wb-msg wb-msg--");
            thread.push_str(role_class);
            thread.push_str("\"><p>");
            thread.push_str(&escape_html(content).replace('\n', "<br>"));
            thread.push_str("</p>");
            if !matches!(status, "" | "complete" | "committed") {
                thread.push_str("<div class=\"wb-msg__meta\">");
                thread.push_str(&escape_html(status));
                thread.push_str("</div>");
            }
            if let Some(citations) = message.get("citations").and_then(Value::as_array) {
                let resolved: Vec<&str> = citations
                    .iter()
                    .filter(|citation| {
                        citation
                            .get("resolved")
                            .and_then(Value::as_bool)
                            .unwrap_or(false)
                    })
                    .filter_map(|citation| citation.get("citation_ref").and_then(Value::as_str))
                    .collect();
                if !resolved.is_empty() {
                    thread.push_str("<ul class=\"wb-msg__citations\" aria-label=\"Citations\">");
                    for citation_ref in resolved {
                        thread.push_str("<li><a class=\"wb-cite\" href=\"/analyses/");
                        thread.push_str(&analysis_id);
                        thread.push_str("/evidence?highlight=");
                        thread.push_str(&escape_html(citation_ref));
                        thread.push_str("\">");
                        thread.push_str(&escape_html(citation_ref));
                        thread.push_str("</a></li>");
                    }
                    thread.push_str("</ul>");
                }
            }
            thread.push_str("</article>");
        }
        rendered = replace_required(
            rendered,
            "<div class=\"wb-thread\" data-wb-thread aria-live=\"polite\"></div>",
            &format!("<div class=\"wb-thread\" data-wb-thread aria-live=\"polite\">{thread}</div>"),
            "SSR message mount is missing",
        )?;
    }
    if selected.is_none() {
        rendered = rendered.replacen("data-wb-select-note hidden", "data-wb-select-note", 1);
    }
    Ok(rendered)
}

fn replace_required(
    source: String,
    needle: &str,
    replacement: &str,
    error: &'static str,
) -> Result<String> {
    if !source.contains(needle) {
        return Err(AppError::Invariant(error));
    }
    Ok(source.replacen(needle, replacement, 1))
}

fn replace_data_field(source: String, field: &str, value: &str) -> Result<String> {
    let prefix = format!("data-wb-field=\"{field}\">");
    let Some(start) = source.find(&prefix) else {
        return Err(AppError::Invariant("SSR overview field is missing"));
    };
    let content_start = start + prefix.len();
    let Some(relative_end) = source[content_start..].find("</dd>") else {
        return Err(AppError::Invariant("SSR overview field is malformed"));
    };
    let content_end = content_start + relative_end;
    let mut output = source;
    output.replace_range(content_start..content_end, &escape_html(value));
    Ok(output)
}

fn json_text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn json_uuid(value: &Value, key: &str) -> Option<String> {
    json_text(value, key)
        .and_then(|value| uuid::Uuid::parse_str(value).ok())
        .map(|value| value.to_string())
}

fn status_label(state: &str) -> &str {
    match state {
        "analyzed" => "Analyzed",
        "degraded" => "Partial results",
        "failed" => "Failed",
        "analyzing" | "promoting" => "Analyzing",
        "starting" => "Starting",
        "start_uncertain" => "Recovering",
        "uploaded" => "Uploaded",
        "uploading" => "Uploading",
        "created" => "Queued",
        "delete_pending" | "deleting" => "Deleting",
        "deleted" => "Deleted",
        _ => state,
    }
}

fn persona_label(persona: &str) -> &str {
    match persona {
        "binary-analyst" => "General analyst",
        "malware-analyst" => "Malware triage",
        "reverse-engineer" => "Vulnerability researcher",
        "incident-responder" => "Incident responder",
        "custom" => "Custom",
        _ => persona,
    }
}

fn format_bytes(bytes: i64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.2} GiB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn renderer_escapes_values_and_rejects_missing_templates() {
        let directory = tempfile::tempdir().unwrap();
        tokio::fs::write(
            directory.path().join("workbench.html"),
            "<h1>{{ title }}</h1>",
        )
        .await
        .unwrap();
        let renderer = TemplateRenderer::new(directory.path().to_path_buf()).unwrap();
        let html = renderer
            .render(TemplateName::Workbench, &serde_json::json!({"title":"<x>"}))
            .await
            .unwrap();
        assert_eq!(html, "<h1>&lt;x&gt;</h1>");
        assert!(renderer
            .render(TemplateName::Confirm, &serde_json::json!({}))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn rich_ssr_is_navigable_and_never_trusts_collection_strings_as_html() {
        let directory = tempfile::tempdir().unwrap();
        tokio::fs::write(
            directory.path().join("list.html"),
            "<div data-wb-analyses hidden></div><span data-wb-analysis-count>—</span>",
        )
        .await
        .unwrap();
        tokio::fs::write(
            directory.path().join("conversation.html"),
            "<div data-wb-sessions hidden></div><div class=\"empty\" data-wb-sessions-empty hidden></div><div class=\"wb-thread\" data-wb-thread aria-live=\"polite\"></div><div class=\"empty\" data-wb-thread-empty hidden></div><div data-wb-select-note hidden></div>",
        )
        .await
        .unwrap();
        let renderer = TemplateRenderer::new(directory.path().to_path_buf()).unwrap();
        let analysis_id = uuid::Uuid::new_v4();
        let conversation_id = uuid::Uuid::new_v4();
        let list = renderer
            .render(
                TemplateName::List,
                &serde_json::json!({
                    "analyses":[{
                        "id":analysis_id,
                        "display_name":"<script>alert(1)</script>",
                        "state":"analyzed",
                        "sample_id":"sha256:abc"
                    }]
                }),
            )
            .await
            .unwrap();
        assert!(list.contains(&format!("href=\"/analyses/{analysis_id}\"")));
        assert!(list.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(!list.contains("<script>"));

        let conversation = renderer
            .render(
                TemplateName::Conversation,
                &serde_json::json!({
                    "analysis_id":analysis_id,
                    "selected_conversation_id":conversation_id,
                    "csrf_token":"csrf\"><script>",
                    "delete_conversation_operation_id":uuid::Uuid::new_v4(),
                    "conversations":[{
                        "id":conversation_id,
                        "title":"<img src=x onerror=alert(1)>",
                        "persona_id":"binary-analyst"
                    }],
                    "messages":[{
                        "role":"assistant",
                        "content":"Evidence <script>alert(2)</script> [ref:safe]",
                        "status":"complete",
                        "citations":[{"citation_ref":"ref:safe","resolved":true}]
                    }]
                }),
            )
            .await
            .unwrap();
        assert!(conversation.contains(&format!("/conversation?conversation_id={conversation_id}")));
        assert!(conversation.contains("&lt;img src=x onerror=alert(1)&gt;"));
        assert!(conversation.contains("&lt;script&gt;alert(2)&lt;/script&gt;"));
        assert!(conversation.contains("evidence?highlight=ref:safe"));
        assert!(!conversation.contains("<script>"));
        assert!(!conversation.contains("<img src=x"));
    }

    #[tokio::test]
    async fn checked_in_templates_have_a_closed_context_contract() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("templates")
            .canonicalize()
            .unwrap();
        let renderer = TemplateRenderer::new(root).unwrap();
        let analysis_id = uuid::Uuid::new_v4();
        let conversation_id = uuid::Uuid::new_v4();
        let operation_id = uuid::Uuid::new_v4();
        let analysis = serde_json::json!({
            "id":analysis_id,
            "display_name":"sample<script>.bin",
            "state":"analyzed",
            "sample_id":"sha256:abc",
            "created_at":"2026-08-23T00:00:00Z",
            "retention_until":"2026-09-22T00:00:00Z",
            "current_stage":"profile",
            "latest_stage":"profile",
            "plan_id":"plan-1"
        });
        let artifact = serde_json::json!({
            "id":uuid::Uuid::new_v4(),
            "artifact_type":"summary<script>",
            "artifact_ref":"ref:summary",
            "mime":"application/json",
            "metadata":{"summary":"<script>alert(1)</script>"}
        });
        renderer
            .render(
                TemplateName::Workbench,
                &serde_json::json!({"title":"Workbench","csrf_token":"csrf","upload_create_operation_id":operation_id}),
            )
            .await
            .unwrap();
        renderer
            .render(
                TemplateName::List,
                &serde_json::json!({"title":"Analyses","analyses":[],"analyses_json":[],"quota":{"used_bytes":0,"reserved_bytes":0,"byte_limit":1024},"quota_json":{"used_bytes":0}}),
            )
            .await
            .unwrap();
        let detail = renderer
            .render(
                TemplateName::Detail,
                &serde_json::json!({
                    "title":"sample.bin","csrf_token":"csrf","promote_operation_id":operation_id,
                    "delete_operation_id":uuid::Uuid::new_v4(),
                    "section":"summary","analysis_id":analysis_id,"analysis":analysis,
                    "analysis_json":analysis,"summary":{"artifact":artifact},
                    "artifacts":[artifact],"artifacts_json":[artifact]
                }),
            )
            .await
            .unwrap();
        assert!(detail.contains("summary&lt;script&gt;"));
        assert!(!detail.contains("<script>alert(1)</script>"));
        renderer
            .render(
                TemplateName::Conversation,
                &serde_json::json!({
                    "title":"Conversation","csrf_token":"csrf",
                    "create_conversation_operation_id":operation_id,
                    "persona_operation_id":uuid::Uuid::new_v4(),
                    "turn_operation_id":uuid::Uuid::new_v4(),
                    "analysis_id":analysis_id,"analysis_json":analysis,
                    "selected_conversation_id":conversation_id,"next_client_seq":1,
                    "conversations":[],"conversations_json":[],"messages":[],"messages_json":[],
                    "delete_conversation_operation_id":operation_id
                }),
            )
            .await
            .unwrap();
        renderer
            .render(
                TemplateName::ContextPreview,
                &serde_json::json!({"title":"Context","analysis_id":analysis_id,"context_json":{}}),
            )
            .await
            .unwrap();
        renderer
            .render(TemplateName::Error, &serde_json::json!({}))
            .await
            .unwrap();
        renderer
            .render(
                TemplateName::Confirm,
                &serde_json::json!({
                    "title":"Confirm","confirm_heading":"Confirm","confirm_message":"Sure?",
                    "confirm_action":"/delete","cancel_href":"/","confirm_submit_label":"Delete",
                    "csrf_token":"csrf","operation_id":operation_id
                }),
            )
            .await
            .unwrap();
    }
}
