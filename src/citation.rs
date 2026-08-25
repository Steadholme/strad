use regex::Regex;
use sha2::{Digest, Sha256};

use crate::{
    bridge::{ArtifactReadRequest, BridgeClient},
    error::Result,
    models::{Message, Turn},
    store::Store,
};

pub async fn resolve(
    store: &Store,
    bridge: &BridgeClient,
    turn: &Turn,
    assistant: &Message,
) -> Result<usize> {
    let matcher = Regex::new(r"\[ref:([a-z0-9_-]{1,240})\]").expect("static citation regex");
    let mut refs: Vec<String> = matcher
        .captures_iter(&assistant.content)
        .map(|capture| format!("ref:{}", &capture[1]))
        .collect();
    refs.sort();
    refs.dedup();
    let sample_id: Option<String> = sqlx::query_scalar(
        "SELECT sample_id FROM analyses WHERE id=$1 AND owner_sub=$2 AND deleted_at IS NULL",
    )
    .bind(turn.analysis_id)
    .bind(&turn.owner_sub)
    .fetch_optional(store.pool())
    .await?
    .flatten();
    let mut resolved = 0;
    for citation_ref in refs {
        let artifact = store
            .artifact_for_ref(&turn.owner_sub, turn.analysis_id, &citation_ref)
            .await?;
        let excerpt = if let (Some(artifact), Some(sample_id)) = (&artifact, sample_id.as_deref()) {
            let response = bridge
                .artifact_read(&ArtifactReadRequest {
                    sample_id,
                    artifact_id: Some(&artifact.upstream_artifact_id),
                    artifact_type: None,
                    path: None,
                    read_mode: "content",
                })
                .await;
            match response {
                Ok(response) => response
                    .value
                    .get("content")
                    .and_then(|value| value.as_str())
                    .filter(|content| {
                        hex::encode(Sha256::digest(content.as_bytes())) == artifact.sha256
                    })
                    .map(extract_excerpt),
                Err(_) => None,
            }
        } else {
            None
        };
        match (&artifact, excerpt) {
            (Some(artifact), Some((excerpt, start, end, sha))) => {
                store
                    .save_citation(
                        assistant.id,
                        turn.analysis_id,
                        &turn.owner_sub,
                        &citation_ref,
                        Some(artifact),
                        Some((&excerpt, start, end, &sha)),
                    )
                    .await?;
                resolved += 1;
            }
            _ => {
                store
                    .save_citation(
                        assistant.id,
                        turn.analysis_id,
                        &turn.owner_sub,
                        &citation_ref,
                        None,
                        None,
                    )
                    .await?;
            }
        }
    }
    Ok(resolved)
}

pub fn annotate_uncited_markdown(markdown: &str, resolved_refs: &[String]) -> String {
    let mut output = Vec::new();
    for paragraph in markdown.split("\n\n") {
        let factual = !paragraph.trim().is_empty()
            && !paragraph.trim_start().starts_with(['#', '`', '>'])
            && paragraph.chars().any(|ch| ch.is_alphabetic());
        let cited = resolved_refs
            .iter()
            .any(|reference| paragraph.contains(&format!("[{reference}]")));
        if factual && !cited {
            output.push("_该事实段落因缺少已验证引用而被隐藏。_".to_string());
        } else {
            output.push(paragraph.to_string());
        }
    }
    output.join("\n\n")
}

fn extract_excerpt(content: &str) -> (String, i64, i64, String) {
    let mut end = content.len().min(2048);
    while !content.is_char_boundary(end) {
        end -= 1;
    }
    let excerpt = content[..end].to_string();
    let sha = hex::encode(Sha256::digest(excerpt.as_bytes()));
    (excerpt, 0, end as i64, sha)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uncited_factual_paragraphs_are_forced_to_disclose() {
        let rendered = annotate_uncited_markdown(
            "The function opens a socket.\n\nA hypothesis [ref:socket].",
            &["ref:socket".into()],
        );
        assert!(!rendered.contains("opens a socket"));
        assert!(rendered.contains("缺少已验证引用"));
        assert!(rendered.ends_with("A hypothesis [ref:socket]."));
    }

    #[test]
    fn excerpt_is_utf8_safe_and_bounded() {
        let (excerpt, start, end, sha) = extract_excerpt(&"界".repeat(1000));
        assert_eq!(start, 0);
        assert!(excerpt.len() <= 2048);
        assert_eq!(end as usize, excerpt.len());
        assert_eq!(sha.len(), 64);
    }
}
