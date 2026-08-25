use std::{
    fs::File as StdFile,
    os::fd::AsRawFd,
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use uuid::Uuid;
use walkdir::WalkDir;

use crate::{
    bridge::{BridgeClient, MutationOutcome},
    config::Config,
    error::{AppError, Result},
    store::{canonical_request_sha, CleanupJob, Store},
};

#[derive(Clone, Debug)]
pub struct CleanupService {
    store: Store,
    bridge: BridgeClient,
    _root_fd: Arc<StdFile>,
    root: Arc<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CleanupManifest {
    schema_version: u32,
    staging_key: String,
    assembled: Option<CleanupFile>,
    chunks: Vec<CleanupFile>,
    sample_sha256: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CleanupFile {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    index: Option<i32>,
    storage_key: String,
    byte_size: i64,
    sha256: String,
}

impl CleanupService {
    pub fn new(config: &Config, store: Store, bridge: BridgeClient) -> Result<Self> {
        let (root_fd, anchored_root) = open_anchored_root(&config.upload_root)?;
        Ok(Self {
            store,
            bridge,
            _root_fd: root_fd,
            root: anchored_root,
        })
    }

    pub async fn run_cleanup_once(&self) -> Result<bool> {
        let Some(job) = self.store.claim_cleanup().await? else {
            return Ok(false);
        };
        match self.clean_claimed(&job).await {
            Ok(()) => {
                self.store.complete_cleanup(&job).await?;
                Ok(true)
            }
            Err(error) => {
                let force_dead = matches!(error, AppError::Invariant(_));
                self.store
                    .fail_cleanup(&job, error.code(), force_dead)
                    .await?;
                tracing::error!(
                    cleanup_job_id = %job.id,
                    analysis_id = %job.analysis_id,
                    code = error.code(),
                    "cleanup job failed closed"
                );
                Ok(false)
            }
        }
    }

    pub async fn run_sample_delete_once(&self) -> Result<bool> {
        let Some(claim) = self.store.claim_sample_delete().await? else {
            return Ok(false);
        };
        let outcome = self
            .bridge
            .delete_sample(
                claim.delete_operation_id,
                &claim.sample_id,
                &claim.sha256,
                Some("last logical reference removed"),
            )
            .await;
        match outcome {
            Ok(MutationOutcome::Complete(result)) if result.sample_id == claim.sample_id => {
                self.store.finish_sample_delete(&claim, true, None).await?;
                Ok(true)
            }
            Ok(MutationOutcome::Complete(_)) => {
                tracing::error!(sample_id = %claim.sample_id, "sample delete returned the wrong sample id");
                self.store
                    .finish_sample_delete(&claim, false, Some("analyzer_contract_violation"))
                    .await?;
                Ok(false)
            }
            Ok(MutationOutcome::Pending) => {
                self.store
                    .finish_sample_delete(&claim, false, Some("analyzer_pending"))
                    .await?;
                Ok(false)
            }
            Err(error) => {
                self.store
                    .finish_sample_delete(&claim, false, Some(error.code()))
                    .await?;
                tracing::warn!(sample_id = %claim.sample_id, code = error.code(), "sample delete will be reconciled");
                Ok(false)
            }
        }
    }

    pub async fn run_retention_once(&self) -> Result<u64> {
        let expired = self.store.expired_analyses(16).await?;
        let mut accepted = 0;
        for (analysis_id, owner_sub) in expired {
            let path = format!("/api/analyses/{analysis_id}/delete");
            let operation_id = Uuid::new_v4();
            let request_sha = canonical_request_sha("POST", &path, &owner_sub, b"");
            match self
                .store
                .request_analysis_delete(&owner_sub, analysis_id, operation_id, &request_sha)
                .await
            {
                Ok(_) => accepted += 1,
                Err(AppError::Api {
                    code: "not_found", ..
                }) => {}
                Err(error) => {
                    tracing::warn!(analysis_id = %analysis_id, code = error.code(), "retention delete failed");
                }
            }
        }
        Ok(accepted)
    }

    async fn clean_claimed(&self, job: &CleanupJob) -> Result<()> {
        let encoded = serde_json::to_vec(&job.manifest)
            .map_err(|_| AppError::Invariant("cleanup manifest is not serializable"))?;
        if hex::encode(Sha256::digest(encoded)) != job.manifest_sha256 {
            return Err(AppError::Invariant("cleanup manifest checksum mismatch"));
        }
        let manifest: CleanupManifest = serde_json::from_value(job.manifest.clone())
            .map_err(|_| AppError::Invariant("cleanup manifest schema drift"))?;
        if manifest.schema_version != 1
            || !is_sha256_opt(manifest.sample_sha256.as_deref())
            || Uuid::parse_str(&manifest.staging_key).is_err()
        {
            return Err(AppError::Invariant("cleanup manifest is invalid"));
        }
        let prefix = format!("{}/", manifest.staging_key);
        for file in manifest.chunks.iter().chain(manifest.assembled.iter()) {
            if !matches!(file.kind.as_str(), "chunk" | "assembled")
                || (file.kind == "chunk" && file.index.is_none())
                || (file.kind == "assembled" && file.index.is_some())
                || file.byte_size <= 0
                || !is_sha256(&file.sha256)
                || !file.storage_key.starts_with(&prefix)
            {
                return Err(AppError::Invariant("cleanup file descriptor is invalid"));
            }
            let path = self.key_path(&file.storage_key)?;
            self.unlink_verified(&path, file.byte_size as u64, &file.sha256)
                .await?;
        }
        self.remove_staging_tree(&manifest.staging_key).await
    }

    fn key_path(&self, key: &str) -> Result<PathBuf> {
        let path = Path::new(key);
        if path.is_absolute()
            || path
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err(AppError::Invariant("cleanup storage key is invalid"));
        }
        let candidate = self.root.join(path);
        if !candidate.starts_with(self.root.as_ref()) {
            return Err(AppError::Invariant("cleanup storage key escaped root"));
        }
        Ok(candidate)
    }

    async fn unlink_verified(
        &self,
        path: &Path,
        expected_size: u64,
        expected_sha: &str,
    ) -> Result<()> {
        let metadata = match tokio::fs::symlink_metadata(path).await {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() != expected_size
            || has_multiple_links(&metadata)
        {
            return Err(AppError::Invariant("cleanup target metadata mismatch"));
        }
        let mut file = tokio::fs::File::open(path).await?;
        let mut digest = Sha256::new();
        let mut buffer = vec![0u8; 1024 * 1024];
        loop {
            let count = file.read(&mut buffer).await?;
            if count == 0 {
                break;
            }
            digest.update(&buffer[..count]);
        }
        if hex::encode(digest.finalize()) != expected_sha {
            return Err(AppError::Invariant("cleanup target digest mismatch"));
        }
        drop(file);
        tokio::fs::remove_file(path).await?;
        if let Some(parent) = path.parent() {
            fsync_dir(parent).await?;
        }
        Ok(())
    }

    async fn remove_staging_tree(&self, staging_key: &str) -> Result<()> {
        let session = self.root.join(
            Uuid::parse_str(staging_key)
                .map_err(|_| AppError::Invariant("cleanup staging key is invalid"))?
                .to_string(),
        );
        let metadata = match tokio::fs::symlink_metadata(&session).await {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(AppError::Invariant(
                "cleanup staging directory is not trusted",
            ));
        }
        let scan_root = session.clone();
        let entries = tokio::task::spawn_blocking(move || {
            let mut entries = Vec::new();
            for entry in WalkDir::new(&scan_root)
                .follow_links(false)
                .contents_first(true)
            {
                let entry =
                    entry.map_err(|_| AppError::Invariant("cleanup staging tree is unreadable"))?;
                let metadata = entry.path().symlink_metadata().map_err(AppError::Io)?;
                if metadata.file_type().is_symlink()
                    || (!metadata.is_dir() && !metadata.is_file())
                    || (metadata.is_file() && has_multiple_links(&metadata))
                {
                    return Err(AppError::Invariant("cleanup staging tree is unsafe"));
                }
                entries.push((entry.path().to_path_buf(), metadata.is_dir()));
            }
            Ok::<_, AppError>(entries)
        })
        .await
        .map_err(|_| AppError::Invariant("cleanup tree scan failed"))??;
        for (path, is_dir) in entries {
            if is_dir {
                tokio::fs::remove_dir(&path).await?;
            } else {
                tokio::fs::remove_file(&path).await?;
            }
            if let Some(parent) = path.parent() {
                fsync_dir(parent).await?;
            }
        }
        fsync_dir(self.root.as_ref()).await
    }
}

fn is_sha256_opt(value: Option<&str>) -> bool {
    value.map(is_sha256).unwrap_or(true)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(unix)]
fn has_multiple_links(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    metadata.nlink() > 1
}

#[cfg(not(unix))]
fn has_multiple_links(_metadata: &std::fs::Metadata) -> bool {
    true
}

async fn fsync_dir(path: &Path) -> Result<()> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || StdFile::open(path)?.sync_all())
        .await
        .map_err(|_| AppError::Invariant("directory fsync task failed"))??;
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_anchored_root(path: &Path) -> Result<(Arc<StdFile>, Arc<PathBuf>)> {
    use rustix::fs::{open, Mode, OFlags};

    let owned = open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    let file = Arc::new(StdFile::from(owned));
    let anchored = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
    if !std::fs::metadata(&anchored)?.is_dir() {
        return Err(AppError::Invariant("cleanup root fd anchor is unavailable"));
    }
    Ok((file, Arc::new(anchored)))
}

#[cfg(not(target_os = "linux"))]
fn open_anchored_root(_path: &Path) -> Result<(Arc<StdFile>, Arc<PathBuf>)> {
    Err(AppError::Invariant(
        "cleanup root fd anchoring requires Linux",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_keys_are_lowercase_sha_and_relative() {
        assert!(is_sha256(&"a".repeat(64)));
        assert!(!is_sha256(&"A".repeat(64)));
        assert!(!is_sha256("../sample"));
    }
}
