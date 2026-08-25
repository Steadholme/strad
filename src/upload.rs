use std::{
    collections::HashSet,
    fs::File as StdFile,
    os::fd::AsRawFd,
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use bytes::Bytes;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;
use walkdir::WalkDir;

use crate::{
    bridge::{BridgeClient, MutationOutcome, OperationState, UploadResult},
    config::{Config, CHUNK_BYTES, MAX_FILE_BYTES},
    error::{AppError, Result},
    models::Analysis,
    store::{ChunkClaim, Store},
};

#[derive(Clone, Debug)]
pub struct UploadService {
    store: Store,
    bridge: BridgeClient,
    _root_fd: Arc<StdFile>,
    root: Arc<PathBuf>,
}

#[derive(Debug)]
pub struct MultipartSpool {
    path: PathBuf,
    pub total_bytes: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContentRange {
    pub start: i64,
    pub end: i64,
    pub total: i64,
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum FinalizeOutcome {
    Complete(Analysis),
    Pending,
    UnknownFile,
}

impl ContentRange {
    pub fn parse(raw: &str) -> Result<Self> {
        let value = raw
            .strip_prefix("bytes ")
            .ok_or_else(|| AppError::invalid("invalid_upload", "Content-Range is invalid."))?;
        let (range, total) = value
            .split_once('/')
            .ok_or_else(|| AppError::invalid("invalid_upload", "Content-Range is invalid."))?;
        let (start, end) = range
            .split_once('-')
            .ok_or_else(|| AppError::invalid("invalid_upload", "Content-Range is invalid."))?;
        let parsed = Self {
            start: parse_decimal(start)?,
            end: parse_decimal(end)?,
            total: parse_decimal(total)?,
        };
        if parsed.start < 0 || parsed.end < parsed.start || parsed.total <= parsed.end {
            return Err(AppError::invalid(
                "invalid_upload",
                "Content-Range is invalid.",
            ));
        }
        Ok(parsed)
    }

    pub fn index(self) -> Result<i32> {
        if self.start % CHUNK_BYTES != 0 {
            return Err(AppError::invalid(
                "invalid_upload",
                "Chunk start is not aligned.",
            ));
        }
        i32::try_from(self.start / CHUNK_BYTES).map_err(|_| {
            AppError::invalid(
                "invalid_upload",
                "Chunk index is outside the allowed range.",
            )
        })
    }

    pub fn checked_len(self) -> Result<i32> {
        i32::try_from(self.end - self.start + 1).map_err(|_| {
            AppError::invalid(
                "invalid_upload",
                "Chunk length is outside the allowed range.",
            )
        })
    }
}

impl UploadService {
    pub async fn new(config: &Config, store: Store, bridge: BridgeClient) -> Result<Self> {
        tokio::fs::create_dir_all(&config.upload_root).await?;
        let metadata = tokio::fs::symlink_metadata(&config.upload_root).await?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(AppError::Invariant(
                "upload root is not a trusted directory",
            ));
        }
        let (root_fd, anchored_root) = open_anchored_root(&config.upload_root)?;
        Ok(Self {
            store,
            bridge,
            _root_fd: root_fd,
            root: anchored_root,
        })
    }

    pub async fn put_chunk(
        &self,
        owner_sub: &str,
        upload_id: Uuid,
        range: ContentRange,
        claimed_sha256: &str,
        body: Bytes,
    ) -> Result<bool> {
        if !is_sha256(claimed_sha256) || body.len() > CHUNK_BYTES as usize {
            return Err(AppError::invalid(
                "invalid_upload",
                "Chunk digest or length is invalid.",
            ));
        }
        let actual = hex::encode(Sha256::digest(&body));
        if actual != claimed_sha256 {
            return Err(AppError::invalid(
                "invalid_upload",
                "Chunk digest does not match its body.",
            ));
        }
        let index = range.index()?;
        let length = range.checked_len()?;
        if length as usize != body.len() {
            return Err(AppError::invalid(
                "invalid_upload",
                "Content-Range length does not match its body.",
            ));
        }
        let claim = self
            .store
            .claim_chunk(
                owner_sub,
                upload_id,
                index,
                range.start,
                range.end,
                length,
                claimed_sha256,
            )
            .await?;
        let ChunkClaim::Claimed {
            session,
            lease_token,
        } = claim
        else {
            return Ok(true);
        };
        if range.total != session.total_bytes {
            self.store
                .abandon_upload_lease(owner_sub, upload_id, lease_token, "range_total_mismatch")
                .await?;
            return Err(AppError::invalid(
                "invalid_upload",
                "Content-Range total does not match the upload session.",
            ));
        }
        let parts = self.session_dir(&session.staging_key)?.join("parts");
        if let Err(error) = ensure_directory(&parts).await {
            let _ = self
                .store
                .abandon_upload_lease(owner_sub, upload_id, lease_token, "storage_unavailable")
                .await;
            return Err(error);
        }
        let final_path = parts.join(format!("{index:02}.part"));
        let temp_path = parts.join(format!(".{index:02}.{lease_token}.tmp"));
        let result = async {
            write_fsync(&temp_path, &body).await?;
            reject_unsafe_existing(&final_path).await?;
            tokio::fs::rename(&temp_path, &final_path).await?;
            fsync_dir(&parts).await?;
            let storage_key = format!("{}/parts/{index:02}.part", session.staging_key);
            self.store
                .commit_chunk(
                    owner_sub,
                    upload_id,
                    lease_token,
                    index,
                    range.start,
                    range.end,
                    length,
                    claimed_sha256,
                    &storage_key,
                )
                .await
        }
        .await;
        if result.is_err() {
            let _ = self
                .store
                .abandon_upload_lease(owner_sub, upload_id, lease_token, "chunk_commit_failed")
                .await;
        }
        result.map(|_| false)
    }

    pub async fn spool_multipart(
        &self,
        operation_id: Uuid,
        field: &mut axum::extract::multipart::Field<'_>,
    ) -> Result<MultipartSpool> {
        let request_id = Uuid::new_v4();
        let path = self
            .root
            .join(format!(".multipart-{operation_id}-{request_id}.tmp"));
        let mut output = tokio::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .await?;
        let streamed =
            async {
                let mut total_bytes = 0i64;
                while let Some(chunk) = field.chunk().await.map_err(|_| {
                    AppError::invalid("invalid_upload", "Multipart file is unreadable.")
                })? {
                    total_bytes = total_bytes.saturating_add(chunk.len() as i64);
                    if total_bytes > MAX_FILE_BYTES {
                        return Err(AppError::api(
                            axum::http::StatusCode::PAYLOAD_TOO_LARGE,
                            "file_too_large",
                            "The file exceeds 500 MiB.",
                            false,
                        ));
                    }
                    output.write_all(&chunk).await?;
                }
                if total_bytes == 0 {
                    return Err(AppError::invalid(
                        "invalid_upload",
                        "The uploaded file is empty.",
                    ));
                }
                output.flush().await?;
                output.sync_all().await?;
                Ok(total_bytes)
            }
            .await;
        drop(output);
        let total_bytes = match streamed {
            Ok(total_bytes) => total_bytes,
            Err(error) => {
                let _ = tokio::fs::remove_file(&path).await;
                let _ = fsync_dir(self.root.as_ref()).await;
                return Err(error);
            }
        };
        let metadata = tokio::fs::symlink_metadata(&path).await?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || has_multiple_links(&metadata)
            || metadata.len() != total_bytes as u64
        {
            return Err(AppError::Invariant("multipart spool is not a trusted file"));
        }
        fsync_dir(self.root.as_ref()).await?;
        Ok(MultipartSpool { path, total_bytes })
    }

    pub async fn ingest_multipart_spool(
        &self,
        owner_sub: &str,
        upload_id: Uuid,
        spool: &MultipartSpool,
    ) -> Result<()> {
        if !spool.path.starts_with(self.root.as_ref()) {
            return Err(AppError::Invariant("multipart spool escaped upload root"));
        }
        let metadata = tokio::fs::symlink_metadata(&spool.path).await?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || has_multiple_links(&metadata)
            || metadata.len() != spool.total_bytes as u64
        {
            return Err(AppError::Invariant("multipart spool is not a trusted file"));
        }
        let mut input = tokio::fs::File::open(&spool.path).await?;
        let mut offset = 0i64;
        while offset < spool.total_bytes {
            let length = (spool.total_bytes - offset).min(CHUNK_BYTES) as usize;
            let mut buffer = vec![0u8; length];
            input.read_exact(&mut buffer).await?;
            let body = Bytes::from(buffer);
            let end = offset + length as i64 - 1;
            let digest = hex::encode(Sha256::digest(&body));
            self.put_chunk(
                owner_sub,
                upload_id,
                ContentRange {
                    start: offset,
                    end,
                    total: spool.total_bytes,
                },
                &digest,
                body,
            )
            .await?;
            offset = end + 1;
        }
        let mut trailing = [0u8; 1];
        if input.read(&mut trailing).await? != 0 {
            return Err(AppError::Invariant(
                "multipart spool grew after durable validation",
            ));
        }
        Ok(())
    }

    pub async fn discard_multipart_spool(&self, spool: &MultipartSpool) -> Result<()> {
        if !spool.path.starts_with(self.root.as_ref()) {
            return Err(AppError::Invariant("multipart spool escaped upload root"));
        }
        match tokio::fs::symlink_metadata(&spool.path).await {
            Ok(metadata)
                if metadata.is_file()
                    && !metadata.file_type().is_symlink()
                    && !has_multiple_links(&metadata) =>
            {
                tokio::fs::remove_file(&spool.path).await?;
                fsync_dir(self.root.as_ref()).await
            }
            Ok(_) => Err(AppError::Invariant("multipart spool is not a trusted file")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    pub async fn finalize(&self, owner_sub: &str, upload_id: Uuid) -> Result<FinalizeOutcome> {
        let claim = self.store.claim_finalize(owner_sub, upload_id).await?;
        let directory = self.session_dir(&claim.session.staging_key)?;
        let assembled = directory.join("assembled.bin");
        let temp = directory.join(format!(".assembled.{}.tmp", claim.lease_token));
        let digest = match self
            .assemble(&claim.chunks, claim.session.total_bytes, &temp, &assembled)
            .await
        {
            Ok(digest) => digest,
            Err(error) => {
                let _ = self
                    .store
                    .abandon_upload_lease(
                        owner_sub,
                        upload_id,
                        claim.lease_token,
                        "assemble_failed",
                    )
                    .await;
                return Err(error);
            }
        };
        self.store
            .mark_forwarding(owner_sub, upload_id, claim.lease_token, &digest)
            .await?;
        let bridge_operation = claim.session.operation_id;
        let outcome = self
            .bridge
            .upload_sample(
                bridge_operation,
                &assembled,
                claim.session.total_bytes as u64,
                &digest,
            )
            .await;
        match outcome {
            Ok(MutationOutcome::Pending) | Err(_) => {
                self.store
                    .mark_upstream_uncertain(upload_id, claim.lease_token)
                    .await?;
                Ok(FinalizeOutcome::Pending)
            }
            Ok(MutationOutcome::Complete(upstream)) => {
                if upstream.sample_id != format!("sha256:{digest}") {
                    self.store
                        .mark_upstream_uncertain(upload_id, claim.lease_token)
                        .await?;
                    return Err(AppError::Invariant(
                        "analyzer returned a different sample digest",
                    ));
                }
                if upstream.file_type == "unknown" {
                    self.store
                        .complete_finalize(
                            owner_sub,
                            upload_id,
                            Some(claim.lease_token),
                            &digest,
                            "unknown",
                        )
                        .await?;
                    if self
                        .store
                        .dispose_finalized_unknown(owner_sub, upload_id, &digest)
                        .await?
                    {
                        self.remove_session_dir(&claim.session.staging_key).await?;
                    }
                    Ok(FinalizeOutcome::UnknownFile)
                } else {
                    let analysis = self
                        .store
                        .complete_finalize(
                            owner_sub,
                            upload_id,
                            Some(claim.lease_token),
                            &digest,
                            &upstream.file_type,
                        )
                        .await?;
                    // Analyzer has durable ownership now. Local staging is no longer authoritative.
                    self.remove_session_dir(&claim.session.staging_key).await?;
                    Ok(FinalizeOutcome::Complete(analysis))
                }
            }
        }
    }

    pub async fn cancel(&self, owner_sub: &str, upload_id: Uuid) -> Result<()> {
        let upload = self.store.begin_cancel(owner_sub, upload_id).await?;
        if upload.lease_token.is_some()
            || matches!(
                upload.state.as_str(),
                "assembling" | "forwarding" | "upstream_uncertain"
            )
        {
            return Ok(());
        }
        self.remove_session_dir(&upload.staging_key).await?;
        self.store.complete_cancel(owner_sub, upload_id).await
    }

    pub async fn reconcile_uncertain(&self) -> Result<u64> {
        let uploads = self.store.uncertain_uploads(16).await?;
        let mut progressed = 0;
        for upload in uploads {
            let Some(digest) = upload.assembled_sha256.as_deref() else {
                continue;
            };
            let assembled = self.session_dir(&upload.staging_key)?.join("assembled.bin");
            if !verify_file(&assembled, upload.total_bytes as u64, digest).await? {
                tracing::error!(upload_id = %upload.id, "uncertain upload spool failed verification");
                continue;
            }
            match self.bridge.operation(upload.operation_id).await {
                Ok(operation) if operation.state == OperationState::Succeeded => {
                    let result: UploadResult = serde_json::from_value(operation.result.ok_or(
                        AppError::Invariant("succeeded upload operation omitted result"),
                    )?)
                    .map_err(|_| AppError::Invariant("reconciled upload schema drift"))?;
                    if result.sample_id != format!("sha256:{digest}") {
                        return Err(AppError::Invariant(
                            "reconciled upload returned a different sample digest",
                        ));
                    }
                    self.store
                        .complete_finalize(
                            &upload.owner_sub,
                            upload.id,
                            None,
                            digest,
                            &result.file_type,
                        )
                        .await?;
                    if result.file_type == "unknown" {
                        if self
                            .store
                            .dispose_finalized_unknown(&upload.owner_sub, upload.id, digest)
                            .await?
                        {
                            self.remove_session_dir(&upload.staging_key).await?;
                        }
                    } else {
                        self.remove_session_dir(&upload.staging_key).await?;
                    }
                    progressed += 1;
                }
                Ok(operation) if operation.state == OperationState::Failed => {
                    if self.store.expire_uncertain_upload(&upload, true).await? {
                        self.remove_session_dir(&upload.staging_key).await?;
                        progressed += 1;
                    }
                }
                Ok(operation)
                    if matches!(
                        operation.state,
                        OperationState::Pending | OperationState::Unknown
                    ) =>
                {
                    if self.store.expire_uncertain_upload(&upload, false).await? {
                        self.remove_session_dir(&upload.staging_key).await?;
                        progressed += 1;
                    }
                }
                Ok(_) | Err(_) => {}
            }
        }
        for upload in self.store.disposition_uploads(16).await? {
            let Some(digest) = upload.assembled_sha256.as_deref() else {
                continue;
            };
            let assembled = self.session_dir(&upload.staging_key)?.join("assembled.bin");
            if !verify_file(&assembled, upload.total_bytes as u64, digest).await? {
                tracing::error!(upload_id = %upload.id, "upload disposition spool failed verification");
                continue;
            }
            let complete = if upload.state == "finalized" {
                self.store
                    .dispose_finalized_unknown(&upload.owner_sub, upload.id, digest)
                    .await?
            } else {
                self.store.complete_unknown_disposition(&upload).await?
            };
            if complete {
                self.remove_session_dir(&upload.staging_key).await?;
                progressed += 1;
            }
        }
        Ok(progressed)
    }

    pub async fn sweep_cancellations(&self) -> Result<u64> {
        let mut progressed = 0;
        for (owner_sub, upload_id) in self.store.cancellable_requested_uploads(16).await? {
            self.cancel(&owner_sub, upload_id).await?;
            progressed += 1;
        }
        for (owner_sub, analysis_id, operation_id) in
            self.store.cancelled_finalized_uploads(16).await?
        {
            let path = format!("/api/analyses/{analysis_id}/delete");
            let request_sha = crate::store::canonical_request_sha("POST", &path, &owner_sub, b"");
            match self
                .store
                .request_analysis_delete(&owner_sub, analysis_id, operation_id, &request_sha)
                .await
            {
                Ok(_) => progressed += 1,
                Err(AppError::Api {
                    code: "not_found", ..
                }) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(progressed)
    }

    pub async fn recover_filesystem(&self) -> Result<()> {
        let chunks = self.store.recovery_chunks().await?;
        let known: HashSet<String> = chunks.iter().map(|row| row.storage_key.clone()).collect();
        let root = self.root.clone();
        let paths = tokio::task::spawn_blocking(move || scan_upload_tree(root.as_ref()))
            .await
            .map_err(|_| AppError::Invariant("upload recovery task failed"))??;
        for path in paths {
            let relative = path
                .strip_prefix(self.root.as_ref())
                .map_err(|_| AppError::Invariant("upload recovery path escaped root"))?;
            let key = relative
                .to_str()
                .ok_or(AppError::Invariant("upload storage key is not UTF-8"))?
                .replace('\\', "/");
            let filename = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");
            if filename.ends_with(".tmp") || (filename.ends_with(".part") && !known.contains(&key))
            {
                tokio::fs::remove_file(&path).await?;
                if let Some(parent) = path.parent() {
                    fsync_dir(parent).await?;
                }
            }
        }
        for chunk in chunks {
            let path = self.key_path(&chunk.storage_key)?;
            if !verify_file(&path, chunk.byte_size as u64, &chunk.sha256).await? {
                if tokio::fs::symlink_metadata(&path).await.is_ok() {
                    tokio::fs::remove_file(&path).await?;
                    if let Some(parent) = path.parent() {
                        fsync_dir(parent).await?;
                    }
                }
                self.store
                    .invalidate_chunk(chunk.upload_id, chunk.chunk_index)
                    .await?;
            }
        }
        Ok(())
    }

    async fn assemble(
        &self,
        chunks: &[crate::models::UploadChunk],
        expected_bytes: i64,
        temp: &Path,
        final_path: &Path,
    ) -> Result<String> {
        let mut output = tokio::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(temp)
            .await?;
        let mut hasher = Sha256::new();
        let mut total = 0i64;
        let mut buffer = vec![0u8; 1024 * 1024];
        for chunk in chunks {
            let path = self.key_path(&chunk.storage_key)?;
            let metadata = tokio::fs::symlink_metadata(&path).await?;
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.len() != chunk.byte_size as u64
                || has_multiple_links(&metadata)
            {
                return Err(AppError::conflict(
                    "state_conflict",
                    "A committed chunk is missing or corrupt.",
                ));
            }
            let mut input = tokio::fs::File::open(&path).await?;
            loop {
                let read = input.read(&mut buffer).await?;
                if read == 0 {
                    break;
                }
                output.write_all(&buffer[..read]).await?;
                hasher.update(&buffer[..read]);
                total += read as i64;
            }
        }
        if total != expected_bytes {
            return Err(AppError::conflict(
                "state_conflict",
                "Committed chunk bytes do not match the upload.",
            ));
        }
        output.flush().await?;
        output.sync_all().await?;
        drop(output);
        reject_unsafe_existing(final_path).await?;
        tokio::fs::rename(temp, final_path).await?;
        let parent = final_path
            .parent()
            .ok_or(AppError::Invariant("assembled file has no parent"))?;
        fsync_dir(parent).await?;
        Ok(hex::encode(hasher.finalize()))
    }

    fn session_dir(&self, staging_key: &str) -> Result<PathBuf> {
        let id = Uuid::parse_str(staging_key)
            .map_err(|_| AppError::Invariant("invalid durable staging key"))?;
        Ok(self.root.join(id.to_string()))
    }

    fn key_path(&self, key: &str) -> Result<PathBuf> {
        let path = Path::new(key);
        if path.is_absolute()
            || path
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err(AppError::Invariant("invalid durable storage key"));
        }
        let candidate = self.root.join(path);
        if !candidate.starts_with(self.root.as_ref()) {
            return Err(AppError::Invariant("durable storage key escaped root"));
        }
        Ok(candidate)
    }

    async fn remove_session_dir(&self, staging_key: &str) -> Result<()> {
        let directory = self.session_dir(staging_key)?;
        match tokio::fs::symlink_metadata(&directory).await {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                let scan_root = directory.clone();
                let entries = tokio::task::spawn_blocking(move || {
                    let mut entries = Vec::new();
                    for entry in WalkDir::new(&scan_root)
                        .follow_links(false)
                        .contents_first(true)
                    {
                        let entry = entry.map_err(|_| {
                            AppError::Invariant("upload staging tree is unreadable")
                        })?;
                        let metadata = entry.path().symlink_metadata().map_err(AppError::Io)?;
                        if metadata.file_type().is_symlink()
                            || (!metadata.is_dir() && !metadata.is_file())
                            || (metadata.is_file() && has_multiple_links(&metadata))
                        {
                            return Err(AppError::Invariant("upload staging tree is unsafe"));
                        }
                        entries.push((entry.path().to_path_buf(), metadata.is_dir()));
                    }
                    Ok::<_, AppError>(entries)
                })
                .await
                .map_err(|_| AppError::Invariant("upload staging scan failed"))??;
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
            Ok(_) => Err(AppError::Invariant("staging directory is not trusted")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

fn scan_upload_tree(root: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    // `root` is the trusted O_NOFOLLOW fd anchor `/proc/self/fd/<n>`, which is
    // represented by procfs as a symlink. It was already validated when opened;
    // scan only descendants so nested links and other unsafe inodes still fail closed.
    for entry in WalkDir::new(root).follow_links(false).min_depth(1) {
        let entry = entry.map_err(|_| AppError::Invariant("upload tree is unreadable"))?;
        let metadata = entry.path().symlink_metadata().map_err(AppError::Io)?;
        if metadata.file_type().is_symlink()
            || (!metadata.is_dir() && !metadata.is_file())
            || (metadata.is_file() && has_multiple_links(&metadata))
        {
            return Err(AppError::Invariant("upload tree contains an unsafe inode"));
        }
        if metadata.is_file() {
            paths.push(entry.path().to_path_buf());
        }
    }
    Ok(paths)
}

async fn ensure_directory(path: &Path) -> Result<()> {
    tokio::fs::create_dir_all(path).await?;
    let metadata = tokio::fs::symlink_metadata(path).await?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(AppError::Invariant(
            "staging path is not a trusted directory",
        ));
    }
    if let Some(parent) = path.parent() {
        fsync_dir(parent).await?;
    }
    Ok(())
}

async fn write_fsync(path: &Path, body: &[u8]) -> Result<()> {
    let mut file = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .await?;
    file.write_all(body).await?;
    file.flush().await?;
    file.sync_all().await?;
    if has_multiple_links(&file.metadata().await?) {
        return Err(AppError::Invariant("new upload file acquired a hardlink"));
    }
    Ok(())
}

async fn reject_unsafe_existing(path: &Path) -> Result<()> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) => {
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || has_multiple_links(&metadata)
            {
                return Err(AppError::Invariant(
                    "upload destination is not a regular file",
                ));
            }
            tokio::fs::remove_file(path).await?;
            if let Some(parent) = path.parent() {
                fsync_dir(parent).await?;
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

async fn fsync_dir(path: &Path) -> Result<()> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || StdFile::open(path)?.sync_all())
        .await
        .map_err(|_| AppError::Invariant("directory fsync task failed"))??;
    Ok(())
}

async fn verify_file(path: &Path, expected_size: u64, expected_sha: &str) -> Result<bool> {
    let metadata = match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() != expected_size
        || has_multiple_links(&metadata)
    {
        return Ok(false);
    }
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()) == expected_sha)
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
        return Err(AppError::Invariant("upload root fd anchor is unavailable"));
    }
    Ok((file, Arc::new(anchored)))
}

#[cfg(not(target_os = "linux"))]
fn open_anchored_root(_path: &Path) -> Result<(Arc<StdFile>, Arc<PathBuf>)> {
    Err(AppError::Invariant(
        "upload root fd anchoring requires Linux",
    ))
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

fn parse_decimal(value: &str) -> Result<i64> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(AppError::invalid(
            "invalid_upload",
            "Content-Range is invalid.",
        ));
    }
    value.parse().map_err(|_| {
        AppError::invalid(
            "invalid_upload",
            "Content-Range is outside the allowed range.",
        )
    })
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_range_is_strict_and_chunk_aligned() {
        let parsed = ContentRange::parse("bytes 8388608-8388614/8388615").unwrap();
        assert_eq!(parsed.index().unwrap(), 1);
        assert_eq!(parsed.checked_len().unwrap(), 7);
        assert!(ContentRange::parse("bytes 1-2/*").is_err());
        assert!(ContentRange::parse("bytes 01-2/3").is_ok());
        assert!(ContentRange::parse("Bytes 0-0/1").is_err());
        assert!(ContentRange {
            start: 1,
            end: 1,
            total: 2
        }
        .index()
        .is_err());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn fd_anchor_survives_root_retarget_and_hardlinks_fail_closed() {
        let temporary = tempfile::tempdir().unwrap();
        let configured = temporary.path().join("uploads");
        std::fs::create_dir(&configured).unwrap();
        let (_fd, anchored) = open_anchored_root(&configured).unwrap();
        let original = temporary.path().join("original");
        std::fs::rename(&configured, &original).unwrap();
        std::fs::create_dir(&configured).unwrap();
        tokio::fs::write(anchored.join("anchored.bin"), b"trusted")
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(original.join("anchored.bin")).unwrap(),
            b"trusted"
        );
        assert!(!configured.join("anchored.bin").exists());

        let file = original.join("linked.bin");
        let alias = original.join("alias.bin");
        std::fs::write(&file, b"payload").unwrap();
        std::fs::hard_link(&file, &alias).unwrap();
        let digest = hex::encode(Sha256::digest(b"payload"));
        assert!(!verify_file(&anchored.join("linked.bin"), 7, &digest)
            .await
            .unwrap());
        assert!(reject_unsafe_existing(&anchored.join("linked.bin"))
            .await
            .is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn recovery_scan_skips_trusted_fd_root_and_rejects_unsafe_descendants() {
        use std::os::unix::{fs::symlink, net::UnixListener};

        let temporary = tempfile::tempdir().unwrap();
        let configured = temporary.path().join("uploads");
        std::fs::create_dir(&configured).unwrap();
        let (_fd, anchored) = open_anchored_root(&configured).unwrap();

        assert!(anchored
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(scan_upload_tree(&anchored).unwrap().is_empty());

        let regular = configured.join("regular.bin");
        std::fs::write(&regular, b"trusted").unwrap();
        let scanned = scan_upload_tree(&anchored).unwrap();
        assert_eq!(scanned, vec![anchored.join("regular.bin")]);

        let nested = configured.join("nested");
        std::fs::create_dir(&nested).unwrap();
        std::fs::write(nested.join("nested.bin"), b"nested").unwrap();
        let scanned = scan_upload_tree(&anchored).unwrap();
        assert!(scanned.contains(&anchored.join("nested/nested.bin")));

        let directory_link = configured.join("directory-link");
        symlink(&nested, &directory_link).unwrap();
        assert!(matches!(
            scan_upload_tree(&anchored),
            Err(AppError::Invariant("upload tree contains an unsafe inode"))
        ));
        std::fs::remove_file(&directory_link).unwrap();

        let nested_link = configured.join("nested-link");
        symlink(&regular, &nested_link).unwrap();
        assert!(matches!(
            scan_upload_tree(&anchored),
            Err(AppError::Invariant("upload tree contains an unsafe inode"))
        ));
        std::fs::remove_file(&nested_link).unwrap();

        let hardlink = configured.join("hardlink.bin");
        std::fs::hard_link(&regular, &hardlink).unwrap();
        assert!(matches!(
            scan_upload_tree(&anchored),
            Err(AppError::Invariant("upload tree contains an unsafe inode"))
        ));
        std::fs::remove_file(&hardlink).unwrap();

        let socket = configured.join("socket");
        let _listener = UnixListener::bind(socket).unwrap();
        assert!(matches!(
            scan_upload_tree(&anchored),
            Err(AppError::Invariant("upload tree contains an unsafe inode"))
        ));
    }

    #[tokio::test]
    async fn multipart_spool_derives_size_from_the_stream_and_is_durable() {
        use axum::{
            body::Body,
            extract::{FromRequest, Multipart},
            http::{header, Request},
        };

        let temporary = tempfile::tempdir().unwrap();
        let upload_root = temporary.path().join("uploads");
        let config = Config::for_tests(upload_root.clone());
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgresql://unused:unused@127.0.0.1:1/unused")
            .unwrap();
        let service = UploadService::new(
            &config,
            Store::from_pool(pool),
            BridgeClient::new(&config).unwrap(),
        )
        .await
        .unwrap();
        let boundary = "strad-boundary";
        let payload = b"durable-stream-bytes";
        let mut body = Vec::new();
        body.extend_from_slice(b"--strad-boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"sample.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n");
        body.extend_from_slice(payload);
        body.extend_from_slice(b"\r\n--strad-boundary--\r\n");
        let request = Request::builder()
            .header(
                header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(Body::from(body))
            .unwrap();
        let mut multipart = Multipart::from_request(request, &()).await.unwrap();
        let mut field = multipart.next_field().await.unwrap().unwrap();
        let spool = service
            .spool_multipart(Uuid::new_v4(), &mut field)
            .await
            .unwrap();
        assert_eq!(spool.total_bytes, payload.len() as i64);
        assert_eq!(tokio::fs::read(&spool.path).await.unwrap(), payload);
        let metadata = tokio::fs::symlink_metadata(&spool.path).await.unwrap();
        assert!(metadata.is_file());
        assert!(!metadata.file_type().is_symlink());
        assert!(!has_multiple_links(&metadata));
        service.discard_multipart_spool(&spool).await.unwrap();
        assert!(tokio::fs::symlink_metadata(&spool.path).await.is_err());
    }
}
