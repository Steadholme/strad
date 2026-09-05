CREATE TABLE IF NOT EXISTS analyze_facade_context_replays (
  issuer TEXT NOT NULL,
  jti TEXT NOT NULL,
  expires_at BIGINT NOT NULL CHECK (expires_at > 0),
  consumed_at BIGINT NOT NULL CHECK (consumed_at > 0),
  PRIMARY KEY (issuer, jti)
);

CREATE INDEX IF NOT EXISTS analyze_facade_context_replays_expiry_idx
  ON analyze_facade_context_replays (expires_at);

CREATE TABLE IF NOT EXISTS analyze_facade_sessions (
  session_id TEXT PRIMARY KEY,
  mcp_session_digest TEXT NOT NULL UNIQUE CHECK (
    length(mcp_session_digest) = 64 AND mcp_session_digest !~ '[^0-9a-f]'
  ),
  application_sub TEXT NOT NULL,
  client_id TEXT NOT NULL,
  credential_id TEXT NOT NULL,
  credential_version BIGINT NOT NULL CHECK (credential_version > 0),
  grant_id TEXT NOT NULL,
  package_id TEXT NOT NULL CHECK (package_id = 'pkg_analyze_mcp_client'),
  package_revision_digest TEXT NOT NULL CHECK (
    length(package_revision_digest) = 64 AND package_revision_digest !~ '[^0-9a-f]'
  ),
  scopes JSONB NOT NULL CHECK (jsonb_typeof(scopes) = 'array'),
  policy_epoch BIGINT NOT NULL CHECK (policy_epoch > 0),
  revocation_epoch BIGINT NOT NULL CHECK (revocation_epoch > 0),
  credential_state TEXT NOT NULL CHECK (credential_state IN ('active', 'overlap')),
  overlap_until BIGINT,
  state TEXT NOT NULL CHECK (state IN ('active', 'terminated')),
  created_at BIGINT NOT NULL CHECK (created_at > 0),
  last_seen_at BIGINT NOT NULL CHECK (last_seen_at >= created_at),
  idle_expires_at BIGINT NOT NULL CHECK (idle_expires_at > last_seen_at),
  absolute_expires_at BIGINT NOT NULL CHECK (absolute_expires_at > created_at),
  terminated_at BIGINT,
  termination_reason TEXT,
  CHECK (
    (credential_state = 'active' AND overlap_until IS NULL) OR
    (credential_state = 'overlap' AND overlap_until IS NOT NULL)
  ),
  CHECK (
    (state = 'active' AND terminated_at IS NULL AND termination_reason IS NULL) OR
    (state = 'terminated' AND terminated_at IS NOT NULL AND termination_reason IS NOT NULL)
  )
);

CREATE INDEX IF NOT EXISTS analyze_facade_sessions_application_idx
  ON analyze_facade_sessions (application_sub, state, revocation_epoch);
CREATE INDEX IF NOT EXISTS analyze_facade_sessions_grant_idx
  ON analyze_facade_sessions (application_sub, grant_id, state);
CREATE INDEX IF NOT EXISTS analyze_facade_sessions_credential_idx
  ON analyze_facade_sessions (application_sub, credential_id, credential_version, state);
CREATE INDEX IF NOT EXISTS analyze_facade_sessions_expiry_idx
  ON analyze_facade_sessions (state, idle_expires_at, absolute_expires_at);

CREATE TABLE IF NOT EXISTS analyze_facade_application_revocation_epochs (
  application_sub TEXT PRIMARY KEY,
  revocation_epoch BIGINT NOT NULL CHECK (revocation_epoch > 0),
  updated_at BIGINT NOT NULL CHECK (updated_at > 0)
);

CREATE TABLE IF NOT EXISTS analyze_facade_revocation_events (
  event_id TEXT PRIMARY KEY,
  application_sub TEXT NOT NULL,
  grant_id TEXT NOT NULL,
  credential_id TEXT,
  credential_version BIGINT,
  policy_epoch BIGINT NOT NULL CHECK (policy_epoch > 0),
  revocation_epoch BIGINT NOT NULL CHECK (revocation_epoch > 0),
  reason TEXT NOT NULL,
  effective_at BIGINT NOT NULL CHECK (effective_at > 0),
  issued_at BIGINT NOT NULL CHECK (issued_at > 0),
  payload_sha256 TEXT NOT NULL CHECK (
    length(payload_sha256) = 64 AND payload_sha256 !~ '[^0-9a-f]'
  ),
  consumed_at BIGINT NOT NULL CHECK (consumed_at > 0),
  terminated_sessions BIGINT NOT NULL CHECK (terminated_sessions >= 0),
  stale BOOLEAN NOT NULL DEFAULT FALSE,
  session_ids JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(session_ids) = 'array')
);

ALTER TABLE analyze_facade_revocation_events
  ADD COLUMN IF NOT EXISTS stale BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE analyze_facade_revocation_events
  ADD COLUMN IF NOT EXISTS session_ids JSONB NOT NULL DEFAULT '[]'::jsonb
  CHECK (jsonb_typeof(session_ids) = 'array');
