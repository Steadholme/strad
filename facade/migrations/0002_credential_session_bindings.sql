CREATE TABLE IF NOT EXISTS analyze_facade_credential_session_bindings (
  application_sub TEXT NOT NULL,
  credential_id TEXT NOT NULL,
  credential_version BIGINT NOT NULL CHECK (credential_version > 0),
  mcp_session_digest TEXT NOT NULL CHECK (
    length(mcp_session_digest) = 64 AND mcp_session_digest !~ '[^0-9a-f]'
  ),
  updated_at BIGINT NOT NULL CHECK (updated_at > 0),
  PRIMARY KEY (application_sub, credential_id)
);

-- 终止记录同样参与回填，重启和升级不能恢复已失效的旧版本。
INSERT INTO analyze_facade_credential_session_bindings
  (application_sub, credential_id, credential_version, mcp_session_digest, updated_at)
SELECT DISTINCT ON (application_sub, credential_id)
  application_sub, credential_id, credential_version, mcp_session_digest, last_seen_at
FROM analyze_facade_sessions
ORDER BY application_sub, credential_id, credential_version DESC, last_seen_at DESC, session_id
ON CONFLICT (application_sub, credential_id) DO NOTHING;
