ALTER TABLE owner_quotas DROP CONSTRAINT owner_quotas_owner_sub_check;
ALTER TABLE owner_quotas ADD CONSTRAINT owner_quotas_owner_sub_check CHECK (
  owner_sub ~ '^user:[^[:cntrl:]]{1,240}$'
  OR owner_sub ~ '^application:[A-Za-z0-9_-]{1,220}$'
);

CREATE TABLE application_operations (
  id bigserial PRIMARY KEY,
  application_sub text NOT NULL CHECK (application_sub ~ '^application:[A-Za-z0-9_-]{1,220}$'),
  canonical_tool text NOT NULL CHECK (canonical_tool IN (
    'analysis.create','analysis.read','analysis.conversation','analysis.upload.cancel'
  )),
  operation_id uuid NOT NULL,
  request_sha256 char(64) NOT NULL CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
  correlation_id uuid NOT NULL,
  state text NOT NULL CHECK (state IN ('leased','downstream_uncertain','completed','failed')),
  lease_token uuid,
  leased_at timestamptz,
  lease_until timestamptz,
  attempt integer NOT NULL DEFAULT 0 CHECK (attempt >= 0),
  dispatch_count integer NOT NULL DEFAULT 0 CHECK (dispatch_count BETWEEN 0 AND 1),
  reservation_active boolean NOT NULL DEFAULT true,
  rate_limit integer NOT NULL CHECK (rate_limit > 0),
  rate_remaining integer NOT NULL CHECK (rate_remaining >= 0),
  rate_reset bigint NOT NULL CHECK (rate_reset >= 0),
  response_status integer CHECK (response_status BETWEEN 100 AND 599),
  response_body jsonb CHECK (response_body IS NULL OR jsonb_typeof(response_body)='object'),
  error_code text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL DEFAULT now()+interval '180 days',
  UNIQUE(application_sub, canonical_tool, operation_id),
  CHECK ((lease_token IS NULL) = (lease_until IS NULL)),
  CHECK ((state='completed') = (response_status IS NOT NULL)),
  CHECK (reservation_active OR state IN ('completed','failed'))
);

CREATE TABLE application_quota_windows (
  application_sub text NOT NULL CHECK (application_sub ~ '^application:[A-Za-z0-9_-]{1,220}$'),
  canonical_tool text NOT NULL CHECK (canonical_tool IN (
    'analysis.create','analysis.read','analysis.conversation','analysis.upload.cancel'
  )),
  window_start timestamptz NOT NULL,
  window_seconds integer NOT NULL CHECK (window_seconds > 0),
  request_limit integer NOT NULL CHECK (request_limit > 0),
  request_count integer NOT NULL DEFAULT 0 CHECK (request_count BETWEEN 0 AND request_limit),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(application_sub,canonical_tool,window_start)
);

CREATE TABLE application_upload_bindings (
  upload_id uuid PRIMARY KEY REFERENCES upload_sessions(id) ON DELETE CASCADE,
  application_sub text NOT NULL CHECK (application_sub ~ '^application:[A-Za-z0-9_-]{1,220}$'),
  finalize_operation_id uuid NOT NULL UNIQUE,
  cancel_operation_id uuid NOT NULL UNIQUE,
  reservation_state text NOT NULL CHECK (reservation_state IN ('reserved','committed','released')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(upload_id,application_sub)
);

CREATE VIEW application_upload_chunks AS
SELECT b.application_sub,c.upload_id,c.chunk_index,c.start_byte,c.end_byte,c.byte_size,c.sha256,c.committed_at
FROM application_upload_bindings b JOIN upload_chunks c ON c.upload_id=b.upload_id;

CREATE TABLE application_audit_events (
  id uuid PRIMARY KEY,
  application_sub text NOT NULL CHECK (application_sub ~ '^application:[A-Za-z0-9_-]{1,220}$'),
  authorization_event_id uuid NOT NULL,
  event_kind text NOT NULL CHECK (event_kind IN ('authorization','operation','reconciliation','support_read')),
  outcome text NOT NULL CHECK (outcome IN (
    'allow','insufficient_scope','deny','indeterminate','stale_decision','expired_decision',
    'decision_digest_mismatch','authorization_unavailable','completed','failed','downstream_uncertain','support_read'
  )),
  canonical_tool text CHECK (canonical_tool IS NULL OR canonical_tool IN (
    'analysis.create','analysis.read','analysis.conversation','analysis.upload.cancel'
  )),
  operation_id uuid,
  decision_digest char(64) CHECK (decision_digest IS NULL OR decision_digest ~ '^[0-9a-f]{64}$'),
  correlation_id uuid NOT NULL,
  details jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(details)='object'),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL DEFAULT now()+interval '180 days',
  UNIQUE(application_sub,authorization_event_id)
);

CREATE TABLE application_audit_outbox (
  id uuid PRIMARY KEY,
  audit_event_id uuid NOT NULL UNIQUE REFERENCES application_audit_events(id) ON DELETE CASCADE,
  application_sub text NOT NULL,
  event_type text NOT NULL,
  payload jsonb NOT NULL CHECK (jsonb_typeof(payload)='object'),
  state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','leased','delivered','dead')),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX application_operations_recovery_idx
  ON application_operations(state,lease_until,expires_at);
CREATE INDEX application_operations_owner_idx
  ON application_operations(application_sub,created_at DESC);
CREATE INDEX application_quota_expiry_idx
  ON application_quota_windows(window_start,window_seconds);
CREATE INDEX application_audit_owner_idx
  ON application_audit_events(application_sub,created_at DESC);
CREATE INDEX application_audit_expiry_idx
  ON application_audit_events(expires_at);
