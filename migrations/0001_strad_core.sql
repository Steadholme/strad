CREATE TABLE owner_quotas (
  owner_sub text PRIMARY KEY CHECK (owner_sub ~ '^user:[^[:cntrl:]]{1,240}$'),
  used_bytes bigint NOT NULL DEFAULT 0 CHECK (used_bytes >= 0),
  reserved_bytes bigint NOT NULL DEFAULT 0 CHECK (reserved_bytes >= 0),
  analysis_count integer NOT NULL DEFAULT 0 CHECK (analysis_count >= 0),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE sample_objects (
  sample_id text PRIMARY KEY CHECK (sample_id ~ '^sha256:[0-9a-f]{64}$'),
  sha256 char(64) NOT NULL UNIQUE CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  byte_size bigint NOT NULL CHECK (byte_size BETWEEN 1 AND 524288000),
  file_type text NOT NULL,
  ref_count integer NOT NULL DEFAULT 0 CHECK (ref_count >= 0),
  lifecycle text NOT NULL CHECK (lifecycle IN ('active','delete_pending','deleting','deleted','delete_failed')),
  delete_after timestamptz,
  delete_operation_id uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((lifecycle IN ('delete_pending','deleting','delete_failed')) = (delete_operation_id IS NOT NULL))
);

CREATE TABLE upload_sessions (
  id uuid PRIMARY KEY,
  operation_id uuid NOT NULL UNIQUE,
  owner_sub text NOT NULL REFERENCES owner_quotas(owner_sub),
  request_sha256 char(64) NOT NULL CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
  filename text NOT NULL CHECK (octet_length(filename) BETWEEN 1 AND 512),
  total_bytes bigint NOT NULL CHECK (total_bytes BETWEEN 1 AND 524288000),
  chunk_size integer NOT NULL DEFAULT 8388608 CHECK (chunk_size = 8388608),
  chunk_count integer NOT NULL CHECK (chunk_count BETWEEN 1 AND 63),
  received_bytes bigint NOT NULL DEFAULT 0 CHECK (received_bytes BETWEEN 0 AND total_bytes),
  reserved_bytes bigint NOT NULL CHECK (reserved_bytes = total_bytes),
  state text NOT NULL CHECK (state IN ('reserved','uploading','assembling','forwarding','upstream_uncertain','finalized','cancel_pending','cancelled','failed','expired')),
  staging_key text NOT NULL UNIQUE CHECK (staging_key ~ '^[0-9a-f-]{36}$'),
  lease_token uuid,
  leased_at timestamptz,
  lease_until timestamptz,
  attempt integer NOT NULL DEFAULT 0 CHECK (attempt >= 0),
  assembled_sha256 char(64) CHECK (assembled_sha256 IS NULL OR assembled_sha256 ~ '^[0-9a-f]{64}$'),
  sample_id text REFERENCES sample_objects(sample_id),
  analysis_id uuid NOT NULL,
  frozen_status integer,
  frozen_location text,
  frozen_body jsonb CHECK (frozen_body IS NULL OR jsonb_typeof(frozen_body)='object'),
  error_code text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  UNIQUE(id, analysis_id, owner_sub),
  UNIQUE(id, sample_id),
  CHECK ((lease_token IS NULL) = (lease_until IS NULL)),
  CHECK ((state='finalized') = (sample_id IS NOT NULL))
);

CREATE TABLE upload_chunks (
  upload_id uuid NOT NULL REFERENCES upload_sessions(id) ON DELETE CASCADE,
  chunk_index integer NOT NULL CHECK (chunk_index BETWEEN 0 AND 62),
  start_byte bigint NOT NULL CHECK (start_byte >= 0),
  end_byte bigint NOT NULL CHECK (end_byte >= start_byte),
  byte_size integer NOT NULL CHECK (byte_size BETWEEN 1 AND 8388608),
  sha256 char(64) NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  storage_key text NOT NULL UNIQUE,
  committed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(upload_id, chunk_index),
  CHECK (start_byte = chunk_index::bigint * 8388608),
  CHECK (end_byte = start_byte + byte_size - 1)
);

CREATE TABLE analyses (
  id uuid PRIMARY KEY,
  owner_sub text NOT NULL REFERENCES owner_quotas(owner_sub),
  upload_id uuid NOT NULL UNIQUE,
  sample_id text REFERENCES sample_objects(sample_id),
  display_name text NOT NULL CHECK (octet_length(display_name) BETWEEN 1 AND 512),
  state text NOT NULL CHECK (state IN ('created','uploading','uploaded','starting','start_uncertain','analyzing','promoting','analyzed','degraded','delete_pending','deleting','deleted','failed')),
  plan_id text,
  case_id text,
  case_artifact_id text,
  current_stage text,
  latest_stage text,
  retention_until timestamptz NOT NULL,
  last_polled_at timestamptz,
  poll_lease_token uuid,
  poll_lease_until timestamptz,
  next_event_seq bigint NOT NULL DEFAULT 1 CHECK (next_event_seq >= 1),
  retained_from_seq bigint NOT NULL DEFAULT 1 CHECK (retained_from_seq >= 1),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  UNIQUE(id, owner_sub),
  UNIQUE(id, sample_id),
  CHECK (retention_until <= created_at + interval '30 days 5 minutes'),
  CHECK ((poll_lease_token IS NULL) = (poll_lease_until IS NULL)),
  CHECK (retained_from_seq <= next_event_seq)
);

ALTER TABLE upload_sessions ADD CONSTRAINT upload_analysis_fk
  FOREIGN KEY (analysis_id, owner_sub) REFERENCES analyses(id, owner_sub) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE analyses ADD CONSTRAINT analysis_upload_owner_fk
  FOREIGN KEY (upload_id, id, owner_sub)
  REFERENCES upload_sessions(id, analysis_id, owner_sub) DEFERRABLE INITIALLY DEFERRED;

CREATE FUNCTION enforce_upload_analysis_sample_match() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  pair_upload_id uuid;
  pair_analysis_id uuid;
  upload_sample text;
  analysis_sample text;
  upload_state text;
BEGIN
  IF TG_TABLE_NAME = 'analyses' THEN
    pair_upload_id := NEW.upload_id;
    pair_analysis_id := NEW.id;
  ELSE
    pair_upload_id := NEW.id;
    pair_analysis_id := NEW.analysis_id;
  END IF;
  SELECT u.sample_id, u.state, a.sample_id
    INTO upload_sample, upload_state, analysis_sample
    FROM upload_sessions u
    JOIN analyses a
      ON a.id=u.analysis_id AND a.upload_id=u.id AND a.owner_sub=u.owner_sub
    WHERE u.id=pair_upload_id AND a.id=pair_analysis_id;
  IF NOT FOUND THEN
    RETURN NEW;
  END IF;
  IF upload_state='finalized' AND
     (analysis_sample IS NULL OR analysis_sample IS DISTINCT FROM upload_sample) THEN
    RAISE EXCEPTION 'finalized upload and analysis sample mismatch';
  END IF;
  IF analysis_sample IS NOT NULL AND
     (upload_state IS DISTINCT FROM 'finalized' OR upload_sample IS DISTINCT FROM analysis_sample) THEN
    RAISE EXCEPTION 'analysis sample requires matching finalized upload';
  END IF;
  RETURN NEW;
END $$;

CREATE CONSTRAINT TRIGGER upload_sample_match
  AFTER INSERT OR UPDATE OF sample_id,state,analysis_id,owner_sub ON upload_sessions
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
  EXECUTE FUNCTION enforce_upload_analysis_sample_match();
CREATE CONSTRAINT TRIGGER analysis_sample_match
  AFTER INSERT OR UPDATE OF sample_id,upload_id,owner_sub ON analyses
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
  EXECUTE FUNCTION enforce_upload_analysis_sample_match();

CREATE TABLE artifacts (
  id uuid PRIMARY KEY,
  analysis_id uuid NOT NULL,
  owner_sub text NOT NULL,
  upstream_artifact_id text NOT NULL,
  artifact_type text NOT NULL,
  artifact_ref text NOT NULL CHECK (artifact_ref ~ '^ref:[a-z0-9_-]{1,240}$'),
  path text NOT NULL CHECK (octet_length(path) BETWEEN 1 AND 2048),
  sha256 char(64) NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  mime text,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(metadata)='object'),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(id, analysis_id, owner_sub),
  UNIQUE(id, analysis_id, owner_sub, artifact_ref),
  UNIQUE(analysis_id, upstream_artifact_id),
  UNIQUE(analysis_id, artifact_ref),
  FOREIGN KEY (analysis_id, owner_sub) REFERENCES analyses(id, owner_sub) ON DELETE CASCADE
);

CREATE TABLE conversations (
  id uuid PRIMARY KEY,
  analysis_id uuid NOT NULL,
  owner_sub text NOT NULL,
  title text NOT NULL CHECK (octet_length(title) BETWEEN 1 AND 240),
  persona_id text NOT NULL CHECK (persona_id ~ '^[a-z0-9_-]{1,64}$'),
  custom_persona text CHECK (custom_persona IS NULL OR octet_length(custom_persona) <= 8000),
  next_seq bigint NOT NULL DEFAULT 1 CHECK (next_seq >= 1),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(id, analysis_id, owner_sub),
  FOREIGN KEY (analysis_id, owner_sub) REFERENCES analyses(id, owner_sub) ON DELETE CASCADE
);

CREATE TABLE turns (
  id uuid PRIMARY KEY,
  conversation_id uuid NOT NULL,
  analysis_id uuid NOT NULL,
  owner_sub text NOT NULL,
  client_seq bigint NOT NULL CHECK (client_seq >= 1),
  operation_id uuid NOT NULL UNIQUE,
  request_sha256 char(64) NOT NULL CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
  state text NOT NULL CHECK (state IN ('accepted','grounding','generating','completed','partial','failed','cancelled')),
  context_marker text,
  context_sha256 char(64) CHECK (context_sha256 IS NULL OR context_sha256 ~ '^[0-9a-f]{64}$'),
  context_pack jsonb CHECK (context_pack IS NULL OR jsonb_typeof(context_pack)='object'),
  frozen_request jsonb CHECK (frozen_request IS NULL OR jsonb_typeof(frozen_request)='object'),
  frozen_prompt_sha256 char(64) CHECK (frozen_prompt_sha256 IS NULL OR frozen_prompt_sha256 ~ '^[0-9a-f]{64}$'),
  generation_lease_token uuid,
  generation_leased_at timestamptz,
  generation_lease_until timestamptz,
  provider_attempt integer NOT NULL DEFAULT 0 CHECK (provider_attempt >= 0),
  provider_started_at timestamptz,
  terminal_at timestamptz,
  error_code text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(conversation_id, client_seq),
  UNIQUE(id, analysis_id, owner_sub),
  UNIQUE(id, conversation_id, analysis_id, owner_sub),
  FOREIGN KEY (conversation_id, analysis_id, owner_sub)
    REFERENCES conversations(id, analysis_id, owner_sub) ON DELETE CASCADE,
  CHECK ((generation_lease_token IS NULL) = (generation_lease_until IS NULL))
);

CREATE TABLE messages (
  id uuid PRIMARY KEY,
  turn_id uuid NOT NULL,
  conversation_id uuid NOT NULL,
  analysis_id uuid NOT NULL,
  owner_sub text NOT NULL,
  seq bigint NOT NULL CHECK (seq >= 1),
  role text NOT NULL CHECK (role IN ('user','assistant')),
  client_seq bigint,
  status text NOT NULL CHECK (status IN ('committed','streaming','complete','partial','failed')),
  content text NOT NULL CHECK (octet_length(content) <= 262144),
  token_count integer NOT NULL DEFAULT 0 CHECK (token_count >= 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(id, analysis_id, owner_sub),
  UNIQUE(conversation_id, seq),
  UNIQUE(turn_id, role),
  FOREIGN KEY (turn_id, conversation_id, analysis_id, owner_sub)
    REFERENCES turns(id, conversation_id, analysis_id, owner_sub) ON DELETE CASCADE,
  CHECK ((role='user' AND client_seq IS NOT NULL AND status='committed') OR
         (role='assistant' AND client_seq IS NULL))
);

CREATE TABLE citations (
  id uuid PRIMARY KEY,
  message_id uuid NOT NULL,
  artifact_id uuid,
  analysis_id uuid NOT NULL,
  owner_sub text NOT NULL,
  citation_ref text NOT NULL CHECK (citation_ref ~ '^ref:[a-z0-9_-]{1,240}$'),
  resolved boolean NOT NULL,
  excerpt text CHECK (excerpt IS NULL OR octet_length(excerpt) <= 8192),
  excerpt_start bigint CHECK (excerpt_start IS NULL OR excerpt_start >= 0),
  excerpt_end bigint CHECK (excerpt_end IS NULL OR excerpt_end >= excerpt_start),
  excerpt_sha256 char(64) CHECK (excerpt_sha256 IS NULL OR excerpt_sha256 ~ '^[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(message_id, citation_ref),
  FOREIGN KEY (message_id, analysis_id, owner_sub)
    REFERENCES messages(id, analysis_id, owner_sub) ON DELETE CASCADE,
  FOREIGN KEY (artifact_id, analysis_id, owner_sub, citation_ref)
    REFERENCES artifacts(id, analysis_id, owner_sub, artifact_ref) ON DELETE RESTRICT,
  CHECK (resolved = (artifact_id IS NOT NULL)),
  CHECK ((excerpt IS NULL AND excerpt_start IS NULL AND excerpt_end IS NULL AND excerpt_sha256 IS NULL) OR
         (resolved AND excerpt IS NOT NULL AND excerpt_start IS NOT NULL AND excerpt_end IS NOT NULL AND excerpt_sha256 IS NOT NULL))
);

CREATE TABLE idempotency_operations (
  owner_sub text NOT NULL,
  scope text NOT NULL,
  operation_id uuid NOT NULL,
  request_sha256 char(64) NOT NULL CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
  state text NOT NULL CHECK (state IN ('leased','downstream_uncertain','completed','failed')),
  lease_token uuid,
  leased_at timestamptz,
  lease_until timestamptz,
  attempt integer NOT NULL DEFAULT 0 CHECK (attempt >= 0),
  resource_location text,
  response_status integer CHECK (response_status BETWEEN 100 AND 599),
  response_body jsonb CHECK (response_body IS NULL OR jsonb_typeof(response_body)='object'),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  PRIMARY KEY(owner_sub, scope, operation_id),
  CHECK ((lease_token IS NULL) = (lease_until IS NULL)),
  CHECK ((state='completed') = (response_status IS NOT NULL))
);

CREATE TABLE outbox (
  id uuid PRIMARY KEY,
  aggregate_type text NOT NULL,
  aggregate_id uuid NOT NULL,
  owner_sub text NOT NULL,
  event_type text NOT NULL,
  payload jsonb NOT NULL CHECK (jsonb_typeof(payload)='object'),
  state text NOT NULL CHECK (state IN ('pending','leased','delivered','dead')),
  lease_token uuid,
  leased_at timestamptz,
  lease_until timestamptz,
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  last_error_code text,
  created_at timestamptz NOT NULL DEFAULT now(),
  delivered_at timestamptz,
  dead_at timestamptz,
  CHECK ((lease_token IS NULL) = (lease_until IS NULL))
);

CREATE TABLE analysis_events (
  id bigserial PRIMARY KEY,
  analysis_id uuid NOT NULL,
  owner_sub text NOT NULL,
  seq bigint NOT NULL CHECK (seq >= 1),
  source_outbox_id uuid UNIQUE REFERENCES outbox(id) ON DELETE SET NULL,
  event_type text NOT NULL,
  payload jsonb NOT NULL CHECK (jsonb_typeof(payload)='object'),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  UNIQUE(analysis_id, seq),
  FOREIGN KEY (analysis_id, owner_sub) REFERENCES analyses(id, owner_sub) ON DELETE CASCADE
);

CREATE TABLE event_deliveries (
  outbox_id uuid NOT NULL REFERENCES outbox(id) ON DELETE CASCADE,
  sink text NOT NULL,
  delivery_key text NOT NULL,
  delivered_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(outbox_id, sink),
  UNIQUE(sink, delivery_key)
);

CREATE TABLE notification_claims (
  owner_sub text NOT NULL,
  kind text NOT NULL,
  window_start timestamptz NOT NULL,
  claimed_at timestamptz NOT NULL DEFAULT now(),
  outcome text NOT NULL DEFAULT 'claimed' CHECK (outcome IN ('claimed','sent','failed')),
  PRIMARY KEY(owner_sub, kind, window_start)
);

CREATE TABLE cleanup_jobs (
  id uuid PRIMARY KEY,
  owner_sub text NOT NULL,
  analysis_id uuid NOT NULL,
  upload_id uuid NOT NULL,
  manifest jsonb NOT NULL CHECK (jsonb_typeof(manifest)='object'),
  manifest_sha256 char(64) NOT NULL CHECK (manifest_sha256 ~ '^[0-9a-f]{64}$'),
  state text NOT NULL CHECK (state IN ('pending','leased','completed','dead')),
  lease_token uuid,
  leased_at timestamptz,
  lease_until timestamptz,
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  last_error_code text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  expires_at timestamptz NOT NULL,
  CHECK ((lease_token IS NULL) = (lease_until IS NULL))
);

CREATE TABLE ai_usage (
  id bigserial PRIMARY KEY,
  owner_sub text NOT NULL,
  analysis_id uuid NOT NULL,
  turn_id uuid NOT NULL,
  prompt_tokens integer NOT NULL CHECK (prompt_tokens >= 0),
  completion_tokens integer NOT NULL CHECK (completion_tokens >= 0),
  model_alias text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(turn_id),
  FOREIGN KEY (turn_id, analysis_id, owner_sub)
    REFERENCES turns(id, analysis_id, owner_sub) ON DELETE CASCADE
);

CREATE INDEX upload_recovery_idx ON upload_sessions(state, lease_until, updated_at);
CREATE INDEX analysis_poll_idx ON analyses(state, poll_lease_until, last_polled_at);
CREATE INDEX analysis_retention_idx ON analyses(retention_until) WHERE deleted_at IS NULL;
CREATE INDEX sample_delete_idx ON sample_objects(delete_after, lifecycle) WHERE ref_count=0;
CREATE INDEX outbox_claim_idx ON outbox(state, next_attempt_at, lease_until);
CREATE INDEX events_resume_idx ON analysis_events(analysis_id, seq);
CREATE INDEX events_expiry_idx ON analysis_events(expires_at);
CREATE INDEX idempotency_recovery_idx ON idempotency_operations(state, lease_until, expires_at);
CREATE INDEX messages_turn_idx ON messages(conversation_id, seq);
CREATE INDEX cleanup_claim_idx ON cleanup_jobs(state, lease_until, created_at);
