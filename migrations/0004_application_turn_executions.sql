CREATE TABLE application_turn_executions (
  turn_id uuid PRIMARY KEY REFERENCES turns(id) ON DELETE CASCADE,
  application_operation_id bigint NOT NULL UNIQUE REFERENCES application_operations(id) ON DELETE CASCADE,
  execution jsonb NOT NULL CHECK (jsonb_typeof(execution) = 'object'),
  provider_state text NOT NULL DEFAULT 'pending'
    CHECK (provider_state IN ('pending','dispatched','completed','uncertain')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
