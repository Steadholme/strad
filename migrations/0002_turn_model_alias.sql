ALTER TABLE turns ADD COLUMN model_alias text;

UPDATE turns AS turn_row
SET model_alias = COALESCE(
  CASE
    WHEN turn_row.frozen_request->>'model' ~ '^[A-Za-z0-9._:/-]{1,128}$'
      THEN turn_row.frozen_request->>'model'
  END,
  (
    SELECT usage.model_alias
    FROM ai_usage AS usage
    WHERE usage.turn_id = turn_row.id
      AND usage.model_alias ~ '^[A-Za-z0-9._:/-]{1,128}$'
  ),
  -- Schema v1 did not persist the model before grounding. Preserve the exact
  -- default pinned by the final v1 release for those still-unfrozen turns.
  'openai/gpt-5.6-luna'
);

ALTER TABLE turns
  ALTER COLUMN model_alias SET NOT NULL,
  ADD CONSTRAINT turns_model_alias_valid
    CHECK (model_alias ~ '^[A-Za-z0-9._:/-]{1,128}$');
