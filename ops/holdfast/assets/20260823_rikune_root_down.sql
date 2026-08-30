\set ON_ERROR_STOP on

BEGIN;

SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '60s';
SELECT pg_advisory_xact_lock(hashtextextended('holdfast:rikune-root', 0));
LOCK TABLE routes IN SHARE ROW EXCLUSIVE MODE;

CREATE TEMP TABLE holdfast_rikune_root_rollback_preimage ON COMMIT DROP AS
SELECT to_jsonb(route) AS route
  FROM routes AS route
 WHERE route.name = 'rikune-root'
    OR (lower(route.host) = 'rikune.w33d.xyz' AND route.path_prefix = '/')
    OR lower(route.host) = 'analyze.w33d.xyz';

COPY (
    SELECT jsonb_build_object(
               'schema_version', 1,
               'event', 'rikune-root-rollback-predelete-summary',
               'row_count', count(*)
           )::TEXT
      FROM holdfast_rikune_root_rollback_preimage
) TO STDOUT;

COPY (
    SELECT jsonb_build_object(
               'schema_version', 1,
               'event', 'rikune-root-rollback-predelete-row',
               'route', route
           )::TEXT
      FROM holdfast_rikune_root_rollback_preimage
     ORDER BY route->>'name', route->>'host', route->>'path_prefix', route::TEXT
) TO STDOUT;

DELETE FROM routes
 WHERE name = 'rikune-root'
    OR (lower(host) = 'rikune.w33d.xyz' AND path_prefix = '/')
    OR lower(host) = 'analyze.w33d.xyz';

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM routes
         WHERE name = 'rikune-root'
            OR (lower(host) = 'rikune.w33d.xyz' AND path_prefix = '/')
            OR lower(host) = 'analyze.w33d.xyz'
    ) THEN
        RAISE EXCEPTION 'rikune-root rollback verification failed';
    END IF;
END
$$;

COMMIT;
