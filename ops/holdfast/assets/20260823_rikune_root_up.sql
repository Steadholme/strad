\set ON_ERROR_STOP on

BEGIN;

SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '60s';
SELECT pg_advisory_xact_lock(hashtextextended('holdfast:rikune-root', 0));
LOCK TABLE routes IN SHARE ROW EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM routes
         WHERE name = 'rikune-root'
    ) THEN
        RAISE EXCEPTION 'rikune-root already exists; refusing apply';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM routes
         WHERE lower(host) = 'rikune.w33d.xyz'
           AND path_prefix = '/'
    ) THEN
        RAISE EXCEPTION 'rikune.w33d.xyz root is already owned by another route';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM routes
         WHERE lower(host) = 'analyze.w33d.xyz'
    ) THEN
        RAISE EXCEPTION 'analyze.w33d.xyz has a route but is a closed tombstone; refusing apply';
    END IF;
END
$$;

INSERT INTO routes (
    name, host, path_prefix, upstream, protected, auth, waf, require_group,
    internal_only, require_permission, permission_resource, risk, require_scope,
    step_up_resume_path
)
VALUES (
    'rikune-root', 'rikune.w33d.xyz', '/', 'http://strad:9360', TRUE, 'sso', FALSE, '',
    FALSE, 'rikune.console.enter', 'route:rikune-root', 'critical', '', ''
);

DO $$
DECLARE
    exact_count INTEGER;
BEGIN
    SELECT count(*)
      INTO exact_count
      FROM routes
     WHERE name = 'rikune-root'
       AND host = 'rikune.w33d.xyz'
       AND path_prefix = '/'
       AND upstream = 'http://strad:9360'
       AND protected = TRUE
       AND auth = 'sso'
       AND waf = FALSE
       AND require_group = ''
       AND internal_only = FALSE
       AND require_permission = 'rikune.console.enter'
       AND permission_resource = 'route:rikune-root'
       AND risk = 'critical'
       AND require_scope = ''
       AND step_up_resume_path = '';
    IF exact_count <> 1 THEN
        RAISE EXCEPTION 'rikune-root apply verification expected one exact row, got %', exact_count;
    END IF;

    IF EXISTS (
        SELECT 1
          FROM routes
         WHERE lower(host) = 'analyze.w33d.xyz'
    ) THEN
        RAISE EXCEPTION 'analyze.w33d.xyz tombstone verification failed';
    END IF;
END
$$;

COMMIT;
