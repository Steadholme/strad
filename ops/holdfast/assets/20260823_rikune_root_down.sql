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
           AND (host, path_prefix, upstream, protected, auth, waf, require_group,
                internal_only, require_permission, permission_resource, risk, require_scope)
               IS DISTINCT FROM
               ('rikune.w33d.xyz', '/', 'http://strad:9360', TRUE, 'sso', FALSE, '',
                FALSE, 'rikune.console.enter', 'route:rikune-root', 'critical', '')
    ) THEN
        RAISE EXCEPTION 'rikune-root authority drifted; refusing rollback';
    END IF;
END
$$;

DELETE FROM routes
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
   AND require_scope = '';

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM routes WHERE name = 'rikune-root') THEN
        RAISE EXCEPTION 'rikune-root rollback verification failed';
    END IF;
END
$$;

COMMIT;
