\set ON_ERROR_STOP on
SELECT CASE
         WHEN count(*) = 1
          AND bool_and(
              host = 'analyze.w33d.xyz'
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
              AND step_up_resume_path = ''
          )
         THEN 'ok'
         ELSE 'invalid'
       END
  FROM routes
 WHERE name = 'rikune-root';
