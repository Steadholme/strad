\set ON_ERROR_STOP on
SELECT CASE WHEN count(*) = 0 THEN 'ok' ELSE 'invalid' END
  FROM routes
 WHERE name = 'rikune-root' OR (host = 'rikune.w33d.xyz' AND path_prefix = '/');
