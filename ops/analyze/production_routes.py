#!/usr/bin/env python3
"""Render transactional Analyze route SQL; never connects to a database."""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
COLUMNS = ('name', 'host', 'path_prefix', 'upstream', 'protected', 'auth', 'waf',
           'require_group', 'internal_only', 'require_permission',
           'permission_resource', 'risk', 'require_scope', 'step_up_resume_path')


def load_routes():
    document = json.loads((ROOT / 'production-routes.json').read_text())
    if document['schema_version'] != 1:
        raise ValueError('unsupported production route schema')
    rows = []
    for source in document['routes']:
        row = {'protected': source['auth'] != 'public', 'waf': False,
               'require_group': '', 'require_permission': '', 'permission_resource': '',
               'risk': '', 'require_scope': '', 'step_up_resume_path': '', **source}
        if set(row) != set(COLUMNS) | {'phase'}:
            raise ValueError('unexpected production route fields')
        internal = row['phase'] == 'internal'
        if row['phase'] not in {'internal', 'public'} or row['internal_only'] != internal:
            raise ValueError('route phase and exposure differ')
        if row['host'] != ('sso.w33d.xyz' if internal else 'analyze.w33d.xyz'):
            raise ValueError('route host escaped the Analyze scope')
        if internal and (row['auth'] != 'public' or not row['name'].startswith('analyze-internal-')):
            raise ValueError('private routes retain backend service authentication')
        if not internal and row['auth'] != ('sso' if row['name'] == 'analyze-access' else 'application'):
            raise ValueError('public route authentication changed')
        rows.append(row)
    if len(rows) != 9 or len({row['name'] for row in rows}) != len(rows):
        raise ValueError('production route set differs')
    return rows


def render(phase, direction):
    if phase not in {'internal', 'public'} or direction not in {'up', 'down'}:
        raise ValueError('invalid route operation')
    rows = load_routes()
    payload = json.dumps(rows, separators=(',', ':')).replace("'", "''")
    columns = ','.join(COLUMNS)
    record = ','.join(f'{name} {"boolean" if name in {"protected", "waf", "internal_only"} else "text"}'
                      for name in ('phase', *COLUMNS))
    matches = ' AND '.join(f'r.{name} IS NOT DISTINCT FROM e.{name}' for name in COLUMNS)
    # The transaction owns only these exact rows. Existing unrelated estate
    # routes are neither updated nor deleted. Drift is not silently overwritten.
    sql = f"""\\set ON_ERROR_STOP on
BEGIN;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '60s';
SELECT pg_advisory_xact_lock(hashtextextended('analyze:public-rollout:v1',0));
LOCK TABLE routes IN SHARE ROW EXCLUSIVE MODE;
CREATE TEMP TABLE analyze_expected ON COMMIT DROP AS
 SELECT * FROM jsonb_to_recordset('{payload}'::jsonb) AS x({record});
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM routes r JOIN analyze_expected e ON r.name=e.name
            WHERE NOT ({matches})) THEN
   RAISE EXCEPTION 'Analyze route drift; refusing overwrite or deletion';
 END IF;
 IF EXISTS (SELECT 1 FROM routes r JOIN analyze_expected e
            ON lower(r.host)=e.host AND starts_with(r.path_prefix,e.path_prefix)
            WHERE NOT EXISTS (SELECT 1 FROM analyze_expected owned WHERE owned.name=r.name)) THEN
   RAISE EXCEPTION 'Analyze route path already owned by another route';
 END IF;
 IF EXISTS (SELECT 1 FROM routes r WHERE lower(r.host)='analyze.w33d.xyz'
            AND NOT EXISTS (SELECT 1 FROM analyze_expected e WHERE e.name=r.name)) THEN
   RAISE EXCEPTION 'Unexpected Analyze host route; refusing rollout';
 END IF;
"""
    if phase == 'public' and direction == 'up':
        sql += """ IF EXISTS (SELECT 1 FROM analyze_expected e WHERE e.phase='internal'
            AND NOT EXISTS (SELECT 1 FROM routes r WHERE r.name=e.name)) THEN
   RAISE EXCEPTION 'Internal Analyze routes must be installed first';
 END IF;
"""
    if phase == 'internal' and direction == 'down':
        sql += """ IF EXISTS (SELECT 1 FROM routes r JOIN analyze_expected e ON r.name=e.name
            WHERE e.phase='public') THEN
   RAISE EXCEPTION 'Close public Analyze routes before removing internal dependencies';
 END IF;
"""
    sql += 'END $$;\n'
    if direction == 'up':
        sql += (f"INSERT INTO routes ({columns}) SELECT {columns} FROM analyze_expected e "
                f"WHERE e.phase='{phase}' AND NOT EXISTS (SELECT 1 FROM routes r WHERE r.name=e.name);\n")
    else:
        sql += f"DELETE FROM routes r USING analyze_expected e WHERE e.phase='{phase}' AND r.name=e.name;\n"
    sql += "SELECT 'analyze-route-operation-complete' AS result;\nCOMMIT;\n"
    return sql


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase', choices=['internal', 'public'], required=True)
    parser.add_argument('--direction', choices=['up', 'down'], required=True)
    args = parser.parse_args()
    print(render(args.phase, args.direction), end='')


if __name__ == '__main__':
    main()
