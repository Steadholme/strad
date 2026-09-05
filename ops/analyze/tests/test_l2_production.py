import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import production_routes as routes


class ProductionWiringTests(unittest.TestCase):
    def test_routes_separate_internal_dependencies_from_public_application_auth(self):
        rows = routes.load_routes()
        self.assertEqual(len([r for r in rows if r['internal_only']]), 6)
        public = {r['name']: r for r in rows if not r['internal_only']}
        self.assertEqual(set(public), {'analyze-access', 'analyze-mcp', 'analyze-uploads'})
        self.assertEqual(public['analyze-access']['auth'], 'sso')
        self.assertEqual(public['analyze-access']['step_up_resume_path'], '/applications/')
        for name in ['analyze-mcp', 'analyze-uploads']:
            self.assertEqual(public[name]['auth'], 'application')
            self.assertTrue(public[name]['protected'])

    def test_route_sql_refuses_drift_and_orders_open_close_without_overwrite(self):
        for phase in ['internal', 'public']:
            for direction in ['up', 'down']:
                sql = routes.render(phase, direction)
                self.assertIn('LOCK TABLE routes IN SHARE ROW EXCLUSIVE MODE', sql)
                self.assertIn('Analyze route drift', sql)
                self.assertIn('Unexpected Analyze host route', sql)
                self.assertNotIn('UPDATE routes', sql)
                self.assertNotIn('TRUNCATE', sql)
        self.assertIn('Internal Analyze routes must be installed first', routes.render('public', 'up'))
        self.assertIn('Close public Analyze routes before', routes.render('internal', 'down'))

    def test_compose_merge_preserves_existing_networks_and_adds_no_public_port(self):
        source = (ROOT / 'compose.production.yml').read_text()
        variables = set(re.findall(r'\$\{([A-Z0-9_]+)', source))
        env = {**os.environ, **{name: name.lower() + '-' + 'x' * 32 for name in variables}}
        for name in variables:
            if name.endswith('_IMAGE'):
                env[name] = 'example.invalid/analyze@sha256:' + 'a' * 64
        env['ANALYZE_FACADE_DATABASE_URL'] = 'postgresql://facade:unit-only@postgres:5432/analyze_facade'
        services = {name: {'image': 'example.invalid/base:unit', 'networks': ['hf-mgmt']}
                    for name in ['sluice', 'sluice-internal', 'access-governance', 'verdict', 'strad', 'rikune-analyzer', 'postgres']}
        services['strad']['networks'] = ['legacy']
        services['postgres']['healthcheck'] = {'test': ['CMD', 'true']}
        base = {'services': services, 'networks': {'hf-mgmt': {'internal': True}, 'legacy': {'internal': True}}}
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'base.json'
            path.write_text(json.dumps(base))
            result = subprocess.run(['docker', 'compose', '-p', 'analyze-render-unit', '-f', str(path),
                '-f', str(ROOT / 'compose.production.yml'), 'config', '--format', 'json'],
                env=env, text=True, capture_output=True, check=True)
        merged = json.loads(result.stdout)
        self.assertEqual(set(merged['services']['strad']['networks']), {'legacy', 'hf-mgmt'})
        self.assertFalse(any(service.get('ports') for service in merged['services'].values()))
        facade = merged['services']['analyze-facade']
        self.assertTrue(facade['read_only'])
        self.assertEqual(set(facade['networks']), {'hf-mgmt'})
        self.assertEqual(facade['environment']['ANALYZE_FACADE_INTERNAL_HOST'], 'sso.w33d.xyz')
        self.assertNotIn('SLUICE_APPLICATION_CONTEXT_SIGNING_KEYRING', facade['environment'])
        for name in ['sluice', 'sluice-internal']:
            self.assertEqual(merged['services'][name]['environment']['TRUSTED_MFA'], 'on')
        access = merged['services']['access-governance']['environment']
        self.assertEqual(access['PUBLIC_HOST'], 'access.w33d.xyz')
        self.assertEqual(access['GATEWAY_ROUTE_NAME'], 'access-root')
        self.assertEqual(access['ACCESS_ANALYZE_EXTERNAL_ORIGIN'], 'https://analyze.w33d.xyz')


if __name__ == '__main__':
    unittest.main()
