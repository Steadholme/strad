import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest

OPS = Path(__file__).resolve().parents[1]
ROOT = OPS.parents[1]
sys.path.insert(0, str(OPS))
import verify_release_ci as ci

REVISION = 'a' * 40


class ReleaseWiringTests(unittest.TestCase):
    def successful_checks(self):
        return {'check_runs': [{'name': name, 'head_sha': REVISION,
            'app': {'slug': 'github-actions'}, 'status': 'completed', 'conclusion': 'success'}
            for name in ci.required_checks()]}

    def test_current_ci_matrix_covers_every_required_release_contract(self):
        workflow = (ROOT / '.github/workflows/ci.yml').read_text()
        matrix = workflow.split('      matrix:\n', 1)[1].split('    services:\n', 1)[0]
        cases = re.findall(r'^          - ([a-z0-9_]+)$', matrix, re.M)
        cases += re.findall(r'^          - test: ([a-z0-9_]+)$', matrix, re.M)
        actual = {*ci.BASE_CHECKS, *('PostgreSQL / ' + name for name in cases)}
        self.assertEqual(actual, set(ci.required_checks()))
        self.assertEqual(len(cases), 24)
        release = (ROOT / '.github/workflows/release.yml').read_text()
        self.assertIn('gh api --paginate --slurp', release)
        self.assertIn('python3 ops/analyze/verify_release_ci.py "${GITHUB_SHA}"', release)

    def test_paginated_exact_revision_ci_passes(self):
        runs = self.successful_checks()['check_runs']
        self.assertEqual(ci.verify([{'check_runs': runs[:10]}, {'check_runs': runs[10:]}], REVISION), 27)

    def test_missing_skipped_stale_untrusted_and_ambiguous_checks_fail_closed(self):
        good = self.successful_checks()
        mutations = []
        missing = copy.deepcopy(good)
        missing['check_runs'].pop()
        mutations.append(missing)
        duplicate = copy.deepcopy(good)
        duplicate['check_runs'].append(duplicate['check_runs'][0])
        mutations.append(duplicate)
        for field, value in [('head_sha', 'b' * 40), ('status', 'queued'),
                             ('conclusion', 'skipped'), ('conclusion', 'failure'),
                             ('app', {'slug': 'other-check-provider'})]:
            changed = copy.deepcopy(good)
            changed['check_runs'][0][field] = value
            mutations.append(changed)
        for document in [*mutations, {}, []]:
            with self.assertRaises(ValueError):
                ci.verify(document, REVISION)

    def test_facade_manifest_and_signing_calls_preserve_legacy_manifest(self):
        workflow = (ROOT / '.github/workflows/release.yml').read_text()
        block = workflow.split('      - name: Create signed release manifest\n', 1)[1]
        block = block.split('      - name: Upload release evidence\n', 1)[0]
        script = textwrap.dedent(block.split('        run: |\n', 1)[1])
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            executable = work / 'cosign'
            # Only verify generated manifests and invocation wiring here. This
            # test double does not produce or attest a cryptographic signature.
            executable.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$SIGNING_CALLS"\n')
            executable.chmod(0o700)
            env = {**os.environ, 'PATH': str(work) + os.pathsep + os.environ['PATH'],
                'SIGNING_CALLS': str(work / 'signing-calls.txt'), 'GITHUB_SHA': REVISION,
                'GITHUB_SERVER_URL': 'https://github.com', 'GITHUB_REPOSITORY': 'Steadholme/strad',
                'STRAD_DIGEST': 'sha256:' + '1' * 64, 'ANALYZER_DIGEST': 'sha256:' + '2' * 64,
                'FACADE_DIGEST': 'sha256:' + '3' * 64,
                'COSIGN_IDENTITY': 'test-identity', 'COSIGN_ISSUER': 'test-issuer',
                'RIKUNE_EXPECTED_SOURCE_REVISION': 'b' * 40,
                'RIKUNE_STATIC_LOCK_SHA256': '4' * 64}
            for key, name in [('STRAD_IMAGE_NAME', 'strad'), ('STRAD_ANALYZER_IMAGE_NAME', 'strad-analyzer'),
                              ('STRAD_FACADE_IMAGE_NAME', 'strad-analyze-facade')]:
                env[key] = 'ghcr.io/steadholme/' + name
            for key in ['STRAD_RUST_BUILDER_IMAGE', 'STRAD_RUNTIME_IMAGE', 'STRAD_NODE_BUILDER_IMAGE', 'RIKUNE_ANALYZER_IMAGE']:
                env[key] = 'example.invalid/build@sha256:' + '5' * 64
            subprocess.run(['bash', '-euo', 'pipefail', '-c', script], cwd=work, env=env,
                           capture_output=True, text=True, check=True)
            legacy_bytes = (work / 'release-images.json').read_bytes()
            legacy = json.loads(legacy_bytes)
            analyze = json.loads((work / 'analyze-images.json').read_text())
            self.assertEqual(legacy['schema_version'], 1)
            self.assertEqual(set(legacy['images']), {'STRAD_IMAGE', 'STRAD_ANALYZER_IMAGE'})
            self.assertEqual(analyze['scope'], 'strad-analyze-components')
            self.assertEqual(analyze['source_revision'], REVISION)
            self.assertEqual(analyze['rikune_source_revision'], 'b' * 40)
            self.assertEqual(analyze['strad_release_manifest_sha256'], hashlib.sha256(legacy_bytes).hexdigest())
            self.assertEqual(analyze['images'], {
                'ANALYZE_STRAD_IMAGE': legacy['images']['STRAD_IMAGE'],
                'ANALYZE_ANALYZER_IMAGE': legacy['images']['STRAD_ANALYZER_IMAGE'],
                'ANALYZE_FACADE_IMAGE': env['STRAD_FACADE_IMAGE_NAME'] + '@' + env['FACADE_DIGEST'],
            })
            calls = (work / 'signing-calls.txt').read_text().splitlines()
            self.assertEqual(len(calls), 4)
            for name in ['release-images', 'analyze-images']:
                self.assertIn(f'sign-blob --yes --bundle {name}.sigstore.json {name}.json', calls)
                self.assertTrue(any(line.startswith(f'verify-blob --bundle {name}.sigstore.json ') for line in calls))
                actual = hashlib.sha256((work / f'{name}.json').read_bytes()).hexdigest()
                self.assertEqual((work / f'{name}.sha256').read_text().split()[0], actual)

    def test_facade_has_build_attestation_and_digest_signature_steps(self):
        workflow = (ROOT / '.github/workflows/release.yml').read_text()
        self.assertIn('file: Dockerfile.facade', workflow)
        self.assertIn('subject-digest: ${{ steps.facade.outputs.digest }}', workflow)
        self.assertIn('cosign sign --yes "${STRAD_FACADE_IMAGE_NAME}@${FACADE_DIGEST}"', workflow)
        self.assertIn('"${STRAD_FACADE_IMAGE_NAME}@${FACADE_DIGEST}"; do', workflow)
        for path in ['analyze-images.json', 'analyze-images.sha256', 'analyze-images.sigstore.json']:
            self.assertIn('            ' + path + '\n', workflow)

    def test_release_requires_explicit_static_digest_and_corrected_root_revision(self):
        workflow = (ROOT / '.github/workflows/release.yml').read_text()
        self.assertIn('RIKUNE_ANALYZER_IMAGE: ${{ inputs.rikune_analyzer_image }}', workflow)
        self.assertIn('RIKUNE_EXPECTED_SOURCE_REVISION: 61e354c5bb7625db30a1132d62b3a2fdb829e8f8', workflow)
        self.assertIn('--repo Last-emo-boy/rikune', workflow)
        self.assertIn('--source-digest "${RIKUNE_EXPECTED_SOURCE_REVISION}"', workflow)
        self.assertIn('--signer-workflow "${GITHUB_REPOSITORY}/.github/workflows/release.yml"', workflow)
        self.assertLess(workflow.index('Verify the corrected Rikune static source pin'),
                        workflow.index('Build and push Strad\n'))


if __name__ == '__main__':
    unittest.main()
