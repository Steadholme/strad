import assert from 'node:assert/strict'
import test from 'node:test'
import { decisionDigest, injectDecisionFault, MODES } from '../decision-faults.mjs'

const request = { v: 2, application_sub: 'application:abcdefghijklmnop', canonical_tool: 'analysis.read' }
const base = { v: 2, subject: request.application_sub, resource: { type: 'analysis', id: 'owned' },
  permission: 'rikune.analysis.read', decision: 'Allow', reason: 'matching projection', evidence: [],
  policy_version: 1, subject_version: 2, policy_epoch: 1, issued_at: 2000, expires_at: 2030 }
base.decision_digest = decisionDigest(request, base)
base.decision_id = 'dec_' + base.decision_digest.slice(0, 32)

test('fault modes never manufacture a new Allow authority', () => {
  for (const mode of MODES) {
    const result = injectDecisionFault(mode, request, base)
    if (mode === 'dependency_failure') { assert.equal(result.status, 503); continue }
    assert.equal(result.status, 200)
    if (mode === 'deny') assert.equal(result.body.decision, 'Deny')
    if (mode === 'indeterminate') assert.equal(result.body.decision, 'Indeterminate')
    if (mode === 'stale_digest') assert.notEqual(result.body.decision_digest, decisionDigest(request, result.body))
    if (mode === 'stale_version') assert.equal(result.body.policy_version, 0)
    if (mode === 'stale_ttl') assert.equal(result.body.expires_at, 1970)
    if (mode !== 'stale_digest') assert.equal(result.body.decision_digest, decisionDigest(request, result.body))
  }
  assert.equal(base.decision, 'Allow')
  assert.equal(base.policy_version, 1)
})

test('a missing, corrupted or non-Allow upstream cannot seed the test', () => {
  assert.throws(() => injectDecisionFault('deny', request, { ...base, decision_digest: '0'.repeat(64) }))
  assert.throws(() => injectDecisionFault('deny', request, { ...base, decision: 'Deny' }))
  assert.throws(() => injectDecisionFault('allow', request, base))
})
