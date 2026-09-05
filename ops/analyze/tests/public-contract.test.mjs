import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

import Ajv2020 from 'ajv/dist/2020.js'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const fixturePath = join(root, 'analyze-public-v1.json')
const schemaPath = join(root, 'analyze-public-v1.schema.json')

test('public contract freezes sustainable approval, origin, CAS, rotation and wire defaults', () => {
  assert.equal(existsSync(fixturePath), true, 'versioned public contract fixture must exist')
  const contract = JSON.parse(readFileSync(fixturePath, 'utf8'))

  assert.equal(contract.schema_version, 1)
  assert.equal(contract.external_origin, 'https://analyze.w33d.xyz')
  assert.deepEqual(contract.sso, {
    issuer: 'https://id.w33d.xyz',
    callback: 'https://id.w33d.xyz/_gw/auth/callback',
    state_required: true,
    nonce_required: true,
    cookie: {
      name: '__Secure-gw',
      domain: '.w33d.xyz',
      path: '/',
      secure: true,
      http_only: true,
      same_site: 'Lax',
    },
  })
  assert.deepEqual(contract.csrf, {
    cookie: {
      name: '__Host-csrf',
      path: '/',
      secure: true,
      http_only: true,
      same_site: 'Strict',
    },
    json_header: 'X-CSRF-Token',
    html_field: 'csrf_token',
  })
  assert.equal(contract.step_up_resume_path, '/applications/')

  assert.deepEqual(contract.control_plane.routes, [
    'POST /api/v1/application-requests',
    'POST /api/v1/application-requests/{id}/submit',
    'GET /api/v1/application-requests/{id}',
    'POST /api/v1/application-requests/{id}/cancel',
  ])
  assert.deepEqual(contract.control_plane.states, [
    'draft',
    'pending_approval',
    'approved',
    'rejected',
    'expired',
    'cancelled',
  ])
  assert.equal(contract.mcp.protocol_version, '2025-11-25')
  assert.equal(contract.mcp.path, '/mcp')
  assert.deepEqual(contract.mcp.tools, [
    { name: 'analysis.create', scope: 'analysis.create' },
    { name: 'analysis.read', scope: 'analysis.read' },
    { name: 'analysis.conversation', scope: 'analysis.conversation' },
    { name: 'analysis.upload.cancel', scope: 'analysis.upload.cancel' },
  ])

  assert.deepEqual(contract.errors, {
    invalid_request: { http: 400, json_rpc: -32602, retryable: false },
    unauthenticated: { http: 401, json_rpc: -32001, retryable: false },
    authentication_unavailable: { http: 503, json_rpc: -32002, retryable: true },
    insufficient_scope: { http: 403, json_rpc: -32003, retryable: false },
    authorization_denied: { http: 403, json_rpc: -32004, retryable: false },
    authorization_unavailable: { http: 503, json_rpc: -32005, retryable: true },
    invalid_session: { http: 404, json_rpc: -32006, retryable: false },
    replay_detected: { http: 409, json_rpc: -32007, retryable: false },
    quota_exceeded: { http: 429, json_rpc: -32008, retryable: true },
    idempotency_mismatch: { http: 409, json_rpc: -32009, retryable: false },
    not_found: { http: 404, json_rpc: -32010, retryable: false },
    analyzer_unavailable: { http: 503, json_rpc: -32011, retryable: true },
    dependency_unavailable: { http: 503, json_rpc: -32012, retryable: true },
  })
  assert.deepEqual(contract.quota.tools, {
    'analysis.create': { requests: 4, window_seconds: 3600, concurrency: 1 },
    'analysis.read': { requests: 120, window_seconds: 60, concurrency: 8 },
    'analysis.conversation': { requests: 12, window_seconds: 60, concurrency: 2 },
    'analysis.upload.cancel': { requests: 30, window_seconds: 60, concurrency: 4 },
  })
  assert.deepEqual(contract.quota.headers, [
    'X-RateLimit-Limit',
    'X-RateLimit-Remaining',
    'X-RateLimit-Reset',
  ])
  assert.equal(contract.quota.storage_bytes_per_application, 2_147_483_648)
  assert.equal(contract.quota.file_bytes, 524_288_000)
  assert.equal(contract.quota.system_concurrency, 32)

  assert.equal(contract.approval.policy_id, 'analyze-application-approval-v1')
  assert.equal(contract.approval.request_expiry_seconds, 604_800)
  assert.deepEqual(contract.approval.slots, [
    'human_sponsor_confirmation',
    'system_policy_decision',
  ])
  assert.equal(contract.approval.system.principal, 'service:access-governance-analyze-approval')
  assert.equal(contract.approval.system.decision_ttl_seconds, 300)
  assert.equal(contract.approval.system.single_consume, true)
  assert.equal(contract.approval.system.login_enabled, false)
  assert.equal(contract.approval.system.credential_issuance, false)
  assert.equal(contract.approval.system.no_default_permissions, true)
  assert.equal(contract.approval.bootstrap.may_consume_application_request, false)
  assert.deepEqual(contract.sponsor_assertion, {
    version: 1,
    issuer: 'https://id.w33d.xyz',
    audience: 'access-governance',
    max_auth_age_seconds: 300,
    ttl_seconds: 300,
    session_binding_pattern: '^[0-9a-f]{64}$',
    producer: 'sluice_live_trusted_mfa',
    single_consume: true,
    filesystem_input: false,
  })

  assert.deepEqual(contract.principal.transitions, {
    pending: ['active', 'revoked', 'expired'],
    active: ['suspended', 'revoked', 'expired'],
    suspended: ['active', 'revoked', 'expired'],
    revoked: [],
    expired: [],
  })
  assert.deepEqual(contract.principal.monotonic_fields, [
    'version',
    'policy_epoch',
    'revocation_epoch',
  ])
  assert.equal(contract.credential.token_pattern, '^app_v1_[A-Za-z0-9_-]{43}$')
  assert.equal(contract.credential.random_bytes, 32)
  assert.equal(contract.credential.lookup, 'HMAC-SHA-256')
  assert.equal(contract.credential.pepper_min_bytes, 32)
  assert.equal(contract.credential.plaintext_persistence, false)
  assert.equal(contract.credential.expiry_clipped_to_source, true)
  assert.deepEqual(contract.credential.states, ['active', 'overlap', 'revoked', 'expired'])
  assert.equal(contract.credential.rotation_overlap_seconds, 300)
  assert.equal(contract.credential.emergency_overlap_seconds, 0)
  assert.equal(contract.credential.revoke_deadline_seconds, 30)

  assert.deepEqual(contract.public_upload.rest, [
    'POST /v1/uploads/{upload_id}/chunks/{chunk_index}',
    'POST /v1/uploads/{upload_id}/finalize',
  ])
  assert.equal(contract.public_upload.cancel_via, 'MCP analysis.upload.cancel only')
  assert.deepEqual(contract.idempotency.unique, [
    'application_sub',
    'canonical_tool',
    'operation_id',
  ])
  assert.equal(contract.authorization.non_allow_audit_exactly_once, true)
  assert.equal(contract.authorization.non_allow_dispatch_count, 0)
  assert.deepEqual(contract.execution.envelope_fields, [
    'version',
    'decision_id',
    'decision_digest',
    'subject_version',
    'application_sub',
    'credential_id',
    'credential_version',
    'policy_epoch',
    'revocation_epoch',
    'request_sha256',
    'mcp_session_digest',
    'issued_at',
    'expires_at',
  ])

  const serialized = JSON.stringify(contract)
  assert.doesNotMatch(serialized, /tbd|placeholder/i)
  assert.equal(serialized.includes('"*"'), false)
  const rejectNull = (value) => {
    assert.notEqual(value, null)
    if (Array.isArray(value)) value.forEach(rejectNull)
    else if (typeof value === 'object') Object.values(value).forEach(rejectNull)
  }
  rejectNull(contract)

  const validate = new Ajv2020({ strict: true }).compile(
    JSON.parse(readFileSync(schemaPath, 'utf8'))
  )
  assert.equal(validate(contract), true)
  for (const changed of [
    { ...structuredClone(contract), unexpected: true },
    (() => {
      const value = structuredClone(contract)
      delete value.credential.rotation_overlap_seconds
      return value
    })(),
    (() => {
      const value = structuredClone(contract)
      value.mcp.tools[0].name = '*'
      return value
    })(),
    (() => {
      const value = structuredClone(contract)
      value.quota.tools['analysis.create'].window_seconds = 0
      return value
    })(),
  ]) {
    assert.equal(validate(changed), false)
  }
})
