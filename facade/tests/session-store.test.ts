import assert from 'node:assert/strict'
import test from 'node:test'

import { sha256Hex } from '../src/canonical.js'
import { MemorySessionStore } from '../src/session-store.js'
import { FIXED_NOW, SESSION, makeContext } from './helpers.js'

test('rotation overlap is original-session-only and emergency revoke is immediate', async () => {
  const store = new MemorySessionStore()
  const initialized = await store.consumeContext(makeContext(), SESSION, true, FIXED_NOW)
  assert.equal(initialized.status, 'accepted')
  if (initialized.status !== 'accepted') return
  assert.equal(initialized.session.credentialId, 'acr_abcdefghijklmnop')
  assert.equal(initialized.session.mcpSessionDigest, sha256Hex(SESSION))
  assert.deepEqual(initialized.session.scopes, [
    'analysis.conversation',
    'analysis.create',
    'analysis.read',
    'analysis.upload.cancel',
  ])

  const overlapUntil = FIXED_NOW + 300
  const rotatedOld = makeContext({
    credential_version: 2,
    credential_state: 'overlap',
    overlap_until: overlapUntil,
  })
  const continued = await store.consumeContext(rotatedOld, SESSION, false, FIXED_NOW + 1)
  assert.equal(continued.status, 'accepted')
  if (continued.status !== 'accepted') return
  assert.equal(continued.session.credentialVersion, 2)
  assert.equal(
    (
      await store.consumeContext(
        makeContext({
          credential_version: 2,
          credential_state: 'overlap',
          overlap_until: overlapUntil,
        }),
        'session_forbidden_rebind',
        true,
        FIXED_NOW + 1
      )
    ).status,
    'invalid_session'
  )
  const newSession = 'session_newcredential'
  const newCredential = makeContext({
    credential_id: 'acr_newcredential000000',
    credential_version: 1,
    mcp_session_digest: sha256Hex(newSession),
  })
  assert.equal(
    (await store.consumeContext(newCredential, newSession, true, FIXED_NOW + 2)).status,
    'accepted'
  )
  assert.equal(
    (
      await store.consumeContext(
        makeContext({
          credential_version: 2,
          credential_state: 'overlap',
          overlap_until: overlapUntil,
        }),
        SESSION,
        false,
        overlapUntil
      )
    ).status,
    'invalid_session'
  )
  assert.equal(
    (
      await store.consumeContext(
        makeContext({
          credential_version: 1,
          credential_state: 'overlap',
          overlap_until: overlapUntil,
        }),
        SESSION,
        false,
        FIXED_NOW + 2
      )
    ).status,
    'invalid_session',
    'credential version rollback must fail closed'
  )
  const oldCredentialRevoked = await store.consumeRevocation(
    {
      v: 1,
      event_id: 'evt_oldcredential000001',
      application_sub: rotatedOld.application_sub,
      grant_id: rotatedOld.grant_id,
      credential_id: rotatedOld.credential_id,
      credential_version: 3,
      policy_epoch: rotatedOld.policy_epoch,
      revocation_epoch: rotatedOld.revocation_epoch + 1,
      reason: 'emergency_revoke',
      effective_at: FIXED_NOW + 3,
      issued_at: FIXED_NOW + 3,
    },
    FIXED_NOW + 3
  )
  assert.equal(oldCredentialRevoked.terminated_sessions, 2)
  assert.ok(oldCredentialRevoked.session_ids.includes(SESSION))
  assert.ok(oldCredentialRevoked.session_ids.includes(newSession))
  const revoked = await store.consumeRevocation(
    {
      v: 1,
      event_id: 'evt_emergency0000000001',
      application_sub: newCredential.application_sub,
      grant_id: newCredential.grant_id,
      credential_id: newCredential.credential_id,
      credential_version: newCredential.credential_version,
      policy_epoch: newCredential.policy_epoch,
      revocation_epoch: newCredential.revocation_epoch + 2,
      reason: 'emergency_revoke',
      effective_at: FIXED_NOW + 3,
      issued_at: FIXED_NOW + 3,
    },
    FIXED_NOW + 3
  )
  assert.equal(revoked.terminated_sessions, 0)
  assert.equal(
    (
      await store.consumeContext(
        makeContext({
          credential_id: newCredential.credential_id,
          credential_version: newCredential.credential_version,
          mcp_session_digest: newCredential.mcp_session_digest,
          revocation_epoch: newCredential.revocation_epoch,
        }),
        newSession,
        false,
        FIXED_NOW + 3
      )
    ).status,
    'invalid_session'
  )
})
