import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import test from 'node:test'

import type {
  AuthorizationAuditRequest,
  FacadeToolRequest,
  FacadeUploadChunkRequest,
  FacadeUploadMutationRequest,
  StradClient,
} from '../src/clients.js'
import { sha256Hex } from '../src/canonical.js'
import { FacadeError } from '../src/errors.js'
import {
  PostgresSessionStore,
  type ApplicationSessionRevokedV1,
  type SessionBinding,
} from '../src/session-store.js'
import { ToolExecutor, type ToolRequestContext } from '../src/tools.js'
import { FIXED_NOW, OPERATION, FakeVerdict, makeContext } from './helpers.js'

const databaseUrl = process.env.FACADE_TEST_DATABASE_URL
if (!databaseUrl) throw new Error('FACADE_TEST_DATABASE_URL is required for PostgreSQL tests')

function identity() {
  const suffix = randomUUID().replaceAll('-', '')
  return Object.freeze({
    applicationSub: `application:${suffix}`,
    clientId: `client_${suffix}`,
    credentialId: `acr_${suffix}`,
    grantId: `grant_${suffix}`,
    sessionId: `session_${suffix}`,
    sessionDigest: sha256Hex(`session_${suffix}`),
  })
}

function revocation(
  applicationSub: string,
  grantId: string,
  revocationEpoch: number,
  overrides: Partial<ApplicationSessionRevokedV1> = {}
): ApplicationSessionRevokedV1 {
  return Object.freeze({
    v: 1,
    event_id: `evt_${randomUUID().replaceAll('-', '')}`,
    application_sub: applicationSub,
    grant_id: grantId,
    credential_id: null,
    credential_version: null,
    policy_epoch: 11,
    revocation_epoch: revocationEpoch,
    reason: 'grant_revoked',
    effective_at: FIXED_NOW,
    issued_at: FIXED_NOW,
    ...overrides,
  })
}

async function initializedSession(
  store: PostgresSessionStore,
  now = FIXED_NOW
): Promise<Readonly<{ identity: ReturnType<typeof identity>; context: ReturnType<typeof makeContext>; session: SessionBinding }>> {
  const ids = identity()
  const context = makeContext({
    application_sub: ids.applicationSub,
    client_id: ids.clientId,
    credential_id: ids.credentialId,
    grant_id: ids.grantId,
    mcp_session_digest: ids.sessionDigest,
    iat: now,
    exp: now + 30,
  })
  const result = await store.consumeContext(context, ids.sessionId, true, now)
  assert.equal(result.status, 'accepted')
  return Object.freeze({ identity: ids, context, session: result.session })
}

test('real PostgreSQL session replay rotation and cascade', async () => {
  const store = new PostgresSessionStore(databaseUrl)
  try {
    await store.migrate()
    const ids = identity()
    const initial = makeContext({
      application_sub: ids.applicationSub,
      client_id: ids.clientId,
      credential_id: ids.credentialId,
      grant_id: ids.grantId,
      mcp_session_digest: ids.sessionDigest,
    })
    const concurrent = await Promise.all([
      store.consumeContext(initial, ids.sessionId, true, FIXED_NOW),
      store.consumeContext(initial, ids.sessionId, true, FIXED_NOW),
    ])
    assert.deepEqual(
      concurrent.map((result) => result.status).sort(),
      ['accepted', 'replay']
    )

    const overlapUntil = FIXED_NOW + 45
    const oldOverlap = makeContext({
      application_sub: ids.applicationSub,
      client_id: ids.clientId,
      credential_id: ids.credentialId,
      grant_id: ids.grantId,
      credential_version: 2,
      credential_state: 'overlap',
      overlap_until: overlapUntil,
      mcp_session_digest: ids.sessionDigest,
    })
    const continued = await store.consumeContext(oldOverlap, ids.sessionId, false, FIXED_NOW + 1)
    assert.equal(continued.status, 'accepted')
    if (continued.status !== 'accepted') throw new Error('old rotation session did not continue')
    assert.equal(continued.session.credentialVersion, 2)

    const forbiddenSession = `session_${randomUUID().replaceAll('-', '')}`
    const forbiddenOverlap = makeContext({
      application_sub: ids.applicationSub,
      client_id: ids.clientId,
      credential_id: ids.credentialId,
      grant_id: ids.grantId,
      credential_version: 2,
      credential_state: 'overlap',
      overlap_until: overlapUntil,
      mcp_session_digest: Buffer.from(forbiddenSession).toString('hex').slice(0, 64),
    })
    assert.equal(
      (await store.consumeContext(forbiddenOverlap, forbiddenSession, true, FIXED_NOW + 1)).status,
      'invalid_session'
    )

    const rotatedSession = `session_${randomUUID().replaceAll('-', '')}`
    const rotatedContext = makeContext({
      application_sub: ids.applicationSub,
      client_id: ids.clientId,
      credential_id: `acr_${randomUUID().replaceAll('-', '')}`,
      credential_version: 1,
      grant_id: ids.grantId,
      mcp_session_digest: Buffer.from(rotatedSession).toString('hex').slice(0, 64),
    })
    assert.equal(
      (await store.consumeContext(rotatedContext, rotatedSession, true, FIXED_NOW + 2)).status,
      'accepted'
    )
    const expiredOverlap = makeContext({
      application_sub: ids.applicationSub,
      client_id: ids.clientId,
      credential_id: ids.credentialId,
      grant_id: ids.grantId,
      credential_version: 2,
      credential_state: 'overlap',
      overlap_until: overlapUntil,
      mcp_session_digest: ids.sessionDigest,
      iat: overlapUntil,
      exp: overlapUntil + 30,
    })
    assert.equal(
      (await store.consumeContext(expiredOverlap, ids.sessionId, false, overlapUntil)).status,
      'invalid_session'
    )

    const rollback = makeContext({
      application_sub: ids.applicationSub,
      client_id: ids.clientId,
      credential_id: ids.credentialId,
      credential_version: 1,
      grant_id: ids.grantId,
      credential_state: 'overlap',
      overlap_until: overlapUntil,
      mcp_session_digest: ids.sessionDigest,
      iat: FIXED_NOW + 2,
      exp: FIXED_NOW + 32,
    })
    assert.equal(
      (await store.consumeContext(rollback, ids.sessionId, false, FIXED_NOW + 2)).status,
      'invalid_session'
    )

    const event = revocation(ids.applicationSub, ids.grantId, 14, {
      credential_id: ids.credentialId,
      credential_version: 3,
    })
    const acknowledgement = await store.consumeRevocation(event, FIXED_NOW + 3)
    assert.equal(acknowledgement.stale, false)
    assert.equal(acknowledgement.terminated_sessions, 2)
    const afterCascade = makeContext({
      application_sub: ids.applicationSub,
      client_id: ids.clientId,
      credential_id: rotatedContext.credential_id,
      credential_version: rotatedContext.credential_version,
      grant_id: ids.grantId,
      mcp_session_digest: rotatedContext.mcp_session_digest,
      iat: FIXED_NOW + 4,
      exp: FIXED_NOW + 34,
    })
    assert.equal(
      (await store.consumeContext(afterCascade, rotatedSession, false, FIXED_NOW + 4)).status,
      'invalid_session'
    )
  } finally {
    await store.close()
  }
})

test('session revocation event is monotonic idempotent', async () => {
  const store = new PostgresSessionStore(databaseUrl)
  try {
    await store.migrate()
    const fixture = await initializedSession(store)
    const event = revocation(fixture.identity.applicationSub, fixture.identity.grantId, 14)
    const first = await store.consumeRevocation(event, FIXED_NOW + 1)
    assert.equal(first.duplicate, false)
    assert.equal(first.stale, false)
    assert.equal(first.terminated_sessions, 1)
    const duplicate = await store.consumeRevocation(event, FIXED_NOW + 2)
    assert.equal(duplicate.duplicate, true)
    assert.equal(duplicate.terminated_sessions, 1)
    assert.equal(duplicate.stale, first.stale)
    assert.deepEqual(duplicate.session_ids, first.session_ids)

    const staleEvent = revocation(fixture.identity.applicationSub, fixture.identity.grantId, 14)
    const stale = await store.consumeRevocation(staleEvent, FIXED_NOW + 3)
    assert.equal(stale.stale, true)
    assert.equal(stale.terminated_sessions, 0)
    const staleDuplicate = await store.consumeRevocation(staleEvent, FIXED_NOW + 4)
    assert.equal(staleDuplicate.duplicate, true)
    assert.equal(staleDuplicate.stale, true)
    assert.deepEqual(staleDuplicate.session_ids, stale.session_ids)
    const oldEpoch = makeContext({
      application_sub: fixture.identity.applicationSub,
      client_id: fixture.identity.clientId,
      credential_id: fixture.identity.credentialId,
      grant_id: fixture.identity.grantId,
      mcp_session_digest: fixture.identity.sessionDigest,
      iat: FIXED_NOW + 4,
      exp: FIXED_NOW + 34,
    })
    assert.equal(
      (await store.consumeContext(oldEpoch, fixture.identity.sessionId, false, FIXED_NOW + 4)).status,
      'invalid_session'
    )
  } finally {
    await store.close()
  }
})

test('out-of-order application epochs terminate every lower-epoch session', async () => {
  const store = new PostgresSessionStore(databaseUrl)
  try {
    await store.migrate()
    const first = identity()
    const secondSession = `session_${randomUUID().replaceAll('-', '')}`
    const secondCredential = `acr_${randomUUID().replaceAll('-', '')}`
    const firstContext = makeContext({
      application_sub: first.applicationSub,
      client_id: first.clientId,
      credential_id: first.credentialId,
      grant_id: first.grantId,
      mcp_session_digest: first.sessionDigest,
    })
    const secondContext = makeContext({
      application_sub: first.applicationSub,
      client_id: first.clientId,
      credential_id: secondCredential,
      grant_id: first.grantId,
      mcp_session_digest: sha256Hex(secondSession),
    })
    assert.equal(
      (await store.consumeContext(firstContext, first.sessionId, true, FIXED_NOW)).status,
      'accepted'
    )
    assert.equal(
      (await store.consumeContext(secondContext, secondSession, true, FIXED_NOW)).status,
      'accepted'
    )

    const epoch15 = revocation(first.applicationSub, first.grantId, 15, {
      credential_id: first.credentialId,
      credential_version: 2,
    })
    const high = await store.consumeRevocation(epoch15, FIXED_NOW + 1)
    assert.equal(high.stale, false)
    assert.equal(high.terminated_sessions, 2)
    assert.deepEqual(new Set(high.session_ids), new Set([first.sessionId, secondSession]))

    const epoch14 = revocation(first.applicationSub, first.grantId, 14, {
      credential_id: secondCredential,
      credential_version: 2,
    })
    const low = await store.consumeRevocation(epoch14, FIXED_NOW + 2)
    assert.equal(low.stale, true)
    assert.equal(low.terminated_sessions, 0)
    const replay = await store.consumeRevocation(epoch14, FIXED_NOW + 3)
    assert.equal(replay.duplicate, true)
    assert.equal(replay.stale, true)
    assert.deepEqual(replay.session_ids, low.session_ids)

    const oldEpoch = makeContext({
      application_sub: first.applicationSub,
      client_id: first.clientId,
      credential_id: secondCredential,
      grant_id: first.grantId,
      mcp_session_digest: sha256Hex(secondSession),
      iat: FIXED_NOW + 4,
      exp: FIXED_NOW + 34,
    })
    assert.equal(
      (await store.consumeContext(oldEpoch, secondSession, false, FIXED_NOW + 4)).status,
      'invalid_session'
    )
  } finally {
    await store.close()
  }
})

test('allow then revoke before release dispatches zero', async () => {
  const store = new PostgresSessionStore(databaseUrl)
  try {
    await store.migrate()
    const fixture = await initializedSession(store)
    let release!: () => void
    let reached!: () => void
    const releasePromise = new Promise<void>((resolve) => (release = resolve))
    const reachedPromise = new Promise<void>((resolve) => (reached = resolve))
    let dispatched = 0
    class RevocationFencedStrad implements StradClient {
      async tool(_canonicalTool: string, request: FacadeToolRequest): Promise<unknown> {
        reached()
        await releasePromise
        const current = await store.pool.query<{ revocation_epoch: string }>(
          `SELECT revocation_epoch FROM analyze_facade_application_revocation_epochs
           WHERE application_sub=$1`,
          [request.application_sub]
        )
        if (Number(current.rows[0]?.revocation_epoch ?? 0) > request.execution.revocation_epoch) {
          throw new FacadeError('unauthenticated', 'Execution was revoked before dispatch.')
        }
        dispatched++
        return { ok: true }
      }

      async uploadChunk(
        _uploadId: string,
        _chunkIndex: number,
        _request: FacadeUploadChunkRequest
      ): Promise<void> {}

      async uploadFinalize(
        _uploadId: string,
        _request: FacadeUploadMutationRequest
      ): Promise<unknown> {
        return { ok: true }
      }

      async audit(_request: AuthorizationAuditRequest): Promise<void> {}
      async probe(): Promise<void> {}
    }

    const executor = new ToolExecutor(
      new FakeVerdict(),
      new RevocationFencedStrad(),
      'https://analyze.w33d.xyz',
      () => FIXED_NOW
    )
    const requestContext: ToolRequestContext = Object.freeze({
      session: fixture.session,
      applicationContext: fixture.context,
    })
    const execution = executor.execute(
      'analysis.read',
      { operation_id: OPERATION, analysis_id: OPERATION },
      requestContext
    )
    await reachedPromise
    await store.consumeRevocation(
      revocation(fixture.identity.applicationSub, fixture.identity.grantId, 14),
      FIXED_NOW + 1
    )
    release()
    await assert.rejects(execution, (error: unknown) => {
      return error instanceof FacadeError && error.code === 'unauthenticated'
    })
    assert.equal(dispatched, 0)
  } finally {
    await store.close()
  }
})
