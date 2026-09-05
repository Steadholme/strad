import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { request as httpRequest } from 'node:http'
import test, { before } from 'node:test'

import type { ApplicationContext } from '../src/application-context.js'
import { sha256Hex } from '../src/canonical.js'
import { createFacadeServer } from '../src/server.js'
import { MemorySessionStore, PostgresSessionStore } from '../src/session-store.js'
import {
  FIXED_NOW, FakeStrad, FakeVerdict, closeTestServer, contextForHttp, facadeFetch,
  listenTestServer, makeContext, requestHeaders, testConfig,
} from './helpers.js'

const databaseUrl = process.env.FACADE_TEST_DATABASE_URL
if (!databaseUrl) throw new Error('FACADE_TEST_DATABASE_URL is required for PostgreSQL tests')
const schema = `supersede_${randomUUID().replaceAll('-', '')}`
const scopedDatabaseUrl = new URL(databaseUrl)
scopedDatabaseUrl.searchParams.set('options', `-c search_path=${schema}`)
const testDatabaseUrl = scopedDatabaseUrl.toString()

before(async () => {
  const setup = new PostgresSessionStore(databaseUrl)
  try {
    await setup.pool.query(`CREATE SCHEMA ${schema}`)
  } finally {
    await setup.close()
  }
})

function fixture() {
  const suffix = randomUUID().replaceAll('-', '')
  const initial = `session_${suffix}`
  const replacement = `replacement_${suffix}`
  const delayed = `delayed_${suffix}`
  const credential = `acr_${suffix}`
  const application = `application:${suffix}`
  function context(
    sessionId: string,
    version: number,
    overrides: Partial<ApplicationContext> = {}
  ): ApplicationContext {
    return makeContext({
      application_sub: application,
      credential_id: credential,
      credential_version: version,
      mcp_session_digest: sha256Hex(sessionId),
      ...overrides,
    })
  }
  return { initial, replacement, delayed, credential, application, context }
}

for (const backend of ['memory', 'postgres'] as const) {
  async function createStore() {
    if (backend === 'memory') return new MemorySessionStore()
    const store = new PostgresSessionStore(testDatabaseUrl)
    await store.migrate()
    return store
  }

  test(`${backend}: initialize supersedes only the same credential and rejects delayed versions`, async () => {
    const store = await createStore()
    const f = fixture()
    try {
      assert.equal((await store.consumeContext(f.context(f.initial, 1), f.initial, true, FIXED_NOW)).status, 'accepted')
      const sibling = `sibling_${f.initial}`
      const siblingContext = () => f.context(sibling, 1, { credential_id: `other_${f.credential}` })
      assert.equal((await store.consumeContext(siblingContext(), sibling, true, FIXED_NOW)).status, 'accepted')
      assert.equal((await store.consumeContext(f.context(f.replacement, 3), f.replacement, true, FIXED_NOW + 1)).status, 'accepted')
      assert.equal(
        (await store.consumeContext(f.context(f.initial, 1), f.initial, false, FIXED_NOW + 2)).status,
        'invalid_session',
        'a superseded session must stop immediately'
      )
      assert.equal(
        (await store.consumeContext(f.context(f.delayed, 2), f.delayed, true, FIXED_NOW + 2)).status,
        'invalid_session',
        'a late initialize must not overwrite a newer Access version'
      )
      assert.equal((await store.consumeContext(f.context(f.replacement, 3), f.replacement, false, FIXED_NOW + 3)).status, 'accepted')
      assert.equal((await store.consumeContext(siblingContext(), sibling, false, FIXED_NOW + 3)).status, 'accepted')
    } finally {
      await store.close()
    }
  })

  test(`${backend}: a credential version cannot initialize two different session digests`, async () => {
    const store = await createStore()
    const f = fixture()
    try {
      assert.equal((await store.consumeContext(f.context(f.initial, 1), f.initial, true, FIXED_NOW)).status, 'accepted')
      assert.equal((await store.consumeContext(f.context(f.replacement, 1), f.replacement, true, FIXED_NOW)).status, 'invalid_session')
      assert.equal((await store.consumeContext(f.context(f.initial, 1), f.initial, false, FIXED_NOW + 1)).status, 'accepted')
      await store.terminateSession(f.initial, 'client_closed', FIXED_NOW + 2)
      assert.equal((await store.consumeContext(f.context(f.replacement, 1), f.replacement, true, FIXED_NOW + 3)).status, 'invalid_session')
      assert.equal((await store.consumeContext(f.context(f.initial, 1), f.initial, true, FIXED_NOW + 3)).status, 'invalid_session')
      assert.equal((await store.consumeContext(f.context(f.replacement, 2), f.replacement, true, FIXED_NOW + 3)).status, 'accepted')
    } finally {
      await store.close()
    }
  })

  test(`${backend}: reconnect never transfers or terminates a rotation parent overlap`, async () => {
    const store = await createStore()
    const f = fixture()
    const overlap = (sessionId = f.initial) => f.context(sessionId, 2, {
      credential_state: 'overlap',
      overlap_until: FIXED_NOW + 300,
    })
    const child = `child_${f.credential}`
    try {
      assert.equal((await store.consumeContext(f.context(f.initial, 1), f.initial, true, FIXED_NOW)).status, 'accepted')
      assert.equal((await store.consumeContext(overlap(), f.initial, false, FIXED_NOW + 1)).status, 'accepted')
      assert.equal((await store.consumeContext(f.context(f.delayed, 1), f.delayed, true, FIXED_NOW + 2)).status, 'invalid_session')
      assert.equal((await store.consumeContext(overlap(f.delayed), f.delayed, true, FIXED_NOW + 2)).status, 'invalid_session')
      assert.equal((await store.consumeContext(f.context(f.replacement, 1, { credential_id: child }), f.replacement, true, FIXED_NOW + 2)).status, 'accepted')
      assert.equal((await store.consumeContext(f.context(f.delayed, 2, { credential_id: child }), f.delayed, true, FIXED_NOW + 3)).status, 'accepted')
      assert.equal((await store.consumeContext(overlap(), f.initial, false, FIXED_NOW + 4)).status, 'accepted')
      assert.equal((await store.consumeContext(f.context(f.replacement, 1, { credential_id: child }), f.replacement, false, FIXED_NOW + 4)).status, 'invalid_session')
      assert.equal((await store.consumeContext(overlap(), f.initial, false, FIXED_NOW + 300)).status, 'invalid_session')
    } finally {
      await store.close()
    }
  })

  test(`${backend}: an observed newer context fences late initialization even before its transport attaches`, async () => {
    const store = await createStore()
    const f = fixture()
    try {
      assert.equal((await store.consumeContext(f.context(f.initial, 1), f.initial, true, FIXED_NOW)).status, 'accepted')
      assert.equal((await store.consumeContext(f.context(f.replacement, 3), f.replacement, false, FIXED_NOW + 1)).status, 'invalid_session')
      assert.equal((await store.consumeContext(f.context(f.delayed, 2), f.delayed, true, FIXED_NOW + 1)).status, 'invalid_session')
      assert.equal((await store.consumeContext(f.context(f.initial, 1), f.initial, false, FIXED_NOW + 1)).status, 'invalid_session')
      assert.equal((await store.consumeContext(f.context(f.replacement, 3), f.replacement, true, FIXED_NOW + 2)).status, 'accepted')
    } finally {
      await store.close()
    }
  })
}

test('PostgreSQL supersede ordering survives concurrent initializes and store restart', async () => {
  const f = fixture()
  const first = new PostgresSessionStore(testDatabaseUrl)
  try {
    await first.migrate()
    assert.equal((await first.consumeContext(f.context(f.initial, 1), f.initial, true, FIXED_NOW)).status, 'accepted')
    const results = await Promise.all([
      first.consumeContext(f.context(f.delayed, 2), f.delayed, true, FIXED_NOW + 1),
      first.consumeContext(f.context(f.replacement, 3), f.replacement, true, FIXED_NOW + 1),
    ])
    assert.ok(['accepted', 'invalid_session'].includes(results[0]!.status))
    assert.equal(results[1]!.status, 'accepted')
  } finally {
    await first.close()
  }
  const restarted = new PostgresSessionStore(testDatabaseUrl)
  try {
    await restarted.migrate()
    assert.equal((await restarted.consumeContext(f.context(f.delayed, 2), f.delayed, true, FIXED_NOW + 2)).status, 'invalid_session')
    assert.equal((await restarted.consumeContext(f.context(f.initial, 1), f.initial, false, FIXED_NOW + 2)).status, 'invalid_session')
    assert.equal((await restarted.consumeContext(f.context(f.replacement, 3), f.replacement, false, FIXED_NOW + 2)).status, 'accepted')
    const persisted = await restarted.pool.query<{ session_id: string }>(
      `SELECT session_id FROM analyze_facade_sessions WHERE application_sub=$1 AND state='active'`,
      [f.application]
    )
    assert.deepEqual(persisted.rows.map((row) => row.session_id), [f.replacement])
  } finally {
    await restarted.close()
  }
})

test('migration backfills terminated credentials without rolling back a newer observed version', async () => {
  const store = new PostgresSessionStore(testDatabaseUrl)
  const f = fixture()
  try {
    await store.migrate()
    assert.equal((await store.consumeContext(f.context(f.initial, 4), f.initial, true, FIXED_NOW)).status, 'accepted')
    await store.terminateSession(f.initial, 'client_closed', FIXED_NOW + 1)
    await store.pool.query(
      'DELETE FROM analyze_facade_credential_session_bindings WHERE application_sub=$1',
      [f.application]
    )
    await store.migrate()
    assert.equal((await store.consumeContext(f.context(f.delayed, 3), f.delayed, true, FIXED_NOW + 2)).status, 'invalid_session')
    assert.equal((await store.consumeContext(f.context(f.initial, 4), f.initial, true, FIXED_NOW + 2)).status, 'invalid_session')
    assert.equal((await store.consumeContext(f.context(f.replacement, 6), f.replacement, false, FIXED_NOW + 2)).status, 'invalid_session')
    await store.migrate()
    assert.equal((await store.consumeContext(f.context(f.delayed, 5), f.delayed, true, FIXED_NOW + 3)).status, 'invalid_session')
    assert.equal((await store.consumeContext(f.context(f.replacement, 6), f.replacement, true, FIXED_NOW + 3)).status, 'accepted')
  } finally {
    await store.close()
  }
})

test('real MCP HTTP reconnect closes old SSE and recovers after facade restart and idle expiry', { timeout: 10000 }, async () => {
  const f = fixture()
  const verdict = new FakeVerdict()
  const strad = new FakeStrad()
  let now = FIXED_NOW
  let store = new PostgresSessionStore(testDatabaseUrl)
  await store.migrate()
  let server = createFacadeServer({ config: testConfig(), sessions: store, verdict, strad, now: () => now })
  let base = await listenTestServer(server)
  async function request(sessionId: string, version: number, initialize: boolean): Promise<Response> {
    const body = JSON.stringify(initialize ? {
      jsonrpc: '2.0', id: 1, method: 'initialize', params: {
        protocolVersion: '2025-11-25', capabilities: {},
        clientInfo: { name: 'reconnect-test', version: '1.0.0' },
      },
    } : { jsonrpc: '2.0', id: 2, method: 'tools/list' })
    const context = contextForHttp('POST', '/mcp', 'analyze-mcp', Buffer.from(body), {
      ...f.context(sessionId, version), body_sha256: sha256Hex(body), iat: now, exp: now + 30,
    })
    return facadeFetch(`${base}/mcp`, {
      method: 'POST', body,
      headers: requestHeaders(context, {
        'content-type': 'application/json', 'mcp-protocol-version': '2025-11-25',
        'mcp-session-id': sessionId,
      }),
    })
  }
  const streamContext = contextForHttp('GET', '/mcp', 'analyze-mcp', Buffer.alloc(0), {
    application_sub: f.application, credential_id: f.credential, mcp_session_digest: sha256Hex(f.initial),
  })
  const streamRequest = httpRequest(`${base}/mcp`, {
    method: 'GET', headers: requestHeaders(streamContext, {
      'mcp-session-id': f.initial, 'mcp-protocol-version': '2025-11-25',
    }),
  })
  try {
    assert.equal((await request(f.initial, 1, true)).status, 200)
    assert.equal((await request(f.initial, 1, false)).status, 200)
    const opened = new Promise<import('node:http').IncomingMessage>((resolve, reject) => {
      streamRequest.once('response', resolve)
      streamRequest.once('error', reject)
      streamRequest.end()
    })
    const stream = await opened
    assert.equal(stream.statusCode, 200)
    const ended = new Promise<void>((resolve, reject) => {
      stream.once('end', resolve)
      stream.once('error', reject)
      stream.resume()
    })
    const reconnected = await request(f.replacement, 2, true)
    assert.equal(reconnected.status, 200)
    assert.equal(reconnected.headers.get('mcp-session-id'), f.replacement)
    await ended
    assert.equal((await request(f.initial, 1, false)).status, 404)
    assert.equal((await request(f.replacement, 2, false)).status, 200)

    await closeTestServer(server)
    await store.close()
    store = new PostgresSessionStore(testDatabaseUrl)
    await store.migrate()
    server = createFacadeServer({ config: testConfig(), sessions: store, verdict, strad, now: () => now })
    base = await listenTestServer(server)
    assert.equal((await request(f.replacement, 2, false)).status, 404)
    assert.equal((await request(f.delayed, 3, true)).status, 200)
    assert.equal((await request(f.replacement, 2, false)).status, 404)
    assert.equal((await request(f.delayed, 3, false)).status, 200)

    now += 901
    assert.equal((await request(f.delayed, 3, false)).status, 404)
    const afterIdle = `idle_${f.initial}`
    assert.equal((await request(afterIdle, 4, true)).status, 200)
    const listed = await request(afterIdle, 4, false)
    assert.equal(listed.status, 200)
    const result = await listed.json() as { result: { tools: Array<{ name: string }> } }
    assert.equal(result.result.tools.length, 4)
    assert.equal(strad.tools.length, 0)
  } finally {
    streamRequest.destroy()
    await closeTestServer(server)
    await store.close()
  }
})
