import assert from 'node:assert/strict'
import { readdir, readFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createServer } from 'node:http'
import { createServer as createTcpServer, type Socket } from 'node:net'
import type { AddressInfo } from 'node:net'
import test from 'node:test'

import { sha256Hex } from '../src/canonical.js'
import { loadConfig } from '../src/config.js'
import { CompositeReadiness } from '../src/health.js'
import { HttpStradClient, type FacadeToolRequest } from '../src/clients.js'
import { createFacadeServer } from '../src/server.js'
import { MemorySessionStore, PostgresSessionStore } from '../src/session-store.js'
import {
  APPLICATION,
  CREDENTIAL,
  FINALIZE,
  FIXED_NOW,
  KEYRING,
  OPERATION,
  SESSION,
  UPLOAD,
  FakeStrad,
  FakeVerdict,
  closeTestServer,
  contextForHttp,
  facadeFetch,
  listenTestServer,
  requestHeaders,
  testConfig,
} from './helpers.js'

async function initializedFixture() {
  const sessions = new MemorySessionStore()
  const verdict = new FakeVerdict()
  const strad = new FakeStrad()
  const server = createFacadeServer({
    config: testConfig(),
    sessions,
    verdict,
    strad,
    now: () => FIXED_NOW,
  })
  const base = await listenTestServer(server)
  const body = JSON.stringify({
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: {
      protocolVersion: '2025-11-25',
      capabilities: {},
      clientInfo: { name: 'facade-contract-test', version: '1.0.0' },
    },
  })
  const context = contextForHttp('POST', '/mcp', 'analyze-mcp', Buffer.from(body))
  const response = await facadeFetch(`${base}/mcp`, {
    method: 'POST',
    headers: requestHeaders(context, { 'content-type': 'application/json' }),
    body,
  })
  assert.equal(response.status, 200)
  assert.equal(response.headers.get('mcp-session-id'), SESSION)
  const initialized = (await response.json()) as Record<string, unknown>
  return { sessions, verdict, strad, server, base, initialized }
}

async function mcpPost(base: string, bodyValue: unknown): Promise<Response> {
  const body = JSON.stringify(bodyValue)
  const context = contextForHttp('POST', '/mcp', 'analyze-mcp', Buffer.from(body))
  return facadeFetch(`${base}/mcp`, {
    method: 'POST',
    headers: requestHeaders(context, {
      'content-type': 'application/json',
      'mcp-protocol-version': '2025-11-25',
    }),
    body,
  })
}

test('initialize lists exact four tools and no extra capabilities', async () => {
  const fixture = await initializedFixture()
  try {
    const result = (fixture.initialized.result ?? {}) as Record<string, unknown>
    assert.equal(result.protocolVersion, '2025-11-25')
    assert.deepEqual(Object.keys((result.capabilities ?? {}) as Record<string, unknown>), ['tools'])

    const listed = await mcpPost(fixture.base, { jsonrpc: '2.0', id: 2, method: 'tools/list' })
    assert.equal(listed.status, 200)
    const listedBody = (await listed.json()) as {
      result: { tools: Array<{ name: string }> }
    }
    assert.deepEqual(
      listedBody.result.tools.map((tool) => tool.name),
      ['analysis.create', 'analysis.read', 'analysis.conversation', 'analysis.upload.cancel']
    )

    const deletedContext = contextForHttp('DELETE', '/mcp', 'analyze-mcp', Buffer.alloc(0))
    const deleted = await facadeFetch(`${fixture.base}/mcp`, {
      method: 'DELETE',
      headers: requestHeaders(deletedContext, { 'mcp-protocol-version': '2025-11-25' }),
    })
    assert.equal(deleted.status, 200)
    const afterClose = await mcpPost(fixture.base, { jsonrpc: '2.0', id: 3, method: 'tools/list' })
    assert.equal(afterClose.status, 404)
  } finally {
    await closeTestServer(fixture.server)
  }
})

test('runtime rejects every MCP protocol except the frozen version', async () => {
  const sessions = new MemorySessionStore()
  const server = createFacadeServer({
    config: testConfig(),
    sessions,
    verdict: new FakeVerdict(),
    strad: new FakeStrad(),
    now: () => FIXED_NOW,
  })
  const base = await listenTestServer(server)
  try {
    for (const protocolVersion of ['2025-03-26', '2026-01-01']) {
      const body = JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: {
          protocolVersion,
          capabilities: {},
          clientInfo: { name: 'frozen-protocol-test', version: '1.0.0' },
        },
      })
      const context = contextForHttp('POST', '/mcp', 'analyze-mcp', Buffer.from(body))
      const response = await facadeFetch(`${base}/mcp`, {
        method: 'POST',
        headers: requestHeaders(context, { 'content-type': 'application/json' }),
        body,
      })
      assert.equal(response.status, 400)
      assert.equal((await response.json() as { error: { code: string } }).error.code, 'invalid_request')
    }
    const validBody = JSON.stringify({
      jsonrpc: '2.0',
      id: 2,
      method: 'initialize',
      params: {
        protocolVersion: '2025-11-25',
        capabilities: {},
        clientInfo: { name: 'frozen-protocol-test', version: '1.0.0' },
      },
    })
    const validContext = contextForHttp('POST', '/mcp', 'analyze-mcp', Buffer.from(validBody))
    assert.equal(
      (
        await facadeFetch(`${base}/mcp`, {
          method: 'POST',
          headers: requestHeaders(validContext, { 'content-type': 'application/json' }),
          body: validBody,
        })
      ).status,
      200
    )
    const listBody = JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'tools/list' })
    const listContext = contextForHttp('POST', '/mcp', 'analyze-mcp', Buffer.from(listBody))
    const oldHeader = await facadeFetch(`${base}/mcp`, {
      method: 'POST',
      headers: requestHeaders(listContext, {
        'content-type': 'application/json',
        'mcp-protocol-version': '2025-03-26',
      }),
      body: listBody,
    })
    assert.equal(oldHeader.status, 400)
  } finally {
    await closeTestServer(server)
  }
})

test('production readiness fails each missing dependency', async () => {
  class FailingSessionStore extends MemorySessionStore {
    fail = false
    override async ping(): Promise<void> {
      if (this.fail) throw new Error('postgres down')
    }
  }
  const sessions = new FailingSessionStore()
  const verdict = new FakeVerdict()
  const strad = new FakeStrad()
  const readiness = () =>
    new CompositeReadiness({
      sessions,
      verdict,
      strad,
      keyring: KEYRING,
      activeKid: 'appctx-2026a',
      now: () => FIXED_NOW,
    })
  await readiness().check()
  for (const fail of [
    () => (sessions.fail = true),
    () => (verdict.probeFailure = true),
    () => (strad.probeFailure = true),
  ]) {
    sessions.fail = false
    verdict.probeFailure = false
    strad.probeFailure = false
    fail()
    await assert.rejects(readiness().check())
  }
  await assert.rejects(
    new CompositeReadiness({
      sessions: new MemorySessionStore(),
      verdict: new FakeVerdict(),
      strad: new FakeStrad(),
      keyring: new Map(),
      activeKid: 'appctx-2026a',
      now: () => FIXED_NOW,
    }).check()
  )
})

test('production readiness bounds hanging PostgreSQL and releases its connection', async () => {
  const sockets = new Set<Socket>()
  const blackhole = createTcpServer((socket) => {
    sockets.add(socket)
    socket.once('close', () => sockets.delete(socket))
  })
  await new Promise<void>((resolve, reject) => {
    blackhole.once('error', reject)
    blackhole.listen(0, '127.0.0.1', resolve)
  })
  const port = (blackhole.address() as AddressInfo).port
  const timeoutMs = 150
  const sessions = new PostgresSessionStore(
    `postgres://facade:facade@127.0.0.1:${port}/facade`,
    timeoutMs
  )
  const facade = createFacadeServer({
    config: testConfig({ requestTimeoutMs: timeoutMs }),
    sessions,
    verdict: new FakeVerdict(),
    strad: new FakeStrad(),
    now: () => FIXED_NOW,
  })
  const base = await listenTestServer(facade)
  try {
    const startedAt = Date.now()
    const response = await Promise.race([
      facadeFetch(`${base}/readyz`),
      new Promise<'hung'>((resolve) => setTimeout(() => resolve('hung'), timeoutMs + 600)),
    ])
    assert.notEqual(response, 'hung', 'readiness exceeded its configured deadline with margin')
    if (response === 'hung') return
    assert.equal(response.status, 503)
    assert.ok(Date.now() - startedAt < timeoutMs + 500)
    const cleanupDeadline = Date.now() + 500
    while (sessions.pool.totalCount > 0 && Date.now() < cleanupDeadline) {
      await new Promise((resolve) => setTimeout(resolve, 20))
    }
    assert.equal(sessions.pool.totalCount, 0, 'timed-out PostgreSQL client must leave the pool')
  } finally {
    for (const socket of sockets) socket.destroy()
    await sessions.close()
    await closeTestServer(facade)
    await new Promise<void>((resolve) => blackhole.close(() => resolve()))
  }
})

test('Facade readiness transitively fails closed on Strad readiness failure and hang', async () => {
  let mode: 'failure' | 'hang' = 'failure'
  const stradServer = createServer((request, response) => {
    if (request.url !== '/readyz') {
      response.writeHead(404)
      response.end()
      return
    }
    if (mode === 'failure') {
      response.writeHead(503)
      response.end()
    }
  })
  const stradOrigin = await listenTestServer(stradServer)
  const timeoutMs = 150
  const facade = createFacadeServer({
    config: testConfig({ requestTimeoutMs: timeoutMs }),
    sessions: new MemorySessionStore(),
    verdict: new FakeVerdict(),
    strad: new HttpStradClient(`${stradOrigin}/`, 's'.repeat(32), timeoutMs),
    now: () => FIXED_NOW,
  })
  const facadeOrigin = await listenTestServer(facade)
  try {
    assert.equal((await facadeFetch(`${facadeOrigin}/readyz`)).status, 503)
    mode = 'hang'
    const startedAt = Date.now()
    const response = await facadeFetch(`${facadeOrigin}/readyz`)
    assert.equal(response.status, 503)
    assert.ok(Date.now() - startedAt < timeoutMs + 500)
  } finally {
    await closeTestServer(facade)
    await closeTestServer(stradServer)
  }
})

test('Strad client cancels an oversized streaming response at its byte limit', async () => {
  const originalFetch = globalThis.fetch
  let pulls = 0
  let cancelled = false
  const responseBody = new ReadableStream<Uint8Array>(
    {
      pull(controller) {
        pulls++
        controller.enqueue(new Uint8Array(1024 * 1024))
        if (pulls === 10) controller.close()
      },
      cancel() {
        cancelled = true
      },
    },
    { highWaterMark: 0 }
  )
  globalThis.fetch = async () => new Response(responseBody, { status: 200 })
  const request = {
    application_sub: APPLICATION,
    operation_id: OPERATION,
    request_sha256: 'a'.repeat(64),
    correlation_id: '550e8400-e29b-41d4-a716-446655440099',
    resource: 'analysis:test',
    body: {},
    execution: {
      version: 1,
      decision_id: 'dec_test',
      decision_digest: 'd'.repeat(64),
      subject_version: 1,
      application_sub: APPLICATION,
      credential_id: CREDENTIAL,
      credential_version: 1,
      policy_epoch: 1,
      revocation_epoch: 1,
      request_sha256: 'a'.repeat(64),
      mcp_session_digest: 'b'.repeat(64),
      issued_at: FIXED_NOW,
      expires_at: FIXED_NOW + 30,
    },
  } satisfies FacadeToolRequest
  try {
    await assert.rejects(
      new HttpStradClient('http://127.0.0.1/', 's'.repeat(32)).tool('analysis.read', request)
    )
    assert.equal(cancelled, true)
    assert.ok(pulls <= 5, `oversized stream consumed ${pulls} chunks`)
  } finally {
    globalThis.fetch = originalFetch
  }
})

test('public REST exposes chunk finalize and rejects cancel', async () => {
  const fixture = await initializedFixture()
  try {
    const chunkBody = Buffer.from('abc')
    const chunkPath = `/v1/uploads/${UPLOAD}/chunks/0`
    const chunkContext = contextForHttp('POST', chunkPath, 'analyze-uploads', chunkBody)
    const chunk = await facadeFetch(`${fixture.base}${chunkPath}`, {
      method: 'POST',
      headers: requestHeaders(chunkContext, {
        'content-range': 'bytes 0-2/3',
        'content-type': 'application/octet-stream',
        'x-chunk-sha256': sha256Hex(chunkBody),
      }),
      body: chunkBody,
    })
    assert.equal(chunk.status, 204)
    assert.equal(fixture.strad.chunks.length, 1)
    assert.equal(fixture.strad.chunks[0]?.request.content_base64, chunkBody.toString('base64'))

    const finalizePath = `/v1/uploads/${UPLOAD}/finalize`
    const finalizeContext = contextForHttp('POST', finalizePath, 'analyze-uploads', Buffer.alloc(0))
    const finalized = await facadeFetch(`${fixture.base}${finalizePath}`, {
      method: 'POST',
      headers: requestHeaders(finalizeContext, { 'idempotency-key': FINALIZE }),
      body: '',
    })
    assert.equal(finalized.status, 202)
    assert.equal(fixture.strad.finalizes.length, 1)
    assert.equal(fixture.strad.finalizes[0]?.request.operation_id, FINALIZE)

    const publicCancel = await facadeFetch(`${fixture.base}/v1/uploads/${UPLOAD}/cancel`, {
      method: 'POST',
      headers: { host: 'analyze.w33d.xyz' },
    })
    assert.equal(publicCancel.status, 404)

    const mcpCancel = await mcpPost(fixture.base, {
      jsonrpc: '2.0',
      id: 9,
      method: 'tools/call',
      params: {
        name: 'analysis.upload.cancel',
        arguments: { operation_id: OPERATION, upload_id: UPLOAD },
      },
    })
    assert.equal(mcpCancel.status, 200)
    assert.equal(fixture.strad.tools.at(-1)?.tool, 'analysis.upload.cancel')
  } finally {
    await closeTestServer(fixture.server)
  }
})

test('revocation ingress is private bearer-only monotonic and closes live sessions', async () => {
  const fixture = await initializedFixture()
  try {
    const event = {
      v: 1,
      event_id: 'evt_revocation000000001',
      application_sub: 'application:abcdefghijklmnop',
      grant_id: 'grant_abcdefghijklmnop',
      credential_id: null,
      credential_version: null,
      policy_epoch: 11,
      revocation_epoch: 14,
      reason: 'grant_revoked',
      effective_at: FIXED_NOW,
      issued_at: FIXED_NOW,
    }
    const path = '/internal/v1/application-session-revocations'
    const denied = await facadeFetch(`${fixture.base}${path}`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${'x'.repeat(32)}`,
        'content-type': 'application/json',
        host: 'analyze-facade:18120',
      },
      body: JSON.stringify(event),
    })
    assert.equal(denied.status, 401)
    const publicHost = await facadeFetch(`${fixture.base}${path}`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${'r'.repeat(32)}`,
        'content-type': 'application/json',
        host: 'analyze.w33d.xyz',
      },
      body: JSON.stringify(event),
    })
    assert.equal(publicHost.status, 404)
    for (let attempt = 0; attempt < 2; attempt++) {
      const accepted = await facadeFetch(`${fixture.base}${path}`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${'r'.repeat(32)}`,
          'content-type': 'application/json',
          host: 'analyze-facade:18120',
        },
        body: JSON.stringify(event),
      })
      assert.equal(accepted.status, 200)
      const body = (await accepted.json()) as { duplicate: boolean }
      assert.equal(body.duplicate, attempt === 1)
    }
    const afterRevoke = await mcpPost(fixture.base, {
      jsonrpc: '2.0',
      id: 10,
      method: 'tools/list',
    })
    assert.equal(afterRevoke.status, 404)
  } finally {
    await closeTestServer(fixture.server)
  }
})

test('raw bearer cookie and unsigned application identity never reach facade clients', async () => {
  const sessions = new MemorySessionStore()
  const verdict = new FakeVerdict()
  const strad = new FakeStrad()
  const server = createFacadeServer({
    config: testConfig(),
    sessions,
    verdict,
    strad,
    now: () => FIXED_NOW,
  })
  const base = await listenTestServer(server)
  try {
    const body = Buffer.from('{}')
    const context = contextForHttp('POST', '/mcp', 'analyze-mcp', body)
    for (const forbidden of [
      { authorization: 'Bearer app_v1_forbidden' },
      { cookie: '__Secure-gw=forbidden' },
      { 'x-application-sub': 'application:attackerattacker' },
    ]) {
      const response = await facadeFetch(`${base}/mcp`, {
        method: 'POST',
        headers: requestHeaders(context, {
          'content-type': 'application/json',
          'mcp-protocol-version': '2025-11-25',
          ...forbidden,
        }),
        body,
      })
      assert.ok([400, 401].includes(response.status))
    }
    assert.equal(verdict.requests.length, 0)
    assert.equal(strad.tools.length, 0)
  } finally {
    await closeTestServer(server)
  }
})

test('configuration rejects defaults equality mutable origin and incomplete keyring', () => {
  const publicKey = KEYRING.get('appctx-2026a')?.publicKey
  assert.ok(publicKey)
  const base = {
    FACADE_DATABASE_URL: 'postgres://facade:facade@127.0.0.1/facade',
    ANALYZE_FACADE_INTERNAL_HOST: 'analyze-facade:18120',
    FACADE_VERDICT_DECISION_URL: 'https://verdict:8443/api/v2/application-check',
    VERDICT_DECISION_TOKEN: 'v'.repeat(32),
    FACADE_STRAD_ORIGIN: 'https://strad:8443/',
    STRAD_FACADE_TOKEN: 's'.repeat(32),
    ACCESS_FACADE_REVOCATION_TOKEN: 'r'.repeat(32),
    SLUICE_APPLICATION_CONTEXT_ACTIVE_KID: 'appctx-2026a',
    SLUICE_APPLICATION_CONTEXT_VERIFICATION_KEYRING: JSON.stringify({
      'appctx-2026a': { public_key: publicKey.toString('base64url'), retired_at: null },
    }),
  }
  assert.equal(loadConfig(base).externalOrigin, 'https://analyze.w33d.xyz/')
  assert.equal(
    loadConfig({ ...base, FACADE_DATABASE_URL: 'postgresql://facade:facade@127.0.0.1/facade' })
      .databaseUrl,
    'postgresql://facade:facade@127.0.0.1/facade'
  )
  assert.throws(() => loadConfig({ ...base, ANALYZE_EXTERNAL_ORIGIN: 'https://other.w33d.xyz' }))
  assert.throws(() => loadConfig({ ...base, STRAD_FACADE_TOKEN: 'v'.repeat(32) }))
  assert.throws(() => loadConfig({ ...base, FACADE_SESSION_IDLE_SECONDS: '901' }))
  assert.throws(() => loadConfig({ ...base, SLUICE_APPLICATION_CONTEXT_VERIFICATION_KEYRING: '{}' }))
  assert.throws(() => loadConfig({ ...base, FACADE_DATABASE_URL: 'https://database.invalid/facade' }))
})

test('runtime import graph excludes Rikune servers', async () => {
  const root = join(dirname(fileURLToPath(import.meta.url)), '../../src')
  const names = (await readdir(root)).filter((name) => name.endsWith('.ts')).sort()
  const source = (
    await Promise.all(names.map((name) => readFile(join(root, name), 'utf8')))
  ).join('\n')
  for (const forbidden of [
    "from '../bridge",
    'src/core/server',
    'AgentGateway',
    'rikune/src',
    'strad-analyzer-bridge/src/server',
  ]) {
    assert.equal(source.includes(forbidden), false, `forbidden runtime import: ${forbidden}`)
  }
})
