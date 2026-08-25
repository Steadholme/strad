import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import type { AddressInfo } from 'node:net'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import test from 'node:test'

import type { BridgeConfig } from '../src/config.js'
import { CHILD_ENV_BASE } from '../src/constants.js'
import { BridgeError } from '../src/errors.js'
import { OperationJournal } from '../src/journal.js'
import type { AnalyzerClient } from '../src/mcp-child.js'
import { closeServer, createBridgeServer } from '../src/server.js'

const token = 'bridge-token-'.padEnd(32, 'x')

class FakeAnalyzer implements AnalyzerClient {
  alive = true
  calls: Array<{ tool: string; args: Record<string, unknown> }> = []
  failure: BridgeError | null = null

  async call(tool: string, args: Record<string, unknown>): Promise<unknown> {
    this.calls.push({ tool, args })
    if (this.failure) throw this.failure
    return { echo: args }
  }

  async probeReady(): Promise<void> {}
  async probeHealth(): Promise<void> {}
  async close(): Promise<void> {}
}

async function fixture(): Promise<{
  base: string
  root: string
  journal: OperationJournal
  analyzer: FakeAnalyzer
  close: () => Promise<void>
}> {
  const root = await mkdtemp(join(tmpdir(), 'strad-server-test-'))
  const journal = new OperationJournal(join(root, 'operations.sqlite'))
  const analyzer = new FakeAnalyzer()
  const config: BridgeConfig = {
    host: '127.0.0.1',
    port: 0,
    bridgeToken: token,
    fileServerApiKey: 'file-server-key-'.padEnd(32, 'y'),
    journalPath: join(root, 'operations.sqlite'),
    spoolRoot: join(root, 'spool'),
    staticLockPath: join(root, 'lock.json'),
    childCommand: '/bin/false',
    childArgs: [],
    childCwd: '/',
    childEnv: CHILD_ENV_BASE,
  }
  const server = createBridgeServer({ config, journal, analyzer })
  await new Promise<void>((resolvePromise) => server.listen(0, '127.0.0.1', resolvePromise))
  const address = server.address() as AddressInfo
  return {
    base: `http://127.0.0.1:${address.port}`,
    root,
    journal,
    analyzer,
    close: async () => {
      await closeServer(server)
      journal.close()
      await rm(root, { recursive: true, force: true })
    },
  }
}

function startBody(): string {
  return JSON.stringify({
    action: 'start',
    sample_id: `sha256:${'a'.repeat(64)}`,
    goal: 'static',
    depth: 'balanced',
    backend_policy: 'auto',
    allow_transformations: false,
    allow_live_execution: false,
    force_refresh: false,
    include_raw_result: false,
  })
}

test('health is public but business routes require exactly valid bearer', async () => {
  const app = await fixture()
  try {
    assert.equal((await fetch(`${app.base}/healthz`)).status, 200)
    const denied = await fetch(`${app.base}/internal/v1/workflows/status`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ action: 'status', plan_id: 'p', include_raw_result: false }),
    })
    assert.equal(denied.status, 401)
    assert.deepEqual(await denied.json(), {
      ok: false,
      error: { code: 'invalid_bridge_credential', retryable: false },
    })
  } finally {
    await app.close()
  }
})

test('mutation binds exact raw body hash and freezes successful replay', async () => {
  const app = await fixture()
  try {
    const body = startBody()
    const operationId = '550e8400-e29b-41d4-a716-446655440010'
    const headers = {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      'x-operation-id': operationId,
      'x-request-sha256': createHash('sha256').update(body).digest('hex'),
    }
    const first = await fetch(`${app.base}/internal/v1/workflows/start`, {
      method: 'POST',
      headers,
      body,
    })
    assert.equal(first.status, 200)
    assert.equal(app.analyzer.calls.length, 1)
    const replay = await fetch(`${app.base}/internal/v1/workflows/start`, {
      method: 'POST',
      headers,
      body,
    })
    assert.equal(replay.status, 200)
    assert.deepEqual(await replay.json(), await first.clone().json().catch(() => undefined))
    assert.equal(app.analyzer.calls.length, 1)
  } finally {
    await app.close()
  }
})

test('strict schema and body hash mismatch fail before analyzer call', async () => {
  const app = await fixture()
  try {
    const body = startBody()
    const baseHeaders = {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      'x-operation-id': '550e8400-e29b-41d4-a716-446655440011',
      'x-request-sha256': '0'.repeat(64),
    }
    const mismatch = await fetch(`${app.base}/internal/v1/workflows/start`, {
      method: 'POST',
      headers: baseHeaders,
      body,
    })
    assert.equal(mismatch.status, 409)
    const extraBody = JSON.stringify({ ...JSON.parse(body), extra: true })
    const invalid = await fetch(`${app.base}/internal/v1/workflows/start`, {
      method: 'POST',
      headers: {
        ...baseHeaders,
        'x-operation-id': '550e8400-e29b-41d4-a716-446655440012',
        'x-request-sha256': createHash('sha256').update(extraBody).digest('hex'),
      },
      body: extraBody,
    })
    assert.equal(invalid.status, 400)
    assert.equal(app.analyzer.calls.length, 0)
  } finally {
    await app.close()
  }
})

test('operation endpoint exposes bounded reconciliation states', async () => {
  const app = await fixture()
  try {
    const operationId = '550e8400-e29b-41d4-a716-446655440013'
    app.journal.begin({
      operationId,
      requestSha256: 'a'.repeat(64),
      kind: 'workflow_run',
      phase: 'mcp_call',
      hardDeadlineAt: new Date(Date.now() + 1_000).toISOString(),
    })
    app.journal.markUnknown(operationId, 'mcp_call')
    const response = await fetch(`${app.base}/internal/v1/operations/${operationId}`, {
      headers: { authorization: `Bearer ${token}` },
    })
    assert.equal(response.status, 200)
    assert.deepEqual(await response.json(), {
      ok: true,
      data: { operation_id: operationId, state: 'unknown' },
    })
  } finally {
    await app.close()
  }
})
