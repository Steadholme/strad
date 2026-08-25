import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { createServer } from 'node:http'
import type { IncomingMessage } from 'node:http'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { type AddressInfo } from 'node:net'
import { join } from 'node:path'
import { Readable } from 'node:stream'
import { tmpdir } from 'node:os'
import test from 'node:test'

import type { BridgeConfig } from '../src/config.js'
import { CHILD_ENV_BASE } from '../src/constants.js'
import { OperationJournal } from '../src/journal.js'
import {
  completeUploadOperation,
  parseUploadHeaders,
  prepareSpoolRoot,
  reconcileUnknownUploads,
  spoolUpload,
} from '../src/upload.js'

function configFor(spoolRoot: string, journalPath: string): BridgeConfig {
  return {
    host: '127.0.0.1',
    port: 18090,
    bridgeToken: 'b'.repeat(32),
    fileServerApiKey: 'f'.repeat(32),
    journalPath,
    spoolRoot,
    staticLockPath: '/app/static-profile.lock.json',
    childCommand: '/usr/local/bin/node',
    childArgs: ['/app/dist/index.js'],
    childCwd: '/app',
    childEnv: CHILD_ENV_BASE,
  }
}

function fakeRequest(rawHeaders: string[]): IncomingMessage {
  return Object.assign(Readable.from([]), { rawHeaders }) as IncomingMessage
}

test('upload headers bind operation, exact length, content digest, and request digest', () => {
  const operationId = '550e8400-e29b-41d4-a716-446655440020'
  const contentSha = 'a'.repeat(64)
  const requestSha = createHash('sha256').update(`sample-upload\n4\n${contentSha}`).digest('hex')
  assert.deepEqual(
    parseUploadHeaders(
      fakeRequest([
        'Content-Type',
        'application/octet-stream',
        'Content-Length',
        '4',
        'X-Content-SHA256',
        contentSha,
        'X-Operation-ID',
        operationId,
        'X-Request-SHA256',
        requestSha,
      ])
    ),
    { operationId, requestSha256: requestSha, contentSha256: contentSha, contentLength: 4 }
  )
})

test('spool write fsyncs, renames, validates digest, and advances journal phase', async () => {
  const root = await mkdtemp(join(tmpdir(), 'strad-upload-test-'))
  const spoolRoot = join(root, 'spool')
  await prepareSpoolRoot(spoolRoot)
  const journal = new OperationJournal(join(root, 'operations.sqlite'))
  try {
    const bytes = Buffer.from('durable upload')
    const upload = {
      operationId: '550e8400-e29b-41d4-a716-446655440021',
      requestSha256: 'a'.repeat(64),
      contentSha256: createHash('sha256').update(bytes).digest('hex'),
      contentLength: bytes.length,
    }
    const finalPath = join(spoolRoot, `${upload.operationId}.bin`)
    journal.begin({
      ...upload,
      kind: 'sample_upload',
      phase: 'spooling',
      spoolPath: finalPath,
      hardDeadlineAt: new Date(Date.now() + 60_000).toISOString(),
    })
    const request = Object.assign(Readable.from([bytes.subarray(0, 4), bytes.subarray(4)]), {
      rawHeaders: [],
    }) as unknown as IncomingMessage
    assert.equal(await spoolUpload(request, spoolRoot, upload, journal), finalPath)
    assert.deepEqual(await readFile(finalPath), bytes)
    assert.equal(journal.get(upload.operationId)?.phase, 'verified')
  } finally {
    journal.close()
    await rm(root, { recursive: true, force: true })
  }
})

test('spool digest mismatch never becomes verified', async () => {
  const root = await mkdtemp(join(tmpdir(), 'strad-upload-test-'))
  const spoolRoot = join(root, 'spool')
  await prepareSpoolRoot(spoolRoot)
  const journal = new OperationJournal(join(root, 'operations.sqlite'))
  try {
    const bytes = Buffer.from('bad digest')
    const upload = {
      operationId: '550e8400-e29b-41d4-a716-446655440022',
      requestSha256: 'a'.repeat(64),
      contentSha256: '0'.repeat(64),
      contentLength: bytes.length,
    }
    journal.begin({
      ...upload,
      kind: 'sample_upload',
      phase: 'spooling',
      spoolPath: join(spoolRoot, `${upload.operationId}.bin`),
      hardDeadlineAt: new Date(Date.now() + 60_000).toISOString(),
    })
    const request = Object.assign(Readable.from([bytes]), {
      rawHeaders: [],
    }) as unknown as IncomingMessage
    await assert.rejects(() => spoolUpload(request, spoolRoot, upload, journal))
    assert.equal(journal.get(upload.operationId)?.phase, 'spooling')
  } finally {
    journal.close()
    await rm(root, { recursive: true, force: true })
  }
})

test('successful downstream upload is unknown when durable spool cleanup fails', async () => {
  const root = await mkdtemp(join(tmpdir(), 'strad-upload-test-'))
  const spoolRoot = join(root, 'spool')
  const journalPath = join(root, 'operations.sqlite')
  await prepareSpoolRoot(spoolRoot)
  const journal = new OperationJournal(journalPath)
  try {
    const bytes = Buffer.from('committed downstream')
    const operationId = '550e8400-e29b-41d4-a716-446655440023'
    const contentSha256 = createHash('sha256').update(bytes).digest('hex')
    const spoolPath = join(spoolRoot, `${operationId}.bin`)
    await writeFile(spoolPath, bytes, { mode: 0o600 })
    journal.begin({
      operationId,
      requestSha256: 'a'.repeat(64),
      kind: 'sample_upload',
      phase: 'spooling',
      spoolPath,
      contentLength: bytes.length,
      contentSha256,
      hardDeadlineAt: new Date(Date.now() + 60_000).toISOString(),
    })
    journal.setPhase(operationId, 'spooling', 'verified')
    const row = journal.get(operationId)
    assert.ok(row)
    const completed = await completeUploadOperation(row, configFor(spoolRoot, journalPath), journal, {
      send: async () => ({ sample_id: `sha256:${contentSha256}`, file_type: 'text/plain' }),
      remove: async () => {
        throw new Error('injected fsync failure')
      },
    })
    assert.equal(completed.state, 'unknown')
    assert.equal(completed.response_status, null)
    assert.ok(completed.resolution_deadline_at)
    assert.deepEqual(await readFile(spoolPath), bytes)
  } finally {
    journal.close()
    await rm(root, { recursive: true, force: true })
  }
})

test('unknown uploads resolve or dead-letter within the frozen 24-hour bound', async () => {
  const root = await mkdtemp(join(tmpdir(), 'strad-upload-test-'))
  const spoolRoot = join(root, 'spool')
  const journalPath = join(root, 'operations.sqlite')
  await prepareSpoolRoot(spoolRoot)
  const journal = new OperationJournal(journalPath)
  try {
    const createUnknown = async (operationId: string, bytes: Buffer): Promise<string> => {
      const contentSha256 = createHash('sha256').update(bytes).digest('hex')
      const spoolPath = join(spoolRoot, `${operationId}.bin`)
      await writeFile(spoolPath, bytes, { mode: 0o600 })
      journal.begin({
        operationId,
        requestSha256: 'a'.repeat(64),
        kind: 'sample_upload',
        phase: 'spooling',
        spoolPath,
        contentLength: bytes.length,
        contentSha256,
        hardDeadlineAt: new Date(Date.now() + 60_000).toISOString(),
      })
      journal.setPhase(operationId, 'spooling', 'verified')
      journal.setPhase(operationId, 'verified', 'upload_call')
      journal.markUnknown(operationId, 'upload_call')
      return spoolPath
    }
    const resolvedId = '550e8400-e29b-41d4-a716-446655440024'
    const expiredId = '550e8400-e29b-41d4-a716-446655440025'
    const resolvedPath = await createUnknown(resolvedId, Buffer.from('remote exists'))
    const expiredPath = await createUnknown(expiredId, Buffer.from('remote absent'))

    const first = await reconcileUnknownUploads(configFor(spoolRoot, journalPath), journal, {
      lookup: async (row) =>
        row.operation_id === resolvedId ? { fileType: 'application/octet-stream' } : null,
    })
    assert.deepEqual(first, { resolved: 1, deadLettered: 0, pending: 1 })
    assert.equal(journal.get(resolvedId)?.state, 'succeeded')
    await assert.rejects(() => readFile(resolvedPath), { code: 'ENOENT' })

    journal.db
      .prepare('UPDATE bridge_operations SET resolution_deadline_at=? WHERE operation_id=?')
      .run(new Date(Date.now() - 1).toISOString(), expiredId)
    const second = await reconcileUnknownUploads(configFor(spoolRoot, journalPath), journal, {
      lookup: async () => null,
      nowMs: Date.now(),
    })
    assert.deepEqual(second, { resolved: 0, deadLettered: 1, pending: 0 })
    assert.equal(journal.get(expiredId)?.phase, 'dead_letter')
    assert.equal(journal.get(expiredId)?.error_code, 'unknown_upload_dead_letter')
    assert.ok(journal.get(expiredId)?.dead_lettered_at)
    await assert.rejects(() => readFile(expiredPath), { code: 'ENOENT' })
  } finally {
    journal.close()
    await rm(root, { recursive: true, force: true })
  }
})
