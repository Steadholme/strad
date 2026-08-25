import assert from 'node:assert/strict'
import { mkdtemp, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import test from 'node:test'

import { BridgeError } from '../src/errors.js'
import { OperationJournal } from '../src/journal.js'

async function withJournal(
  run: (journal: OperationJournal, root: string) => Promise<void> | void
): Promise<void> {
  const root = await mkdtemp(join(tmpdir(), 'strad-journal-test-'))
  const journal = new OperationJournal(join(root, 'state', 'operations.sqlite'))
  try {
    await run(journal, root)
  } finally {
    journal.close()
    await rm(root, { recursive: true, force: true })
  }
}

const operation = {
  operationId: '550e8400-e29b-41d4-a716-446655440000',
  requestSha256: 'a'.repeat(64),
  kind: 'workflow_run',
  phase: 'mcp_call',
  hardDeadlineAt: new Date(Date.now() + 60_000).toISOString(),
}

test('operation IDs bind request hash and kind permanently', async () => {
  await withJournal((journal) => {
    assert.equal(journal.begin(operation).created, true)
    assert.equal(journal.begin(operation).created, false)
    assert.throws(
      () => journal.begin({ ...operation, requestSha256: 'b'.repeat(64) }),
      (error: unknown) => error instanceof BridgeError && error.code === 'idempotency_mismatch'
    )
    assert.throws(
      () => journal.begin({ ...operation, kind: 'sample_delete' }),
      (error: unknown) => error instanceof BridgeError && error.code === 'idempotency_mismatch'
    )
  })
})

test('terminal response freezes and cannot be overwritten', async () => {
  await withJournal((journal) => {
    journal.begin(operation)
    const completed = journal.succeed(operation.operationId, 200, { ok: true, data: { id: 1 } })
    assert.equal(completed.state, 'succeeded')
    assert.throws(() =>
      journal.fail(
        operation.operationId,
        503,
        { ok: false, error: { code: 'late', retryable: true } },
        'late',
        true
      )
    )
  })
})

test('crash recovery separates interrupted, verified, and ambiguous uploads', async () => {
  await withJournal((journal, root) => {
    const base = {
      ...operation,
      kind: 'sample_upload',
      contentLength: 4,
      contentSha256: 'b'.repeat(64),
      spoolPath: join(root, 'spool.bin'),
    }
    journal.begin({ ...base, operationId: '550e8400-e29b-41d4-a716-446655440001', phase: 'spooling' })
    journal.begin({ ...base, operationId: '550e8400-e29b-41d4-a716-446655440002', phase: 'spooling' })
    journal.setPhase('550e8400-e29b-41d4-a716-446655440002', 'spooling', 'verified')
    journal.begin({ ...base, operationId: '550e8400-e29b-41d4-a716-446655440003', phase: 'spooling' })
    journal.setPhase('550e8400-e29b-41d4-a716-446655440003', 'spooling', 'verified')
    journal.setPhase('550e8400-e29b-41d4-a716-446655440003', 'verified', 'upload_call')

    const recovered = journal.recoverAfterCrash()
    assert.equal(recovered.interruptedUploads.length, 1)
    assert.equal(recovered.verifiedUploads.length, 1)
    assert.equal(journal.get('550e8400-e29b-41d4-a716-446655440001')?.state, 'failed')
    assert.equal(journal.get('550e8400-e29b-41d4-a716-446655440002')?.state, 'in_flight')
    assert.equal(journal.get('550e8400-e29b-41d4-a716-446655440003')?.state, 'unknown')
  })
})

test('unknown transition is deadline-bound and rejects an unexpected phase', async () => {
  await withJournal((journal) => {
    journal.begin(operation)
    assert.throws(
      () => journal.markUnknown(operation.operationId, 'upload_call'),
      /unknown-state CAS failed/
    )
    journal.markUnknown(operation.operationId, 'mcp_call')
    const row = journal.get(operation.operationId)
    assert.equal(row?.state, 'unknown')
    assert.ok(row?.unknown_since)
    assert.ok(row?.resolution_deadline_at)
    const bound = Date.parse(row?.resolution_deadline_at ?? '') - Date.parse(row?.unknown_since ?? '')
    assert.equal(bound, 24 * 60 * 60 * 1000)
  })
})
