import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  realpathSync,
} from 'node:fs'
import { dirname, resolve } from 'node:path'

import Database from 'better-sqlite3'

import { BridgeError } from './errors.js'

export type OperationState = 'in_flight' | 'succeeded' | 'failed' | 'unknown'

export type OperationRow = {
  operation_id: string
  request_sha256: string
  kind: string
  state: OperationState
  phase: string
  response_status: number | null
  response_json: string | null
  error_code: string | null
  retryable: number | null
  content_length: number | null
  content_sha256: string | null
  spool_path: string | null
  started_at: string
  updated_at: string
  hard_deadline_at: string
  unknown_since: string | null
  resolution_deadline_at: string | null
  dead_lettered_at: string | null
}

export type BeginOperation = {
  operationId: string
  requestSha256: string
  kind: string
  phase: string
  hardDeadlineAt: string
  contentLength?: number
  contentSha256?: string
  spoolPath?: string
}

export class OperationJournal {
  readonly db: Database.Database

  constructor(path: string) {
    const parent = dirname(path)
    mkdirSync(parent, { recursive: true, mode: 0o700 })
    const parentStat = lstatSync(parent)
    if (
      !parentStat.isDirectory() ||
      parentStat.isSymbolicLink() ||
      realpathSync(parent) !== resolve(parent)
    ) {
      throw new Error('bridge journal parent is unsafe')
    }
    if (existsSync(path)) {
      const existing = lstatSync(path)
      if (!existing.isFile() || existing.isSymbolicLink() || existing.nlink !== 1) {
        throw new Error('bridge journal is unsafe')
      }
    }
    this.db = new Database(path)
    chmodSync(path, 0o600)
    const created = lstatSync(path)
    if (!created.isFile() || created.isSymbolicLink() || created.nlink !== 1) {
      this.db.close()
      throw new Error('bridge journal is unsafe after open')
    }
    this.db.pragma('journal_mode = WAL')
    this.db.pragma('synchronous = FULL')
    this.db.pragma('foreign_keys = ON')
    this.db.pragma('busy_timeout = 5000')
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS bridge_operations (
        operation_id TEXT PRIMARY KEY CHECK (
          operation_id GLOB '[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]-*'
        ),
        request_sha256 TEXT NOT NULL CHECK (
          length(request_sha256)=64 AND request_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        kind TEXT NOT NULL,
        state TEXT NOT NULL CHECK (state IN ('in_flight','succeeded','failed','unknown')),
        phase TEXT NOT NULL,
        response_status INTEGER CHECK (response_status IS NULL OR response_status BETWEEN 100 AND 599),
        response_json TEXT,
        error_code TEXT,
        retryable INTEGER CHECK (retryable IS NULL OR retryable IN (0,1)),
        content_length INTEGER,
        content_sha256 TEXT,
        spool_path TEXT,
        started_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        hard_deadline_at TEXT NOT NULL,
        unknown_since TEXT,
        resolution_deadline_at TEXT,
        dead_lettered_at TEXT,
        CHECK ((state IN ('succeeded','failed')) = (response_status IS NOT NULL)),
        CHECK ((state IN ('succeeded','failed')) = (response_json IS NOT NULL))
      );
      CREATE INDEX IF NOT EXISTS bridge_operations_recovery_idx
        ON bridge_operations(state, phase, updated_at);
    `)
    const columns = new Set(
      (this.db.prepare('PRAGMA table_info(bridge_operations)').all() as Array<{ name: string }>).map(
        (column) => column.name
      )
    )
    for (const [name, type] of [
      ['unknown_since', 'TEXT'],
      ['resolution_deadline_at', 'TEXT'],
      ['dead_lettered_at', 'TEXT'],
    ] as const) {
      if (!columns.has(name)) this.db.exec(`ALTER TABLE bridge_operations ADD COLUMN ${name} ${type}`)
    }
  }

  begin(input: BeginOperation): { created: boolean; row: OperationRow } {
    return this.db.transaction(() => {
      const now = new Date().toISOString()
      const result = this.db
        .prepare(
          `INSERT OR IGNORE INTO bridge_operations (
             operation_id, request_sha256, kind, state, phase,
             content_length, content_sha256, spool_path,
             started_at, updated_at, hard_deadline_at
           ) VALUES (?, ?, ?, 'in_flight', ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          input.operationId,
          input.requestSha256,
          input.kind,
          input.phase,
          input.contentLength ?? null,
          input.contentSha256 ?? null,
          input.spoolPath ?? null,
          now,
          now,
          input.hardDeadlineAt
        )
      const row = this.getRequired(input.operationId)
      if (row.request_sha256 !== input.requestSha256 || row.kind !== input.kind) {
        throw new BridgeError(
          409,
          'idempotency_mismatch',
          false,
          'Operation ID is already bound to another request'
        )
      }
      return { created: result.changes === 1, row }
    })()
  }

  get(operationId: string): OperationRow | null {
    return (
      (this.db
        .prepare('SELECT * FROM bridge_operations WHERE operation_id=?')
        .get(operationId) as OperationRow | undefined) ?? null
    )
  }

  private getRequired(operationId: string): OperationRow {
    const row = this.get(operationId)
    if (!row) throw new Error('bridge operation disappeared')
    return row
  }

  setPhase(operationId: string, expectedPhase: string, nextPhase: string): void {
    const result = this.db
      .prepare(
        `UPDATE bridge_operations SET phase=?, updated_at=?
         WHERE operation_id=? AND state='in_flight' AND phase=?`
      )
      .run(nextPhase, new Date().toISOString(), operationId, expectedPhase)
    if (result.changes !== 1) throw new Error('bridge operation phase CAS failed')
  }

  succeed(operationId: string, status: number, body: unknown): OperationRow {
    return this.finish(operationId, 'succeeded', status, body, null, false)
  }

  fail(
    operationId: string,
    status: number,
    body: unknown,
    errorCode: string,
    retryable: boolean
  ): OperationRow {
    return this.finish(operationId, 'failed', status, body, errorCode, retryable)
  }

  private finish(
    operationId: string,
    state: 'succeeded' | 'failed',
    status: number,
    body: unknown,
    errorCode: string | null,
    retryable: boolean
  ): OperationRow {
    const responseJson = JSON.stringify(body)
    const result = this.db
      .prepare(
        `UPDATE bridge_operations
         SET state=?, phase='frozen', response_status=?, response_json=?, error_code=?, retryable=?, updated_at=?
         WHERE operation_id=? AND state='in_flight'`
      )
      .run(
        state,
        status,
        responseJson,
        errorCode,
        retryable ? 1 : 0,
        new Date().toISOString(),
        operationId
      )
    if (result.changes !== 1) {
      const row = this.getRequired(operationId)
      if (row.state === state && row.response_json === responseJson) return row
      throw new Error('bridge operation terminal CAS failed')
    }
    return this.getRequired(operationId)
  }

  markUnknown(operationId: string, expectedPhase?: string): void {
    const now = new Date()
    const deadline = new Date(now.getTime() + 24 * 60 * 60 * 1000)
    const clause = expectedPhase ? ' AND phase=?' : ''
    const values: unknown[] = [
      now.toISOString(),
      now.toISOString(),
      deadline.toISOString(),
      operationId,
    ]
    if (expectedPhase) values.push(expectedPhase)
    const result = this.db
      .prepare(
        `UPDATE bridge_operations
         SET state='unknown', phase='unknown', updated_at=?,
             unknown_since=COALESCE(unknown_since, ?),
             resolution_deadline_at=COALESCE(resolution_deadline_at, ?)
         WHERE operation_id=? AND state='in_flight'${clause}`
      )
      .run(...values)
    if (result.changes !== 1) {
      const row = this.getRequired(operationId)
      if (row.state === 'unknown') return
      throw new Error('bridge operation unknown-state CAS failed')
    }
  }

  markAllMcpInFlightUnknown(): number {
    const now = new Date()
    const deadline = new Date(now.getTime() + 24 * 60 * 60 * 1000)
    const result = this.db
      .prepare(
        `UPDATE bridge_operations
         SET state='unknown', phase='unknown', updated_at=?,
             unknown_since=COALESCE(unknown_since, ?),
             resolution_deadline_at=COALESCE(resolution_deadline_at, ?)
         WHERE state='in_flight' AND phase IN ('mcp_call','upload_call')`
      )
      .run(now.toISOString(), now.toISOString(), deadline.toISOString())
    return result.changes
  }

  listUnknownUploads(limit = 64): OperationRow[] {
    if (!Number.isInteger(limit) || limit < 1 || limit > 256) throw new Error('invalid sweep limit')
    return this.db
      .prepare(
        `SELECT * FROM bridge_operations
         WHERE kind='sample_upload' AND state='unknown' AND phase='unknown'
         ORDER BY unknown_since, operation_id LIMIT ?`
      )
      .all(limit) as OperationRow[]
  }

  resolveUnknownUpload(operationId: string, body: unknown): OperationRow {
    const responseJson = JSON.stringify(body)
    const result = this.db
      .prepare(
        `UPDATE bridge_operations
         SET state='succeeded', phase='frozen', response_status=200, response_json=?,
             error_code=NULL, retryable=0, spool_path=NULL, updated_at=?
         WHERE operation_id=? AND kind='sample_upload' AND state='unknown' AND phase='unknown'`
      )
      .run(responseJson, new Date().toISOString(), operationId)
    if (result.changes !== 1) throw new Error('unknown upload resolution CAS failed')
    return this.getRequired(operationId)
  }

  deadLetterUnknownUpload(operationId: string): OperationRow {
    const now = new Date().toISOString()
    const result = this.db
      .prepare(
        `UPDATE bridge_operations
         SET phase='dead_letter', error_code='unknown_upload_dead_letter', retryable=0,
             spool_path=NULL, dead_lettered_at=?, updated_at=?
         WHERE operation_id=? AND kind='sample_upload' AND state='unknown' AND phase='unknown'`
      )
      .run(now, now, operationId)
    if (result.changes !== 1) throw new Error('unknown upload dead-letter CAS failed')
    return this.getRequired(operationId)
  }

  recoverAfterCrash(): { interruptedUploads: OperationRow[]; verifiedUploads: OperationRow[] } {
    return this.db.transaction(() => {
      const interruptedUploads = this.db
        .prepare(
          `SELECT * FROM bridge_operations
           WHERE kind='sample_upload' AND state='in_flight' AND phase='spooling'`
        )
        .all() as OperationRow[]
      const interruptedBody = {
        error: {
          code: 'upload_interrupted',
          message: 'Upload stream was interrupted before durable verification',
          retryable: true,
        },
      }
      for (const row of interruptedUploads) {
        this.fail(row.operation_id, 503, interruptedBody, 'upload_interrupted', true)
      }
      this.markAllMcpInFlightUnknown()
      const verifiedUploads = this.db
        .prepare(
          `SELECT * FROM bridge_operations
           WHERE kind='sample_upload' AND state='in_flight' AND phase='verified'
           ORDER BY started_at, operation_id`
        )
        .all() as OperationRow[]
      return { interruptedUploads, verifiedUploads }
    })()
  }

  close(): void {
    this.db.close()
  }
}
