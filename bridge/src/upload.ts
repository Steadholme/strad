import { createHash, randomUUID } from 'node:crypto'
import { createReadStream } from 'node:fs'
import {
  lstat,
  mkdir,
  open,
  readdir,
  realpath,
  rename,
  unlink,
} from 'node:fs/promises'
import type { IncomingMessage } from 'node:http'
import http from 'node:http'
import { once } from 'node:events'
import { basename, join, resolve } from 'node:path'

import { z } from 'zod'

import { MAX_CHILD_RESPONSE_BYTES, MAX_UPLOAD_BYTES } from './constants.js'
import type { BridgeConfig } from './config.js'
import { BridgeError, safeBridgeError } from './errors.js'
import type { OperationJournal, OperationRow } from './journal.js'
import {
  constantTimeDigestEqual,
  requireOperationId,
  requireRequestSha,
  SHA256_PATTERN,
  sha256Hex,
  singleHeader,
} from './security.js'

const uploadResponseSchema = z
  .object({
    ok: z.literal(true),
    data: z
      .object({
        sample_id: z.string().regex(/^sha256:[0-9a-f]{64}$/),
        filename: z.string(),
        size: z.number().int().min(1).max(MAX_UPLOAD_BYTES),
        uploaded_at: z.string(),
        existed: z.boolean(),
        file_type: z.string().min(1).max(128),
      })
      .strict(),
  })
  .strict()

const sampleLookupResponseSchema = z
  .object({
    ok: z.literal(true),
    data: z
      .object({
        sample_id: z.string().regex(/^sha256:[0-9a-f]{64}$/),
        size: z.number().int().min(1).max(MAX_UPLOAD_BYTES),
        uploaded_at: z.string().min(1).max(128),
        file_type: z.string().min(1).max(128),
        analyses: z
          .array(
            z
              .object({
                id: z.string().min(1).max(256),
                stage: z.string().min(1).max(128),
                status: z.string().min(1).max(128),
                completed_at: z.string().nullable(),
              })
              .strict()
          )
          .max(4096),
        download_url: z.string().url().max(2048),
      })
      .strict(),
  })
  .strict()

type UploadCompletionDependencies = {
  readonly send?: typeof sendMultipartToChild
  readonly remove?: (path: string, root: string, allowMissing: boolean) => Promise<void>
  readonly now?: () => number
}

export type UnknownUploadLookup = (
  row: OperationRow,
  config: BridgeConfig
) => Promise<{ readonly fileType: string } | null>

export type UnknownUploadSweepOptions = {
  readonly lookup?: UnknownUploadLookup
  readonly nowMs?: number
  readonly limit?: number
}

export type UploadStart = {
  readonly operationId: string
  readonly requestSha256: string
  readonly contentSha256: string
  readonly contentLength: number
}

export function parseUploadHeaders(req: IncomingMessage): UploadStart {
  if (singleHeader(req, 'content-type')?.toLowerCase() !== 'application/octet-stream') {
    throw new BridgeError(
      400,
      'invalid_request',
      false,
      'Content-Type must be application/octet-stream'
    )
  }
  if (singleHeader(req, 'transfer-encoding', false) !== null) {
    throw new BridgeError(400, 'invalid_request', false, 'Transfer-Encoding is not supported')
  }
  if (singleHeader(req, 'content-encoding', false) !== null) {
    throw new BridgeError(400, 'invalid_request', false, 'Content-Encoding is not supported')
  }
  const lengthHeader = singleHeader(req, 'content-length')
  if (!lengthHeader || !/^[1-9][0-9]*$/.test(lengthHeader)) {
    throw new BridgeError(400, 'invalid_request', false, 'A positive Content-Length is required')
  }
  const contentLength = Number(lengthHeader)
  if (!Number.isSafeInteger(contentLength) || contentLength > MAX_UPLOAD_BYTES) {
    throw new BridgeError(413, 'file_too_large', false, 'Sample exceeds the 500 MiB limit')
  }
  const contentSha256 = singleHeader(req, 'x-content-sha256')
  if (!contentSha256 || !SHA256_PATTERN.test(contentSha256)) {
    throw new BridgeError(400, 'invalid_request', false, 'X-Content-SHA256 is invalid')
  }
  const operationId = requireOperationId(req)
  const requestSha256 = requireRequestSha(req)
  const computedRequestSha = sha256Hex(
    `sample-upload\n${contentLength}\n${contentSha256}`
  )
  if (!constantTimeDigestEqual(requestSha256, computedRequestSha)) {
    throw new BridgeError(409, 'idempotency_mismatch', false, 'Upload request hash mismatch')
  }
  return { operationId, requestSha256, contentSha256, contentLength }
}

async function syncDirectory(path: string): Promise<void> {
  const directory = await open(path, 'r')
  try {
    await directory.sync()
  } finally {
    await directory.close()
  }
}

async function durableRemoveSpool(
  path: string,
  root: string,
  allowMissing: boolean
): Promise<void> {
  try {
    await unlink(path)
  } catch (error) {
    if (!allowMissing || (error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
  }
  await syncDirectory(root)
}

export async function prepareSpoolRoot(path: string): Promise<void> {
  await mkdir(path, { recursive: true, mode: 0o700 })
  const [stat, canonical] = await Promise.all([lstat(path), realpath(path)])
  if (
    !stat.isDirectory() ||
    stat.isSymbolicLink() ||
    canonical !== resolve(path) ||
    (stat.mode & 0o777) !== 0o700 ||
    (process.getuid !== undefined && stat.uid !== process.getuid()) ||
    (process.getgid !== undefined && stat.gid !== process.getgid())
  ) {
    throw new Error('bridge spool root is not a canonical directory')
  }
}

async function assertVerifiedSpool(
  path: string,
  expectedLength: number,
  expectedSha256: string
): Promise<void> {
  const stat = await lstat(path)
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size !== expectedLength) {
    throw new Error('verified upload spool metadata mismatch')
  }
  const digest = createHash('sha256')
  for await (const chunk of createReadStream(path)) digest.update(chunk as Buffer)
  if (!constantTimeDigestEqual(digest.digest('hex'), expectedSha256)) {
    throw new Error('verified upload spool digest mismatch')
  }
}

export async function spoolUpload(
  req: IncomingMessage,
  root: string,
  upload: UploadStart,
  journal: OperationJournal
): Promise<string> {
  const partPath = join(root, `${upload.operationId}.part`)
  const finalPath = join(root, `${upload.operationId}.bin`)
  const file = await open(partPath, 'wx', 0o600)
  const digest = createHash('sha256')
  let bytesWritten = 0
  let closed = false
  try {
    for await (const chunk of req) {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
      bytesWritten += bytes.length
      if (bytesWritten > upload.contentLength || bytesWritten > MAX_UPLOAD_BYTES) {
        throw new BridgeError(400, 'invalid_upload', false, 'Upload body exceeds Content-Length')
      }
      digest.update(bytes)
      await file.write(bytes)
    }
    if (bytesWritten !== upload.contentLength) {
      throw new BridgeError(400, 'invalid_upload', false, 'Upload body length mismatch')
    }
    const actualSha = digest.digest('hex')
    if (!constantTimeDigestEqual(actualSha, upload.contentSha256)) {
      throw new BridgeError(400, 'invalid_upload', false, 'Upload body digest mismatch')
    }
    await file.sync()
    await file.close()
    closed = true
    await rename(partPath, finalPath)
    await syncDirectory(root)
    await assertVerifiedSpool(finalPath, upload.contentLength, upload.contentSha256)
    journal.setPhase(upload.operationId, 'spooling', 'verified')
    return finalPath
  } catch (error) {
    if (!closed) await file.close().catch(() => undefined)
    await unlink(partPath).catch(() => undefined)
    throw error
  }
}

async function readBoundedResponse(response: http.IncomingMessage): Promise<Buffer> {
  const declared = response.headers['content-length']
  if (
    typeof declared === 'string' &&
    (!/^[0-9]+$/.test(declared) || Number(declared) > MAX_CHILD_RESPONSE_BYTES)
  ) {
    response.destroy()
    throw new Error('child response is too large')
  }
  const chunks: Buffer[] = []
  let total = 0
  for await (const chunk of response) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
    total += bytes.length
    if (total > MAX_CHILD_RESPONSE_BYTES) {
      response.destroy()
      throw new Error('child response is too large')
    }
    chunks.push(bytes)
  }
  return Buffer.concat(chunks, total)
}

async function sendMultipartToChild(
  path: string,
  upload: Pick<UploadStart, 'contentLength' | 'contentSha256'>,
  apiKey: string,
  hardTimeoutMs: number
): Promise<unknown> {
  const boundary = `strad-${randomUUID()}`
  const prefix = Buffer.from(
    `--${boundary}\r\n` +
      'Content-Disposition: form-data; name="file"; filename="sample.bin"\r\n' +
      'Content-Type: application/octet-stream\r\n\r\n',
    'utf8'
  )
  const suffix = Buffer.from(`\r\n--${boundary}--\r\n`, 'utf8')
  const contentLength = prefix.length + upload.contentLength + suffix.length

  return await new Promise<unknown>((resolvePromise, rejectPromise) => {
    let connected = false
    let settled = false
    let request: http.ClientRequest
    let hardTimer: NodeJS.Timeout
    const resolveOnce = (value: unknown): void => {
      if (settled) return
      settled = true
      clearTimeout(hardTimer)
      resolvePromise(value)
    }
    const rejectOnce = (error: unknown): void => {
      if (settled) return
      settled = true
      clearTimeout(hardTimer)
      rejectPromise(error)
    }
    request = http.request(
      {
        hostname: '127.0.0.1',
        port: 18080,
        path: '/api/v1/samples',
        method: 'POST',
        headers: {
          'content-type': `multipart/form-data; boundary=${boundary}`,
          'content-length': String(contentLength),
          'x-api-key': apiKey,
          connection: 'close',
        },
        agent: false,
      },
      async (response) => {
        try {
          const bytes = await readBoundedResponse(response)
          if (response.statusCode !== 201) {
            throw new BridgeError(
              502,
              'analyzer_contract_violation',
              false,
              'Analyzer upload endpoint rejected the frozen request'
            )
          }
          if (!(response.headers['content-type'] ?? '').toString().startsWith('application/json')) {
            throw new BridgeError(
              502,
              'analyzer_contract_violation',
              false,
              'Analyzer upload response is not JSON'
            )
          }
          const parsed = uploadResponseSchema.parse(JSON.parse(bytes.toString('utf8')) as unknown)
          if (
            parsed.data.sample_id !== `sha256:${upload.contentSha256}` ||
            parsed.data.size !== upload.contentLength
          ) {
            throw new BridgeError(
              502,
              'analyzer_contract_violation',
              false,
              'Analyzer upload sample identity mismatch'
            )
          }
          resolveOnce({
            sample_id: parsed.data.sample_id,
            file_type: parsed.data.file_type,
          })
        } catch (error) {
          rejectOnce(
            error instanceof BridgeError
              ? error
              : new BridgeError(
                  502,
                  'analyzer_contract_violation',
                  false,
                  'Analyzer upload response violates its schema'
                )
          )
        }
      }
    )
    request.on('socket', (socket) => {
      socket.once('connect', () => {
        connected = true
      })
    })
    request.on('error', (error) => {
      const uncertain = connected
        ? new BridgeError(
            503,
            'downstream_uncertain',
            false,
            'Analyzer upload outcome is uncertain',
            5
          )
        : new BridgeError(503, 'analyzer_unavailable', true, 'Analyzer is unavailable', 5)
      rejectOnce(Object.assign(uncertain, { cause: error }))
    })
    hardTimer = setTimeout(() => {
      const timeout = new BridgeError(
        503,
        connected ? 'downstream_uncertain' : 'analyzer_unavailable',
        !connected,
        connected
          ? 'Analyzer upload outcome is uncertain'
          : 'Analyzer upload did not connect before its hard deadline',
        5
      )
      request.destroy(timeout)
      rejectOnce(timeout)
    }, hardTimeoutMs)
    hardTimer.unref()

    void (async () => {
      try {
        if (!request.write(prefix)) await once(request, 'drain')
        for await (const chunk of createReadStream(path)) {
          if (!request.write(chunk)) await once(request, 'drain')
        }
        request.end(suffix)
      } catch (error) {
        request.destroy(error as Error)
      }
    })()
  })
}

export async function completeUploadOperation(
  row: OperationRow,
  config: BridgeConfig,
  journal: OperationJournal,
  dependencies: UploadCompletionDependencies = {}
): Promise<OperationRow> {
  if (
    row.content_length === null ||
    row.content_sha256 === null ||
    row.spool_path === null ||
    basename(row.spool_path) !== `${row.operation_id}.bin` ||
    resolve(row.spool_path) !== join(resolve(config.spoolRoot), `${row.operation_id}.bin`)
  ) {
    throw new Error('upload journal has an invalid spool locator')
  }
  const now = dependencies.now ?? Date.now
  const remove = dependencies.remove ?? durableRemoveSpool
  const send = dependencies.send ?? sendMultipartToChild
  const freezeUnknown = (expectedPhase: string): OperationRow => {
    journal.markUnknown(row.operation_id, expectedPhase)
    const unknown = journal.get(row.operation_id)
    if (!unknown) throw new Error('upload operation disappeared')
    return unknown
  }
  try {
    await assertVerifiedSpool(row.spool_path, row.content_length, row.content_sha256)
  } catch {
    try {
      await remove(row.spool_path, config.spoolRoot, false)
    } catch {
      return freezeUnknown('verified')
    }
    return journal.fail(
      row.operation_id,
      500,
      { ok: false, error: { code: 'spool_integrity_violation', retryable: false } },
      'spool_integrity_violation',
      false
    )
  }
  const hardDeadline = Date.parse(row.hard_deadline_at)
  const remainingMs = hardDeadline - now()
  if (!Number.isFinite(hardDeadline) || remainingMs <= 0) {
    try {
      await remove(row.spool_path, config.spoolRoot, false)
    } catch {
      return freezeUnknown('verified')
    }
    const failed = journal.fail(
      row.operation_id,
      503,
      { ok: false, error: { code: 'upload_deadline_exceeded', retryable: true } },
      'upload_deadline_exceeded',
      true
    )
    return failed
  }
  journal.setPhase(row.operation_id, 'verified', 'upload_call')
  try {
    const data = await send(
      row.spool_path,
      { contentLength: row.content_length, contentSha256: row.content_sha256 },
      config.fileServerApiKey,
      remainingMs
    )
    try {
      await remove(row.spool_path, config.spoolRoot, false)
    } catch {
      return freezeUnknown('upload_call')
    }
    const body = { ok: true, data }
    return journal.succeed(row.operation_id, 200, body)
  } catch (error) {
    const safe = safeBridgeError(error)
    if (safe.code === 'downstream_uncertain' || safe.code === 'analyzer_contract_violation') {
      return freezeUnknown('upload_call')
    }
    try {
      await remove(row.spool_path, config.spoolRoot, false)
    } catch {
      return freezeUnknown('upload_call')
    }
    const failed = journal.fail(
      row.operation_id,
      safe.status,
      { ok: false, error: { code: safe.code, retryable: safe.retryable } },
      safe.code,
      safe.retryable
    )
    return failed
  }
}

function validateUnknownSpoolLocator(row: OperationRow, config: BridgeConfig): string | null {
  if (row.spool_path === null) return null
  if (
    basename(row.spool_path) !== `${row.operation_id}.bin` ||
    resolve(row.spool_path) !== join(resolve(config.spoolRoot), `${row.operation_id}.bin`)
  ) {
    throw new Error('unknown upload journal has an invalid spool locator')
  }
  return row.spool_path
}

export const lookupAnalyzerSample: UnknownUploadLookup = async (row, config) => {
  if (row.content_sha256 === null || row.content_length === null) {
    throw new Error('unknown upload lacks its immutable content identity')
  }
  const expectedSampleId = `sha256:${row.content_sha256}`
  const response = await fetch(
    `http://127.0.0.1:18080/api/v1/samples/${encodeURIComponent(expectedSampleId)}`,
    {
      method: 'GET',
      headers: { 'x-api-key': config.fileServerApiKey, connection: 'close' },
      redirect: 'error',
      signal: AbortSignal.timeout(5_000),
    }
  )
  const declared = response.headers.get('content-length')
  if (
    declared !== null &&
    (!/^[0-9]+$/.test(declared) || Number(declared) > MAX_CHILD_RESPONSE_BYTES)
  ) {
    await response.body?.cancel()
    throw new Error('analyzer reconciliation response is too large')
  }
  if (response.status === 404) {
    await response.body?.cancel()
    return null
  }
  if (response.status !== 200 || !response.body) {
    await response.body?.cancel()
    throw new Error('analyzer reconciliation endpoint failed')
  }
  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      total += value.byteLength
      if (total > MAX_CHILD_RESPONSE_BYTES) {
        await reader.cancel()
        throw new Error('analyzer reconciliation response is too large')
      }
      chunks.push(value)
    }
  } finally {
    reader.releaseLock()
  }
  const bytes = Buffer.concat(chunks.map((chunk) => Buffer.from(chunk)), total)
  const parsed = sampleLookupResponseSchema.parse(JSON.parse(bytes.toString('utf8')) as unknown)
  if (parsed.data.sample_id !== expectedSampleId || parsed.data.size !== row.content_length) {
    throw new Error('analyzer reconciliation identity mismatch')
  }
  return { fileType: parsed.data.file_type }
}

export async function reconcileUnknownUploads(
  config: BridgeConfig,
  journal: OperationJournal,
  options: UnknownUploadSweepOptions = {}
): Promise<{ readonly resolved: number; readonly deadLettered: number; readonly pending: number }> {
  const lookup = options.lookup ?? lookupAnalyzerSample
  const nowMs = options.nowMs ?? Date.now()
  const rows = journal.listUnknownUploads(options.limit ?? 16)
  let resolved = 0
  let deadLettered = 0
  let pending = 0
  await Promise.all(
    rows.map(async (row) => {
      const deadline = row.resolution_deadline_at
        ? Date.parse(row.resolution_deadline_at)
        : Number.NaN
      if (!Number.isFinite(deadline)) {
        throw new Error('unknown upload lacks a valid resolution deadline')
      }
      let found: { readonly fileType: string } | null = null
      try {
        found = await lookup(row, config)
      } catch {
        // Lookup errors stay retryable only until the immutable 24-hour deadline.
      }
      const spoolPath = validateUnknownSpoolLocator(row, config)
      if (found) {
        if (spoolPath) await durableRemoveSpool(spoolPath, config.spoolRoot, true)
        journal.resolveUnknownUpload(row.operation_id, {
          ok: true,
          data: { sample_id: `sha256:${row.content_sha256}`, file_type: found.fileType },
        })
        resolved += 1
        return
      }
      if (nowMs >= deadline) {
        if (spoolPath) await durableRemoveSpool(spoolPath, config.spoolRoot, true)
        journal.deadLetterUnknownUpload(row.operation_id)
        deadLettered += 1
        return
      }
      pending += 1
    })
  )
  return { resolved, deadLettered, pending }
}

export async function cleanOrphanSpools(
  root: string,
  journal: OperationJournal
): Promise<void> {
  const entries = await readdir(root, { withFileTypes: true })
  for (const entry of entries) {
    if (!/^[0-9a-f-]{36}\.(?:part|bin)$/.test(entry.name)) {
      throw new Error('unexpected entry in dedicated bridge spool root')
    }
    const path = join(root, entry.name)
    const stat = await lstat(path)
    if (!entry.isFile() || !stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) {
      throw new Error('unsafe orphan spool entry')
    }
    const operationId = entry.name.slice(0, 36)
    const row = journal.get(operationId)
    const keep =
      entry.name.endsWith('.bin') &&
      row !== null &&
      row.spool_path === join(root, entry.name) &&
      (row.phase === 'verified' || row.phase === 'upload_call' || row.state === 'unknown')
    if (keep) continue
    await unlink(path)
  }
  await syncDirectory(root)
}
