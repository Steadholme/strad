import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'

import { ZodError } from 'zod'

import { MAX_MCP_RESPONSE_BYTES, ROUTES } from './constants.js'
import type { BridgeConfig } from './config.js'
import { BridgeError, safeBridgeError } from './errors.js'
import { readJsonBody, sendJson } from './http-utils.js'
import type { OperationJournal, OperationRow } from './journal.js'
import type { AnalyzerClient } from './mcp-child.js'
import {
  authenticate,
  constantTimeDigestEqual,
  requireOperationId,
  requireRequestSha,
  sha256Hex,
  UUID_PATTERN,
} from './security.js'
import { parseRouteBody } from './schemas.js'
import {
  completeUploadOperation,
  parseUploadHeaders,
  spoolUpload,
} from './upload.js'

type BridgeDependencies = {
  readonly config: BridgeConfig
  readonly journal: OperationJournal
  readonly analyzer: AnalyzerClient
}

function errorBody(error: BridgeError): unknown {
  return { ok: false, error: { code: error.code, retryable: error.retryable } }
}

function operationState(row: OperationRow): 'pending' | 'succeeded' | 'failed' | 'unknown' {
  return row.state === 'in_flight' ? 'pending' : row.state
}

function parseFrozen(row: OperationRow): Record<string, unknown> {
  if (!row.response_json) throw new Error('terminal operation lacks frozen response')
  const parsed = JSON.parse(row.response_json) as unknown
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error('frozen response is invalid')
  }
  return parsed as Record<string, unknown>
}

function sendFrozen(response: ServerResponse, row: OperationRow): void {
  if (row.state === 'succeeded' || row.state === 'failed') {
    if (row.response_status === null) throw new Error('terminal operation lacks status')
    sendJson(response, row.response_status, parseFrozen(row))
    return
  }
  sendJson(response, 202, {
    ok: true,
    data: {
      operation_id: row.operation_id,
      state: 'pending',
      status_url: `/internal/v1/operations/${row.operation_id}`,
    },
  })
}

function sendOperation(response: ServerResponse, row: OperationRow): void {
  const state = operationState(row)
  const data: Record<string, unknown> = { operation_id: row.operation_id, state }
  if (row.state === 'succeeded') {
    const frozen = parseFrozen(row)
    data.result = frozen.data
  } else if (row.state === 'failed') {
    const frozen = parseFrozen(row)
    data.error = frozen.error
  }
  sendJson(response, 200, { ok: true, data })
}

async function waitForOperation(
  operation: Promise<OperationRow>,
  waiterMs: number
): Promise<OperationRow | null> {
  let timer: NodeJS.Timeout | undefined
  const timeout = new Promise<null>((resolvePromise) => {
    timer = setTimeout(() => resolvePromise(null), waiterMs)
    timer.unref()
  })
  try {
    return await Promise.race([operation, timeout])
  } finally {
    if (timer) clearTimeout(timer)
  }
}

function ensureResponseBounded(data: unknown, limit: number): void {
  const bytes = Buffer.byteLength(JSON.stringify(data), 'utf8')
  if (bytes > limit) {
    throw new BridgeError(
      502,
      'analyzer_contract_violation',
      false,
      'Analyzer response exceeds its frozen bound'
    )
  }
}

async function executeMutation(
  operationId: string,
  tool: string,
  args: Record<string, unknown>,
  hardMs: number,
  responseLimit: number,
  journal: OperationJournal,
  analyzer: AnalyzerClient
): Promise<OperationRow> {
  try {
    const data = await analyzer.call(tool, args, hardMs)
    ensureResponseBounded(data, responseLimit)
    return journal.succeed(operationId, 200, { ok: true, data })
  } catch (error) {
    const safe = safeBridgeError(error)
    const current = journal.get(operationId)
    if (!current) throw new Error('bridge operation disappeared')
    if (current.state !== 'in_flight') return current
    if (safe.code === 'downstream_uncertain') {
      journal.markUnknown(operationId, 'mcp_call')
      const unknown = journal.get(operationId)
      if (!unknown) throw new Error('bridge operation disappeared')
      return unknown
    }
    return journal.fail(
      operationId,
      safe.status,
      errorBody(safe),
      safe.code,
      safe.retryable
    )
  }
}

async function handleJsonRoute(
  req: IncomingMessage,
  response: ServerResponse,
  pathname: string,
  dependencies: BridgeDependencies
): Promise<void> {
  const spec = ROUTES[pathname]
  if (!spec) throw new BridgeError(404, 'not_found', false, 'Route not found')
  const { raw, value } = await readJsonBody(req)
  const args = parseRouteBody(pathname, value)

  if (!spec.mutation) {
    const data = await dependencies.analyzer.call(spec.tool, args, spec.hardMs)
    ensureResponseBounded(data, spec.responseLimit)
    sendJson(response, 200, { ok: true, data })
    return
  }

  const operationId = requireOperationId(req)
  const requestSha = requireRequestSha(req)
  const actualRequestSha = sha256Hex(raw)
  if (!constantTimeDigestEqual(requestSha, actualRequestSha)) {
    throw new BridgeError(409, 'idempotency_mismatch', false, 'Request hash mismatch')
  }
  const started = dependencies.journal.begin({
    operationId,
    requestSha256: requestSha,
    kind: spec.tool,
    phase: 'mcp_call',
    hardDeadlineAt: new Date(Date.now() + spec.hardMs).toISOString(),
  })
  if (!started.created) {
    sendFrozen(response, started.row)
    return
  }
  const task = executeMutation(
    operationId,
    spec.tool,
    args,
    spec.hardMs,
    spec.responseLimit,
    dependencies.journal,
    dependencies.analyzer
  )
  const settled = await waitForOperation(task, spec.waiterMs)
  sendFrozen(response, settled ?? started.row)
}

async function handleUpload(
  req: IncomingMessage,
  response: ServerResponse,
  dependencies: BridgeDependencies
): Promise<void> {
  const waiterDeadline = Date.now() + 900_000
  const upload = parseUploadHeaders(req)
  const finalPath = `${dependencies.config.spoolRoot}/${upload.operationId}.bin`
  const started = dependencies.journal.begin({
    operationId: upload.operationId,
    requestSha256: upload.requestSha256,
    kind: 'sample_upload',
    phase: 'spooling',
    hardDeadlineAt: new Date(Date.now() + 1_800_000).toISOString(),
    contentLength: upload.contentLength,
    contentSha256: upload.contentSha256,
    spoolPath: finalPath,
  })
  if (!started.created) {
    response.setHeader('connection', 'close')
    req.pause()
    sendFrozen(response, started.row)
    response.once('finish', () => req.destroy())
    return
  }
  try {
    await spoolUpload(req, dependencies.config.spoolRoot, upload, dependencies.journal)
  } catch (error) {
    const safe = safeBridgeError(error)
    const row = dependencies.journal.fail(
      upload.operationId,
      safe.status,
      errorBody(safe),
      safe.code,
      safe.retryable
    )
    sendFrozen(response, row)
    return
  }
  const verified = dependencies.journal.get(upload.operationId)
  if (!verified) throw new Error('verified upload operation disappeared')
  const task = completeUploadOperation(verified, dependencies.config, dependencies.journal)
  const settled = await waitForOperation(task, Math.max(0, waiterDeadline - Date.now()))
  sendFrozen(response, settled ?? verified)
}

async function routeRequest(
  req: IncomingMessage,
  response: ServerResponse,
  dependencies: BridgeDependencies
): Promise<void> {
  const url = new URL(req.url ?? '/', 'http://bridge.invalid')
  if (url.search.length > 0) {
    throw new BridgeError(400, 'invalid_request', false, 'Query parameters are not accepted')
  }
  const pathname = url.pathname

  if (pathname === '/healthz' && req.method === 'GET') {
    await dependencies.analyzer.probeHealth()
    sendJson(response, 200, { status: 'healthy' })
    return
  }
  if (pathname === '/readyz' && req.method === 'GET') {
    await dependencies.analyzer.probeReady()
    sendJson(response, 200, { status: 'ready' })
    return
  }

  authenticate(req, dependencies.config.bridgeToken)
  const operationMatch = pathname.match(/^\/internal\/v1\/operations\/([^/]+)$/)
  if (operationMatch && req.method === 'GET') {
    const operationId = operationMatch[1]
    if (!operationId || !UUID_PATTERN.test(operationId)) {
      throw new BridgeError(400, 'invalid_request', false, 'Operation ID is invalid')
    }
    const row = dependencies.journal.get(operationId)
    if (!row) throw new BridgeError(404, 'not_found', false, 'Operation not found')
    sendOperation(response, row)
    return
  }
  if (pathname === '/internal/v1/samples/upload' && req.method === 'POST') {
    await handleUpload(req, response, dependencies)
    return
  }
  if (ROUTES[pathname] && req.method === 'POST') {
    await handleJsonRoute(req, response, pathname, dependencies)
    return
  }
  throw new BridgeError(404, 'not_found', false, 'Route not found')
}

export function createBridgeServer(dependencies: BridgeDependencies): Server {
  const server = createServer((req, response) => {
    void routeRequest(req, response, dependencies).catch((error: unknown) => {
      if (response.headersSent) {
        response.destroy()
        return
      }
      const safe =
        error instanceof ZodError
          ? new BridgeError(400, 'invalid_request', false, 'Request body violates its schema')
          : safeBridgeError(error)
      sendJson(response, safe.status, errorBody(safe), safe.retryAfterSeconds)
    })
  })
  server.requestTimeout = 1_810_000
  server.headersTimeout = 10_000
  server.keepAliveTimeout = 5_000
  server.maxHeadersCount = 32
  return server
}

export async function listen(server: Server, host: string, port: number): Promise<void> {
  await new Promise<void>((resolvePromise, rejectPromise) => {
    const onError = (error: Error) => rejectPromise(error)
    server.once('error', onError)
    server.listen(port, host, () => {
      server.off('error', onError)
      resolvePromise()
    })
  })
}

export async function closeServer(server: Server): Promise<void> {
  if (!server.listening) return
  await new Promise<void>((resolvePromise, rejectPromise) => {
    server.close((error) => (error ? rejectPromise(error) : resolvePromise()))
    server.closeIdleConnections()
  })
}

export const INTERNAL_RESPONSE_BOUND = MAX_MCP_RESPONSE_BYTES
