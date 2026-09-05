import { AsyncLocalStorage } from 'node:async_hooks'
import { createHash, timingSafeEqual } from 'node:crypto'
import { createServer, type IncomingMessage, type ServerResponse, type Server as HttpServer } from 'node:http'

import { Server as McpProtocolServer } from '@modelcontextprotocol/sdk/server/index.js'
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'
import {
  CallToolRequestSchema,
  ErrorCode,
  isInitializeRequest,
  ListToolsRequestSchema,
  McpError,
} from '@modelcontextprotocol/sdk/types.js'

import {
  rejectRawPublicCredentials,
  requireSingleHeader,
  verifyApplicationContext,
  type ApplicationContext,
} from './application-context.js'
import { SHA256_PATTERN, UUID_PATTERN, sha256Hex } from './canonical.js'
import type { FacadeConfig } from './config.js'
import { FacadeError, safeFacadeError } from './errors.js'
import { CompositeReadiness } from './health.js'
import {
  applicationSessionRevokedV1Schema,
  type SessionBinding,
  type SessionStore,
} from './session-store.js'
import { PUBLIC_TOOLS, TOOL_DEFINITIONS, ToolExecutor, type ToolRequestContext } from './tools.js'
import type { StradClient, VerdictClient } from './clients.js'

const MAX_MCP_BODY = 1024 * 1024
const MAX_REVOCATION_BODY = 64 * 1024
const MAX_CHUNK_BODY = 8_388_608
const MCP_ROUTE = 'analyze-mcp'
const UPLOAD_ROUTE = 'analyze-uploads'

type LiveMcpSession = {
  readonly transport: StreamableHTTPServerTransport
  readonly server: McpProtocolServer
}

export type FacadeServerDependencies = Readonly<{
  config: FacadeConfig
  sessions: SessionStore
  verdict: VerdictClient
  strad: StradClient
  now?: () => number
}>

function sendJson(response: ServerResponse, status: number, body: unknown): void {
  const encoded = Buffer.from(JSON.stringify(body), 'utf8')
  response.writeHead(status, {
    'cache-control': 'private, no-store',
    'content-length': encoded.length,
    'content-type': 'application/json; charset=utf-8',
    'x-content-type-options': 'nosniff',
  })
  response.end(encoded)
}

function sendError(response: ServerResponse, error: unknown): void {
  const safe = safeFacadeError(error)
  if (response.headersSent) {
    response.destroy()
    return
  }
  if (safe.retryable) response.setHeader('retry-after', '5')
  if (safe.code === 'unauthenticated') response.setHeader('www-authenticate', 'Bearer')
  sendJson(response, safe.httpStatus, safe.body())
}

async function readBody(request: IncomingMessage, limit: number): Promise<Buffer> {
  const declared = request.headers['content-length']
  if (declared !== undefined) {
    const length = Number(declared)
    if (!Number.isInteger(length) || length < 0 || length > limit) {
      throw new FacadeError('invalid_request', 'Request body exceeds its frozen bound.')
    }
  }
  const chunks: Buffer[] = []
  let size = 0
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
    size += bytes.length
    if (size > limit) throw new FacadeError('invalid_request', 'Request body exceeds its frozen bound.')
    chunks.push(bytes)
  }
  return Buffer.concat(chunks)
}

function secureTokenEqual(supplied: string, expected: string): boolean {
  const digest = (value: string): Buffer => createHash('sha256').update(value, 'utf8').digest()
  return timingSafeEqual(digest(supplied), digest(expected))
}

function authenticatePrivate(request: IncomingMessage, expected: string): void {
  let supplied = ''
  try {
    const authorization = requireSingleHeader(request, 'authorization')
    const match = authorization.match(/^Bearer ([\x21-\x7e]+)$/)
    supplied = match?.[1] ?? ''
  } catch {
    supplied = ''
  }
  if (!secureTokenEqual(supplied, expected) || supplied === '') {
    throw new FacadeError('unauthenticated', 'The private facade credential is invalid.')
  }
  if ((request.headers.cookie ?? '') !== '') {
    throw new FacadeError('unauthenticated', 'Cookies are not accepted on private facade routes.')
  }
}

function exactHost(request: IncomingMessage): string {
  return requireSingleHeader(request, 'host').toLowerCase()
}

function mcpSessionId(request: IncomingMessage): string {
  const value = requireSingleHeader(request, 'mcp-session-id')
  if (value.length > 256 || !/^[\x21-\x7e]+$/.test(value)) {
    throw new FacadeError('invalid_request', 'Mcp-Session-Id is invalid.')
  }
  return value
}

function requiredPublicHeader(request: IncomingMessage, name: string): string {
  const value = requireSingleHeader(request, name)
  if (value.length > 4096 || /[\r\n\0]/.test(value)) {
    throw new FacadeError('invalid_request', `${name} is invalid.`)
  }
  return value
}

function createMcpServer(
  executor: ToolExecutor,
  requestContext: AsyncLocalStorage<ToolRequestContext>
): McpProtocolServer {
  const server = new McpProtocolServer(
    { name: '@w33d/analyze-mcp-facade', version: '1.0.0' },
    { capabilities: { tools: {} }, instructions: 'Approved static-analysis application tools only.' }
  )
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [...TOOL_DEFINITIONS] }))
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const context = requestContext.getStore()
    if (!context) {
      throw new McpError(ErrorCode.InternalError, 'Analyze request context is unavailable.')
    }
    try {
      const result = await executor.execute(
        request.params.name,
        request.params.arguments ?? {},
        context
      )
      return { content: [{ type: 'text', text: JSON.stringify(result) }] }
    } catch (error) {
      const safe = safeFacadeError(error)
      throw new McpError(safe.jsonRpcCode as ErrorCode, JSON.stringify(safe.body()))
    }
  })
  return server
}

function parseJsonBody(body: Buffer): unknown {
  try {
    return JSON.parse(body.toString('utf8')) as unknown
  } catch {
    throw new FacadeError('invalid_request', 'Request body is not valid JSON.')
  }
}

export function createFacadeServer(dependencies: FacadeServerDependencies): HttpServer {
  const liveSessions = new Map<string, LiveMcpSession>()
  const requestContext = new AsyncLocalStorage<ToolRequestContext>()
  const executor = new ToolExecutor(
    dependencies.verdict,
    dependencies.strad,
    dependencies.config.externalOrigin.replace(/\/$/, ''),
    dependencies.now
  )
  const readiness = new CompositeReadiness({
    sessions: dependencies.sessions,
    verdict: dependencies.verdict,
    strad: dependencies.strad,
    keyring: dependencies.config.applicationContextKeyring,
    activeKid: dependencies.config.applicationContextActiveKid,
    timeoutMs: dependencies.config.requestTimeoutMs,
    ...(dependencies.now === undefined ? {} : { now: dependencies.now }),
  })
  const now = dependencies.now ?? (() => Math.floor(Date.now() / 1000))

  async function closeLiveSession(sessionId: string): Promise<void> {
    const live = liveSessions.get(sessionId)
    liveSessions.delete(sessionId)
    if (live) {
      await live.transport.close().catch(() => undefined)
      await live.server.close().catch(() => undefined)
    }
  }

  async function bindPublicRequest(
    request: IncomingMessage,
    body: Buffer,
    route: string,
    initialize: boolean
  ): Promise<{ readonly context: ApplicationContext; readonly session: SessionBinding }> {
    rejectRawPublicCredentials(request)
    const sessionId = mcpSessionId(request)
    const url = new URL(request.url ?? '/', dependencies.config.externalOrigin)
    const context = verifyApplicationContext(
      request,
      dependencies.config.applicationContextKeyring,
      {
        method: request.method ?? '',
        normalizedPath: url.pathname,
        route,
        body,
        mcpSessionId: sessionId,
      },
      now()
    )
    let consumed
    try {
      consumed = await dependencies.sessions.consumeContext(context, sessionId, initialize, now())
    } catch {
      throw new FacadeError('authentication_unavailable', 'The application session store is unavailable.')
    }
    if (consumed.status === 'replay') {
      throw new FacadeError('replay_detected', 'The signed application request was already consumed.', context.correlation_id)
    }
    if (consumed.status === 'invalid_session') {
      await closeLiveSession(sessionId)
      throw new FacadeError('invalid_session', 'The MCP session is not active.', context.correlation_id)
    }
    if (consumed.status !== 'accepted') {
      throw new FacadeError('authentication_unavailable', 'The application session result is invalid.')
    }
    for (const superseded of consumed.supersededSessionIds ?? []) {
      await closeLiveSession(superseded)
    }
    return { context, session: consumed.session }
  }

  async function handleMcp(
    request: IncomingMessage,
    response: ServerResponse,
    body: Buffer
  ): Promise<void> {
    const sessionId = mcpSessionId(request)
    let parsed: unknown
    let initialize = false
    if (request.method === 'POST') {
      parsed = parseJsonBody(body)
      initialize = isInitializeRequest(parsed)
    }
    if (initialize) {
      const protocolVersion = (parsed as { params?: { protocolVersion?: unknown } }).params
        ?.protocolVersion
      if (protocolVersion !== FROZEN_PROTOCOL_VERSION) {
        throw new FacadeError('invalid_request', 'The MCP protocol version is not supported.')
      }
      const supplied = request.headers['mcp-protocol-version']
      if (supplied !== undefined && supplied !== FROZEN_PROTOCOL_VERSION) {
        throw new FacadeError('invalid_request', 'The MCP protocol version is not supported.')
      }
    } else if (
      requireSingleHeader(request, 'mcp-protocol-version') !== FROZEN_PROTOCOL_VERSION
    ) {
      throw new FacadeError('invalid_request', 'The MCP protocol version is not supported.')
    }
    const bound = await bindPublicRequest(request, body, MCP_ROUTE, initialize)
    let live = liveSessions.get(sessionId)
    if (initialize) {
      if (live) throw new FacadeError('invalid_session', 'The MCP session is already initialized.')
      const mcpServer = createMcpServer(executor, requestContext)
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => sessionId,
        enableJsonResponse: true,
        onsessioninitialized: (initialized) => {
          if (initialized !== sessionId) throw new Error('MCP session generator drifted')
        },
        onsessionclosed: async (closed) => {
          liveSessions.delete(closed)
          await dependencies.sessions.terminateSession(closed, 'client_closed', now())
        },
      })
      live = { transport, server: mcpServer }
      liveSessions.set(sessionId, live)
      await mcpServer.connect(transport as Parameters<McpProtocolServer['connect']>[0])
    }
    if (!live) {
      throw new FacadeError('invalid_session', 'The MCP session is not attached to this facade instance.')
    }
    await requestContext.run(
      { session: bound.session, applicationContext: bound.context },
      async () => live?.transport.handleRequest(request, response, parsed)
    )
    if (request.method === 'DELETE') await closeLiveSession(sessionId)
  }

  async function handleUpload(
    request: IncomingMessage,
    response: ServerResponse,
    pathname: string
  ): Promise<boolean> {
    const chunk = pathname.match(/^\/v1\/uploads\/([0-9a-f-]+)\/chunks\/([0-9]+)$/)
    const finalize = pathname.match(/^\/v1\/uploads\/([0-9a-f-]+)\/finalize$/)
    if (!chunk && !finalize) return false
    if (request.method !== 'POST') {
      throw new FacadeError('not_found', 'The requested upload route does not exist.')
    }
    if (chunk) {
      const uploadId = chunk[1] ?? ''
      const chunkIndex = Number(chunk[2])
      if (!UUID_PATTERN.test(uploadId) || !Number.isSafeInteger(chunkIndex) || chunkIndex < 0) {
        throw new FacadeError('invalid_request', 'Upload chunk route is invalid.')
      }
      const body = await readBody(request, MAX_CHUNK_BODY)
      const contentRange = requiredPublicHeader(request, 'content-range')
      const chunkSha256 = requiredPublicHeader(request, 'x-chunk-sha256')
      if (!SHA256_PATTERN.test(chunkSha256) || sha256Hex(body) !== chunkSha256) {
        throw new FacadeError('invalid_request', 'X-Chunk-Sha256 does not match the upload chunk.')
      }
      const range = contentRange.match(/^bytes ([0-9]+)-([0-9]+)\/([0-9]+)$/)
      if (!range) throw new FacadeError('invalid_request', 'Content-Range is invalid.')
      const start = Number(range[1])
      const end = Number(range[2])
      const total = Number(range[3])
      if (
        !Number.isSafeInteger(start) ||
        !Number.isSafeInteger(end) ||
        !Number.isSafeInteger(total) ||
        start > end ||
        end >= total ||
        end - start + 1 !== body.length ||
        Math.floor(start / MAX_CHUNK_BODY) !== chunkIndex
      ) {
        throw new FacadeError('invalid_request', 'Content-Range does not match this chunk.')
      }
      const bound = await bindPublicRequest(request, body, UPLOAD_ROUTE, false)
      const digestBody = Object.freeze({
        content_range: contentRange,
        chunk_sha256: chunkSha256,
        content_base64: body.toString('base64'),
      })
      const authorized = await executor.authorize(
        { session: bound.session, applicationContext: bound.context },
        'analysis.create',
        `${uploadId}/${chunkIndex}`,
        digestBody,
        null
      )
      await dependencies.strad.uploadChunk(uploadId, chunkIndex, {
        application_sub: bound.session.applicationSub,
        request_sha256: authorized.requestSha256,
        correlation_id: authorized.correlationId,
        ...digestBody,
        execution: authorized.envelope,
      })
      response.writeHead(204, { 'cache-control': 'private, no-store' })
      response.end()
      return true
    }
    const uploadId = finalize?.[1] ?? ''
    if (!UUID_PATTERN.test(uploadId)) throw new FacadeError('invalid_request', 'Upload ID is invalid.')
    const body = await readBody(request, 2)
    if (body.length !== 0) throw new FacadeError('invalid_request', 'Finalize body must be empty.')
    const finalizeOperationId = requiredPublicHeader(request, 'idempotency-key')
    if (!UUID_PATTERN.test(finalizeOperationId)) {
      throw new FacadeError('invalid_request', 'Idempotency-Key is invalid.')
    }
    const bound = await bindPublicRequest(request, body, UPLOAD_ROUTE, false)
    const authorized = await executor.authorize(
      { session: bound.session, applicationContext: bound.context },
      'analysis.create',
      `${uploadId}/finalize`,
      Object.freeze({}),
      finalizeOperationId
    )
    const result = await dependencies.strad.uploadFinalize(uploadId, {
      application_sub: bound.session.applicationSub,
      operation_id: finalizeOperationId,
      request_sha256: authorized.requestSha256,
      correlation_id: authorized.correlationId,
      execution: authorized.envelope,
    })
    sendJson(response, 202, result)
    return true
  }

  const server = createServer((request, response) => {
    void (async () => {
      const url = new URL(request.url ?? '/', dependencies.config.externalOrigin)
      if (url.search !== '') throw new FacadeError('invalid_request', 'Query parameters are not accepted.')
      const pathname = url.pathname
      if (pathname === '/healthz' && request.method === 'GET') {
        sendJson(response, 200, { status: 'healthy' })
        return
      }
      if (pathname === '/readyz' && request.method === 'GET') {
        try {
          await readiness.check()
          sendJson(response, 200, { status: 'ready' })
        } catch {
          throw new FacadeError('dependency_unavailable', 'Analyze is not ready.')
        }
        return
      }
      if (pathname === '/internal/v1/application-session-revocations') {
        if (
          request.method !== 'POST' ||
          exactHost(request) !== dependencies.config.internalHost.toLowerCase()
        ) {
          throw new FacadeError('not_found', 'The requested route does not exist.')
        }
        authenticatePrivate(request, dependencies.config.accessFacadeRevocationToken)
        const body = await readBody(request, MAX_REVOCATION_BODY)
        let event
        try {
          event = applicationSessionRevokedV1Schema.parse(parseJsonBody(body))
        } catch {
          throw new FacadeError('invalid_request', 'Revocation event violates its frozen contract.')
        }
        if (event.effective_at > now() + 5 || event.issued_at > now() + 30) {
          throw new FacadeError('invalid_request', 'Revocation event timing is invalid.')
        }
        const acknowledgement = await dependencies.sessions.consumeRevocation(event, now())
        for (const sessionId of acknowledgement.session_ids) await closeLiveSession(sessionId)
        sendJson(response, 200, {
          v: acknowledgement.v,
          event_id: acknowledgement.event_id,
          revocation_epoch: acknowledgement.revocation_epoch,
          terminated_sessions: acknowledgement.terminated_sessions,
          duplicate: acknowledgement.duplicate,
          stale: acknowledgement.stale,
        })
        return
      }
      if (exactHost(request) !== new URL(dependencies.config.externalOrigin).host.toLowerCase()) {
        throw new FacadeError('not_found', 'The requested route does not exist.')
      }
      if (pathname === '/mcp') {
        if (!['GET', 'POST', 'DELETE'].includes(request.method ?? '')) {
          throw new FacadeError('not_found', 'The requested MCP route does not exist.')
        }
        const body = request.method === 'POST' ? await readBody(request, MAX_MCP_BODY) : Buffer.alloc(0)
        await handleMcp(request, response, body)
        return
      }
      if (await handleUpload(request, response, pathname)) return
      throw new FacadeError('not_found', 'The requested route does not exist.')
    })().catch((error: unknown) => sendError(response, error))
  })
  server.requestTimeout = 30_000
  server.headersTimeout = 10_000
  server.keepAliveTimeout = 5_000
  server.maxHeadersCount = 32
  server.on('close', () => {
    for (const sessionId of liveSessions.keys()) void closeLiveSession(sessionId)
  })
  return server
}

export async function listen(server: HttpServer, address: string): Promise<void> {
  const separator = address.lastIndexOf(':')
  const host = address.slice(0, separator).replace(/^\[|\]$/g, '')
  const port = Number(address.slice(separator + 1))
  await new Promise<void>((resolve, reject) => {
    const onError = (error: Error): void => reject(error)
    server.once('error', onError)
    server.listen(port, host, () => {
      server.off('error', onError)
      resolve()
    })
  })
}

export async function closeServer(server: HttpServer): Promise<void> {
  if (!server.listening) return
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()))
    server.closeIdleConnections()
  })
}

export const FROZEN_PROTOCOL_VERSION = '2025-11-25'
export const FROZEN_PUBLIC_TOOLS = PUBLIC_TOOLS
