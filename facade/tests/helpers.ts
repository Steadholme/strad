import { generateKeyPairSync, randomBytes, sign } from 'node:crypto'
import type { Server as HttpServer } from 'node:http'
import { request as httpRequest } from 'node:http'
import type { AddressInfo } from 'node:net'

import type { ApplicationContext, VerificationKeyring } from '../src/application-context.js'
import { sha256Hex } from '../src/canonical.js'
import type {
  AuthorizationAuditRequest,
  DecisionV2,
  FacadeToolRequest,
  FacadeUploadChunkRequest,
  FacadeUploadMutationRequest,
  RequestV2,
  StradClient,
  VerdictClient,
} from '../src/clients.js'
import type { FacadeConfig } from '../src/config.js'
import { recomputeDecisionDigest } from '../src/tools.js'

export const FIXED_NOW = 1_900_000_000
export const APPLICATION = 'application:abcdefghijklmnop'
export const SESSION = 'session_abcdefghijklmnop'
export const CREDENTIAL = 'acr_abcdefghijklmnop'
export const OPERATION = '550e8400-e29b-41d4-a716-446655440010'
export const ANALYSIS = '550e8400-e29b-41d4-a716-446655440011'
export const UPLOAD = '550e8400-e29b-41d4-a716-446655440012'
export const FINALIZE = '550e8400-e29b-41d4-a716-446655440013'

const keys = generateKeyPairSync('ed25519')
const publicDer = keys.publicKey.export({ format: 'der', type: 'spki' })
const rawPublic = Buffer.from(publicDer).subarray(-32)
export const KEYRING: VerificationKeyring = new Map([
  ['appctx-2026a', Object.freeze({ publicKey: rawPublic, retiredAt: null })],
])

const jtiProcessPrefix = randomBytes(12)
let jtiCounter = 1

export function makeContext(
  overrides: Partial<ApplicationContext> = {}
): ApplicationContext {
  const jti = Buffer.alloc(16)
  jtiProcessPrefix.copy(jti)
  jti.writeUInt32BE(jtiCounter++, 12)
  return Object.freeze({
    v: 1,
    kid: 'appctx-2026a',
    iss: 'sluice',
    aud: 'analyze-facade',
    application_sub: APPLICATION,
    client_id: 'client_abcdefghijklmnop',
    credential_id: CREDENTIAL,
    credential_version: 1,
    grant_id: 'grant_abcdefghijklmnop',
    package_id: 'pkg_analyze_mcp_client',
    package_revision_digest: 'c'.repeat(64),
    scopes: [
      'analysis.conversation',
      'analysis.create',
      'analysis.read',
      'analysis.upload.cancel',
    ] as ApplicationContext['scopes'],
    method: 'POST',
    normalized_path: '/mcp',
    route: 'analyze-mcp',
    body_sha256: 'a'.repeat(64),
    request_id: `req_${jti.toString('hex')}`,
    correlation_id: `corr_${jti.toString('hex')}`,
    jti: jti.toString('base64url'),
    mcp_session_digest: sha256Hex(SESSION),
    credential_state: 'active',
    overlap_until: null,
    policy_epoch: 11,
    revocation_epoch: 13,
    iat: FIXED_NOW,
    exp: FIXED_NOW + 30,
    ...overrides,
  })
}

export function signedHeaders(context: ApplicationContext): Record<string, string> {
  const canonical = Buffer.from(JSON.stringify(context), 'utf8')
  return {
    'x-application-ctx-kid': context.kid,
    'x-application-ctx': canonical.toString('base64url'),
    'x-application-ctx-sig': sign(null, canonical, keys.privateKey).toString('base64url'),
  }
}

export function requestHeaders(
  context: ApplicationContext,
  extra: Record<string, string> = {}
): Record<string, string> {
  return {
    accept: 'application/json, text/event-stream',
    host: 'analyze.w33d.xyz',
    'mcp-session-id': SESSION,
    ...signedHeaders(context),
    ...extra,
  }
}

const permission: Readonly<Record<string, string>> = Object.freeze({
  'analysis.create': 'rikune.analysis.create',
  'analysis.read': 'rikune.analysis.read',
  'analysis.conversation': 'rikune.conversation.use',
  'analysis.upload.cancel': 'rikune.upload.cancel',
})

export function allowDecision(request: RequestV2, now = FIXED_NOW): DecisionV2 {
  const partial: DecisionV2 = {
    v: 2,
    decision_id: 'pending',
    decision_digest: '0'.repeat(64),
    decision: 'Allow',
    subject: request.application_sub,
    resource: request.resource,
    permission: permission[request.canonical_tool] ?? 'invalid',
    reason: 'matching application projection',
    evidence: [],
    policy_version: 5,
    subject_version: 7,
    policy_epoch: request.policy_epoch,
    issued_at: now,
    expires_at: now + 30,
  }
  const digest = recomputeDecisionDigest(request, partial)
  return Object.freeze({
    ...partial,
    decision_id: `dec_${digest.slice(0, 32)}`,
    decision_digest: digest,
  })
}

export class FakeVerdict implements VerdictClient {
  readonly requests: RequestV2[] = []
  probeFailure = false
  mutate: ((decision: DecisionV2, request: RequestV2) => DecisionV2) | null = null

  async check(request: RequestV2): Promise<DecisionV2> {
    this.requests.push(request)
    const decision = allowDecision(request)
    return this.mutate ? this.mutate(decision, request) : decision
  }

  async probe(): Promise<void> {
    if (this.probeFailure) throw new Error('verdict down')
  }
}

export class FakeStrad implements StradClient {
  readonly tools: Array<{ tool: string; request: FacadeToolRequest }> = []
  readonly chunks: Array<{ uploadId: string; index: number; request: FacadeUploadChunkRequest }> = []
  readonly finalizes: Array<{ uploadId: string; request: FacadeUploadMutationRequest }> = []
  readonly auditEvents = new Map<string, AuthorizationAuditRequest>()
  auditCalls = 0
  probeFailure = false

  async tool(canonicalTool: string, request: FacadeToolRequest): Promise<unknown> {
    this.tools.push({ tool: canonicalTool, request })
    if (canonicalTool === 'analysis.create') {
      return {
        analysis_id: ANALYSIS,
        upload_id: UPLOAD,
        finalize_operation_id: FINALIZE,
        chunk_size: 8_388_608,
        chunk_count: 1,
      }
    }
    return { ok: true }
  }

  async uploadChunk(
    uploadId: string,
    index: number,
    request: FacadeUploadChunkRequest
  ): Promise<void> {
    this.chunks.push({ uploadId, index, request })
  }

  async uploadFinalize(uploadId: string, request: FacadeUploadMutationRequest): Promise<unknown> {
    this.finalizes.push({ uploadId, request })
    return { upload_id: uploadId, state: 'accepted' }
  }

  async audit(request: AuthorizationAuditRequest): Promise<void> {
    this.auditCalls++
    this.auditEvents.set(request.authorization_event_id, request)
  }

  async probe(): Promise<void> {
    if (this.probeFailure) throw new Error('strad down')
  }
}

export function testConfig(overrides: Partial<FacadeConfig> = {}): FacadeConfig {
  return Object.freeze({
    bindAddress: '127.0.0.1:0',
    databaseUrl: 'postgres://facade:facade@127.0.0.1/facade',
    externalOrigin: 'https://analyze.w33d.xyz/',
    internalHost: 'analyze-facade:18120',
    verdictDecisionUrl: 'http://127.0.0.1/api/v2/application-check',
    verdictDecisionToken: 'v'.repeat(32),
    stradOrigin: 'http://127.0.0.1/',
    stradFacadeToken: 's'.repeat(32),
    accessFacadeRevocationToken: 'r'.repeat(32),
    applicationContextActiveKid: 'appctx-2026a',
    applicationContextKeyring: KEYRING,
    requestTimeoutMs: 3000,
    sessionIdleSeconds: 900,
    sessionAbsoluteSeconds: 86400,
    ...overrides,
  })
}

export async function listenTestServer(server: HttpServer): Promise<string> {
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  const address = server.address() as AddressInfo
  return `http://127.0.0.1:${address.port}`
}

export async function closeTestServer(server: HttpServer): Promise<void> {
  await new Promise<void>((resolve) => server.close(() => resolve()))
  server.closeIdleConnections()
}

export async function facadeFetch(input: string, init: RequestInit = {}): Promise<Response> {
  const url = new URL(input)
  const headers = new Headers(init.headers)
  const body =
    init.body === undefined || init.body === null
      ? null
      : typeof init.body === 'string'
        ? Buffer.from(init.body)
        : Buffer.isBuffer(init.body)
          ? init.body
          : null
  if (init.body !== undefined && init.body !== null && body === null) {
    throw new Error('facadeFetch accepts only string or Buffer bodies')
  }
  if (body !== null && !headers.has('content-length')) {
    headers.set('content-length', String(body.length))
  }
  return new Promise<Response>((resolve, reject) => {
    const request = httpRequest(
      url,
      {
        method: init.method ?? 'GET',
        headers: Object.fromEntries(headers.entries()),
      },
      (response) => {
        const chunks: Buffer[] = []
        response.on('data', (chunk: Buffer) => chunks.push(chunk))
        response.once('end', () => {
          const responseHeaders = new Headers()
          for (const [name, value] of Object.entries(response.headers)) {
            if (Array.isArray(value)) {
              for (const item of value) responseHeaders.append(name, item)
            } else if (value !== undefined) {
              responseHeaders.set(name, value)
            }
          }
          const responseBody = response.statusCode === 204 ? null : Buffer.concat(chunks)
          resolve(
            new Response(responseBody, {
              status: response.statusCode ?? 500,
              headers: responseHeaders,
            })
          )
        })
      }
    )
    request.once('error', reject)
    if (body !== null) request.end(body)
    else request.end()
  })
}

export function contextForHttp(
  method: string,
  path: string,
  route: string,
  body: Buffer,
  overrides: Partial<ApplicationContext> = {}
): ApplicationContext {
  return makeContext({
    method,
    normalized_path: path,
    route,
    body_sha256: sha256Hex(body),
    ...overrides,
  })
}
