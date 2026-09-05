import { z } from 'zod'

import { SHA256_PATTERN, UUID_PATTERN } from './canonical.js'
import { FacadeError, type FacadeErrorCode } from './errors.js'

const resourceSchema = z
  .object({ type: z.string().min(1).max(64), id: z.string().min(1).max(512) })
  .strict()
const evidenceSchema = z
  .object({
    edge_id: z.string(),
    source_grant_id: z.string(),
    effect: z.enum(['allow', 'deny']),
    path: z.array(z.string()),
    condition_result: z.string(),
  })
  .strict()

export const requestV2Schema = z
  .object({
    v: z.literal(2),
    application_sub: z.string(),
    client_id: z.string(),
    credential_id: z.string(),
    credential_version: z.number().int().positive(),
    grant_id: z.string(),
    package_id: z.literal('pkg_analyze_mcp_client'),
    package_revision_digest: z.string().regex(SHA256_PATTERN),
    scopes: z.array(z.string()).min(1),
    canonical_tool: z.string(),
    resource: resourceSchema,
    session_id: z.string(),
    request_sha256: z.string().regex(SHA256_PATTERN),
    policy_epoch: z.number().int().positive(),
    revocation_epoch: z.number().int().positive(),
    correlation_id: z.string(),
  })
  .strict()

export const decisionV2Schema = z
  .object({
    v: z.literal(2),
    decision_id: z.string().min(1).max(256),
    decision_digest: z.string().regex(SHA256_PATTERN),
    decision: z.enum(['Allow', 'Deny', 'Indeterminate']),
    subject: z.string(),
    resource: resourceSchema,
    permission: z.string(),
    reason: z.string(),
    evidence: z.array(evidenceSchema).max(256),
    policy_version: z.number().int().nonnegative(),
    subject_version: z.number().int().nonnegative(),
    policy_epoch: z.number().int().nonnegative(),
    issued_at: z.number().int().positive(),
    expires_at: z.number().int().positive(),
  })
  .strict()

export type RequestV2 = Readonly<z.infer<typeof requestV2Schema>>
export type DecisionV2 = Readonly<z.infer<typeof decisionV2Schema>>

export type ExecutionEnvelopeV1 = Readonly<{
  version: 1
  decision_id: string
  decision_digest: string
  subject_version: number
  application_sub: string
  credential_id: string
  credential_version: number
  policy_epoch: number
  revocation_epoch: number
  request_sha256: string
  mcp_session_digest: string
  issued_at: number
  expires_at: number
}>

export type AuthorizationOutcome =
  | 'insufficient_scope'
  | 'deny'
  | 'indeterminate'
  | 'stale_decision'
  | 'expired_decision'
  | 'decision_digest_mismatch'
  | 'authorization_unavailable'

export type AuthorizationAuditRequest = Readonly<{
  application_sub: string
  authorization_event_id: string
  outcome: AuthorizationOutcome
  canonical_tool: string | null
  operation_id: string | null
  decision_digest: string | null
  correlation_id: string
}>

export type FacadeToolRequest = Readonly<{
  application_sub: string
  operation_id: string
  request_sha256: string
  correlation_id: string
  resource: string
  body: unknown
  execution: ExecutionEnvelopeV1
}>

export type FacadeUploadChunkRequest = Readonly<{
  application_sub: string
  request_sha256: string
  correlation_id: string
  content_range: string
  chunk_sha256: string
  content_base64: string
  execution: ExecutionEnvelopeV1
}>

export type FacadeUploadMutationRequest = Readonly<{
  application_sub: string
  operation_id: string
  request_sha256: string
  correlation_id: string
  execution: ExecutionEnvelopeV1
}>

export interface VerdictClient {
  check(request: RequestV2): Promise<DecisionV2>
  probe(): Promise<void>
}

export interface StradClient {
  tool(canonicalTool: string, request: FacadeToolRequest): Promise<unknown>
  uploadChunk(
    uploadId: string,
    chunkIndex: number,
    request: FacadeUploadChunkRequest
  ): Promise<void>
  uploadFinalize(uploadId: string, request: FacadeUploadMutationRequest): Promise<unknown>
  audit(request: AuthorizationAuditRequest): Promise<void>
  probe(): Promise<void>
}

const knownErrorCodes = new Set<FacadeErrorCode>([
  'invalid_request',
  'unauthenticated',
  'authentication_unavailable',
  'insufficient_scope',
  'authorization_denied',
  'authorization_unavailable',
  'invalid_session',
  'replay_detected',
  'quota_exceeded',
  'idempotency_mismatch',
  'not_found',
  'analyzer_unavailable',
  'dependency_unavailable',
])

async function boundedJson(response: Response, limit: number): Promise<unknown> {
  const declared = response.headers.get('content-length')
  if (declared !== null) {
    const length = Number(declared)
    if (!Number.isSafeInteger(length) || length < 1 || length > limit) {
      await response.body?.cancel().catch(() => undefined)
      throw new Error('invalid bounded JSON response')
    }
  }
  const reader = response.body?.getReader()
  if (!reader) throw new Error('invalid bounded JSON response')
  const chunks: Uint8Array[] = []
  let size = 0
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      if (value.byteLength > limit - size) {
        await reader.cancel().catch(() => undefined)
        throw new Error('invalid bounded JSON response')
      }
      size += value.byteLength
      chunks.push(value)
    }
  } catch (error) {
    await reader.cancel().catch(() => undefined)
    throw error
  } finally {
    reader.releaseLock()
  }
  if (size === 0) throw new Error('invalid bounded JSON response')
  return JSON.parse(Buffer.concat(chunks, size).toString('utf8')) as unknown
}

function dependencySignal(timeoutMs: number): AbortSignal {
  return AbortSignal.timeout(timeoutMs)
}

function validateServiceUrl(value: string): URL {
  const url = new URL(value)
  if (url.username !== '' || url.password !== '' || url.search !== '' || url.hash !== '') {
    throw new Error('unsafe service URL')
  }
  return url
}

function appendPath(origin: string, path: string): string {
  const url = validateServiceUrl(origin)
  url.pathname = path
  return url.toString()
}

function mapStradError(body: unknown): FacadeError {
  const parsed = z
    .object({
      error: z
        .object({ code: z.string(), correlation_id: z.string().optional() })
        .passthrough(),
    })
    .passthrough()
    .safeParse(body)
  const code = parsed.success ? parsed.data.error.code : 'dependency_unavailable'
  const correlation = parsed.success ? (parsed.data.error.correlation_id ?? null) : null
  return new FacadeError(
    knownErrorCodes.has(code as FacadeErrorCode)
      ? (code as FacadeErrorCode)
      : 'dependency_unavailable',
    'The Strad application operation was rejected.',
    correlation
  )
}

export class HttpVerdictClient implements VerdictClient {
  constructor(
    private readonly endpoint: string,
    private readonly token: string,
    private readonly timeoutMs = 3000
  ) {}

  async check(request: RequestV2): Promise<DecisionV2> {
    let response: Response
    try {
      response = await fetch(this.endpoint, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${this.token}`,
          'cache-control': 'no-store',
          'content-type': 'application/json',
          pragma: 'no-cache',
        },
        body: JSON.stringify(request),
        redirect: 'error',
        signal: dependencySignal(this.timeoutMs),
      })
    } catch {
      throw new FacadeError('authorization_unavailable', 'Verdict is unavailable.')
    }
    if (response.status !== 200 && response.status !== 503) {
      throw new FacadeError('authorization_unavailable', 'Verdict is unavailable.')
    }
    try {
      const decision = Object.freeze(
        decisionV2Schema.parse(await boundedJson(response, 128 * 1024))
      )
      if (response.status === 503 && decision.decision !== 'Indeterminate') {
        throw new Error('Verdict 503 must be indeterminate')
      }
      return decision
    } catch {
      throw new FacadeError('authorization_unavailable', 'Verdict returned an invalid decision.')
    }
  }

  async probe(): Promise<void> {
    const url = new URL(this.endpoint)
    url.pathname = '/readyz'
    const response = await fetch(url, {
      redirect: 'error',
      signal: dependencySignal(this.timeoutMs),
    })
    if (!response.ok) throw new Error('Verdict readiness failed')
  }
}

export class HttpStradClient implements StradClient {
  constructor(
    private readonly origin: string,
    private readonly token: string,
    private readonly timeoutMs = 3000
  ) {}

  private async postJson(
    path: string,
    body: unknown,
    headers: Readonly<Record<string, string>> = {}
  ): Promise<Response> {
    try {
      return await fetch(appendPath(this.origin, path), {
        method: 'POST',
        headers: {
          authorization: `Bearer ${this.token}`,
          'content-type': 'application/json',
          ...headers,
        },
        body: JSON.stringify(body),
        redirect: 'error',
        signal: dependencySignal(this.timeoutMs),
      })
    } catch {
      throw new FacadeError('dependency_unavailable', 'Strad is unavailable.')
    }
  }

  async tool(canonicalTool: string, request: FacadeToolRequest): Promise<unknown> {
    const response = await this.postJson(
      `/internal/v1/facade/tools/${encodeURIComponent(canonicalTool)}`,
      request
    )
    if (!response.ok) {
      const body = await boundedJson(response, 64 * 1024).catch(() => null)
      throw mapStradError(body)
    }
    try {
      return await boundedJson(response, 4 * 1024 * 1024)
    } catch {
      throw new FacadeError('dependency_unavailable', 'Strad returned an invalid response.')
    }
  }

  async uploadChunk(
    uploadId: string,
    chunkIndex: number,
    request: FacadeUploadChunkRequest
  ): Promise<void> {
    const response = await this.postJson(
      `/internal/v1/facade/uploads/${encodeURIComponent(uploadId)}/chunks/${chunkIndex}`,
      request
    )
    if (response.status !== 204) {
      const body = await boundedJson(response, 64 * 1024).catch(() => null)
      throw mapStradError(body)
    }
  }

  async uploadFinalize(uploadId: string, request: FacadeUploadMutationRequest): Promise<unknown> {
    const response = await this.postJson(
      `/internal/v1/facade/uploads/${encodeURIComponent(uploadId)}/finalize`,
      request,
      { 'idempotency-key': request.operation_id }
    )
    if (!response.ok) {
      const body = await boundedJson(response, 64 * 1024).catch(() => null)
      throw mapStradError(body)
    }
    try {
      return await boundedJson(response, 4 * 1024 * 1024)
    } catch {
      throw new FacadeError('dependency_unavailable', 'Strad returned an invalid response.')
    }
  }

  async audit(request: AuthorizationAuditRequest): Promise<void> {
    if (!UUID_PATTERN.test(request.authorization_event_id)) {
      throw new FacadeError('authorization_unavailable', 'Authorization audit identity is invalid.')
    }
    const response = await this.postJson('/internal/v1/facade/audit/authorization', request)
    if (response.status !== 204) {
      throw new FacadeError('authorization_unavailable', 'Authorization audit is unavailable.')
    }
  }

  async probe(): Promise<void> {
    const response = await fetch(appendPath(this.origin, '/readyz'), {
      redirect: 'error',
      signal: dependencySignal(this.timeoutMs),
    })
    if (!response.ok) throw new Error('Strad readiness failed')
  }
}
