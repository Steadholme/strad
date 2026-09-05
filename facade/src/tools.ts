import { sha256Hex, stableUuid, canonicalApplicationRequestSha, UUID_PATTERN } from './canonical.js'
import {
  decisionV2Schema,
  requestV2Schema,
  type AuthorizationAuditRequest,
  type AuthorizationOutcome,
  type DecisionV2,
  type ExecutionEnvelopeV1,
  type FacadeToolRequest,
  type RequestV2,
  type StradClient,
  type VerdictClient,
} from './clients.js'
import { FacadeError } from './errors.js'
import type { SessionBinding } from './session-store.js'
import type { ApplicationContext } from './application-context.js'
import { z } from 'zod'

export const PUBLIC_TOOLS = Object.freeze([
  'analysis.create',
  'analysis.read',
  'analysis.conversation',
  'analysis.upload.cancel',
] as const)
export type PublicTool = (typeof PUBLIC_TOOLS)[number]

const TOOL_SCOPE: Readonly<Record<PublicTool, string>> = Object.freeze({
  'analysis.create': 'analysis.create',
  'analysis.read': 'analysis.read',
  'analysis.conversation': 'analysis.conversation',
  'analysis.upload.cancel': 'analysis.upload.cancel',
})

const VERDICT_PERMISSION: Readonly<Record<PublicTool, string>> = Object.freeze({
  'analysis.create': 'rikune.analysis.create',
  'analysis.read': 'rikune.analysis.read',
  'analysis.conversation': 'rikune.conversation.use',
  'analysis.upload.cancel': 'rikune.upload.cancel',
})

const operationId = z.string().regex(UUID_PATTERN)
const analysisCreateSchema = z
  .object({
    operation_id: operationId,
    filename: z.string().min(1).max(255),
    total_bytes: z.number().int().positive().max(524_288_000),
  })
  .strict()
const analysisReadBaseSchema = z
  .object({ operation_id: operationId, analysis_id: operationId })
  .strict()
const analysisReadSchema = z.union([
  analysisReadBaseSchema,
  analysisReadBaseSchema.extend({ conversation_id: operationId, turn_id: operationId }).strict(),
])
const analysisConversationCreateSchema = z
  .object({
    operation_id: operationId,
    analysis_id: operationId,
    title: z.string().min(1).max(200),
    persona_id: z.string().min(1).max(200).optional(),
  })
  .strict()
const analysisConversationSchema = z.union([
  analysisConversationCreateSchema,
  z.object({
    operation_id: operationId,
    analysis_id: operationId,
    conversation_id: operationId,
    client_seq: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
    message: z.string().min(1).max(8192).refine(
      (value) => !value.includes('\0') && Buffer.byteLength(value, 'utf8') <= 8192
    ),
    model: z.string().min(1).max(128).regex(/^[A-Za-z0-9._:/-]+$/).optional(),
  }).strict(),
])
const analysisUploadCancelSchema = z
  .object({ operation_id: operationId, upload_id: operationId })
  .strict()

export const TOOL_DEFINITIONS = Object.freeze([
  {
    name: 'analysis.create',
    description: 'Create an analysis and its resumable upload reservation.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['operation_id', 'filename', 'total_bytes'],
      properties: {
        operation_id: { type: 'string', pattern: UUID_PATTERN.source },
        filename: { type: 'string', minLength: 1, maxLength: 255 },
        total_bytes: { type: 'integer', minimum: 1, maximum: 524_288_000 },
      },
    },
  },
  {
    name: 'analysis.read',
    description: 'Read an application-owned analysis, or one conversation turn and its result.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['operation_id', 'analysis_id'],
      oneOf: [
        { not: { anyOf: [{ required: ['conversation_id'] }, { required: ['turn_id'] }] } },
        { required: ['conversation_id', 'turn_id'] },
      ],
      properties: {
        operation_id: { type: 'string', pattern: UUID_PATTERN.source },
        analysis_id: { type: 'string', pattern: UUID_PATTERN.source },
        conversation_id: { type: 'string', pattern: UUID_PATTERN.source },
        turn_id: { type: 'string', pattern: UUID_PATTERN.source },
      },
    },
  },
  {
    name: 'analysis.conversation',
    description: 'Create a conversation with title, or submit a turn with conversation_id, client_seq and message. Read the returned turn with analysis.read.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['operation_id', 'analysis_id'],
      oneOf: [
        {
          required: ['title'],
          not: { anyOf: [
            { required: ['conversation_id'] }, { required: ['client_seq'] },
            { required: ['message'] }, { required: ['model'] },
          ] },
        },
        {
          required: ['conversation_id', 'client_seq', 'message'],
          not: { anyOf: [{ required: ['title'] }, { required: ['persona_id'] }] },
        },
      ],
      properties: {
        operation_id: { type: 'string', pattern: UUID_PATTERN.source },
        analysis_id: { type: 'string', pattern: UUID_PATTERN.source },
        title: { type: 'string', minLength: 1, maxLength: 200 },
        persona_id: { type: 'string', minLength: 1, maxLength: 200 },
        conversation_id: { type: 'string', pattern: UUID_PATTERN.source },
        client_seq: { type: 'integer', minimum: 1, maximum: Number.MAX_SAFE_INTEGER },
        message: { type: 'string', minLength: 1, maxLength: 8192, pattern: '^[^\\u0000]*$', description: 'At most 8192 UTF-8 bytes.' },
        model: { type: 'string', minLength: 1, maxLength: 128, pattern: '^[A-Za-z0-9._:/-]+$', description: 'A model from the NewAPI catalog; omitted uses the configured default.' },
      },
    },
  },
  {
    name: 'analysis.upload.cancel',
    description: 'Cancel an application-owned upload through the authorization path.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['operation_id', 'upload_id'],
      properties: {
        operation_id: { type: 'string', pattern: UUID_PATTERN.source },
        upload_id: { type: 'string', pattern: UUID_PATTERN.source },
      },
    },
  },
] as const)

export type ToolRequestContext = Readonly<{
  session: SessionBinding
  applicationContext: ApplicationContext
}>

export type AuthorizedOperation = Readonly<{
  request: RequestV2
  envelope: ExecutionEnvelopeV1
  requestSha256: string
  correlationId: string
}>

function isPublicTool(value: string): value is PublicTool {
  return (PUBLIC_TOOLS as readonly string[]).includes(value)
}

export function recomputeDecisionDigest(request: RequestV2, decision: DecisionV2): string {
  const canonical = JSON.stringify({
    domain: 'w33d.verdict.application-decision.v2',
    request,
    subject: decision.subject,
    resource: decision.resource,
    permission: decision.permission,
    decision: decision.decision,
    reason: decision.reason,
    evidence: decision.evidence,
    policy_version: decision.policy_version,
    subject_version: decision.subject_version,
    policy_epoch: decision.policy_epoch,
    issued_at: decision.issued_at,
    expires_at: decision.expires_at,
  })
  return sha256Hex(canonical)
}

function deepEqual(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right)
}

type DecisionValidation =
  | Readonly<{ ok: true; decision: DecisionV2 }>
  | Readonly<{ ok: false; outcome: AuthorizationOutcome; code: 'authorization_denied' | 'authorization_unavailable' }>

export function validateDecision(
  rawDecision: unknown,
  request: RequestV2,
  nowSeconds: number
): DecisionValidation {
  const parsed = decisionV2Schema.safeParse(rawDecision)
  if (!parsed.success) {
    return { ok: false, outcome: 'authorization_unavailable', code: 'authorization_unavailable' }
  }
  const decision = Object.freeze(parsed.data)
  if (
    decision.subject !== request.application_sub ||
    !deepEqual(decision.resource, request.resource) ||
    !isPublicTool(request.canonical_tool) ||
    decision.permission !== VERDICT_PERMISSION[request.canonical_tool] ||
    decision.policy_version < 0 ||
    decision.subject_version < 0 ||
    decision.policy_epoch < 0
  ) {
    return { ok: false, outcome: 'stale_decision', code: 'authorization_unavailable' }
  }
  if (
    decision.expires_at - decision.issued_at !== 30 ||
    decision.issued_at > nowSeconds ||
    decision.expires_at <= nowSeconds
  ) {
    return { ok: false, outcome: 'expired_decision', code: 'authorization_unavailable' }
  }
  const digest = recomputeDecisionDigest(request, decision)
  if (
    decision.decision_digest !== digest ||
    decision.decision_id !== `dec_${digest.slice(0, 32)}`
  ) {
    return {
      ok: false,
      outcome: 'decision_digest_mismatch',
      code: 'authorization_unavailable',
    }
  }
  if (decision.decision === 'Deny') {
    return { ok: false, outcome: 'deny', code: 'authorization_denied' }
  }
  if (decision.decision === 'Indeterminate') {
    return { ok: false, outcome: 'indeterminate', code: 'authorization_unavailable' }
  }
  if (
    decision.policy_version <= 0 ||
    decision.subject_version <= 0 ||
    decision.policy_epoch <= 0 ||
    decision.policy_epoch !== request.policy_epoch
  ) {
    return { ok: false, outcome: 'stale_decision', code: 'authorization_unavailable' }
  }
  return { ok: true, decision }
}

export class ToolExecutor {
  constructor(
    private readonly verdict: VerdictClient,
    private readonly strad: StradClient,
    private readonly externalOrigin = 'https://analyze.w33d.xyz',
    private readonly now: () => number = () => Math.floor(Date.now() / 1000)
  ) {}

  private async auditAndThrow(
    context: ToolRequestContext,
    canonicalTool: PublicTool,
    operationId: string | null,
    requestSha256: string,
    outcome: AuthorizationOutcome,
    code: 'insufficient_scope' | 'authorization_denied' | 'authorization_unavailable',
    decisionDigest: string | null
  ): Promise<never> {
    const correlationId = stableUuid(
      'w33d.analyze.correlation.v1',
      context.applicationContext.correlation_id
    )
    const audit: AuthorizationAuditRequest = Object.freeze({
      application_sub: context.session.applicationSub,
      authorization_event_id: stableUuid(
        'w33d.analyze.authorization-event.v1',
        context.session.applicationSub,
        canonicalTool,
        operationId ?? requestSha256
      ),
      outcome,
      canonical_tool: canonicalTool,
      operation_id: operationId,
      decision_digest: decisionDigest,
      correlation_id: correlationId,
    })
    try {
      await this.strad.audit(audit)
    } catch {
      throw new FacadeError(
        'authorization_unavailable',
        'Authorization could not be durably audited.',
        correlationId
      )
    }
    const message =
      code === 'insufficient_scope'
        ? 'The application grant does not include this tool.'
        : code === 'authorization_denied'
          ? 'Verdict denied this application operation.'
          : 'Application authorization is unavailable.'
    throw new FacadeError(code, message, correlationId)
  }

  async authorize(
    context: ToolRequestContext,
    canonicalTool: PublicTool,
    resourceId: string,
    body: unknown,
    operationId: string | null
  ): Promise<AuthorizedOperation> {
    const requestSha256 = canonicalApplicationRequestSha(
      context.session.applicationSub,
      canonicalTool,
      resourceId,
      body
    )
    const requiredScope = TOOL_SCOPE[canonicalTool]
    if (!context.session.scopes.includes(requiredScope)) {
      await this.auditAndThrow(
        context,
        canonicalTool,
        operationId,
        requestSha256,
        'insufficient_scope',
        'insufficient_scope',
        null
      )
    }
    const correlationId = stableUuid(
      'w33d.analyze.correlation.v1',
      context.applicationContext.correlation_id
    )
    const request = Object.freeze(
      requestV2Schema.parse({
        v: 2,
        application_sub: context.session.applicationSub,
        client_id: context.session.clientId,
        credential_id: context.session.credentialId,
        credential_version: context.session.credentialVersion,
        grant_id: context.session.grantId,
        package_id: context.session.packageId,
        package_revision_digest: context.session.packageRevisionDigest,
        scopes: [...context.session.scopes],
        canonical_tool: canonicalTool,
        resource: { type: 'analysis', id: resourceId },
        session_id: context.session.sessionId,
        request_sha256: requestSha256,
        policy_epoch: context.session.policyEpoch,
        revocation_epoch: context.session.revocationEpoch,
        correlation_id: correlationId,
      })
    )
    let rawDecision: DecisionV2
    try {
      rawDecision = await this.verdict.check(request)
    } catch {
      return await this.auditAndThrow(
        context,
        canonicalTool,
        operationId,
        requestSha256,
        'authorization_unavailable',
        'authorization_unavailable',
        null
      )
    }
    const checked = validateDecision(rawDecision, request, this.now())
    if (!checked.ok) {
      return await this.auditAndThrow(
        context,
        canonicalTool,
        operationId,
        requestSha256,
        checked.outcome,
        checked.code,
        rawDecision.decision_digest
      )
    }
    const envelope: ExecutionEnvelopeV1 = Object.freeze({
      version: 1,
      decision_id: checked.decision.decision_id,
      decision_digest: checked.decision.decision_digest,
      subject_version: checked.decision.subject_version,
      application_sub: context.session.applicationSub,
      credential_id: context.session.credentialId,
      credential_version: context.session.credentialVersion,
      policy_epoch: context.session.policyEpoch,
      revocation_epoch: context.session.revocationEpoch,
      request_sha256: requestSha256,
      mcp_session_digest: context.session.mcpSessionDigest,
      issued_at: checked.decision.issued_at,
      expires_at: checked.decision.expires_at,
    })
    return Object.freeze({ request, envelope, requestSha256, correlationId })
  }

  async execute(
    canonicalToolValue: string,
    rawArguments: unknown,
    context: ToolRequestContext
  ): Promise<unknown> {
    if (!isPublicTool(canonicalToolValue)) {
      throw new FacadeError('not_found', 'The requested Analyze tool does not exist.')
    }
    let operationIdValue: string
    let resource: string
    let body: Readonly<Record<string, unknown>>
    try {
      switch (canonicalToolValue) {
        case 'analysis.create': {
          const input = analysisCreateSchema.parse(rawArguments)
          operationIdValue = input.operation_id
          resource = 'collection'
          body = Object.freeze({ filename: input.filename, total_bytes: input.total_bytes })
          break
        }
        case 'analysis.read': {
          const input = analysisReadSchema.parse(rawArguments)
          operationIdValue = input.operation_id
          resource = input.analysis_id
          body = Object.freeze('conversation_id' in input
            ? { conversation_id: input.conversation_id, turn_id: input.turn_id }
            : {})
          break
        }
        case 'analysis.conversation': {
          const input = analysisConversationSchema.parse(rawArguments)
          operationIdValue = input.operation_id
          resource = input.analysis_id
          body = Object.freeze('conversation_id' in input ? {
            analysis_id: input.analysis_id,
            conversation_id: input.conversation_id,
            client_seq: input.client_seq,
            message: input.message,
            ...(input.model === undefined ? {} : { model: input.model }),
          } : {
            analysis_id: input.analysis_id,
            title: input.title,
            ...(input.persona_id === undefined ? {} : { persona_id: input.persona_id }),
          })
          break
        }
        case 'analysis.upload.cancel': {
          const input = analysisUploadCancelSchema.parse(rawArguments)
          operationIdValue = input.operation_id
          resource = input.upload_id
          body = Object.freeze({})
          break
        }
      }
    } catch {
      throw new FacadeError('invalid_request', 'Tool arguments violate the frozen contract.')
    }
    const authorized = await this.authorize(
      context,
      canonicalToolValue,
      resource,
      body,
      operationIdValue
    )
    const request: FacadeToolRequest = Object.freeze({
      application_sub: context.session.applicationSub,
      operation_id: operationIdValue,
      request_sha256: authorized.requestSha256,
      correlation_id: authorized.correlationId,
      resource,
      body,
      execution: authorized.envelope,
    })
    const result = await this.strad.tool(canonicalToolValue, request)
    if (canonicalToolValue !== 'analysis.create') return result
    const created = z
      .object({
        analysis_id: z.string().regex(UUID_PATTERN),
        upload_id: z.string().regex(UUID_PATTERN),
        finalize_operation_id: z.string().regex(UUID_PATTERN),
        chunk_size: z.number().int().positive(),
        chunk_count: z.number().int().positive(),
      })
      .strict()
      .parse(result)
    return Object.freeze({
      ...created,
      chunk_url_template: `${this.externalOrigin}/v1/uploads/${created.upload_id}/chunks/{chunk_index}`,
      finalize_url: `${this.externalOrigin}/v1/uploads/${created.upload_id}/finalize`,
    })
  }
}
