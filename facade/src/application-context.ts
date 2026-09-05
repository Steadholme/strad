import { verify } from 'node:crypto'
import type { IncomingMessage } from 'node:http'

import { z } from 'zod'

import {
  APPLICATION_SUB_PATTERN,
  SHA256_PATTERN,
  sha256Hex,
} from './canonical.js'
import { FacadeError } from './errors.js'

export const APPLICATION_CONTEXT_HEADERS = Object.freeze({
  kid: 'x-application-ctx-kid',
  context: 'x-application-ctx',
  signature: 'x-application-ctx-sig',
})

const opaque = z.string().min(1).max(256).regex(/^[A-Za-z0-9_.-]+$/)
const digest = z.string().regex(SHA256_PATTERN)
const publicScope = z.enum([
  'analysis.create',
  'analysis.read',
  'analysis.conversation',
  'analysis.upload.cancel',
])
const contextSchema = z
  .object({
    v: z.literal(1),
    kid: z.string().regex(/^[a-z0-9][a-z0-9-]{0,31}$/),
    iss: z.literal('sluice'),
    aud: z.literal('analyze-facade'),
    application_sub: z.string().regex(APPLICATION_SUB_PATTERN),
    client_id: opaque,
    credential_id: opaque,
    credential_version: z.number().int().positive(),
    grant_id: opaque,
    package_id: z.literal('pkg_analyze_mcp_client'),
    package_revision_digest: digest,
    scopes: z.array(publicScope).min(1).max(4),
    method: z.string().min(1).max(16).regex(/^[A-Z]+$/),
    normalized_path: z.string().min(1).max(4096).startsWith('/'),
    route: opaque,
    body_sha256: digest,
    request_id: opaque,
    correlation_id: opaque,
    jti: z.string().regex(/^[A-Za-z0-9_-]{22}$/),
    mcp_session_digest: digest,
    credential_state: z.enum(['active', 'overlap']),
    overlap_until: z.number().int().positive().nullable(),
    policy_epoch: z.number().int().positive(),
    revocation_epoch: z.number().int().positive(),
    iat: z.number().int().positive(),
    exp: z.number().int().positive(),
  })
  .strict()

export type ApplicationContext = Readonly<z.infer<typeof contextSchema>>

export type VerificationKey = Readonly<{
  publicKey: Buffer
  retiredAt: number | null
}>

export type VerificationKeyring = ReadonlyMap<string, VerificationKey>

const keyringSchema = z.record(
  z
    .object({
      public_key: z.string().min(1).max(128),
      retired_at: z.number().int().positive().nullable(),
    })
    .strict()
)

export function parseVerificationKeyring(activeKid: string, raw: string): VerificationKeyring {
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    throw new Error('SLUICE_APPLICATION_CONTEXT_VERIFICATION_KEYRING is invalid')
  }
  const values = keyringSchema.parse(parsed)
  const entries = Object.entries(values)
  if (entries.length < 1 || entries.length > 2 || !(activeKid in values)) {
    throw new Error('Application context keyring must contain current and at most one previous key')
  }
  const keyring = new Map<string, VerificationKey>()
  for (const [kid, value] of entries) {
    if (!/^[a-z0-9][a-z0-9-]{0,31}$/.test(kid)) throw new Error('Invalid application key id')
    let decoded: Buffer
    try {
      decoded = Buffer.from(value.public_key, 'base64url')
    } catch {
      throw new Error('Invalid application verification key')
    }
    if (decoded.length !== 32 || decoded.toString('base64url') !== value.public_key) {
      throw new Error('Invalid application verification key')
    }
    if (kid === activeKid && value.retired_at !== null) {
      throw new Error('The active application verification key cannot be retired')
    }
    if (kid !== activeKid && value.retired_at === null) {
      throw new Error('A previous application verification key must be retired')
    }
    keyring.set(kid, Object.freeze({ publicKey: decoded, retiredAt: value.retired_at }))
  }
  return keyring
}

export function keyringReady(
  keyring: VerificationKeyring,
  activeKid: string,
  nowSeconds: number
): boolean {
  const active = keyring.get(activeKid)
  if (active === undefined || active.retiredAt !== null || nowSeconds <= 0) return false
  for (const [kid, key] of keyring) {
    if (
      kid !== activeKid &&
      (key.retiredAt === null || key.retiredAt > nowSeconds || nowSeconds >= key.retiredAt + 300)
    ) {
      return false
    }
  }
  return true
}

function rawHeaderValues(request: IncomingMessage, expected: string): string[] {
  const values: string[] = []
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    if (request.rawHeaders[index]?.toLowerCase() === expected) {
      values.push(request.rawHeaders[index + 1] ?? '')
    }
  }
  return values
}

export function requireSingleHeader(request: IncomingMessage, name: string): string {
  const values = rawHeaderValues(request, name.toLowerCase())
  if (values.length !== 1 || values[0] === undefined || values[0].length === 0) {
    throw new FacadeError('invalid_request', `Exactly one ${name} header is required.`)
  }
  return values[0]
}

export function rejectRawPublicCredentials(request: IncomingMessage): void {
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    const name = request.rawHeaders[index]?.toLowerCase() ?? ''
    if (name === 'authorization' || name === 'proxy-authorization' || name === 'cookie') {
      throw new FacadeError('unauthenticated', 'Raw credentials are not accepted by Analyze.')
    }
    if (
      name.startsWith('x-application-') &&
      !(Object.values(APPLICATION_CONTEXT_HEADERS) as string[]).includes(name)
    ) {
      throw new FacadeError('invalid_request', 'Untrusted application identity headers are rejected.')
    }
  }
}

export type ExpectedApplicationRequest = Readonly<{
  method: string
  normalizedPath: string
  route: string
  body: Buffer
  mcpSessionId: string
}>

function ed25519Spki(publicKey: Buffer): Buffer {
  return Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), publicKey])
}

export function verifyApplicationContext(
  request: IncomingMessage,
  keyring: VerificationKeyring,
  expected: ExpectedApplicationRequest,
  nowSeconds = Math.floor(Date.now() / 1000)
): ApplicationContext {
  rejectRawPublicCredentials(request)
  const kid = requireSingleHeader(request, APPLICATION_CONTEXT_HEADERS.kid)
  const encoded = requireSingleHeader(request, APPLICATION_CONTEXT_HEADERS.context)
  const encodedSignature = requireSingleHeader(request, APPLICATION_CONTEXT_HEADERS.signature)
  let canonical: Buffer
  let signature: Buffer
  try {
    canonical = Buffer.from(encoded, 'base64url')
    signature = Buffer.from(encodedSignature, 'base64url')
  } catch {
    throw new FacadeError('unauthenticated', 'The signed application context is invalid.')
  }
  if (
    canonical.length === 0 ||
    canonical.length > 16 * 1024 ||
    signature.length !== 64 ||
    canonical.toString('base64url') !== encoded ||
    signature.toString('base64url') !== encodedSignature
  ) {
    throw new FacadeError('unauthenticated', 'The signed application context is invalid.')
  }
  let context: ApplicationContext
  try {
    context = Object.freeze(contextSchema.parse(JSON.parse(canonical.toString('utf8'))))
  } catch {
    throw new FacadeError('unauthenticated', 'The signed application context is invalid.')
  }
  if (
    JSON.stringify(context) !== canonical.toString('utf8') ||
    context.kid !== kid ||
    context.exp - context.iat !== 30 ||
    nowSeconds < context.iat - 5 ||
    nowSeconds > context.exp + 5 ||
    context.scopes.some((scope, index) => index > 0 && (context.scopes[index - 1] ?? '') >= scope) ||
    (context.credential_state === 'active' && context.overlap_until !== null) ||
    (context.credential_state === 'overlap' &&
      (context.overlap_until === null || context.overlap_until <= context.iat))
  ) {
    throw new FacadeError('unauthenticated', 'The signed application context is invalid.')
  }
  const key = keyring.get(kid)
  if (
    key === undefined ||
    (key.retiredAt !== null &&
      (context.iat > key.retiredAt || nowSeconds >= key.retiredAt + 300))
  ) {
    throw new FacadeError(
      'authentication_unavailable',
      'The application verification key is unavailable.'
    )
  }
  const publicKey = { key: ed25519Spki(key.publicKey), format: 'der' as const, type: 'spki' as const }
  if (!verify(null, canonical, publicKey, signature)) {
    throw new FacadeError('unauthenticated', 'The signed application context is invalid.')
  }
  if (
    context.method !== expected.method ||
    context.normalized_path !== expected.normalizedPath ||
    context.route !== expected.route ||
    context.body_sha256 !== sha256Hex(expected.body) ||
    context.mcp_session_digest !== sha256Hex(expected.mcpSessionId)
  ) {
    throw new FacadeError('unauthenticated', 'The signed application context does not bind this request.')
  }
  return context
}
