import { createHash, timingSafeEqual } from 'node:crypto'
import type { IncomingMessage } from 'node:http'

import { BridgeError } from './errors.js'

export const SHA256_PATTERN = /^[0-9a-f]{64}$/
export const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

function headerValues(req: IncomingMessage, expectedName: string): string[] {
  const values: string[] = []
  for (let index = 0; index < req.rawHeaders.length; index += 2) {
    if (req.rawHeaders[index]?.toLowerCase() === expectedName.toLowerCase()) {
      values.push(req.rawHeaders[index + 1] ?? '')
    }
  }
  return values
}

export function singleHeader(req: IncomingMessage, name: string, required = true): string | null {
  const values = headerValues(req, name)
  if (values.length === 0 && !required) return null
  if (values.length !== 1 || values[0] === undefined || values[0].length === 0) {
    throw new BridgeError(400, 'invalid_request', false, `Exactly one ${name} header is required`)
  }
  return values[0]
}

function tokenDigest(value: string): Buffer {
  return createHash('sha256').update(value, 'utf8').digest()
}

export function authenticate(req: IncomingMessage, expectedToken: string): void {
  let authorization: string | null = null
  try {
    authorization = singleHeader(req, 'authorization')
  } catch {
    // Authentication failures deliberately share one response while still
    // performing the fixed-length digest comparison below.
  }
  const match = authorization?.match(/^Bearer ([\x21-\x7e]+)$/)
  const supplied = match?.[1] ?? ''
  const valid = timingSafeEqual(tokenDigest(supplied), tokenDigest(expectedToken))
  if (!match || !valid) {
    throw new BridgeError(401, 'invalid_bridge_credential', false, 'Invalid bridge credential')
  }
}

export function requireOperationId(req: IncomingMessage): string {
  const value = singleHeader(req, 'x-operation-id')
  if (!value || !UUID_PATTERN.test(value)) {
    throw new BridgeError(400, 'invalid_request', false, 'X-Operation-ID must be a canonical UUID')
  }
  return value
}

export function requireRequestSha(req: IncomingMessage): string {
  const value = singleHeader(req, 'x-request-sha256')
  if (!value || !SHA256_PATTERN.test(value)) {
    throw new BridgeError(
      400,
      'invalid_request',
      false,
      'X-Request-SHA256 must be lowercase SHA-256'
    )
  }
  return value
}

export function sha256Hex(value: string | Buffer): string {
  return createHash('sha256').update(value).digest('hex')
}

export function constantTimeDigestEqual(left: string, right: string): boolean {
  return timingSafeEqual(Buffer.from(left, 'ascii'), Buffer.from(right, 'ascii'))
}
