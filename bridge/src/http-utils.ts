import type { IncomingMessage, ServerResponse } from 'node:http'

import { MAX_JSON_BYTES } from './constants.js'
import { BridgeError } from './errors.js'
import { singleHeader } from './security.js'

export async function readJsonBody(
  req: IncomingMessage
): Promise<{ raw: Buffer; value: unknown }> {
  const contentType = singleHeader(req, 'content-type')
  if (contentType?.toLowerCase() !== 'application/json') {
    throw new BridgeError(400, 'invalid_request', false, 'Content-Type must be application/json')
  }
  if (singleHeader(req, 'content-encoding', false) !== null) {
    throw new BridgeError(400, 'invalid_request', false, 'Content-Encoding is not supported')
  }
  const declaredHeader = singleHeader(req, 'content-length', false)
  if (declaredHeader !== null) {
    if (!/^[0-9]+$/.test(declaredHeader) || Number(declaredHeader) > MAX_JSON_BYTES) {
      throw new BridgeError(413, 'request_too_large', false, 'JSON request is too large')
    }
  }
  const chunks: Buffer[] = []
  let total = 0
  for await (const chunk of req) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
    total += bytes.length
    if (total > MAX_JSON_BYTES) {
      throw new BridgeError(413, 'request_too_large', false, 'JSON request is too large')
    }
    chunks.push(bytes)
  }
  if (declaredHeader !== null && total !== Number(declaredHeader)) {
    throw new BridgeError(400, 'invalid_request', false, 'Content-Length mismatch')
  }
  const raw = Buffer.concat(chunks, total)
  let value: unknown
  try {
    value = JSON.parse(raw.toString('utf8')) as unknown
  } catch {
    throw new BridgeError(400, 'invalid_request', false, 'Body is not valid JSON')
  }
  return { raw, value }
}

export function sendJson(
  response: ServerResponse,
  status: number,
  body: unknown,
  retryAfterSeconds?: number
): void {
  const encoded = Buffer.from(JSON.stringify(body), 'utf8')
  response.writeHead(status, {
    'cache-control': 'private, no-store',
    'content-type': 'application/json; charset=utf-8',
    'content-length': String(encoded.length),
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
    ...(retryAfterSeconds === undefined
      ? {}
      : { 'retry-after': String(retryAfterSeconds) }),
  })
  response.end(encoded)
}
