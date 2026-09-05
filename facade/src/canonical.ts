import { createHash } from 'node:crypto'

export const SHA256_PATTERN = /^[0-9a-f]{64}$/
export const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
export const APPLICATION_SUB_PATTERN = /^application:[A-Za-z0-9_-]{16,128}$/

export function sha256Hex(value: string | Buffer): string {
  return createHash('sha256').update(value).digest('hex')
}

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(',')}]`
  const entries = Object.entries(value as Record<string, unknown>).sort(([left], [right]) =>
    left < right ? -1 : left > right ? 1 : 0
  )
  return `{${entries
    .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`)
    .join(',')}}`
}

export function canonicalApplicationRequestSha(
  applicationSub: string,
  canonicalTool: string,
  resource: string,
  body: unknown
): string {
  const digest = createHash('sha256')
  for (const part of [applicationSub, canonicalTool, resource, canonicalJson(body)]) {
    const encoded = Buffer.from(part, 'utf8')
    const size = Buffer.alloc(8)
    size.writeBigUInt64BE(BigInt(encoded.length))
    digest.update(size)
    digest.update(encoded)
  }
  return digest.digest('hex')
}

export function stableUuid(domain: string, ...parts: string[]): string {
  const digest = createHash('sha256')
    .update(domain, 'utf8')
    .update('\0')
    .update(parts.join('\0'), 'utf8')
    .digest()
  const bytes = Buffer.from(digest.subarray(0, 16))
  bytes[6] = ((bytes[6] ?? 0) & 0x0f) | 0x50
  bytes[8] = ((bytes[8] ?? 0) & 0x3f) | 0x80
  const hex = bytes.toString('hex')
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}
