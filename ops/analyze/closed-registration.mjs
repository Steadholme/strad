import { createServer } from 'node:https'
import { readFileSync, statSync } from 'node:fs'
import { createHash, createHmac, createPrivateKey, randomBytes, timingSafeEqual, X509Certificate } from 'node:crypto'

// 仅用于独立闭网身份域；不会连接 Access、数据库或其他服务。
// 容器运行时固定为 node:22-bookworm-slim@sha256:d649c27dae7ba0137b3cef5dd75baa422c08dc3d9e3fc0c23dfb172dc3cc6436。
const base = '/internal/v1/identity/registration'
const signatureHeader = 'x-keystone-regsig'
const versionHeader = 'x-keystone-registration-feed-version'
const consumer = 'access-governance-registration-v1'
const clockSkew = 60
const maxBody = 4096
const maxNonces = 8192
const maxSnapshots = 128
const hash = value => createHash('sha256').update(value).digest('hex')
const visible = value => typeof value === 'string' && value.length > 0 && !/[^\x21-\x7e]/.test(value)
const validKid = value => visible(value) && value.length <= 64 && !/[^A-Za-z0-9._-]/.test(value)
const lowerHex = (value, length) => typeof value === 'string' && value.length === length && !/[^0-9a-f]/.test(value)

class FeedError extends Error {
  constructor(status, code) {
    super(code)
    this.status = status
    this.code = code
  }
}

function config() {
  const required = name => {
    const value = process.env[name]
    if (!value) throw new Error('invalid configuration')
    return value
  }
  const kid = required('L2_REGISTRATION_MAC_KID')
  const key = required('L2_REGISTRATION_MAC_KEY')
  if (!validKid(kid) || !visible(key) || key.length < 32 || key.length > 512) {
    throw new Error('invalid configuration')
  }
  const seed = required('L2_REGISTRATION_SUBJECTS_JSON')
  if (Buffer.byteLength(seed) > 65536) throw new Error('invalid configuration')
  const subjects = JSON.parse(seed)
  if (!Array.isArray(subjects) || subjects.length === 0 || subjects.length > 1024 ||
      subjects.some(subject => !visible(subject) || !subject.startsWith('user:') ||
        subject.length <= 5 || subject.length > 512) || new Set(subjects).size !== subjects.length) {
    throw new Error('invalid configuration')
  }
  const pem = name => {
    const path = required(name)
    if (!path.startsWith('/') || path.length > 4096 || /[\n\r\0]/.test(path)) throw new Error('invalid configuration')
    const info = statSync(path)
    if (!info.isFile() || info.size === 0 || info.size > 65536) throw new Error('invalid configuration')
    return readFileSync(path)
  }
  const ca = pem('L2_REGISTRATION_TLS_CA')
  const cert = pem('L2_REGISTRATION_TLS_CERT')
  const tlsKey = pem('L2_REGISTRATION_TLS_KEY')
  // 单一显式 fixture CA；不读取系统根证书，也不接收调用者提供的信任设置。
  if ((ca.toString().match(/-----BEGIN CERTIFICATE-----/g) ?? []).length !== 1) {
    throw new Error('invalid configuration')
  }
  const authority = new X509Certificate(ca)
  const server = new X509Certificate(cert)
  const now = Date.now()
  if (!authority.ca || server.ca || !server.checkIssued(authority) || !server.verify(authority.publicKey) ||
      !server.checkPrivateKey(createPrivateKey(tlsKey)) || [authority, server].some(certificate =>
        Date.parse(certificate.validFrom) > now || Date.parse(certificate.validTo) <= now)) {
    throw new Error('invalid configuration')
  }
  return { kid, key, subjects: subjects.sort(), ca, cert, tlsKey }
}

function seedFeed(subjects) {
  // 每个显式 subject 有一个固定版本的 genesis 注册事件；不模拟后续身份变更。
  const rows = subjects.map((subject, index) => ({
    ordinal: index + 1, subject, account_version: 1, registration_state: 'registered',
    email_verified: true, enabled: true,
    payload_hash: hash(`registration-payload-v1\n${subject}\n1\nregistered\n1\n1`),
  }))
  const events = rows.map(({ ordinal, ...row }) => ({
    cursor: ordinal, event_id: `ire_${ordinal.toString(16).padStart(16, '0')}_${row.payload_hash.slice(0, 16)}`,
    ...row, occurred_at: 1,
  }))
  const digest = hash(`registration-snapshot-v1\n${rows.length}` + rows.map(row =>
    `\nR\t${row.ordinal}\t${row.subject}\t${row.account_version}\tregistered\t1\t1\t${row.payload_hash}`).join(''))
  const last = events.at(-1)
  return {
    rows, events,
    manifest: { generation: 1, high_watermark: rows.length,
      high_watermark_event_id: last.event_id, high_watermark_payload_hash: last.payload_hash, digest },
  }
}

function values(req, name) {
  const found = []
  for (let index = 0; index < req.rawHeaders.length; index += 2) {
    if (req.rawHeaders[index].toLowerCase() === name) found.push(req.rawHeaders[index + 1])
  }
  return found
}

function integer(raw) {
  if (typeof raw !== 'string' || !raw.length || /[^0-9]/.test(raw) ||
      (raw.length > 1 && raw.startsWith('0'))) return null
  const value = Number(raw)
  return Number.isSafeInteger(value) ? value : null
}

function authenticate(req, body, configuration, nonces) {
  const headers = values(req, signatureHeader)
  if (!req.socket.authorized || headers.length !== 1 || headers[0].length > 256 ||
      values(req, 'authorization').length !== 0) throw new FeedError(401, 'invalid_signature')
  const fields = new Map()
  for (const pair of headers[0].split(',')) {
    const equals = pair.indexOf('=')
    const name = pair.slice(0, equals)
    const value = pair.slice(equals + 1)
    if (equals < 1 || !['kid', 'ts', 'nonce', 'mac'].includes(name) || !value || fields.has(name)) {
      throw new FeedError(401, 'invalid_signature')
    }
    fields.set(name, value)
  }
  const kid = fields.get('kid')
  const timestamp = integer(fields.get('ts'))
  const nonce = fields.get('nonce')
  const mac = fields.get('mac')
  if (fields.size !== 4 || !validKid(kid) || timestamp === null || !lowerHex(nonce, 32) || !lowerHex(mac, 64)) {
    throw new FeedError(401, 'invalid_signature')
  }
  if (kid !== configuration.kid) throw new FeedError(401, 'unknown_kid')
  const now = Math.floor(Date.now() / 1000)
  if (Math.abs(now - timestamp) > clockSkew) throw new FeedError(401, 'stale')
  const separator = req.url.indexOf('?')
  const path = separator < 0 ? req.url : req.url.slice(0, separator)
  const query = separator < 0 ? '' : req.url.slice(separator + 1)
  // 与 Access canonical_mac_bytes 一致：原始 query 按字节排序，末尾没有 LF。
  const canonical = ['regfeed-v1', 'access-governance', 'keystone-registration', req.method,
    path, query.split('&').sort().join('&'), hash(body), kid, String(timestamp), nonce].join('\n')
  const expected = createHmac('sha256', configuration.key).update(canonical).digest()
  if (!timingSafeEqual(expected, Buffer.from(mac, 'hex'))) throw new FeedError(401, 'bad_mac')
  // 认证成功之后才能回显 nonce，包括 replay 和容量耗尽错误。
  req.ackedNonce = nonce
  for (const [previous, expiry] of nonces) {
    if (expiry < now) nonces.delete(previous)
  }
  const nonceHash = hash(nonce)
  if (nonces.has(nonceHash)) throw new FeedError(401, 'replay')
  if (nonces.size >= maxNonces) throw new FeedError(503, 'registration_feed_unavailable')
  nonces.set(nonceHash, now + clockSkew * 2)
  return { path, query, hasQuery: separator >= 0 }
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let size = 0
    req.on('data', chunk => {
      size += chunk.length
      if (size > maxBody) {
        chunks.length = 0
        reject(new FeedError(413, 'body_too_large'))
      } else {
        chunks.push(chunk)
      }
    })
    req.once('end', () => resolve(Buffer.concat(chunks)))
    req.once('error', () => reject(new FeedError(400, 'invalid_request')))
  })
}

function pageQuery(query, cursorName, maxLimit, head) {
  const fields = new Map()
  for (const pair of query.split('&')) {
    const parts = pair.split('=')
    if (parts.length !== 2 || ![cursorName, 'limit'].includes(parts[0]) || fields.has(parts[0])) {
      throw new FeedError(400, 'invalid_request')
    }
    fields.set(parts[0], integer(parts[1]))
  }
  const after = fields.get(cursorName)
  const limit = fields.get('limit')
  if (fields.size !== 2 || after === null || limit === null || limit < 1 || limit > maxLimit || after > head) {
    throw new FeedError(400, 'invalid_request')
  }
  return { after, limit }
}

function acknowledge(body, feed, storedCursor) {
  let request
  let text
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(body)
    request = JSON.parse(text)
  } catch {
    throw new FeedError(400, 'invalid_request')
  }
  const keys = ['consumer', 'generation', 'cursor', 'event_id', 'payload_hash']
  // 客户端的固定 ACK DTO 没有转义字符或浮点数；不能接受 JSON.parse 的重复字段覆盖。
  const names = [...text.matchAll(/"([a-z_]+)"\s*:/g)].map(match => match[1])
  if (!request || typeof request !== 'object' || Array.isArray(request) ||
      text.includes('\\') || !/"generation"\s*:\s*(0|[1-9][0-9]*)\s*[,}]/.test(text) ||
      !/"cursor"\s*:\s*(0|[1-9][0-9]*)\s*[,}]/.test(text) ||
      Object.keys(request).length !== keys.length || keys.some(key => !Object.hasOwn(request, key)) ||
      names.length !== keys.length || new Set(names).size !== keys.length ||
      request.consumer !== consumer || !Number.isSafeInteger(request.generation) || request.generation < 1 ||
      !Number.isSafeInteger(request.cursor) || request.cursor < 1 ||
      !lowerHex(request.payload_hash, 64) || typeof request.event_id !== 'string' ||
      request.event_id.length !== 37 || !/^ire_[0-9a-f]{16}_[0-9a-f]{16}$/.test(request.event_id)) {
    throw new FeedError(400, 'invalid_request')
  }
  if (request.generation !== feed.manifest.generation) throw new FeedError(409, 'ack_generation_conflict')
  if (request.cursor > feed.events.length) throw new FeedError(409, 'ack_ahead')
  const event = feed.events[request.cursor - 1]
  if (request.event_id !== event.event_id || request.payload_hash !== event.payload_hash) {
    throw new FeedError(409, 'ack_event_mismatch')
  }
  if (request.cursor < storedCursor) throw new FeedError(409, 'ack_regression')
  return { consumer, generation: request.generation, stored_cursor: request.cursor }
}

function json(res, status, value) {
  res.writeHead(status, {
    'Content-Type': 'application/json', 'Cache-Control': 'private, no-store',
    Vary: 'X-Keystone-RegSig, X-Keystone-Registration-Feed-Version',
    'X-Content-Type-Options': 'nosniff', Connection: 'close',
  })
  res.end(JSON.stringify(value))
}

function start(configuration) {
  const feed = seedFeed(configuration.subjects)
  const nonces = new Map()
  const snapshots = new Set()
  let storedCursor = 0
  const server = createServer({
    ca: configuration.ca, cert: configuration.cert, key: configuration.tlsKey,
    requestCert: true, rejectUnauthorized: true, minVersion: 'TLSv1.2', maxHeaderSize: 8192,
    requestTimeout: 5000, headersTimeout: 5000,
  }, async (req, res) => {
    try {
      const body = await readBody(req)
      const { path, query, hasQuery } = authenticate(req, body, configuration, nonces)
      const versions = values(req, versionHeader)
      if (versions.length !== 1 || versions[0] !== '2') throw new FeedError(400, 'invalid_version')
      if (path.length > 512 || !path.startsWith('/') || path.startsWith('//') || /[\n\r\0#]/.test(path) ||
          query.length > 256 || /[\n\r\0#]/.test(query)) throw new FeedError(400, 'invalid_request')
      let method
      if (path === `${base}/snapshot` || path === `${base}/ack`) method = 'POST'
      else if (path.startsWith(`${base}/snapshot/`) || path === `${base}/changes`) method = 'GET'
      else throw new FeedError(404, 'not_found')
      if (req.method !== method) throw new FeedError(405, 'method_not_allowed')
      if ((path !== `${base}/ack` && body.length) || (method === 'POST' && hasQuery)) {
        throw new FeedError(400, 'invalid_request')
      }
      let response
      let status = 200
      if (path === `${base}/snapshot`) {
        if (snapshots.size >= maxSnapshots) throw new FeedError(503, 'registration_feed_unavailable')
        const id = `irs_${randomBytes(16).toString('hex')}`
        snapshots.add(id)
        response = { snapshot_id: id, ...feed.manifest, count: feed.rows.length }
        status = 201
      } else if (path.startsWith(`${base}/snapshot/`)) {
        const id = path.slice(`${base}/snapshot/`.length)
        if (id.length !== 36 || !id.startsWith('irs_') || !lowerHex(id.slice(4), 32)) {
          throw new FeedError(400, 'invalid_request')
        }
        if (!snapshots.has(id)) throw new FeedError(410, 'resnapshot_required')
        const { after, limit } = pageQuery(query, 'after_ordinal', 1000, feed.rows.length)
        const rows = feed.rows.slice(after, after + limit)
        const next = after + rows.length
        response = { snapshot_id: id, ...feed.manifest, rows, next_after_ordinal: next, done: next === feed.rows.length }
      } else if (path === `${base}/changes`) {
        const { after, limit } = pageQuery(query, 'after', 500, feed.events.length)
        response = { generation: feed.manifest.generation, events: feed.events.slice(after, after + limit),
          head_cursor: feed.events.length, retention_floor_cursor: 0 }
      } else {
        const types = values(req, 'content-type')
        if (types.length !== 1 || types[0] !== 'application/json') throw new FeedError(400, 'invalid_request')
        response = acknowledge(body, feed, storedCursor)
        // 仅保留源端已实际接收的 cursor；Access 提交及其 ACK 状态仍完全由真实 worker 负责。
        storedCursor = response.stored_cursor
      }
      json(res, status, { ...response, acked_nonce: req.ackedNonce })
    } catch (error) {
      const status = error instanceof FeedError ? error.status : 500
      const code = error instanceof FeedError ? error.code : 'registration_feed_unavailable'
      const response = { error: code }
      if (req.ackedNonce) response.acked_nonce = req.ackedNonce
      json(res, status, response)
    }
  })
  server.setTimeout(5000, socket => socket.destroy())
  server.on('error', () => {
    console.error('closed registration fixture startup error')
    process.exit(1)
  })
  server.listen(9443, '0.0.0.0')
}

try {
  start(config())
} catch {
  console.error('closed registration fixture configuration error')
  process.exit(1)
}
