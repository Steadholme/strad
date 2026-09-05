import { createServer as httpServer, request } from 'node:http'
import { createServer as httpsServer } from 'node:https'
import { createSecureContext } from 'node:tls'
import { readFileSync } from 'node:fs'
import { createHash, generateKeyPairSync, randomBytes, sign, timingSafeEqual } from 'node:crypto'
import { MODES, injectDecisionFault } from './decision-faults.mjs'

// 常规模式只转发。显式闭网负例模式只注入拒绝或损坏响应，不能产生新的授权。
const bundle = readFileSync('/run/l2/access.pem')
const testCert = readFileSync('/run/l2/test.crt')
const testKey = readFileSync('/run/l2/test.key')
const testContext = createSecureContext({ cert: testCert, key: testKey })
const accessContext = createSecureContext({ cert: bundle, key: bundle })
const issuer = 'https://id.w33d.xyz'
const redirect = 'https://id.w33d.xyz/_gw/auth/callback'
const subject = process.env.L2_TEST_SUBJECT
if (!/^usr_[A-Za-z0-9_-]{43}$/.test(subject ?? '')) throw new Error('closed test subject is required')
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'l2-oidc', alg: 'RS256', use: 'sig' }
const codes = new Map()
const assurances = new Map()
const counts = { authorizations: 0, token_exchanges: 0, assurance_lookups: 0 }
const faultCases = new Set()

async function decisionFault(req, res, upstream) {
  let control
  try { control = JSON.parse(readFileSync('/run/l2/decision-fault.json', 'utf8')) }
  catch { return false }
  if (!MODES.has(control.mode) || !/^[a-f0-9]{32}$/.test(control.case_id ?? '') ||
      !/^application:[A-Za-z0-9_-]{16,128}$/.test(control.application_sub ?? '') ||
      control.expires_at <= Date.now() / 1000 || faultCases.has(control.case_id)) return false
  const body = await readBody(req)
  const parsed = JSON.parse(body)
  const matched = parsed.application_sub === control.application_sub && parsed.canonical_tool === 'analysis.read'
  if (matched) faultCases.add(control.case_id)
  await new Promise((resolve, reject) => {
    const forwarded = request({ hostname: upstream.hostname, port: upstream.port, path: req.url,
      method: req.method, headers: { ...req.headers, host: upstream.host }, timeout: 5000 }, incoming => {
      const chunks = []; let size = 0
      incoming.on('data', chunk => {
        size += chunk.length
        if (size > 65536) incoming.destroy(new Error('Decision response too large'))
        else chunks.push(chunk)
      })
      incoming.once('error', reject)
      incoming.on('end', () => {
        try {
          const raw = Buffer.concat(chunks)
          if (!matched || incoming.statusCode !== 200) {
            res.writeHead(incoming.statusCode, incoming.headers); res.end(raw); resolve(); return
          }
          const original = JSON.parse(raw.toString('utf8'))
          const changed = injectDecisionFault(control.mode, parsed, original)
          console.log('L2_DECISION_FAULT ' + JSON.stringify({ case_id: control.case_id, mode: control.mode,
            application_sub: parsed.application_sub, upstream_decision_id: original.decision_id,
            upstream_digest: original.decision_digest, response_status: changed.status }))
          json(res, changed.status, changed.body); resolve()
        } catch (error) { reject(error) }
      })
    })
    forwarded.once('timeout', () => forwarded.destroy(new Error('Decision timeout')))
    forwarded.once('error', reject)
    forwarded.end(body)
  })
  return true
}
const sameSecret = (left, right) => typeof left === 'string' && typeof right === 'string' &&
  Buffer.byteLength(left) === Buffer.byteLength(right) && timingSafeEqual(Buffer.from(left), Buffer.from(right))
const json = (res, status, value) => {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' })
  res.end(JSON.stringify(value))
}
async function readBody(req) {
  const chunks = []; let size = 0
  for await (const chunk of req) {
    size += chunk.length
    if (size > 65536) throw new Error('body too large')
    chunks.push(chunk)
  }
  return Buffer.concat(chunks).toString('utf8')
}

// 独立的闭网 OIDC fixture：测试身份只在本进程中存在，断开即销毁。
// Sponsor 和系统审批始终由真正的 Sluice / Access 代码产生。
async function oidc(req, res) {
  const url = new URL(req.url, issuer)
  const now = Math.floor(Date.now() / 1000)
  if (req.method === 'GET' && url.pathname === '/.well-known/openid-configuration') {
    json(res, 200, { issuer, authorization_endpoint: issuer + '/authorize', token_endpoint: issuer + '/token',
      jwks_uri: issuer + '/jwks', response_types_supported: ['code'], subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256'], code_challenge_methods_supported: ['S256'] })
  } else if (req.method === 'GET' && url.pathname === '/jwks') {
    json(res, 200, { keys: [jwk] })
  } else if (req.method === 'GET' && url.pathname === '/authorize') {
    const params = url.searchParams
    if (params.get('client_id') !== 'access-governance' || params.get('redirect_uri') !== redirect ||
        params.get('response_type') !== 'code' || !params.get('state') || !params.get('nonce') ||
        params.get('code_challenge_method') !== 'S256' || !params.get('code_challenge')) {
      json(res, 400, { error: 'invalid_request' }); return
    }
    const code = randomBytes(32).toString('base64url')
    codes.set(code, { nonce: params.get('nonce'), challenge: params.get('code_challenge'), issuedAt: now })
    counts.authorizations++
    const callback = new URL(redirect)
    callback.searchParams.set('code', code); callback.searchParams.set('state', params.get('state'))
    res.writeHead(302, { Location: callback.toString(), 'Cache-Control': 'no-store' }); res.end()
  } else if (req.method === 'POST' && url.pathname === '/token') {
    const params = new URLSearchParams(await readBody(req))
    const code = params.get('code'); const pending = codes.get(code)
    if (!pending || now - pending.issuedAt > 60 || params.get('client_id') !== 'access-governance' ||
        !sameSecret(params.get('client_secret'), process.env.L2_OIDC_CLIENT_SECRET) ||
        params.get('redirect_uri') !== redirect || params.get('grant_type') !== 'authorization_code' ||
        createHash('sha256').update(params.get('code_verifier') ?? '').digest('base64url') !== pending.challenge) {
      json(res, 400, { error: 'invalid_grant' }); return
    }
    codes.delete(code)
    const binding = randomBytes(32).toString('hex')
    assurances.set(binding, { subject, auth_time: now })
    const claims = { iss: issuer, sub: subject, aud: 'access-governance', iat: now, exp: now + 300,
      nonce: pending.nonce, auth_time: now, acr: 'hf-aal-strong', amr: ['hwk', 'user'],
      hf_mfa: { aal: 'MFA_STRONG', uv: true, sb: binding, fe: 1 } }
    const unsigned = [ { alg: 'RS256', typ: 'JWT', kid: jwk.kid }, claims ].map(v => Buffer.from(JSON.stringify(v)).toString('base64url')).join('.')
    counts.token_exchanges++
    json(res, 200, { token_type: 'Bearer', expires_in: 300, scope: 'openid',
      access_token: randomBytes(32).toString('base64url'), id_token: unsigned + '.' + sign('RSA-SHA256', Buffer.from(unsigned), privateKey).toString('base64url') })
  } else if (req.method === 'POST' && url.pathname === '/internal/v1/session-assurance') {
    if (!sameSecret(req.headers.authorization, 'Bearer ' + process.env.L2_ASSURANCE_TOKEN)) {
      json(res, 401, { error: 'unauthenticated' }); return
    }
    const query = JSON.parse(await readBody(req))
    const known = assurances.get(query.session_binding)
    counts.assurance_lookups++
    const live = known?.subject === query.subject && now - known.auth_time <= 300
    json(res, 200, { result: live ? 'live' : 'absent', subject: query.subject,
      session_binding: live ? query.session_binding : null, aal: live ? 'MFA_STRONG' : 'AAL_NONE',
      uv: live, auth_time: live ? known.auth_time : 0, factor_epoch: 1, as_of: now })
  } else { json(res, 404, { error: 'not_found' }) }
}

function target(host, path) {
  if (host === 'id.w33d.xyz' && path.startsWith('/_gw/auth/')) return { hostname: 'sluice', port: 9090, host }
  if (host === 'analyze.w33d.xyz') {
    if (path.startsWith('/internal/')) return null
    return { hostname: 'sluice', port: 9090, host }
  }
  if (host !== 'access.w33d.xyz') return null
  if (path === '/internal/v1/application-execution-fence/check') return { hostname: 'access', port: 9390, host }
  if (path === '/internal/v1/application-session-revocations') return { hostname: 'facade', port: 18120, host: 'facade:18120' }
  if (path === '/api/v2/application-check') return { hostname: 'verdict', port: 9140, host }
  if (path === '/readyz' || path.startsWith('/internal/v1/facade/') || path.startsWith('/internal/v1/governance/')) return { hostname: 'strad', port: 9360, host }
  return null
}

async function proxy(req, res) {
  if (req.headers.host === 'id.w33d.xyz' && !req.url.startsWith('/_gw/auth/')) {
    try { await oidc(req, res) } catch { json(res, 400, { error: 'invalid_request' }) }
    return
  }
  const upstream = target(req.headers.host, req.url)
  if (!upstream) { res.writeHead(404); res.end(); return }
  if (req.headers.host === 'access.w33d.xyz' && req.url === '/api/v2/application-check') {
    try { if (await decisionFault(req, res, upstream)) return }
    catch { if (!res.headersSent) json(res, 503, { error: 'closed_decision_fault_failed' }); else res.end(); return }
  }
  const forwarded = request({
    hostname: upstream.hostname, port: upstream.port, path: req.url, method: req.method,
    headers: { ...req.headers, host: upstream.host }, timeout: 10000,
  }, incoming => { res.writeHead(incoming.statusCode, incoming.headers); incoming.pipe(res) })
  forwarded.once('timeout', () => forwarded.destroy(new Error('upstream timeout')))
  forwarded.once('error', () => { if (!res.headersSent) res.writeHead(502); res.end() })
  req.once('aborted', () => forwarded.destroy())
  req.pipe(forwarded)
}

// 不预装默认证书；混用 ECDSA/RSA 时必须由 SNI 单独选择完整上下文。
httpsServer({ SNICallback: (name, callback) => {
  if (name === 'analyze.w33d.xyz' || name === 'id.w33d.xyz') callback(null, testContext)
  else if (name === 'access.w33d.xyz') callback(null, accessContext)
  else callback(new Error('unknown closed TLS origin'))
}}, proxy).listen(443, '0.0.0.0')

// 健康检查与业务观察分离；不返回任何凭据或会话内容。
httpServer((req, res) => {
  if (req.url === '/observations') {
    json(res, 200, { fixture: 'closed-test-issuer', subject, ...counts }); return
  }
  res.writeHead(req.url === '/healthz' ? 200 : 404, { 'Content-Type': 'application/json' })
  res.end(req.url === '/healthz' ? '{"status":"ready"}' : '{}')
}).listen(18130, '0.0.0.0')
