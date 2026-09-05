import { createServer } from 'node:http'
import { timingSafeEqual } from 'node:crypto'

// 闭网 synthetic 人类域：空 workforce 来源及三个隔离 lifecycle 接收端。
// 只记录通过真实 HTTP 收到的状态，不连接 Access DB，也不代表生产服务。
function configuration() {
  const subjects = JSON.parse(process.env.L2_REGISTRATION_SUBJECTS_JSON ?? '')
  if (!Array.isArray(subjects) || !subjects.length || subjects.length > 1024 ||
      subjects.some(value => typeof value !== 'string' || !/^user:[!-~]{1,250}$/.test(value)) ||
      new Set(subjects).size !== subjects.length) throw new Error('configuration')
  const tokens = Object.fromEntries(['CENSUS', 'LIFECYCLE_SLUICE', 'LIFECYCLE_NEWAPI', 'LIFECYCLE_KEYSTONE']
    .map(name => [name, process.env[`L2_${name}_TOKEN`]]))
  if (Object.values(tokens).some(value => typeof value !== 'string' || !/^[!-~]{32,512}$/.test(value)) ||
      new Set(Object.values(tokens)).size !== 4) throw new Error('configuration')
  return { subjects: new Set(subjects.map(value => value.slice(5))), tokens }
}

let config
try { config = configuration() } catch {
  process.stderr.write('closed lifecycle fixture configuration error\n')
  process.exit(1)
}
const states = new Map()
function send(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'private, no-store', Vary: 'Authorization' })
  res.end(JSON.stringify(data))
}
const server = createServer(async (req, res) => {
  const url = new URL(req.url, 'http://closed-lifecycle:9081')
  const target = ['/sluice', '/newapi', '/keystone'].includes(url.pathname) ? url.pathname.slice(1) : null
  const census = url.pathname === '/internal/v1/workforce/changes'
  if (!target && !census) return send(res, 404, { error: 'not_found' })
  const token = config.tokens[census ? 'CENSUS' : `LIFECYCLE_${target.toUpperCase()}`]
  const actual = Buffer.from(req.headers.authorization ?? '')
  const expected = Buffer.from(`Bearer ${token}`)
  const authCount = req.rawHeaders.filter((value, index) => index % 2 === 0 && value.toLowerCase() === 'authorization').length
  if (authCount !== 1 || actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
    return send(res, 401, { error: 'unauthorized' })
  }
  if (req.method !== (census ? 'GET' : 'POST')) return send(res, 405, { error: 'method_not_allowed' })
  const chunks = []
  let length = 0
  try {
    for await (const chunk of req) {
      length += chunk.length
      if (length > 4096) return send(res, 413, { error: 'too_large' })
      chunks.push(chunk)
    }
    if (census) {
      if (length || url.searchParams.size !== 2 || url.searchParams.get('after') !== '0' ||
          !/^[1-9][0-9]{0,2}$/.test(url.searchParams.get('limit') ?? '') ||
          Number(url.searchParams.get('limit')) > 100) return send(res, 400, { error: 'invalid_cursor' })
      return send(res, 200, { items: [], next_cursor: 0, has_more: false })
    }
    if (url.search || req.headers['content-type'] !== 'application/json') return send(res, 400, { error: 'invalid_request' })
    const value = JSON.parse(Buffer.concat(chunks).toString('utf8'))
    const keys = ['subject', 'state', 'source_event_id', 'source_version', 'correlation_id']
    if (!value || Object.keys(value).sort().join() !== keys.sort().join() ||
        !config.subjects.has(value.subject) || !['active', 'frozen', 'terminated'].includes(value.state) ||
        !Number.isSafeInteger(value.source_version) || value.source_version <= 0 ||
        !new RegExp(`^effective:[1-9][0-9]*:${value.source_version}:[0-9a-f]{64}$`).test(value.source_event_id) ||
        value.correlation_id !== `effective:user:${value.subject}:${value.source_version}` ||
        req.headers['x-correlation-id'] !== value.correlation_id) return send(res, 400, { error: 'invalid_request' })
    const key = `${target}:${value.subject}`
    const old = states.get(key)
    if (old && (old.source_version > value.source_version || (old.source_version === value.source_version &&
        (old.state !== value.state || old.source_event_id !== value.source_event_id)))) return send(res, 409, { error: 'version_conflict' })
    const replayed = old?.source_version === value.source_version
    states.set(key, value)
    return send(res, 200, { subject: value.subject, state: value.state, source_version: value.source_version, replayed })
  } catch {
    return send(res, 400, { error: 'invalid_request' })
  }
})
server.requestTimeout = 5000
server.headersTimeout = 5000
server.maxHeadersCount = 32
server.listen(9081, '0.0.0.0')
