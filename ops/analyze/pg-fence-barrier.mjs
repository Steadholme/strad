// Coordinate a real wait at Strad's existing advisory lock. The observer emits
// NOTIFY only after pg_locks proves that the real request is waiting.
import pg from '../../facade/node_modules/pg/lib/index.js'
import readline from 'node:readline'

const config = {
  host: process.env.L2_PG_HOST, port: 5432, user: 'l2',
  password: process.env.L2_PG_PASSWORD, database: 'strad_l2',
  connectionTimeoutMillis: 5000,
}
const channel = process.env.L2_BARRIER_CHANNEL
if (!/^analyze_fence_[a-f0-9]{16}$/.test(channel ?? '')) throw new Error('Invalid barrier channel')
const locker = new pg.Client(config)
const observer = new pg.Client(config)
let closing = false
let interval
let notified = false
let checking = false

async function close() {
  if (closing) return
  closing = true
  clearInterval(interval)
  await locker.query('SELECT pg_advisory_unlock(824004001::bigint)').catch(() => {})
  await Promise.all([locker.end().catch(() => {}), observer.end().catch(() => {})])
  process.stdout.write(JSON.stringify({ event: 'released' }) + '\n')
  process.exit(0)
}

process.on('SIGTERM', () => void close())
process.on('SIGINT', () => void close())
const input = readline.createInterface({ input: process.stdin })
input.on('line', line => { if (line === 'release') void close() })
input.on('close', () => void close())

try {
  await locker.connect()
  await observer.connect()
  observer.on('notification', message => {
    if (message.channel === channel && message.payload === 'blocked') {
      process.stdout.write(JSON.stringify({ event: 'blocked', notified: true }) + '\n')
    }
  })
  await observer.query(`LISTEN ${channel}`)
  await locker.query('SELECT pg_advisory_lock(824004001::bigint)')
  const { rows } = await locker.query('SELECT pg_backend_pid() AS pid')
  const pid = rows[0].pid
  process.stdout.write(JSON.stringify({ event: 'locked', pid }) + '\n')
  interval = setInterval(async () => {
    if (checking || notified || closing) return
    checking = true
    try {
      const result = await observer.query(`SELECT EXISTS (
        SELECT 1 FROM pg_locks held JOIN pg_locks waiter
          ON waiter.locktype=held.locktype AND waiter.database=held.database
         AND waiter.classid=held.classid AND waiter.objid=held.objid
         AND waiter.objsubid=held.objsubid
        WHERE held.pid=$1 AND held.locktype='advisory' AND held.granted
          AND NOT waiter.granted AND waiter.pid<>$1) AS blocked`, [pid])
      if (result.rows[0].blocked) {
        notified = true
        await observer.query('SELECT pg_notify($1,$2)', [channel, 'blocked'])
      }
    } catch {
      process.stdout.write(JSON.stringify({ event: 'observer_error' }) + '\n')
      await close()
    } finally {
      checking = false
    }
  }, 25)
} catch (error) {
  process.stdout.write(JSON.stringify({ event: 'barrier_error', code: error.code ?? null }) + '\n')
  await close()
}
