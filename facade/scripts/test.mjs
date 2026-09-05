import { readdirSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { join } from 'node:path'

import pg from 'pg'

const { Client } = pg

const testDirectory = new URL('../dist/tests/', import.meta.url)
const tests = readdirSync(testDirectory)
  .filter((name) => name.endsWith('.test.js'))
  .sort()
  .map((name) => join(testDirectory.pathname, name))
let container = null
const environment = { ...process.env }
function cleanupContainer() {
  if (!container) return
  spawnSync('docker', ['rm', '-f', container], { stdio: 'ignore' })
  container = null
}
process.once('SIGINT', () => {
  cleanupContainer()
  process.exit(130)
})
process.once('SIGTERM', () => {
  cleanupContainer()
  process.exit(143)
})
try {
  if (!environment.FACADE_TEST_DATABASE_URL) {
    const suffix = randomUUID().replaceAll('-', '').slice(0, 16)
    const name = `analyze-facade-test-pg18-${suffix}`
    const password = `test-${randomUUID()}`
    const started = spawnSync(
      'docker',
      [
        'run',
        '-d',
        '--rm',
        '--name',
        name,
        '-e',
        `POSTGRES_PASSWORD=${password}`,
        '-e',
        'POSTGRES_USER=facade',
        '-e',
        'POSTGRES_DB=facade',
        '-p',
        '127.0.0.1::5432',
        'postgres:18-alpine',
      ],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }
    )
    if (started.status !== 0) throw new Error('failed to start disposable PostgreSQL')
    container = name
    const portResult = spawnSync('docker', ['port', name, '5432/tcp'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    const port = portResult.stdout.trim().match(/:([0-9]+)$/)?.[1]
    if (portResult.status !== 0 || !port) {
      throw new Error('failed to resolve disposable PostgreSQL port')
    }
    const testDatabaseUrl = `postgres://facade:${encodeURIComponent(password)}@127.0.0.1:${port}/facade`
    let ready = false
    for (let attempt = 0; attempt < 120; attempt++) {
      const client = new Client({ connectionString: testDatabaseUrl, connectionTimeoutMillis: 500 })
      try {
        await client.connect()
        await client.query('SELECT 1')
        await client.end()
        ready = true
        break
      } catch {
        await client.end().catch(() => undefined)
        await new Promise((resolve) => setTimeout(resolve, 250))
      }
    }
    if (!ready) throw new Error('disposable PostgreSQL did not become ready')
    environment.FACADE_TEST_DATABASE_URL = testDatabaseUrl
  }
  const result = spawnSync(process.execPath, ['--test', ...process.argv.slice(2), ...tests], {
    env: environment,
    stdio: 'inherit',
  })
  process.exitCode = result.status ?? 1
} finally {
  cleanupContainer()
}
