import { resolve } from 'node:path'

import { CHILD_ENV_BASE } from './constants.js'

const MIN_SECRET_BYTES = 32

export type BridgeConfig = {
  readonly host: string
  readonly port: number
  readonly bridgeToken: string
  readonly fileServerApiKey: string
  readonly journalPath: string
  readonly spoolRoot: string
  readonly staticLockPath: string
  readonly childCommand: string
  readonly childArgs: readonly string[]
  readonly childCwd: string
  readonly childEnv: Readonly<Record<string, string>>
}

function requiredSecret(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name]?.trim()
  if (!value || Buffer.byteLength(value, 'utf8') < MIN_SECRET_BYTES) {
    throw new Error(`${name} must contain at least ${MIN_SECRET_BYTES} UTF-8 bytes`)
  }
  return value
}

function parsePort(value: string | undefined): number {
  if (value === undefined) return 18090
  if (!/^[0-9]{1,5}$/.test(value)) throw new Error('STRAD_BRIDGE_PORT must be a TCP port')
  const port = Number(value)
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
    throw new Error('STRAD_BRIDGE_PORT must be a TCP port')
  }
  return port
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): BridgeConfig {
  const bridgeToken = requiredSecret(env, 'STRAD_BRIDGE_TOKEN')
  const fileServerApiKey = requiredSecret(env, 'RIKUNE_FILE_SERVER_API_KEY')
  if (bridgeToken === fileServerApiKey) {
    throw new Error('STRAD_BRIDGE_TOKEN and RIKUNE_FILE_SERVER_API_KEY must differ')
  }

  const stateRoot = resolve(env.STRAD_BRIDGE_STATE_ROOT ?? '/data/state')
  const spoolRoot = resolve(env.STRAD_BRIDGE_SPOOL_ROOT ?? '/data/storage/bridge-ingest')
  const staticLockPath = resolve(env.RIKUNE_STATIC_LOCK_PATH ?? '/app/static-profile.lock.json')
  if (stateRoot !== '/data/state') {
    throw new Error('STRAD_BRIDGE_STATE_ROOT must be /data/state')
  }
  if (spoolRoot !== '/data/storage/bridge-ingest') {
    throw new Error('STRAD_BRIDGE_SPOOL_ROOT must be /data/storage/bridge-ingest')
  }
  if (staticLockPath !== '/app/static-profile.lock.json') {
    throw new Error('RIKUNE_STATIC_LOCK_PATH must be /app/static-profile.lock.json')
  }
  const childEnv = Object.freeze({
    ...CHILD_ENV_BASE,
    API_KEY: fileServerApiKey,
  })

  return Object.freeze({
    host: env.STRAD_BRIDGE_HOST?.trim() || '0.0.0.0',
    port: parsePort(env.STRAD_BRIDGE_PORT),
    bridgeToken,
    fileServerApiKey,
    journalPath: resolve(stateRoot, 'bridge-operations.sqlite'),
    spoolRoot,
    staticLockPath,
    childCommand: '/usr/local/bin/node',
    childArgs: Object.freeze(['/app/dist/index.js']),
    childCwd: '/app',
    childEnv,
  })
}
