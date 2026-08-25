import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import test from 'node:test'
import type { IncomingMessage } from 'node:http'

import { loadConfig } from '../src/config.js'
import { STATIC_PLUGINS } from '../src/constants.js'
import { authenticate, requireOperationId } from '../src/security.js'
import {
  STATIC_PROFILE_LOCK_SHA256,
  validateStaticBackendEnvironment,
  validateStaticLock,
} from '../src/static-lock.js'
import { withoutSdkInheritedEnvironment } from '../src/mcp-child.js'

function requestWithRawHeaders(rawHeaders: string[]): IncomingMessage {
  return { rawHeaders } as IncomingMessage
}

test('child environment is an exact allowlist and does not inherit parent values', () => {
  const config = loadConfig({
    STRAD_BRIDGE_TOKEN: 'b'.repeat(32),
    RIKUNE_FILE_SERVER_API_KEY: 'f'.repeat(32),
    AWS_SECRET_ACCESS_KEY: 'must-not-leak',
    NODE_OPTIONS: '--inspect=0.0.0.0:9229',
  })
  assert.equal(config.childEnv.API_KEY, 'f'.repeat(32))
  assert.equal(config.childEnv.RUNTIME_MODE, 'disabled')
  assert.equal(config.childEnv.ALLOW_LIVE_EXECUTION, undefined)
  assert.equal(config.childEnv.AWS_SECRET_ACCESS_KEY, undefined)
  assert.equal(config.childEnv.NODE_OPTIONS, undefined)
})

test('SDK default parent environment is scrubbed only for the child spawn window', async () => {
  const originalHome = process.env.HOME
  const originalTerm = process.env.TERM
  process.env.HOME = '/parent/home/must-not-leak'
  process.env.TERM = 'parent-terminal-must-not-leak'
  try {
    await withoutSdkInheritedEnvironment(async () => {
      assert.equal(process.env.HOME, undefined)
      assert.equal(process.env.TERM, undefined)
    })
    assert.equal(process.env.HOME, '/parent/home/must-not-leak')
    assert.equal(process.env.TERM, 'parent-terminal-must-not-leak')
  } finally {
    if (originalHome === undefined) delete process.env.HOME
    else process.env.HOME = originalHome
    if (originalTerm === undefined) delete process.env.TERM
    else process.env.TERM = originalTerm
  }
})

test('config rejects short or equal bridge and file-server secrets', () => {
  assert.throws(() =>
    loadConfig({ STRAD_BRIDGE_TOKEN: 'short', RIKUNE_FILE_SERVER_API_KEY: 'f'.repeat(32) })
  )
  assert.throws(() =>
    loadConfig({
      STRAD_BRIDGE_TOKEN: 'x'.repeat(32),
      RIKUNE_FILE_SERVER_API_KEY: 'x'.repeat(32),
    })
  )
})

test('bearer authentication rejects duplicate and malformed headers', () => {
  const token = 't'.repeat(32)
  assert.doesNotThrow(() =>
    authenticate(requestWithRawHeaders(['Authorization', `Bearer ${token}`]), token)
  )
  assert.throws(() =>
    authenticate(
      requestWithRawHeaders([
        'Authorization',
        `Bearer ${token}`,
        'Authorization',
        `Bearer ${token}`,
      ]),
      token
    )
  )
  assert.throws(() =>
    authenticate(requestWithRawHeaders(['Authorization', `bearer ${token}`]), token)
  )
})

test('operation id must be a canonical UUID', () => {
  assert.equal(
    requireOperationId(
      requestWithRawHeaders(['X-Operation-ID', '550e8400-e29b-41d4-a716-446655440000'])
    ),
    '550e8400-e29b-41d4-a716-446655440000'
  )
  assert.throws(() =>
    requireOperationId(
      requestWithRawHeaders(['X-Operation-ID', '550E8400-E29B-41D4-A716-446655440000'])
    )
  )
})

test('static lock must contain the exact ordered 100-plugin positive list', () => {
  assert.equal(
    STATIC_PROFILE_LOCK_SHA256,
    '32e3ea5103ff73c413062b17ad3bb4e7270fbcd6fd1325f6a7f3dc831bee83ef'
  )
  const digest = createHash('sha256').update(STATIC_PLUGINS.join(',')).digest('hex')
  const lock = {
    schema_version: 1,
    profile: 'static',
    plugins: [...STATIC_PLUGINS],
    ordered_csv_sha256: digest,
    static_workflow_stages: ['fast_profile', 'enrich_static', 'function_map'],
    required_backends: [
      {
        name: 'java',
        path: '/java',
        environment: [{ name: 'JAVA_HOME', value: '/java-home', required: true }],
        version_args: ['-version'],
        allowed_exit_codes: [0],
        version_pattern: '21',
      },
      {
        name: 'ghidra-analyze-headless',
        path: '/ghidra',
        environment: [
          { name: 'GHIDRA_INSTALL_DIR', value: '/ghidra-home', required: true },
          { name: 'GHIDRA_PATH', value: '/ghidra-home', required: false },
        ],
        version_args: [],
        allowed_exit_codes: [1],
        version_file: '/ghidra.properties',
        version_pattern: '12',
      },
      {
        name: 'rizin',
        path: '/rizin',
        environment: [{ name: 'RIZIN_PATH', value: '/rizin', required: true }],
        version_args: ['-v'],
        allowed_exit_codes: [0],
        version_pattern: '0.8',
      },
    ],
    generated_by: 'scripts/generate-docker.mjs',
    generator_version: 1,
  }
  assert.equal(validateStaticLock(lock).plugins.length, 100)
  const wrong = { ...lock, plugins: [...lock.plugins] }
  wrong.plugins[0] = 'wrong'
  assert.throws(() => validateStaticLock(wrong))
  assert.throws(() => validateStaticLock({ ...lock, ordered_csv_sha256: '0'.repeat(64) }))
  const validated = validateStaticLock(lock)
  validateStaticBackendEnvironment(validated, {
    JAVA_HOME: '/java-home',
    GHIDRA_INSTALL_DIR: '/ghidra-home',
    RIZIN_PATH: '/rizin',
  })
  assert.throws(() =>
    validateStaticBackendEnvironment(validated, {
      JAVA_HOME: '/wrong',
      GHIDRA_INSTALL_DIR: '/ghidra-home',
      RIZIN_PATH: '/rizin',
    })
  )
  assert.throws(() =>
    validateStaticBackendEnvironment(validated, {
      JAVA_HOME: '/java-home',
      GHIDRA_INSTALL_DIR: '/ghidra-home',
      GHIDRA_PATH: '/wrong',
      RIZIN_PATH: '/rizin',
    })
  )
})
