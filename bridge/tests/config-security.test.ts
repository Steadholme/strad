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

function staticLockFixture(
  javaEnvironment: readonly unknown[] = [
    { name: 'JAVA_HOME', value: '/java-home', required: true },
  ]
) {
  return {
    schema_version: 1,
    profile: 'static',
    plugins: [...STATIC_PLUGINS],
    ordered_csv_sha256: createHash('sha256').update(STATIC_PLUGINS.join(',')).digest('hex'),
    static_workflow_stages: ['fast_profile', 'enrich_static', 'function_map'],
    required_backends: [
      {
        name: 'java',
        path: '/java',
        environment: [...javaEnvironment],
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
}

test('static lock must contain the exact ordered 100-plugin positive list', () => {
  assert.equal(
    STATIC_PROFILE_LOCK_SHA256,
    '32e3ea5103ff73c413062b17ad3bb4e7270fbcd6fd1325f6a7f3dc831bee83ef'
  )
  const lock = staticLockFixture()
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

test('static lock accepts the Rikune v1.4.1 environment union and enforces it fail closed', () => {
  const javaEnvironment = [
    { name: 'JAVA_HOME', value: '/opt/java/openjdk', required: true },
    {
      name: 'PATH',
      value: '/opt/java/openjdk/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin',
      required: true,
    },
    { name: 'PYTHON_PATH', value: '/usr/local/bin/python3.12', required: true },
    { name: 'PYTHONPATH', value: '/app/workers', required: true },
    { name: 'HOME', value: '/tmp/rikune-home', required: true },
    { name: 'XDG_CONFIG_HOME', value: '/tmp/rikune-home/.config', required: true },
    { name: 'XDG_CACHE_HOME', value: '/tmp/rikune-home/.cache', required: true },
    { name: 'CONFIG_PATH', must_be_unset: true },
    { name: 'NODE_OPTIONS', must_be_unset: true },
    { name: 'NODE_PATH', must_be_unset: true },
    { name: 'LD_PRELOAD', must_be_unset: true },
    { name: 'PYTHONHOME', must_be_unset: true },
  ] as const
  const lock = staticLockFixture(javaEnvironment)
  const validated = validateStaticLock(lock)
  assert.equal(validated.required_backends[0]?.environment.length, 12)

  const matchingEnvironment = {
    JAVA_HOME: '/opt/java/openjdk',
    PATH: '/opt/java/openjdk/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin',
    PYTHON_PATH: '/usr/local/bin/python3.12',
    PYTHONPATH: '/app/workers',
    HOME: '/tmp/rikune-home',
    XDG_CONFIG_HOME: '/tmp/rikune-home/.config',
    XDG_CACHE_HOME: '/tmp/rikune-home/.cache',
    GHIDRA_INSTALL_DIR: '/ghidra-home',
    RIZIN_PATH: '/rizin',
  }
  assert.doesNotThrow(() => validateStaticBackendEnvironment(validated, matchingEnvironment))
  assert.throws(
    () =>
      validateStaticBackendEnvironment(validated, {
        ...matchingEnvironment,
        NODE_OPTIONS: '',
      }),
    /NODE_OPTIONS must be unset/
  )

  assert.throws(
    () => validateStaticLock(staticLockFixture([...javaEnvironment, javaEnvironment[0]])),
    /duplicate backend environment bindings/
  )
  assert.throws(() =>
    validateStaticLock(
      staticLockFixture([
        ...javaEnvironment.slice(0, -1),
        { name: 'PYTHONHOME', must_be_unset: true, required: false },
      ])
    )
  )
  assert.throws(() =>
    validateStaticLock(
      staticLockFixture(
        Array.from({ length: 17 }, (_, index) => ({
          name: `BOUNDED_ENV_${index}`,
          must_be_unset: true,
        }))
      )
    )
  )
})
