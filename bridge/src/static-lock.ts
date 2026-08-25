import { createHash } from 'node:crypto'
import { constants as fsConstants } from 'node:fs'
import { access, lstat, readFile } from 'node:fs/promises'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'

import { z } from 'zod'

import { STATIC_PLUGINS, STATIC_WORKFLOW_STAGES } from './constants.js'

const execFileAsync = promisify(execFile)
export const STATIC_PROFILE_LOCK_SHA256 =
  '32e3ea5103ff73c413062b17ad3bb4e7270fbcd6fd1325f6a7f3dc831bee83ef'

const backendEnvironmentSchema = z
  .object({
    name: z.string().regex(/^[A-Z][A-Z0-9_]*$/),
    value: z.string().startsWith('/').max(512),
    required: z.boolean(),
  })
  .strict()

const backendSchema = z
  .object({
    name: z.string().regex(/^[a-z0-9][a-z0-9._-]{0,63}$/),
    path: z.string().startsWith('/').max(512),
    environment: z.array(backendEnvironmentSchema).min(1).max(4),
    version_args: z.array(z.string().min(1).max(128)).max(8),
    allowed_exit_codes: z.array(z.number().int().min(0).max(255)).min(1).max(8),
    version_file: z.string().startsWith('/').max(512).optional(),
    version_pattern: z.string().min(1).max(512),
  })
  .strict()

export const staticLockSchema = z
  .object({
    schema_version: z.literal(1),
    profile: z.literal('static'),
    plugins: z.array(z.string().regex(/^[a-z0-9][a-z0-9-]*$/)).length(100),
    ordered_csv_sha256: z.string().regex(/^[0-9a-f]{64}$/),
    static_workflow_stages: z.tuple([
      z.literal('fast_profile'),
      z.literal('enrich_static'),
      z.literal('function_map'),
    ]),
    required_backends: z.array(backendSchema).min(3).max(32),
    generated_by: z.literal('scripts/generate-docker.mjs'),
    generator_version: z.literal(1),
  })
  .strict()

export type StaticProfileLock = z.infer<typeof staticLockSchema>

function orderedCsvSha(values: readonly string[]): string {
  return createHash('sha256').update(values.join(','), 'utf8').digest('hex')
}

export function validateStaticLock(value: unknown): StaticProfileLock {
  const lock = staticLockSchema.parse(value)
  if (new Set(lock.plugins).size !== lock.plugins.length) {
    throw new Error('static profile lock contains duplicate plugins')
  }
  if (lock.plugins.some((plugin, index) => plugin !== STATIC_PLUGINS[index])) {
    throw new Error('static profile plugin order or membership differs from bridge contract')
  }
  if (lock.ordered_csv_sha256 !== orderedCsvSha(lock.plugins)) {
    throw new Error('static profile ordered CSV digest mismatch')
  }
  if (
    lock.static_workflow_stages.some(
      (stage, index) => stage !== STATIC_WORKFLOW_STAGES[index]
    )
  ) {
    throw new Error('static workflow stage lock mismatch')
  }
  const backendNames = new Set(lock.required_backends.map((backend) => backend.name))
  if (backendNames.size !== lock.required_backends.length) {
    throw new Error('static profile lock contains duplicate backend names')
  }
  if (
    lock.required_backends.some(
      (backend) => new Set(backend.allowed_exit_codes).size !== backend.allowed_exit_codes.length
    )
  ) {
    throw new Error('static profile lock contains duplicate allowed exit codes')
  }
  if (
    lock.required_backends.some(
      (backend) =>
        new Set(backend.environment.map((binding) => binding.name)).size !==
        backend.environment.length
    )
  ) {
    throw new Error('static profile lock contains duplicate backend environment bindings')
  }
  for (const requiredName of ['java', 'ghidra-analyze-headless', 'rizin']) {
    if (!backendNames.has(requiredName)) {
      throw new Error(`static profile lock lacks required backend ${requiredName}`)
    }
  }
  return lock
}

export function validateStaticBackendEnvironment(
  lock: StaticProfileLock,
  environment: NodeJS.ProcessEnv = process.env
): void {
  for (const backend of lock.required_backends) {
    for (const binding of backend.environment) {
      const actual = environment[binding.name]
      if (
        (binding.required && actual !== binding.value) ||
        (!binding.required && actual !== undefined && actual !== binding.value)
      ) {
        throw new Error(
          `backend environment mismatch for ${backend.name}: ${binding.name}`
        )
      }
    }
  }
}

async function assertRegularExecutable(path: string): Promise<void> {
  const stat = await lstat(path)
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) {
    throw new Error('required backend path is not a single-link regular file')
  }
  await access(path, fsConstants.X_OK)
}

async function verifyBackend(backend: StaticProfileLock['required_backends'][number]): Promise<void> {
  await assertRegularExecutable(backend.path)
  let pattern: RegExp
  try {
    pattern = new RegExp(backend.version_pattern, 'u')
  } catch {
    throw new Error(`invalid version pattern for ${backend.name}`)
  }
  let output = ''
  let exitCode = 0
  try {
    const result = await execFileAsync(backend.path, backend.version_args, {
      encoding: 'utf8',
      timeout: 30_000,
      maxBuffer: 64 * 1024,
      windowsHide: true,
    })
    output = `${result.stdout}\n${result.stderr}`
  } catch (error) {
    const failure = error as Error & {
      stdout?: string
      stderr?: string
      killed?: boolean
      code?: string | number
    }
    if (failure.killed || typeof failure.code === 'string') throw error
    if (typeof failure.code !== 'number') throw error
    exitCode = failure.code
    output = `${failure.stdout ?? ''}\n${failure.stderr ?? ''}`
  }
  if (!backend.allowed_exit_codes.includes(exitCode)) {
    throw new Error(`backend exit code mismatch for ${backend.name}`)
  }
  if (backend.version_file) {
    const stat = await lstat(backend.version_file)
    if (
      !stat.isFile() ||
      stat.isSymbolicLink() ||
      stat.nlink !== 1 ||
      stat.size < 1 ||
      stat.size > 64 * 1024
    ) {
      throw new Error(`backend version file is unsafe for ${backend.name}`)
    }
    output += `\n${await readFile(backend.version_file, 'utf8')}`
  }
  if (!pattern.test(output)) throw new Error(`backend version mismatch for ${backend.name}`)
  if (backend.name === 'java') {
    const match = output.match(/version\s+"?(\d+)/iu)
    if (!match?.[1] || Number(match[1]) < 21) throw new Error('Java 21 or newer is required')
  }
}

export async function loadAndVerifyStaticLock(path: string): Promise<StaticProfileLock> {
  const stat = await lstat(path)
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size > 1024 * 1024) {
    throw new Error('static profile lock is not a bounded regular file')
  }
  const raw = await readFile(path, 'utf8')
  if (createHash('sha256').update(raw, 'utf8').digest('hex') !== STATIC_PROFILE_LOCK_SHA256) {
    throw new Error('static profile lock file digest differs from the frozen OCI contract')
  }
  const lock = validateStaticLock(JSON.parse(raw) as unknown)
  validateStaticBackendEnvironment(lock)
  await Promise.all(lock.required_backends.map((backend) => verifyBackend(backend)))
  return lock
}
