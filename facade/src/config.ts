import { z } from 'zod'

import { parseVerificationKeyring, type VerificationKeyring } from './application-context.js'

const addressPattern = /^[A-Za-z0-9.:[\]-]+:[0-9]{1,5}$/

export type FacadeConfig = Readonly<{
  bindAddress: string
  databaseUrl: string
  externalOrigin: string
  internalHost: string
  verdictDecisionUrl: string
  verdictDecisionToken: string
  stradOrigin: string
  stradFacadeToken: string
  accessFacadeRevocationToken: string
  applicationContextActiveKid: string
  applicationContextKeyring: VerificationKeyring
  requestTimeoutMs: number
  sessionIdleSeconds: 900
  sessionAbsoluteSeconds: 86400
}>

const exactUrl = (name: string, value: string, path: string | null): string => {
  const parsed = new URL(value)
  const loopback = ['127.0.0.1', 'localhost', '[::1]', '::1'].includes(parsed.hostname)
  if (
    (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && loopback)) ||
    parsed.username !== '' ||
    parsed.password !== '' ||
    parsed.search !== '' ||
    parsed.hash !== '' ||
    (path !== null && parsed.pathname !== path)
  ) {
    throw new Error(`${name} is not an exact secure URL`)
  }
  return parsed.toString().replace(/\/$/, path === '/' ? '/' : '')
}

function secret(name: string, value: string | undefined): string {
  if (!value || Buffer.byteLength(value, 'utf8') < 32 || /[\r\n\0]/.test(value)) {
    throw new Error(`${name} is required and must contain at least 32 bytes`)
  }
  return value
}

function positiveInteger(name: string, value: string | undefined, fallback: number): number {
  const parsed = value === undefined ? fallback : Number(value)
  if (!Number.isInteger(parsed) || parsed < 100 || parsed > 30_000) {
    throw new Error(`${name} is invalid`)
  }
  return parsed
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): FacadeConfig {
  const bindAddress = env.ANALYZE_FACADE_BIND_ADDR ?? '0.0.0.0:18120'
  if (!addressPattern.test(bindAddress)) throw new Error('ANALYZE_FACADE_BIND_ADDR is invalid')
  const databaseUrl = z.string().url().parse(env.FACADE_DATABASE_URL)
  if (!['postgres:', 'postgresql:'].includes(new URL(databaseUrl).protocol)) {
    throw new Error('FACADE_DATABASE_URL must use PostgreSQL')
  }
  const externalOrigin = exactUrl(
    'ANALYZE_EXTERNAL_ORIGIN',
    env.ANALYZE_EXTERNAL_ORIGIN ?? 'https://analyze.w33d.xyz',
    '/'
  )
  if (externalOrigin !== 'https://analyze.w33d.xyz/') {
    throw new Error('ANALYZE_EXTERNAL_ORIGIN is immutable')
  }
  const internalHost = z
    .string()
    .min(1)
    .max(253)
    .regex(/^[A-Za-z0-9.-]+(?::[0-9]{1,5})?$/)
    .parse(env.ANALYZE_FACADE_INTERNAL_HOST)
  const verdictDecisionToken = secret('VERDICT_DECISION_TOKEN', env.VERDICT_DECISION_TOKEN)
  const stradFacadeToken = secret('STRAD_FACADE_TOKEN', env.STRAD_FACADE_TOKEN)
  const accessFacadeRevocationToken = secret(
    'ACCESS_FACADE_REVOCATION_TOKEN',
    env.ACCESS_FACADE_REVOCATION_TOKEN
  )
  const uniqueSecrets = new Set([
    verdictDecisionToken,
    stradFacadeToken,
    accessFacadeRevocationToken,
  ])
  if (uniqueSecrets.size !== 3) throw new Error('Facade service credentials must be pairwise distinct')
  const applicationContextActiveKid = z
    .string()
    .regex(/^[a-z0-9][a-z0-9-]{0,31}$/)
    .parse(env.SLUICE_APPLICATION_CONTEXT_ACTIVE_KID)
  const applicationContextKeyring = parseVerificationKeyring(
    applicationContextActiveKid,
    env.SLUICE_APPLICATION_CONTEXT_VERIFICATION_KEYRING ?? ''
  )
  const idle = Number(env.FACADE_SESSION_IDLE_SECONDS ?? '900')
  const absolute = Number(env.FACADE_SESSION_ABSOLUTE_SECONDS ?? '86400')
  if (idle !== 900 || absolute !== 86400) throw new Error('Facade session TTLs are immutable')
  return Object.freeze({
    bindAddress,
    databaseUrl,
    externalOrigin,
    internalHost,
    verdictDecisionUrl: exactUrl(
      'FACADE_VERDICT_DECISION_URL',
      z.string().url().parse(env.FACADE_VERDICT_DECISION_URL),
      '/api/v2/application-check'
    ),
    verdictDecisionToken,
    stradOrigin: exactUrl(
      'FACADE_STRAD_ORIGIN',
      z.string().url().parse(env.FACADE_STRAD_ORIGIN),
      '/'
    ),
    stradFacadeToken,
    accessFacadeRevocationToken,
    applicationContextActiveKid,
    applicationContextKeyring,
    requestTimeoutMs: positiveInteger(
      'FACADE_DEPENDENCY_TIMEOUT_MS',
      env.FACADE_DEPENDENCY_TIMEOUT_MS,
      3000
    ),
    sessionIdleSeconds: 900,
    sessionAbsoluteSeconds: 86400,
  })
}
