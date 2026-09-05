import { readFile } from 'node:fs/promises'

import { Pool, type PoolClient } from 'pg'
import { z } from 'zod'

import type { ApplicationContext } from './application-context.js'
import { canonicalJson, sha256Hex } from './canonical.js'

export type SessionBinding = Readonly<{
  sessionId: string
  mcpSessionDigest: string
  applicationSub: string
  clientId: string
  credentialId: string
  credentialVersion: number
  grantId: string
  packageId: 'pkg_analyze_mcp_client'
  packageRevisionDigest: string
  scopes: readonly string[]
  policyEpoch: number
  revocationEpoch: number
  credentialState: 'active' | 'overlap'
  overlapUntil: number | null
  createdAt: number
  lastSeenAt: number
  idleExpiresAt: number
  absoluteExpiresAt: number
}>

export type ConsumeContextResult =
  | Readonly<{ status: 'accepted'; session: SessionBinding; supersededSessionIds?: readonly string[] }>
  | Readonly<{ status: 'replay' | 'invalid_session' }>

const opaque = z.string().min(1).max(256).regex(/^[A-Za-z0-9_.:-]+$/)
export const applicationSessionRevokedV1Schema = z
  .object({
    v: z.literal(1),
    event_id: opaque,
    application_sub: z.string().regex(/^application:[A-Za-z0-9_-]{16,128}$/),
    grant_id: opaque,
    credential_id: opaque.nullable(),
    credential_version: z.number().int().positive().nullable(),
    policy_epoch: z.number().int().positive(),
    revocation_epoch: z.number().int().positive(),
    reason: z.string().min(1).max(256).regex(/^[A-Za-z0-9_.:-]+$/),
    effective_at: z.number().int().positive(),
    issued_at: z.number().int().positive(),
  })
  .strict()
  .superRefine((value, issue) => {
    if ((value.credential_id === null) !== (value.credential_version === null)) {
      issue.addIssue({ code: z.ZodIssueCode.custom, message: 'credential lineage is incomplete' })
    }
  })

export type ApplicationSessionRevokedV1 = z.infer<typeof applicationSessionRevokedV1Schema>

export type RevocationAcknowledgement = Readonly<{
  v: 1
  event_id: string
  revocation_epoch: number
  terminated_sessions: number
  duplicate: boolean
  stale: boolean
  session_ids: readonly string[]
}>

export interface SessionStore {
  consumeContext(
    context: ApplicationContext,
    sessionId: string,
    initialize: boolean,
    nowSeconds: number
  ): Promise<ConsumeContextResult>
  consumeRevocation(
    event: ApplicationSessionRevokedV1,
    nowSeconds: number
  ): Promise<RevocationAcknowledgement>
  terminateSession(sessionId: string, reason: string, nowSeconds: number): Promise<void>
  ping(): Promise<void>
  close(): Promise<void>
}

function sessionFromContext(
  context: ApplicationContext,
  sessionId: string,
  nowSeconds: number
): SessionBinding {
  return Object.freeze({
    sessionId,
    mcpSessionDigest: context.mcp_session_digest,
    applicationSub: context.application_sub,
    clientId: context.client_id,
    credentialId: context.credential_id,
    credentialVersion: context.credential_version,
    grantId: context.grant_id,
    packageId: context.package_id,
    packageRevisionDigest: context.package_revision_digest,
    scopes: Object.freeze([...context.scopes]),
    policyEpoch: context.policy_epoch,
    revocationEpoch: context.revocation_epoch,
    credentialState: context.credential_state,
    overlapUntil: context.overlap_until,
    createdAt: nowSeconds,
    lastSeenAt: nowSeconds,
    idleExpiresAt: nowSeconds + 900,
    absoluteExpiresAt: nowSeconds + 86400,
  })
}

function sameLineage(session: SessionBinding, context: ApplicationContext): boolean {
  return (
    session.mcpSessionDigest === context.mcp_session_digest &&
    session.applicationSub === context.application_sub &&
    session.clientId === context.client_id &&
    session.credentialId === context.credential_id &&
    session.grantId === context.grant_id &&
    session.packageId === context.package_id &&
    session.packageRevisionDigest === context.package_revision_digest &&
    session.policyEpoch === context.policy_epoch &&
    session.revocationEpoch === context.revocation_epoch &&
    JSON.stringify(session.scopes) === JSON.stringify(context.scopes)
  )
}

function usableSession(
  session: SessionBinding,
  context: ApplicationContext,
  nowSeconds: number
): boolean {
  if (
    session.idleExpiresAt <= nowSeconds ||
    session.absoluteExpiresAt <= nowSeconds ||
    !sameLineage(session, context)
  ) {
    return false
  }
  if (context.credential_state === 'active') {
    return (
      session.credentialState === 'active' &&
      context.overlap_until === null &&
      context.credential_version === session.credentialVersion
    )
  }
  return (
    context.overlap_until !== null &&
    context.overlap_until > nowSeconds &&
    (session.overlapUntil === null || session.overlapUntil === context.overlap_until) &&
    (context.credential_version === session.credentialVersion ||
      (session.credentialState === 'active' &&
        context.credential_version === session.credentialVersion + 1))
  )
}

export class MemorySessionStore implements SessionStore {
  private readonly replays = new Set<string>()
  private readonly sessions = new Map<string, SessionBinding>()
  private readonly initializedSessionIds = new Set<string>()
  private readonly credentialBindings = new Map<string, Readonly<{ version: number; digest: string }>>()
  private readonly events = new Map<string, RevocationAcknowledgement>()
  private readonly revocationEpochs = new Map<string, number>()

  async consumeContext(
    context: ApplicationContext,
    sessionId: string,
    initialize: boolean,
    nowSeconds: number
  ): Promise<ConsumeContextResult> {
    const replayKey = `${context.iss}\0${context.jti}`
    if (this.replays.has(replayKey)) return { status: 'replay' }
    this.replays.add(replayKey)
    const knownEpoch = this.revocationEpochs.get(context.application_sub) ?? 0
    if (context.revocation_epoch < knownEpoch) return { status: 'invalid_session' }
    if (context.revocation_epoch > knownEpoch) {
      this.revocationEpochs.set(context.application_sub, context.revocation_epoch)
      for (const [id, session] of this.sessions) {
        if (
          session.applicationSub === context.application_sub &&
          session.revocationEpoch < context.revocation_epoch
        ) {
          this.sessions.delete(id)
        }
      }
    }
    if (initialize && context.credential_state !== 'active') {
      return { status: 'invalid_session' }
    }
    const credentialKey = `${context.application_sub}\0${context.credential_id}`
    const binding = this.credentialBindings.get(credentialKey)
    if (binding && (
      context.credential_version < binding.version ||
      (context.credential_version === binding.version && context.mcp_session_digest !== binding.digest)
    )) {
      return { status: 'invalid_session' }
    }
    this.credentialBindings.set(credentialKey, {
      version: context.credential_version,
      digest: context.mcp_session_digest,
    })
    if (initialize) {
      if (this.initializedSessionIds.has(sessionId)) return { status: 'invalid_session' }
      const superseded: string[] = []
      for (const [id, session] of this.sessions) {
        if (session.applicationSub === context.application_sub && session.credentialId === context.credential_id) {
          this.sessions.delete(id)
          superseded.push(id)
        }
      }
      const created = sessionFromContext(context, sessionId, nowSeconds)
      this.initializedSessionIds.add(sessionId)
      this.sessions.set(sessionId, created)
      return { status: 'accepted', session: created, supersededSessionIds: Object.freeze(superseded) }
    }
    const current = this.sessions.get(sessionId)
    if (!current || !usableSession(current, context, nowSeconds)) {
      if (current && current.revocationEpoch !== context.revocation_epoch) {
        this.sessions.delete(sessionId)
      }
      return { status: 'invalid_session' }
    }
    const touched = Object.freeze({
      ...current,
      credentialVersion: context.credential_version,
      credentialState: context.credential_state,
      overlapUntil: context.overlap_until,
      lastSeenAt: nowSeconds,
      idleExpiresAt: Math.min(nowSeconds + 900, current.absoluteExpiresAt),
    })
    this.sessions.set(sessionId, touched)
    return { status: 'accepted', session: touched }
  }

  async consumeRevocation(
    event: ApplicationSessionRevokedV1,
    nowSeconds: number
  ): Promise<RevocationAcknowledgement> {
    const existing = this.events.get(event.event_id)
    if (existing) return Object.freeze({ ...existing, duplicate: true })
    const knownEpoch = this.revocationEpochs.get(event.application_sub) ?? 0
    const stale = event.revocation_epoch <= knownEpoch
    const terminated: string[] = []
    if (!stale) {
      this.revocationEpochs.set(event.application_sub, event.revocation_epoch)
      for (const [id, session] of this.sessions) {
        const target =
          session.applicationSub === event.application_sub &&
          (session.revocationEpoch < event.revocation_epoch ||
            (event.credential_id === null
              ? session.grantId === event.grant_id
              : session.grantId === event.grant_id &&
                session.credentialId === event.credential_id))
        if (target) {
          this.sessions.delete(id)
          terminated.push(id)
        }
      }
    }
    const acknowledgement = Object.freeze({
      v: 1 as const,
      event_id: event.event_id,
      revocation_epoch: event.revocation_epoch,
      terminated_sessions: terminated.length,
      duplicate: false,
      stale,
      session_ids: Object.freeze(terminated),
    })
    this.events.set(event.event_id, acknowledgement)
    void nowSeconds
    return acknowledgement
  }

  async terminateSession(sessionId: string): Promise<void> {
    this.sessions.delete(sessionId)
  }

  async ping(): Promise<void> {}
  async close(): Promise<void> {}
}

type SessionRow = {
  session_id: string
  mcp_session_digest: string
  application_sub: string
  client_id: string
  credential_id: string
  credential_version: string | number
  grant_id: string
  package_id: 'pkg_analyze_mcp_client'
  package_revision_digest: string
  scopes: string[]
  policy_epoch: string | number
  revocation_epoch: string | number
  credential_state: 'active' | 'overlap'
  overlap_until: string | number | null
  created_at: string | number
  last_seen_at: string | number
  idle_expires_at: string | number
  absolute_expires_at: string | number
}

function numberValue(value: string | number): number {
  return typeof value === 'number' ? value : Number(value)
}

function fromRow(row: SessionRow): SessionBinding {
  return Object.freeze({
    sessionId: row.session_id,
    mcpSessionDigest: row.mcp_session_digest,
    applicationSub: row.application_sub,
    clientId: row.client_id,
    credentialId: row.credential_id,
    credentialVersion: numberValue(row.credential_version),
    grantId: row.grant_id,
    packageId: row.package_id,
    packageRevisionDigest: row.package_revision_digest,
    scopes: Object.freeze([...row.scopes]),
    policyEpoch: numberValue(row.policy_epoch),
    revocationEpoch: numberValue(row.revocation_epoch),
    credentialState: row.credential_state,
    overlapUntil: row.overlap_until === null ? null : numberValue(row.overlap_until),
    createdAt: numberValue(row.created_at),
    lastSeenAt: numberValue(row.last_seen_at),
    idleExpiresAt: numberValue(row.idle_expires_at),
    absoluteExpiresAt: numberValue(row.absolute_expires_at),
  })
}

export class PostgresSessionStore implements SessionStore {
  readonly pool: Pool

  constructor(databaseUrl: string, timeoutMs = 3000) {
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1) {
      throw new Error('PostgreSQL timeout is invalid')
    }
    // Leave cleanup time inside the outer readiness deadline so a failed connect
    // cannot outlive the response that reports it unhealthy.
    const operationTimeoutMs = Math.max(1, Math.floor(timeoutMs * 0.8))
    this.pool = new Pool({
      connectionString: databaseUrl,
      connectionTimeoutMillis: operationTimeoutMs,
      query_timeout: operationTimeoutMs,
      max: 12,
    })
    this.pool.on('error', () => undefined)
  }

  async migrate(): Promise<void> {
    for (const filename of ['0001_facade_sessions.sql', '0002_credential_session_bindings.sql']) {
      const migration = await readFile(new URL(`../../migrations/${filename}`, import.meta.url), 'utf8')
      await this.pool.query(migration)
    }
  }

  private async consumeReplay(
    client: PoolClient,
    context: ApplicationContext,
    nowSeconds: number
  ): Promise<boolean> {
    const inserted = await client.query(
      `INSERT INTO analyze_facade_context_replays (issuer,jti,expires_at,consumed_at)
       VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
      [context.iss, context.jti, context.exp, nowSeconds]
    )
    return inserted.rowCount === 1
  }

  async consumeContext(
    context: ApplicationContext,
    sessionId: string,
    initialize: boolean,
    nowSeconds: number
  ): Promise<ConsumeContextResult> {
    const client = await this.pool.connect()
    try {
      await client.query('BEGIN')
      if (!(await this.consumeReplay(client, context, nowSeconds))) {
        await client.query('COMMIT')
        return { status: 'replay' }
      }
      const insertedEpoch = await client.query<{ revocation_epoch: string | number }>(
        `INSERT INTO analyze_facade_application_revocation_epochs
           (application_sub,revocation_epoch,updated_at) VALUES ($1,$2,$3)
         ON CONFLICT DO NOTHING RETURNING revocation_epoch`,
        [context.application_sub, context.revocation_epoch, nowSeconds]
      )
      let knownEpoch = insertedEpoch.rows[0]
        ? numberValue(insertedEpoch.rows[0].revocation_epoch)
        : 0
      let epochAdvanced = insertedEpoch.rowCount === 1
      if (!epochAdvanced) {
        const epoch = await client.query<{ revocation_epoch: string | number }>(
          `SELECT revocation_epoch FROM analyze_facade_application_revocation_epochs
           WHERE application_sub=$1 FOR UPDATE`,
          [context.application_sub]
        )
        const row = epoch.rows[0]
        if (!row) throw new Error('application revocation epoch disappeared')
        knownEpoch = numberValue(row.revocation_epoch)
      }
      if (context.revocation_epoch < knownEpoch) {
        await client.query('COMMIT')
        return { status: 'invalid_session' }
      }
      if (context.revocation_epoch > knownEpoch) {
        await client.query(
          `UPDATE analyze_facade_application_revocation_epochs
           SET revocation_epoch=$2,updated_at=$3 WHERE application_sub=$1`,
          [context.application_sub, context.revocation_epoch, nowSeconds]
        )
        epochAdvanced = true
      }
      if (epochAdvanced) {
        await client.query(
          `UPDATE analyze_facade_sessions SET state='terminated',terminated_at=$1,
             termination_reason='epoch_advanced'
           WHERE application_sub=$2 AND state='active' AND revocation_epoch < $3`,
          [nowSeconds, context.application_sub, context.revocation_epoch]
        )
      }
      if (initialize && context.credential_state !== 'active') {
        await client.query('COMMIT')
        return { status: 'invalid_session' }
      }
      // 即使新连接尚未附着，也持久保存 Access 已签发的版本，拒绝迟到的旧初始化。
      const binding = await client.query(
        `INSERT INTO analyze_facade_credential_session_bindings
           (application_sub,credential_id,credential_version,mcp_session_digest,updated_at)
         VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (application_sub,credential_id) DO UPDATE
           SET credential_version=EXCLUDED.credential_version,
               mcp_session_digest=EXCLUDED.mcp_session_digest,updated_at=EXCLUDED.updated_at
         WHERE analyze_facade_credential_session_bindings.credential_version < EXCLUDED.credential_version
            OR (analyze_facade_credential_session_bindings.credential_version = EXCLUDED.credential_version
                AND analyze_facade_credential_session_bindings.mcp_session_digest = EXCLUDED.mcp_session_digest)
         RETURNING credential_version`,
        [context.application_sub, context.credential_id, context.credential_version, context.mcp_session_digest, nowSeconds]
      )
      if (binding.rowCount !== 1) {
        await client.query('COMMIT')
        return { status: 'invalid_session' }
      }
      if (initialize) {
        const inserted = await client.query<SessionRow>(
          `INSERT INTO analyze_facade_sessions
             (session_id,mcp_session_digest,application_sub,client_id,credential_id,
              credential_version,grant_id,package_id,package_revision_digest,scopes,
              policy_epoch,revocation_epoch,credential_state,overlap_until,state,
              created_at,last_seen_at,idle_expires_at,absolute_expires_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12,$13,$14,'active',$15,$15,$16,$17)
           ON CONFLICT DO NOTHING RETURNING *`,
          [
            sessionId,
            context.mcp_session_digest,
            context.application_sub,
            context.client_id,
            context.credential_id,
            context.credential_version,
            context.grant_id,
            context.package_id,
            context.package_revision_digest,
            JSON.stringify(context.scopes),
            context.policy_epoch,
            context.revocation_epoch,
            context.credential_state,
            context.overlap_until,
            nowSeconds,
            nowSeconds + 900,
            nowSeconds + 86400,
          ]
        )
        const row = inserted.rows[0]
        if (!row) {
          await client.query('COMMIT')
          return { status: 'invalid_session' }
        }
        const superseded = await client.query<{ session_id: string }>(
          `UPDATE analyze_facade_sessions SET state='terminated',terminated_at=$1,
             termination_reason='session_superseded'
           WHERE application_sub=$2 AND credential_id=$3 AND session_id<>$4 AND state='active'
           RETURNING session_id`,
          [nowSeconds, context.application_sub, context.credential_id, sessionId]
        )
        await client.query('COMMIT')
        return {
          status: 'accepted',
          session: fromRow(row),
          supersededSessionIds: Object.freeze(superseded.rows.map((old) => old.session_id)),
        }
      }
      const selected = await client.query<SessionRow & { state: string }>(
        `SELECT * FROM analyze_facade_sessions WHERE session_id=$1 FOR UPDATE`,
        [sessionId]
      )
      const row = selected.rows[0]
      if (!row || row.state !== 'active') {
        await client.query('COMMIT')
        return { status: 'invalid_session' }
      }
      const session = fromRow(row)
      if (!usableSession(session, context, nowSeconds)) {
        if (
          session.idleExpiresAt <= nowSeconds ||
          session.absoluteExpiresAt <= nowSeconds ||
          session.revocationEpoch !== context.revocation_epoch
        ) {
          await client.query(
            `UPDATE analyze_facade_sessions SET state='terminated',terminated_at=$1,
               termination_reason='session_invalidated' WHERE session_id=$2 AND state='active'`,
            [nowSeconds, sessionId]
          )
        }
        await client.query('COMMIT')
        return { status: 'invalid_session' }
      }
      const touched = await client.query<SessionRow>(
        `UPDATE analyze_facade_sessions SET credential_version=$1,credential_state=$2,overlap_until=$3,
           last_seen_at=$4,idle_expires_at=LEAST($5,absolute_expires_at)
         WHERE session_id=$6 AND state='active' RETURNING *`,
        [
          context.credential_version,
          context.credential_state,
          context.overlap_until,
          nowSeconds,
          nowSeconds + 900,
          sessionId,
        ]
      )
      await client.query('COMMIT')
      const touchedRow = touched.rows[0]
      return touchedRow
        ? { status: 'accepted', session: fromRow(touchedRow) }
        : { status: 'invalid_session' }
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined)
      throw error
    } finally {
      client.release()
    }
  }

  async consumeRevocation(
    event: ApplicationSessionRevokedV1,
    nowSeconds: number
  ): Promise<RevocationAcknowledgement> {
    const client = await this.pool.connect()
    try {
      await client.query('BEGIN')
      const digest = sha256Hex(canonicalJson(event))
      const inserted = await client.query(
        `INSERT INTO analyze_facade_revocation_events
           (event_id,application_sub,grant_id,credential_id,credential_version,policy_epoch,
            revocation_epoch,reason,effective_at,issued_at,payload_sha256,consumed_at,terminated_sessions)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,0) ON CONFLICT DO NOTHING`,
        [
          event.event_id,
          event.application_sub,
          event.grant_id,
          event.credential_id,
          event.credential_version,
          event.policy_epoch,
          event.revocation_epoch,
          event.reason,
          event.effective_at,
          event.issued_at,
          digest,
          nowSeconds,
        ]
      )
      if (inserted.rowCount !== 1) {
        const existing = await client.query<{
          payload_sha256: string
          revocation_epoch: string | number
          terminated_sessions: string | number
          stale: boolean
          session_ids: unknown
        }>(
          `SELECT payload_sha256,revocation_epoch,terminated_sessions,stale,session_ids
           FROM analyze_facade_revocation_events WHERE event_id=$1`,
          [event.event_id]
        )
        const row = existing.rows[0]
        if (!row || row.payload_sha256 !== digest) throw new Error('revocation event id collision')
        if (
          !Array.isArray(row.session_ids) ||
          row.session_ids.some((value) => typeof value !== 'string')
        ) {
          throw new Error('revocation acknowledgement is malformed')
        }
        await client.query('COMMIT')
        return Object.freeze({
          v: 1,
          event_id: event.event_id,
          revocation_epoch: numberValue(row.revocation_epoch),
          terminated_sessions: numberValue(row.terminated_sessions),
          duplicate: true,
          stale: row.stale,
          session_ids: Object.freeze(row.session_ids as string[]),
        })
      }
      const insertedEpoch = await client.query<{ revocation_epoch: string | number }>(
        `INSERT INTO analyze_facade_application_revocation_epochs
           (application_sub,revocation_epoch,updated_at) VALUES ($1,$2,$3)
         ON CONFLICT DO NOTHING RETURNING revocation_epoch`,
        [event.application_sub, event.revocation_epoch, nowSeconds]
      )
      let stale = false
      if (insertedEpoch.rowCount !== 1) {
        const current = await client.query<{ revocation_epoch: string | number }>(
          `SELECT revocation_epoch FROM analyze_facade_application_revocation_epochs
           WHERE application_sub=$1 FOR UPDATE`,
          [event.application_sub]
        )
        const row = current.rows[0]
        if (!row) throw new Error('application revocation epoch disappeared')
        const knownEpoch = numberValue(row.revocation_epoch)
        stale = event.revocation_epoch <= knownEpoch
        if (!stale) {
          await client.query(
            `UPDATE analyze_facade_application_revocation_epochs
             SET revocation_epoch=$2,updated_at=$3 WHERE application_sub=$1`,
            [event.application_sub, event.revocation_epoch, nowSeconds]
          )
        }
      }
      let sessionIds: string[] = []
      if (!stale) {
        const parameters: unknown[] = [nowSeconds, event.application_sub, event.revocation_epoch]
        let target = 'grant_id=$4'
        parameters.push(event.grant_id)
        if (event.credential_id !== null) {
          target = 'grant_id=$4 AND credential_id=$5'
          parameters.push(event.credential_id)
        }
        const terminated = await client.query<{ session_id: string }>(
          `UPDATE analyze_facade_sessions SET state='terminated',terminated_at=$1,
             termination_reason='revoked'
           WHERE application_sub=$2 AND state='active'
             AND (revocation_epoch < $3 OR (${target})) RETURNING session_id`,
          parameters
        )
        sessionIds = terminated.rows.map((row) => row.session_id)
      }
      await client.query(
        `UPDATE analyze_facade_revocation_events
         SET terminated_sessions=$1,stale=$2,session_ids=$3::jsonb WHERE event_id=$4`,
        [sessionIds.length, stale, JSON.stringify(sessionIds), event.event_id]
      )
      await client.query('COMMIT')
      return Object.freeze({
        v: 1,
        event_id: event.event_id,
        revocation_epoch: event.revocation_epoch,
        terminated_sessions: sessionIds.length,
        duplicate: false,
        stale,
        session_ids: Object.freeze(sessionIds),
      })
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined)
      throw error
    } finally {
      client.release()
    }
  }

  async terminateSession(sessionId: string, reason: string, nowSeconds: number): Promise<void> {
    await this.pool.query(
      `UPDATE analyze_facade_sessions SET state='terminated',terminated_at=$1,termination_reason=$2
       WHERE session_id=$3 AND state='active'`,
      [nowSeconds, reason, sessionId]
    )
  }

  async ping(): Promise<void> {
    const client = await this.pool.connect()
    let healthy = false
    try {
      await client.query('SELECT 1')
      healthy = true
    } finally {
      client.release(!healthy)
    }
  }

  async close(): Promise<void> {
    await this.pool.end()
  }
}
