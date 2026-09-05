import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import test from 'node:test'

import { HttpVerdictClient, type DecisionV2, type RequestV2 } from '../src/clients.js'
import type { ApplicationContext } from '../src/application-context.js'
import { FacadeError } from '../src/errors.js'
import { canonicalApplicationRequestSha } from '../src/canonical.js'
import { MemorySessionStore } from '../src/session-store.js'
import { recomputeDecisionDigest, ToolExecutor } from '../src/tools.js'
import {
  ANALYSIS,
  FIXED_NOW,
  OPERATION,
  SESSION,
  FakeStrad,
  FakeVerdict,
  allowDecision,
  closeTestServer,
  listenTestServer,
  makeContext,
} from './helpers.js'

async function toolContext(scopes?: ApplicationContext['scopes']) {
  const applicationContext = makeContext(scopes ? { scopes: [...scopes] } : {})
  const store = new MemorySessionStore()
  const consumed = await store.consumeContext(applicationContext, SESSION, true, FIXED_NOW)
  assert.equal(consumed.status, 'accepted')
  if (consumed.status !== 'accepted') throw new Error('test session was not created')
  return { session: consumed.session, applicationContext }
}

function decisionAs(
  request: RequestV2,
  kind: DecisionV2['decision'],
  overrides: Partial<DecisionV2> = {}
): DecisionV2 {
  const initial = allowDecision(request)
  const changed: DecisionV2 = {
    ...initial,
    decision: kind,
    decision_id: 'pending',
    decision_digest: '0'.repeat(64),
    ...overrides,
  }
  const digest = recomputeDecisionDigest(request, changed)
  return { ...changed, decision_id: `dec_${digest.slice(0, 32)}`, decision_digest: digest }
}

test('conversation submits one owned turn and read selects its durable result', async () => {
  const verdict = new FakeVerdict()
  const strad = new FakeStrad()
  const executor = new ToolExecutor(verdict, strad, undefined, () => FIXED_NOW)
  const conversationId = '550e8400-e29b-41d4-a716-446655440081'
  const turnId = '550e8400-e29b-41d4-a716-446655440082'
  const context = await toolContext()
  const turn = {
    operation_id: OPERATION, analysis_id: ANALYSIS, conversation_id: conversationId,
    client_seq: 1, message: 'Explain this binary.', model: 'glm-5.2',
  }
  await executor.execute('analysis.conversation', turn, context)
  const submitted = strad.tools[0]
  assert.ok(submitted)
  assert.equal(submitted.tool, 'analysis.conversation')
  const expectedBody = {
    analysis_id: ANALYSIS, conversation_id: conversationId,
    client_seq: 1, message: turn.message, model: 'glm-5.2',
  }
  assert.deepEqual(submitted.request.body, expectedBody)
  assert.equal(submitted.request.operation_id, OPERATION)
  assert.equal(submitted.request.application_sub, context.session.applicationSub)
  assert.equal(submitted.request.execution.request_sha256, canonicalApplicationRequestSha(
    context.session.applicationSub, 'analysis.conversation', ANALYSIS, expectedBody
  ))
  assert.equal(Object.keys(submitted.request.execution).length, 13)
  await executor.execute('analysis.read', {
    operation_id: OPERATION, analysis_id: ANALYSIS, conversation_id: conversationId, turn_id: turnId,
  }, context)
  assert.deepEqual(strad.tools[1]?.request.body, { conversation_id: conversationId, turn_id: turnId })
  assert.equal(verdict.requests.length, 2)
})

test('conversation turn arguments reject mixed modes and incomplete result selectors before dispatch', async () => {
  const verdict = new FakeVerdict()
  const strad = new FakeStrad()
  const executor = new ToolExecutor(verdict, strad, undefined, () => FIXED_NOW)
  const context = await toolContext()
  const base = { operation_id: OPERATION, analysis_id: ANALYSIS }
  const turn = { ...base, conversation_id: OPERATION, client_seq: 1, message: 'Explain.' }
  for (const body of [
    { ...turn, title: 'Mixed create and turn' },
    { ...turn, persona_id: 'binary-analyst' },
    { ...turn, client_seq: 0 },
    { ...turn, message: '' },
    { ...turn, message: '\0' },
    { ...turn, message: '中'.repeat(3000) },
    { ...turn, model: '' },
    { ...base, message: 'No conversation' },
    { ...base, conversation_id: OPERATION },
  ]) {
    await assert.rejects(executor.execute('analysis.conversation', body, context),
      (error: unknown) => error instanceof FacadeError && error.code === 'invalid_request')
  }
  for (const body of [
    { ...base, conversation_id: OPERATION },
    { ...base, turn_id: OPERATION },
    { ...base, conversation_id: OPERATION, turn_id: 'invalid' },
  ]) {
    await assert.rejects(executor.execute('analysis.read', body, context),
      (error: unknown) => error instanceof FacadeError && error.code === 'invalid_request')
  }
  assert.equal(verdict.requests.length, 0)
  assert.equal(strad.tools.length, 0)
})

test('decision digest ttl and versions gate dispatch while non-allow audits once', async () => {
  const verdict = new FakeVerdict()
  const strad = new FakeStrad()
  const executor = new ToolExecutor(verdict, strad, 'https://analyze.w33d.xyz', () => FIXED_NOW)
  const context = await toolContext()
  verdict.mutate = (decision) => ({ ...decision, decision_digest: 'f'.repeat(64) })
  await assert.rejects(
    executor.execute(
      'analysis.read',
      { operation_id: OPERATION, analysis_id: ANALYSIS },
      context
    ),
    (error: unknown) => error instanceof FacadeError && error.code === 'authorization_unavailable'
  )
  assert.equal(strad.tools.length, 0)
  assert.equal(strad.auditEvents.size, 1)
  assert.equal([...strad.auditEvents.values()][0]?.outcome, 'decision_digest_mismatch')

  await assert.rejects(
    executor.execute(
      'analysis.read',
      { operation_id: OPERATION, analysis_id: ANALYSIS },
      context
    )
  )
  assert.equal(strad.auditEvents.size, 1, 'logical replay must have one durable audit row')
  assert.equal(strad.tools.length, 0)

  verdict.mutate = (decision) => ({
    ...decision,
    subject_version: decision.subject_version + 1,
  })
  await assert.rejects(
    executor.execute(
      'analysis.read',
      { operation_id: '550e8400-e29b-41d4-a716-446655440020', analysis_id: ANALYSIS },
      await toolContext()
    ),
    FacadeError
  )
  assert.equal(strad.tools.length, 0)

  verdict.mutate = (_decision, request) => allowDecision(request, FIXED_NOW - 30)
  await assert.rejects(
    executor.execute(
      'analysis.read',
      { operation_id: '550e8400-e29b-41d4-a716-446655440021', analysis_id: ANALYSIS },
      await toolContext()
    ),
    (error: unknown) => error instanceof FacadeError && error.code === 'authorization_unavailable'
  )
  assert.equal(strad.tools.length, 0)
  assert.equal(
    [...strad.auditEvents.values()].some((event) => event.outcome === 'expired_decision'),
    true
  )
})

test('logical authorization replay ignores per-request jti and request id', async () => {
  const verdict = new FakeVerdict()
  const strad = new FakeStrad()
  const executor = new ToolExecutor(verdict, strad, undefined, () => FIXED_NOW)
  const first = await toolContext(['analysis.read'])
  const second = await toolContext(['analysis.read'])
  assert.notEqual(first.applicationContext.jti, second.applicationContext.jti)
  assert.notEqual(first.applicationContext.request_id, second.applicationContext.request_id)
  for (const context of [first, second]) {
    await assert.rejects(
      executor.execute(
        'analysis.create',
        { operation_id: OPERATION, filename: 'sample.bin', total_bytes: 7 },
        context
      ),
      (error: unknown) => error instanceof FacadeError && error.code === 'insufficient_scope'
    )
  }
  await assert.rejects(
    executor.execute(
      'analysis.create',
      {
        operation_id: '550e8400-e29b-41d4-a716-446655440099',
        filename: 'sample.bin',
        total_bytes: 7,
      },
      await toolContext(['analysis.read'])
    ),
    (error: unknown) => error instanceof FacadeError && error.code === 'insufficient_scope'
  )
  assert.equal(verdict.requests.length, 0)
  assert.equal(strad.tools.length, 0)
  assert.equal(strad.auditCalls, 3, 'every request must receive a durable acknowledgement')
  assert.equal(
    strad.auditEvents.size,
    2,
    'one logical replay must deduplicate without colliding with another operation'
  )
})

test('Verdict 200 Deny and 503 Indeterminate preserve DecisionV2 while failures stay closed', async () => {
  type Mode =
    | 'deny'
    | 'indeterminate'
    | 'tampered'
    | 'malformed'
    | 'deny-503'
    | 'server-error'
  let mode: Mode = 'deny'
  const verdictServer = createServer((request, response) => {
    const chunks: Buffer[] = []
    request.on('data', (chunk: Buffer) => chunks.push(chunk))
    request.on('end', () => {
      const requestV2 = JSON.parse(Buffer.concat(chunks).toString('utf8')) as RequestV2
      const kind = mode === 'deny' || mode === 'deny-503' ? 'Deny' : 'Indeterminate'
      const decision = decisionAs(
        requestV2,
        kind,
        kind === 'Deny'
          ? { subject_version: 0 }
          : { policy_version: 0, subject_version: 0, policy_epoch: 0 }
      )
      const body =
        mode === 'tampered'
          ? { ...decision, decision_digest: 'f'.repeat(64) }
          : mode === 'malformed'
            ? { ...decision, unexpected: true }
            : decision
      const status =
        mode === 'server-error'
          ? 500
          : mode === 'indeterminate' ||
              mode === 'tampered' ||
              mode === 'malformed' ||
              mode === 'deny-503'
            ? 503
            : 200
      response.writeHead(status, { 'content-type': 'application/json' })
      response.end(JSON.stringify(body))
    })
  })
  const origin = await listenTestServer(verdictServer)
  try {
    const strad = new FakeStrad()
    const executor = new ToolExecutor(
      new HttpVerdictClient(`${origin}/api/v2/application-check`, 'v'.repeat(32)),
      strad,
      undefined,
      () => FIXED_NOW
    )
    const cases: ReadonlyArray<
      readonly [Mode, string, string, string | null]
    > = [
      ['deny', '550e8400-e29b-41d4-a716-446655440031', 'authorization_denied', 'deny'],
      [
        'indeterminate',
        '550e8400-e29b-41d4-a716-446655440032',
        'authorization_unavailable',
        'indeterminate',
      ],
      [
        'tampered',
        '550e8400-e29b-41d4-a716-446655440033',
        'authorization_unavailable',
        'decision_digest_mismatch',
      ],
      [
        'deny-503',
        '550e8400-e29b-41d4-a716-446655440034',
        'authorization_unavailable',
        'authorization_unavailable',
      ],
      [
        'malformed',
        '550e8400-e29b-41d4-a716-446655440036',
        'authorization_unavailable',
        'authorization_unavailable',
      ],
      [
        'server-error',
        '550e8400-e29b-41d4-a716-446655440035',
        'authorization_unavailable',
        'authorization_unavailable',
      ],
    ]
    for (const [caseMode, operation, code, outcome] of cases) {
      mode = caseMode
      await assert.rejects(
        executor.execute(
          'analysis.read',
          { operation_id: operation, analysis_id: ANALYSIS },
          await toolContext()
        ),
        (error: unknown) => error instanceof FacadeError && error.code === code
      )
      assert.equal([...strad.auditEvents.values()].at(-1)?.outcome, outcome)
    }
    assert.equal(strad.tools.length, 0)
    const events = [...strad.auditEvents.values()]
    assert.match(events[0]?.decision_digest ?? '', /^[0-9a-f]{64}$/)
    assert.match(events[1]?.decision_digest ?? '', /^[0-9a-f]{64}$/)
    assert.equal(events[3]?.decision_digest, null)
    assert.equal(events[4]?.decision_digest, null)
    assert.equal(events[5]?.decision_digest, null)
  } finally {
    await closeTestServer(verdictServer)
  }
})

test('complete RequestV2 and every non-allow audit by authorization event', async () => {
  const verdict = new FakeVerdict()
  const strad = new FakeStrad()
  const order: string[] = []
  const originalCheck = verdict.check.bind(verdict)
  verdict.check = async (request) => {
    order.push('verdict')
    return originalCheck(request)
  }
  const originalTool = strad.tool.bind(strad)
  strad.tool = async (tool, request) => {
    order.push('strad')
    return originalTool(tool, request)
  }
  const executor = new ToolExecutor(verdict, strad, 'https://analyze.w33d.xyz', () => FIXED_NOW)
  const result = (await executor.execute(
    'analysis.create',
    { operation_id: OPERATION, filename: 'sample.bin', total_bytes: 7 },
    await toolContext()
  )) as Record<string, unknown>
  assert.deepEqual(order, ['verdict', 'strad'])
  assert.equal(result.chunk_url_template, `https://analyze.w33d.xyz/v1/uploads/550e8400-e29b-41d4-a716-446655440012/chunks/{chunk_index}`)
  assert.equal(result.finalize_url, `https://analyze.w33d.xyz/v1/uploads/550e8400-e29b-41d4-a716-446655440012/finalize`)
  const request = verdict.requests[0]
  assert.ok(request)
  assert.deepEqual(Object.keys(request), [
    'v',
    'application_sub',
    'client_id',
    'credential_id',
    'credential_version',
    'grant_id',
    'package_id',
    'package_revision_digest',
    'scopes',
    'canonical_tool',
    'resource',
    'session_id',
    'request_sha256',
    'policy_epoch',
    'revocation_epoch',
    'correlation_id',
  ])
  assert.equal(request.canonical_tool, 'analysis.create')
  assert.ok(request.scopes.includes('analysis.create'))
  const envelope = strad.tools[0]?.request.execution
  assert.ok(envelope)
  assert.deepEqual(Object.keys(envelope).sort(), [
    'application_sub',
    'credential_id',
    'credential_version',
    'decision_digest',
    'decision_id',
    'expires_at',
    'issued_at',
    'mcp_session_digest',
    'policy_epoch',
    'request_sha256',
    'revocation_epoch',
    'subject_version',
    'version',
  ])

  const insufficientStrad = new FakeStrad()
  const insufficientVerdict = new FakeVerdict()
  const insufficient = new ToolExecutor(
    insufficientVerdict,
    insufficientStrad,
    'https://analyze.w33d.xyz',
    () => FIXED_NOW
  )
  await assert.rejects(
    insufficient.execute(
      'analysis.create',
      { operation_id: OPERATION, filename: 'sample.bin', total_bytes: 7 },
      await toolContext(['analysis.read'])
    ),
    (error: unknown) => error instanceof FacadeError && error.code === 'insufficient_scope'
  )
  assert.equal(insufficientVerdict.requests.length, 0, 'scope gate must precede Verdict')
  assert.equal(insufficientStrad.tools.length, 0)
  assert.equal(insufficientStrad.auditEvents.size, 1)
  assert.equal([...insufficientStrad.auditEvents.values()][0]?.decision_digest, null)

  for (const kind of ['Deny', 'Indeterminate'] as const) {
    const nonAllowVerdict = new FakeVerdict()
    const nonAllowStrad = new FakeStrad()
    nonAllowVerdict.mutate = (_decision, requestValue) => decisionAs(requestValue, kind)
    const nonAllow = new ToolExecutor(nonAllowVerdict, nonAllowStrad, undefined, () => FIXED_NOW)
    await assert.rejects(
      nonAllow.execute(
        'analysis.read',
        { operation_id: OPERATION, analysis_id: ANALYSIS },
        await toolContext()
      ),
      FacadeError
    )
    assert.equal(nonAllowStrad.tools.length, 0)
    assert.equal(nonAllowStrad.auditEvents.size, 1)
    assert.equal(
      [...nonAllowStrad.auditEvents.values()][0]?.outcome,
      kind === 'Deny' ? 'deny' : 'indeterminate'
    )
  }
})
