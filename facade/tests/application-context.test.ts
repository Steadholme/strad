import assert from 'node:assert/strict'
import type { IncomingMessage } from 'node:http'
import test from 'node:test'

import {
  parseVerificationKeyring,
  keyringReady,
  rejectRawPublicCredentials,
  verifyApplicationContext,
  type ApplicationContext,
} from '../src/application-context.js'
import { sha256Hex } from '../src/canonical.js'
import { FacadeError } from '../src/errors.js'
import {
  FIXED_NOW,
  KEYRING,
  SESSION,
  makeContext,
  signedHeaders,
} from './helpers.js'

function requestFrom(headers: Record<string, string | string[]>): IncomingMessage {
  const rawHeaders: string[] = []
  for (const [name, raw] of Object.entries(headers)) {
    for (const value of Array.isArray(raw) ? raw : [raw]) rawHeaders.push(name, value)
  }
  return { rawHeaders } as IncomingMessage
}

test('signed context verifies every trusted binding and rejects replay-family headers', () => {
  const body = Buffer.from('{"jsonrpc":"2.0"}')
  const context = makeContext({ body_sha256: sha256Hex(body) })
  const request = requestFrom(signedHeaders(context))
  const verified = verifyApplicationContext(
    request,
    KEYRING,
    {
      method: 'POST',
      normalizedPath: '/mcp',
      route: 'analyze-mcp',
      body,
      mcpSessionId: SESSION,
    },
    FIXED_NOW
  )
  assert.equal(verified.application_sub, context.application_sub)
  assert.equal(verified.credential_id, context.credential_id)
  assert.equal(verified.package_revision_digest, context.package_revision_digest)
  assert.equal(verified.mcp_session_digest, sha256Hex(SESSION))

  for (const header of ['x-application-ctx-kid', 'x-application-ctx', 'x-application-ctx-sig']) {
    const signed = signedHeaders(context)
    const duplicate = requestFrom({ ...signed, [header]: [signed[header] ?? '', signed[header] ?? ''] })
    assert.throws(
      () =>
        verifyApplicationContext(
          duplicate,
          KEYRING,
          { method: 'POST', normalizedPath: '/mcp', route: 'analyze-mcp', body, mcpSessionId: SESSION },
          FIXED_NOW
        ),
      FacadeError
    )
  }
  assert.throws(
    () => rejectRawPublicCredentials(requestFrom({ authorization: 'Bearer forbidden' })),
    (error: unknown) => error instanceof FacadeError && error.code === 'unauthenticated'
  )
  assert.throws(
    () => rejectRawPublicCredentials(requestFrom({ cookie: 'estate=forbidden' })),
    (error: unknown) => error instanceof FacadeError && error.code === 'unauthenticated'
  )
  assert.throws(
    () => rejectRawPublicCredentials(requestFrom({ 'x-application-sub': context.application_sub })),
    (error: unknown) => error instanceof FacadeError && error.code === 'invalid_request'
  )
  const internalScope = makeContext({
    body_sha256: sha256Hex(body),
    scopes: ['rikune.analysis.read'] as unknown as ApplicationContext['scopes'],
  })
  assert.throws(
    () =>
      verifyApplicationContext(
        requestFrom(signedHeaders(internalScope)),
        KEYRING,
        { method: 'POST', normalizedPath: '/mcp', route: 'analyze-mcp', body, mcpSessionId: SESSION },
        FIXED_NOW
      ),
    (error: unknown) => error instanceof FacadeError && error.code === 'unauthenticated'
  )
})

test('context signature timing route body session and previous key fail closed', () => {
  const body = Buffer.from('{}')
  const context = makeContext({ body_sha256: sha256Hex(body) })
  const cases = [
    { method: 'GET', normalizedPath: '/mcp', route: 'analyze-mcp', body, mcpSessionId: SESSION },
    { method: 'POST', normalizedPath: '/other', route: 'analyze-mcp', body, mcpSessionId: SESSION },
    { method: 'POST', normalizedPath: '/mcp', route: 'other', body, mcpSessionId: SESSION },
    { method: 'POST', normalizedPath: '/mcp', route: 'analyze-mcp', body: Buffer.from('x'), mcpSessionId: SESSION },
    { method: 'POST', normalizedPath: '/mcp', route: 'analyze-mcp', body, mcpSessionId: 'other-session' },
  ]
  for (const expected of cases) {
    assert.throws(
      () => verifyApplicationContext(requestFrom(signedHeaders(context)), KEYRING, expected, FIXED_NOW),
      FacadeError
    )
  }
  assert.throws(
    () =>
      verifyApplicationContext(
        requestFrom(signedHeaders(context)),
        KEYRING,
        { method: 'POST', normalizedPath: '/mcp', route: 'analyze-mcp', body, mcpSessionId: SESSION },
        FIXED_NOW + 36
      ),
    FacadeError
  )
  const key = KEYRING.get('appctx-2026a')
  assert.ok(key)
  const expiredPrevious = new Map([
    ['appctx-2026a', { publicKey: key.publicKey, retiredAt: FIXED_NOW - 301 }],
  ])
  assert.throws(
    () =>
      verifyApplicationContext(
        requestFrom(signedHeaders(context)),
        expiredPrevious,
        { method: 'POST', normalizedPath: '/mcp', route: 'analyze-mcp', body, mcpSessionId: SESSION },
        FIXED_NOW
      ),
    (error: unknown) => error instanceof FacadeError && error.code === 'authentication_unavailable'
  )
})

test('verification keyring is public only current plus one previous', () => {
  const key = KEYRING.get('appctx-2026a')
  assert.ok(key)
  const raw = JSON.stringify({
    'appctx-2026a': { public_key: key.publicKey.toString('base64url'), retired_at: null },
  })
  assert.equal(parseVerificationKeyring('appctx-2026a', raw).size, 1)
  assert.throws(() => parseVerificationKeyring('missing', raw))
  assert.throws(() =>
    parseVerificationKeyring(
      'appctx-2026a',
      JSON.stringify({
        'appctx-2026a': { public_key: key.publicKey.toString('base64url'), retired_at: null },
        previous: { public_key: key.publicKey.toString('base64url'), retired_at: 1 },
        older: { public_key: key.publicKey.toString('base64url'), retired_at: 1 },
      })
    )
  )
  assert.throws(() =>
    parseVerificationKeyring(
      'appctx-2026a',
      JSON.stringify({
        'appctx-2026a': { public_key: key.publicKey.toString('base64url'), retired_at: null },
        previous: { public_key: key.publicKey.toString('base64url'), retired_at: null },
      })
    )
  )
  const previous = new Map([
    ['appctx-2026a', { publicKey: key.publicKey, retiredAt: null }],
    ['previous', { publicKey: key.publicKey, retiredAt: FIXED_NOW }],
  ])
  assert.equal(keyringReady(previous, 'appctx-2026a', FIXED_NOW), true)
  assert.equal(keyringReady(previous, 'appctx-2026a', FIXED_NOW + 299), true)
  assert.equal(keyringReady(previous, 'appctx-2026a', FIXED_NOW + 300), false)
  assert.equal(
    keyringReady(
      new Map([
        ['appctx-2026a', { publicKey: key.publicKey, retiredAt: null }],
        ['previous', { publicKey: key.publicKey, retiredAt: FIXED_NOW + 1 }],
      ]),
      'appctx-2026a',
      FIXED_NOW
    ),
    false
  )

  const body = Buffer.from('{}')
  const retiredContext = makeContext({
    kid: 'previous',
    body_sha256: sha256Hex(body),
    iat: FIXED_NOW,
    exp: FIXED_NOW + 30,
  })
  assert.equal(
    verifyApplicationContext(
      requestFrom(signedHeaders(retiredContext)),
      previous,
      { method: 'POST', normalizedPath: '/mcp', route: 'analyze-mcp', body, mcpSessionId: SESSION },
      FIXED_NOW
    ).kid,
    'previous'
  )
  const freshlySignedByPrevious = makeContext({
    kid: 'previous',
    body_sha256: sha256Hex(body),
    iat: FIXED_NOW + 1,
    exp: FIXED_NOW + 31,
  })
  assert.throws(
    () =>
      verifyApplicationContext(
        requestFrom(signedHeaders(freshlySignedByPrevious)),
        previous,
        { method: 'POST', normalizedPath: '/mcp', route: 'analyze-mcp', body, mcpSessionId: SESSION },
        FIXED_NOW + 1
      ),
    (error: unknown) => error instanceof FacadeError && error.code === 'authentication_unavailable'
  )
})
