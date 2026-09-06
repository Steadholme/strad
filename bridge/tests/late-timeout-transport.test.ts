import assert from 'node:assert/strict'
import test from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js'
import {
  CallToolRequestSchema, ErrorCode, McpError, type JSONRPCMessage,
} from '@modelcontextprotocol/sdk/types.js'

import { LateTimeoutTransport } from '../src/late-timeout-transport.js'

const timeoutReason = String(McpError.fromError(ErrorCode.RequestTimeout, 'Request timed out'))

function fixture() {
  const forwarded: JSONRPCMessage[] = []
  const errors: Error[] = []
  let late = 0
  let closed = 0
  const inner: Transport = { async start() {}, async send() {}, async close() {} }
  const transport = new LateTimeoutTransport(inner, () => { late++ })
  transport.onmessage = message => forwarded.push(message)
  transport.onerror = error => errors.push(error)
  transport.onclose = () => { closed++ }
  const request = (id: number) => transport.send({ jsonrpc: '2.0', id, method: 'ping' })
  const cancel = (id: number, reason = timeoutReason) => transport.send({
    jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: id, reason },
  })
  const respond = (id: number) => inner.onmessage?.({ jsonrpc: '2.0', id, result: {} })
  return { inner, transport, forwarded, errors, request, cancel, respond,
    late: () => late, closed: () => closed }
}

test('only one late response for an actually timed-out outgoing request is discarded', async () => {
  const f = fixture()
  await f.transport.start()
  await f.request(1)
  await f.cancel(1)
  f.respond(1)
  assert.equal(f.late(), 1)
  assert.equal(f.forwarded.length, 0)
  f.respond(1) // A duplicate is still an unknown response for the SDK to reject.
  await f.cancel(2) // A fabricated cancellation without an outgoing request is not trusted.
  f.respond(2)
  await f.request(3)
  await f.cancel(3, 'caller aborted')
  f.respond(3)
  f.respond(999)
  assert.deepEqual(f.forwarded.map(message => 'id' in message ? message.id : null), [1, 2, 3, 999])
})

test('completed requests cannot become timeout tombstones and transport failures propagate', async () => {
  const f = fixture()
  await f.transport.start()
  await f.request(1)
  f.respond(1)
  await f.cancel(1)
  f.respond(1)
  const parseError = new SyntaxError('invalid JSON')
  f.inner.onerror?.(parseError)
  f.inner.onclose?.()
  assert.equal(f.late(), 0)
  assert.equal(f.forwarded.length, 2)
  assert.deepEqual(f.errors, [parseError])
  assert.equal(f.closed(), 1)
  f.inner.send = async () => { throw new Error('broken pipe') }
  await assert.rejects(f.request(2), /broken pipe/)
})

test('timeout tracking stays bounded and old evictions fail closed', async () => {
  const f = fixture()
  await f.transport.start()
  for (let id = 0; id < 1000; id++) {
    await f.request(id)
    await f.cancel(id)
  }
  for (let id = 0; id < 1000; id++) f.respond(id)
  assert.equal(f.late(), 256)
  assert.equal(f.forwarded.length, 744)
})

test('real SDK timeout plus delayed reply does not become a fatal unknown-ID error', async () => {
  const [wire, peer] = InMemoryTransport.createLinkedPair()
  let release!: () => void
  const gate = new Promise<void>(resolve => { release = resolve })
  let delayedId: string | number | undefined
  const server = new Server({ name: 'delayed-child', version: '1' }, { capabilities: { tools: {} } })
  server.setRequestHandler(CallToolRequestSchema, async (_request, extra) => {
    delayedId = extra.requestId
    await gate
    return { content: [{ type: 'text', text: 'sensitive body must never be logged' }] }
  })
  const client = new Client({ name: 'probe', version: '1' })
  const errors: Error[] = []
  let late = 0
  client.onerror = error => errors.push(error)
  await server.connect(peer)
  await client.connect(new LateTimeoutTransport(wire, () => { late++ }))
  try {
    await assert.rejects(client.callTool({ name: 'slow' }, undefined, { timeout: 5 }),
      error => error instanceof McpError && error.code === ErrorCode.RequestTimeout)
    // Model the response already in flight before a busy child can process the
    // cancellation. The current SDK server itself suppresses replies once it
    // has handled cancellation, unlike a response already on the stdio pipe.
    assert.notEqual(delayedId, undefined)
    await peer.send({ jsonrpc: '2.0', id: delayedId!, result: {
      content: [{ type: 'text', text: 'sensitive body must never be logged' }],
    } })
    release()
    await new Promise(resolve => setImmediate(resolve))
    assert.equal(late, 1)
    assert.equal(errors.length, 0)
    await client.ping() // The same initialized MCP connection remains useful.
    await peer.send({ jsonrpc: '2.0', id: 999, result: {} })
    assert.equal(errors.length, 1)
    assert.match(errors[0]!.message, /^Received a response for an unknown message ID:/)
  } finally {
    release()
    await client.close()
    await server.close()
  }
})
