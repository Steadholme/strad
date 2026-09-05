import assert from 'node:assert/strict'
import test from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { AjvJsonSchemaValidator } from '@modelcontextprotocol/sdk/validation/ajv'

import { REQUIRED_TOOL_NAMES } from '../src/constants.js'
import { verifyFrozenToolCatalog } from '../src/tool-catalog.js'

function fixture() {
  const validator = new AjvJsonSchemaValidator()
  let compiled = 0
  let requests = 0
  const client = new Client({ name: 'catalog-retention-test', version: '1' }, {
    jsonSchemaValidator: {
      getValidator(schema) {
        compiled++
        return validator.getValidator(schema)
      },
    },
  })
  const catalog = { tools: REQUIRED_TOOL_NAMES.map(name => ({
    name, inputSchema: { type: 'object' as const },
    outputSchema: { type: 'object' as const, properties: { ok: { type: 'boolean' } } },
  })) }
  // The actual SDK still runs listTools/cacheToolMetadata/AJV. Only the wire
  // response is doubled, including fresh JSON schema objects per response.
  client.request = (async () => {
    requests++
    return structuredClone(catalog)
  }) as Client['request']
  return { client, catalog, compiled: () => compiled, requests: () => requests }
}

test('repeated real SDK listTools compiles fresh schemas: reproduces retained-cache cause', async () => {
  const run = fixture()
  for (let i = 0; i < 10; i++) await run.client.listTools()
  assert.equal(run.compiled(), REQUIRED_TOOL_NAMES.length * 10)
})

test('1000 live catalog probes retain only the boot validators and reject schema drift', async () => {
  const run = fixture()
  const fingerprint = await verifyFrozenToolCatalog(run.client, null)
  for (let i = 0; i < 1000; i++) {
    assert.equal(await verifyFrozenToolCatalog(run.client, fingerprint), fingerprint)
  }
  assert.equal(run.requests(), 1001)
  assert.equal(run.compiled(), REQUIRED_TOOL_NAMES.length)
  run.catalog.tools[0]!.outputSchema.properties.ok.type = 'string'
  await assert.rejects(verifyFrozenToolCatalog(run.client, fingerprint), /schemas changed/)
  assert.equal(run.compiled(), REQUIRED_TOOL_NAMES.length)
})

test('live tool-set drift still fails closed without compiling new validators', async () => {
  const run = fixture()
  const fingerprint = await verifyFrozenToolCatalog(run.client, null)
  run.catalog.tools.pop()
  await assert.rejects(verifyFrozenToolCatalog(run.client, fingerprint), /six-tool contract/)
})
