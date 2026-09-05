import { createHash } from 'node:crypto'

import type { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { ListToolsResultSchema } from '@modelcontextprotocol/sdk/types.js'

import { REQUIRED_TOOL_NAMES } from './constants.js'

/** Compile SDK output validators once; subsequent probes still verify the live catalog. */
export async function verifyFrozenToolCatalog(
  client: Client,
  previousFingerprint: string | null
): Promise<string> {
  const options = { timeout: 5_000, maxTotalTimeout: 5_000 }
  // SDK listTools() recompiles anonymous output schemas on every response. AJV
  // retains those schema objects even when the SDK replaces its validator map.
  // A raw, schema-validated request avoids that unbounded readiness-probe cache.
  const result = previousFingerprint === null
    ? await client.listTools(undefined, options)
    : await client.request({ method: 'tools/list' }, ListToolsResultSchema, options)
  const tools = [...result.tools].sort((left, right) =>
    left.name < right.name ? -1 : left.name > right.name ? 1 : 0)
  if (result.nextCursor !== undefined || tools.length !== REQUIRED_TOOL_NAMES.length ||
      tools.some((tool, index) => tool.name !== REQUIRED_TOOL_NAMES[index])) {
    throw new Error('child MCP visible tool set differs from the frozen six-tool contract')
  }
  const fingerprint = createHash('sha256').update(JSON.stringify(tools.map(tool => ({
    name: tool.name,
    inputSchema: tool.inputSchema,
    outputSchema: tool.outputSchema,
    execution: tool.execution,
  })))).digest('hex')
  if (previousFingerprint !== null && fingerprint !== previousFingerprint) {
    throw new Error('child MCP tool schemas changed after boot validation')
  }
  return fingerprint
}
