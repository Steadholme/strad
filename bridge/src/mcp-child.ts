import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import {
  DEFAULT_INHERITED_ENV_VARS,
  StdioClientTransport,
} from '@modelcontextprotocol/sdk/client/stdio.js'

import {
  ACTIVATION_TARGETS,
  BUSINESS_TOOL_NAMES,
  MAX_MCP_RESPONSE_BYTES,
  REQUIRED_TOOL_NAMES,
} from './constants.js'
import type { BridgeConfig } from './config.js'
import { BridgeError } from './errors.js'
import {
  loadAndVerifyStaticLock,
  validateStaticBackendEnvironment,
} from './static-lock.js'
import { validateAndProjectBusinessResult } from './schemas.js'

type JsonRecord = Record<string, unknown>

export interface AnalyzerClient {
  readonly alive: boolean
  call(tool: string, args: JsonRecord, hardTimeoutMs: number): Promise<unknown>
  probeReady(): Promise<void>
  probeHealth(): Promise<void>
  close(): Promise<void>
}

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

let inheritedEnvironmentWindow: Promise<void> = Promise.resolve()

export async function withoutSdkInheritedEnvironment<T>(
  action: () => Promise<T>
): Promise<T> {
  const previousWindow = inheritedEnvironmentWindow
  let releaseWindow!: () => void
  inheritedEnvironmentWindow = new Promise<void>((resolve) => {
    releaseWindow = resolve
  })
  await previousWindow
  const saved = new Map<string, string | undefined>()
  for (const name of DEFAULT_INHERITED_ENV_VARS) {
    saved.set(name, process.env[name])
    delete process.env[name]
  }
  try {
    return await action()
  } finally {
    for (const [name, value] of saved) {
      if (value === undefined) delete process.env[name]
      else process.env[name] = value
    }
    releaseWindow()
  }
}

function structuredError(result: JsonRecord): { code: string; retryable: boolean } | null {
  const structured = result.structuredContent
  if (!isRecord(structured)) return null
  const error = structured.error
  if (!isRecord(error) || typeof error.code !== 'string') return null
  return { code: error.code, retryable: error.retryable === true }
}

function unwrapResult(raw: unknown): unknown {
  if (!isRecord(raw)) {
    throw new BridgeError(
      502,
      'analyzer_contract_violation',
      false,
      'Analyzer returned an invalid MCP result'
    )
  }
  const error = structuredError(raw)
  if (raw.isError === true || error) {
    if (error?.code === 'E_SAMPLE_BUSY') {
      throw new BridgeError(409, 'state_conflict', true, 'Sample is busy')
    }
    if (error?.code === 'E_SAMPLE_CONFIRMATION_MISMATCH') {
      throw new BridgeError(
        500,
        'analyzer_contract_violation',
        false,
        'Analyzer rejected a server-generated confirmation digest'
      )
    }
    throw new BridgeError(
      502,
      'analyzer_contract_violation',
      error?.retryable ?? false,
      'Analyzer tool failed its structured contract'
    )
  }
  const structured = raw.structuredContent
  if (!isRecord(structured) || structured.ok !== true || !('data' in structured)) {
    throw new BridgeError(
      502,
      'analyzer_contract_violation',
      false,
      'Analyzer omitted required structured content'
    )
  }
  return structured.data
}

function mapMcpFailure(error: unknown): BridgeError {
  if (error instanceof BridgeError) return error
  const candidate = isRecord(error) ? error : null
  const code = candidate?.code
  if (code === -32601 || code === -32602) {
    return new BridgeError(
      502,
      'analyzer_contract_violation',
      false,
      'Analyzer MCP method or parameters drifted'
    )
  }
  const name = error instanceof Error ? error.name : ''
  if (name === 'AbortError' || name === 'McpError') {
    return new BridgeError(
      503,
      'downstream_uncertain',
      false,
      'Analyzer mutation outcome is uncertain',
      5
    )
  }
  return new BridgeError(503, 'analyzer_unavailable', true, 'Analyzer is unavailable', 5)
}

async function boundedLoopbackProbe(path: string, timeoutMs: number): Promise<void> {
  const response = await fetch(`http://127.0.0.1:18080${path}`, {
    method: 'GET',
    redirect: 'error',
    signal: AbortSignal.timeout(timeoutMs),
  })
  if (response.status !== 200) throw new Error('child HTTP probe failed')
  const declared = response.headers.get('content-length')
  if (declared !== null && Number(declared) > 64 * 1024) throw new Error('child probe too large')
  if (!response.body) throw new Error('child probe omitted its body')
  const reader = response.body.getReader()
  let total = 0
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      total += value.byteLength
      if (total > 64 * 1024) {
        await reader.cancel()
        throw new Error('child probe too large')
      }
    }
  } finally {
    reader.releaseLock()
  }
}

export class RikuneChild implements AnalyzerClient {
  private readonly client = new Client({ name: 'strad-analyzer-bridge', version: '1.0.0' })
  private transport: StdioClientTransport | null = null
  private closing = false
  private initialized = false
  private bootVerified = false
  private startPromise: Promise<void> | null = null

  constructor(
    private readonly config: BridgeConfig,
    private readonly onFatal: (reason: 'close' | 'error') => void
  ) {}

  get alive(): boolean {
    return (
      this.bootVerified && this.initialized && !this.closing && this.transport?.pid !== null
    )
  }

  async start(): Promise<void> {
    this.startPromise ??= this.startOnce()
    return this.startPromise
  }

  private async startOnce(): Promise<void> {
    const lock = await loadAndVerifyStaticLock(this.config.staticLockPath)
    validateStaticBackendEnvironment(lock, this.config.childEnv)
    const transport = new StdioClientTransport({
      command: this.config.childCommand,
      args: [...this.config.childArgs],
      env: { ...this.config.childEnv },
      cwd: this.config.childCwd,
      stderr: 'inherit',
    })
    this.transport = transport
    this.client.onclose = () => {
      this.initialized = false
      this.bootVerified = false
      this.transport = null
      if (!this.closing) this.onFatal('close')
    }
    this.client.onerror = () => {
      if (!this.closing) this.onFatal('error')
    }
    // The SDK merges a small parent-env allowlist even when `env` is supplied.
    // Startup is single-threaded, so scrub that list until spawn captures the
    // explicitly frozen child environment, then restore PID 1 immediately.
    try {
      await withoutSdkInheritedEnvironment(() => this.client.connect(transport))
      this.initialized = true
      await this.waitForHttpReady(120_000)
      for (const canonicalName of ACTIVATION_TARGETS) {
        const data = unwrapResult(
          await this.client.callTool(
            {
              name: 'workflow_search',
              arguments: { action: 'activate', tool_name: canonicalName },
            },
            undefined,
            { timeout: 30_000, maxTotalTimeout: 30_000 }
          )
        )
        if (!isRecord(data)) throw new Error('activation result is not an object')
        const activated = data.activated_tools
        if (
          !Array.isArray(activated) ||
          !activated.every((item) => typeof item === 'string') ||
          !activated.some(
            (item) => item === canonicalName || item === canonicalName.replaceAll('.', '_')
          )
        ) {
          throw new Error(`activation was not proven for ${canonicalName}`)
        }
      }
      await this.verifyExactToolSet()
      await this.passiveStatusProbe()
      this.bootVerified = true
    } catch (error) {
      this.bootVerified = false
      this.initialized = false
      this.closing = true
      this.transport = null
      try {
        await this.client.close()
      } catch {
        // Preserve the original startup failure while still attempting cleanup.
      }
      throw error
    }
  }

  async call(tool: string, args: JsonRecord, hardTimeoutMs: number): Promise<unknown> {
    if (!this.alive || !BUSINESS_TOOL_NAMES.includes(tool as never)) {
      throw new BridgeError(503, 'analyzer_unavailable', true, 'Analyzer is unavailable', 5)
    }
    try {
      const raw = await this.client.callTool(
        { name: tool, arguments: args },
        undefined,
        {
          timeout: hardTimeoutMs,
          maxTotalTimeout: hardTimeoutMs,
          resetTimeoutOnProgress: false,
        }
      )
      if (Buffer.byteLength(JSON.stringify(raw), 'utf8') > MAX_MCP_RESPONSE_BYTES) {
        throw new BridgeError(
          502,
          'analyzer_contract_violation',
          false,
          'Analyzer MCP response exceeds the bridge bound'
        )
      }
      const data = unwrapResult(raw)
      try {
        return validateAndProjectBusinessResult(tool, args, data)
      } catch {
        throw new BridgeError(
          502,
          'analyzer_contract_violation',
          false,
          'Analyzer business output violates the frozen schema'
        )
      }
    } catch (error) {
      throw mapMcpFailure(error)
    }
  }

  private async verifyExactToolSet(): Promise<void> {
    const result = await this.client.listTools()
    const names = result.tools.map((tool) => tool.name).sort()
    if (
      names.length !== REQUIRED_TOOL_NAMES.length ||
      names.some((name, index) => name !== REQUIRED_TOOL_NAMES[index])
    ) {
      throw new Error('child MCP visible tool set differs from the frozen six-tool contract')
    }
  }

  private async passiveStatusProbe(): Promise<void> {
    unwrapResult(
      await this.client.callTool(
        { name: 'workflow_search', arguments: { action: 'status' } },
        undefined,
        { timeout: 5_000, maxTotalTimeout: 5_000 }
      )
    )
  }

  private async waitForHttpReady(deadlineMs: number): Promise<void> {
    const deadline = Date.now() + deadlineMs
    let lastFailure: unknown = null
    while (Date.now() < deadline) {
      try {
        await boundedLoopbackProbe('/api/v1/ready', 5_000)
        return
      } catch (error) {
        lastFailure = error
        await new Promise((resolve) => setTimeout(resolve, 500))
      }
    }
    throw lastFailure instanceof Error ? lastFailure : new Error('child readiness timed out')
  }

  async probeHealth(): Promise<void> {
    if (!this.alive) throw new Error('child is not alive')
    await boundedLoopbackProbe('/api/v1/health', 5_000)
  }

  async probeReady(): Promise<void> {
    if (!this.bootVerified || !this.alive) throw new Error('child is not initialized')
    const lock = await loadAndVerifyStaticLock(this.config.staticLockPath)
    validateStaticBackendEnvironment(lock, this.config.childEnv)
    await Promise.all([
      boundedLoopbackProbe('/api/v1/ready', 10_000),
      this.verifyExactToolSet(),
      this.passiveStatusProbe(),
    ])
  }

  async close(): Promise<void> {
    if (this.closing) return
    this.closing = true
    this.initialized = false
    this.bootVerified = false
    this.transport = null
    await this.client.close()
  }
}
