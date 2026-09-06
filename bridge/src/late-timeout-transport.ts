import type { Transport, TransportSendOptions } from '@modelcontextprotocol/sdk/shared/transport.js'
import {
  isJSONRPCErrorResponse,
  isJSONRPCRequest,
  isJSONRPCResultResponse,
  type JSONRPCMessage,
  type RequestId,
} from '@modelcontextprotocol/sdk/types.js'

// SDK 1.27.1 removes a timed-out request before sending this cancellation. A
// healthy but busy child can still finish that request: the SDK then reports
// "Received a response for an unknown message ID", which is not a broken pipe.
const SDK_TIMEOUT_REASON = 'McpError: MCP error -32001: Request timed out'
const MAX_TRACKED_REQUESTS = 512
const MAX_TIMED_OUT_REQUESTS = 256

function boundedAdd(ids: Set<RequestId>, id: RequestId, limit: number): void {
  ids.add(id)
  if (ids.size > limit) ids.delete(ids.values().next().value!)
}

/** Drop only a first response to a real request cancelled by the SDK timeout. */
export class LateTimeoutTransport implements Transport {
  onclose?: NonNullable<Transport['onclose']>
  onerror?: NonNullable<Transport['onerror']>
  onmessage?: NonNullable<Transport['onmessage']>
  private readonly pending = new Set<RequestId>()
  private readonly timedOut = new Set<RequestId>()

  constructor(
    private readonly inner: Transport,
    private readonly onLateTimeoutResponse: () => void
  ) {}

  async start(): Promise<void> {
    this.inner.onclose = () => {
      this.pending.clear()
      this.timedOut.clear()
      this.onclose?.()
    }
    this.inner.onerror = (error) => this.onerror?.(error)
    this.inner.onmessage = (message, extra) => {
      if ((isJSONRPCResultResponse(message) || isJSONRPCErrorResponse(message)) &&
          message.id !== undefined) {
        this.pending.delete(message.id)
        if (this.timedOut.delete(message.id)) {
          // Do not forward (or log) the body: the caller has already failed and
          // mutation outcomes must stay uncertain until durable reconciliation.
          this.onLateTimeoutResponse()
          return
        }
      }
      this.onmessage?.(message, extra)
    }
    await this.inner.start()
  }

  async send(message: JSONRPCMessage, options?: TransportSendOptions): Promise<void> {
    if (isJSONRPCRequest(message)) {
      boundedAdd(this.pending, message.id, MAX_TRACKED_REQUESTS)
    } else if ('method' in message && message.method === 'notifications/cancelled') {
      const id = message.params?.requestId
      if ((typeof id === 'number' || typeof id === 'string') && this.pending.delete(id) &&
          message.params?.reason === SDK_TIMEOUT_REASON) {
        boundedAdd(this.timedOut, id, MAX_TIMED_OUT_REQUESTS)
      }
    }
    // Failed sends still reach the SDK error path; they are never suppressed.
    await this.inner.send(message, options)
  }

  async close(): Promise<void> {
    this.pending.clear()
    this.timedOut.clear()
    await this.inner.close()
  }
}
