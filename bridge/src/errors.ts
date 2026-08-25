export class BridgeError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly retryable: boolean,
    message: string,
    readonly retryAfterSeconds?: number
  ) {
    super(message)
    this.name = 'BridgeError'
  }
}

export function safeBridgeError(error: unknown): BridgeError {
  if (error instanceof BridgeError) return error
  return new BridgeError(503, 'analyzer_unavailable', true, 'Analyzer is unavailable', 5)
}
