export type FacadeErrorCode =
  | 'invalid_request'
  | 'unauthenticated'
  | 'authentication_unavailable'
  | 'insufficient_scope'
  | 'authorization_denied'
  | 'authorization_unavailable'
  | 'invalid_session'
  | 'replay_detected'
  | 'quota_exceeded'
  | 'idempotency_mismatch'
  | 'not_found'
  | 'analyzer_unavailable'
  | 'dependency_unavailable'

const ERROR_CONTRACT: Readonly<
  Record<FacadeErrorCode, { readonly http: number; readonly jsonRpc: number; readonly retryable: boolean }>
> = Object.freeze({
  invalid_request: { http: 400, jsonRpc: -32602, retryable: false },
  unauthenticated: { http: 401, jsonRpc: -32001, retryable: false },
  authentication_unavailable: { http: 503, jsonRpc: -32002, retryable: true },
  insufficient_scope: { http: 403, jsonRpc: -32003, retryable: false },
  authorization_denied: { http: 403, jsonRpc: -32004, retryable: false },
  authorization_unavailable: { http: 503, jsonRpc: -32005, retryable: true },
  invalid_session: { http: 404, jsonRpc: -32006, retryable: false },
  replay_detected: { http: 409, jsonRpc: -32007, retryable: false },
  quota_exceeded: { http: 429, jsonRpc: -32008, retryable: true },
  idempotency_mismatch: { http: 409, jsonRpc: -32009, retryable: false },
  not_found: { http: 404, jsonRpc: -32010, retryable: false },
  analyzer_unavailable: { http: 503, jsonRpc: -32011, retryable: true },
  dependency_unavailable: { http: 503, jsonRpc: -32012, retryable: true },
})

export class FacadeError extends Error {
  readonly code: FacadeErrorCode
  readonly httpStatus: number
  readonly jsonRpcCode: number
  readonly retryable: boolean
  readonly correlationId: string | null

  constructor(code: FacadeErrorCode, message: string, correlationId: string | null = null) {
    super(message)
    this.name = 'FacadeError'
    this.code = code
    this.httpStatus = ERROR_CONTRACT[code].http
    this.jsonRpcCode = ERROR_CONTRACT[code].jsonRpc
    this.retryable = ERROR_CONTRACT[code].retryable
    this.correlationId = correlationId
  }

  body(): Readonly<Record<string, unknown>> {
    return Object.freeze({
      error: Object.freeze({
        code: this.code,
        message: this.message,
        correlation_id: this.correlationId,
        retryable: this.retryable,
        json_rpc: this.jsonRpcCode,
      }),
    })
  }
}

export function safeFacadeError(error: unknown): FacadeError {
  return error instanceof FacadeError
    ? error
    : new FacadeError('dependency_unavailable', 'A required Analyze dependency is unavailable.')
}
