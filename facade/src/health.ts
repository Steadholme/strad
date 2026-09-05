import { keyringReady, type VerificationKeyring } from './application-context.js'
import type { StradClient, VerdictClient } from './clients.js'
import type { SessionStore } from './session-store.js'

export type ReadinessDependencies = Readonly<{
  sessions: SessionStore
  verdict: VerdictClient
  strad: StradClient
  keyring: VerificationKeyring
  activeKid: string
  timeoutMs?: number
  now?: () => number
}>

async function withinTimeout<T>(operation: Promise<T>, timeoutMs: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined
  try {
    return await Promise.race([
      operation,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error('readiness deadline exceeded')), timeoutMs)
      }),
    ])
  } finally {
    if (timer !== undefined) clearTimeout(timer)
  }
}

export class CompositeReadiness {
  constructor(private readonly dependencies: ReadinessDependencies) {}

  async check(): Promise<void> {
    const now = (this.dependencies.now ?? (() => Math.floor(Date.now() / 1000)))()
    if (!keyringReady(this.dependencies.keyring, this.dependencies.activeKid, now)) {
      throw new Error('application context keyring is not ready')
    }
    const results = await withinTimeout(
      Promise.allSettled([
        this.dependencies.sessions.ping(),
        this.dependencies.verdict.probe(),
        this.dependencies.strad.probe(),
      ]),
      this.dependencies.timeoutMs ?? 3000
    )
    if (results.some((result) => result.status === 'rejected')) {
      throw new Error('one or more Analyze dependencies are not ready')
    }
  }
}
