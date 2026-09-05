import { HttpStradClient, HttpVerdictClient } from './clients.js'
import { loadConfig } from './config.js'
import { createFacadeServer, listen } from './server.js'
import { PostgresSessionStore } from './session-store.js'

async function main(): Promise<void> {
  const config = loadConfig()
  const sessions = new PostgresSessionStore(config.databaseUrl, config.requestTimeoutMs)
  await sessions.migrate()
  const verdict = new HttpVerdictClient(
    config.verdictDecisionUrl,
    config.verdictDecisionToken,
    config.requestTimeoutMs
  )
  const strad = new HttpStradClient(
    config.stradOrigin,
    config.stradFacadeToken,
    config.requestTimeoutMs
  )
  const server = createFacadeServer({ config, sessions, verdict, strad })
  const shutdown = async (): Promise<void> => {
    server.close()
    await sessions.close()
  }
  process.once('SIGINT', () => void shutdown())
  process.once('SIGTERM', () => void shutdown())
  await listen(server, config.bindAddress)
}

await main()
