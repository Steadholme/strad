import type { Server } from 'node:http'

import { loadConfig } from './config.js'
import { OperationJournal } from './journal.js'
import { RikuneChild } from './mcp-child.js'
import { closeServer, createBridgeServer, listen } from './server.js'
import {
  cleanOrphanSpools,
  completeUploadOperation,
  prepareSpoolRoot,
  reconcileUnknownUploads,
} from './upload.js'

async function main(): Promise<void> {
  process.umask(0o077)
  const config = loadConfig()
  await prepareSpoolRoot(config.spoolRoot)
  const journal = new OperationJournal(config.journalPath)
  const recovery = journal.recoverAfterCrash()
  // Orphan sweeping is startup-only. Running it while the server accepts uploads
  // can race the live .part -> .bin transition and destroy an in-flight spool.
  await cleanOrphanSpools(config.spoolRoot, journal)

  let server: Server | null = null
  let shuttingDown = false
  let reconciliationTimer: NodeJS.Timeout | null = null
  let reconciliationInFlight = false
  const fatal = (): void => {
    if (shuttingDown) return
    shuttingDown = true
    journal.markAllMcpInFlightUnknown()
    process.exitCode = 1
    if (server?.listening) {
      server.closeAllConnections()
      void closeServer(server).finally(() => setImmediate(() => process.exit(1)))
    } else {
      setImmediate(() => process.exit(1))
    }
  }
  const child = new RikuneChild(config, fatal)

  try {
    await child.start()
    await reconcileUnknownUploads(config, journal)
    server = createBridgeServer({ config, journal, analyzer: child })
    await listen(server, config.host, config.port)

    reconciliationTimer = setInterval(() => {
      if (reconciliationInFlight || shuttingDown) return
      reconciliationInFlight = true
      void reconcileUnknownUploads(config, journal)
        .catch(() => fatal())
        .finally(() => {
          reconciliationInFlight = false
        })
    }, 5 * 60 * 1000)
    reconciliationTimer.unref()

    for (const row of recovery.verifiedUploads) {
      void completeUploadOperation(row, config, journal).catch(() => fatal())
    }

    const shutdown = async (signal: NodeJS.Signals): Promise<void> => {
      if (shuttingDown) return
      shuttingDown = true
      process.stderr.write(`${JSON.stringify({ level: 'info', event: 'shutdown', signal })}\n`)
      const deadline = setTimeout(() => process.exit(1), 10_000)
      deadline.unref()
      try {
        if (reconciliationTimer) clearInterval(reconciliationTimer)
        if (server) await closeServer(server)
        await child.close()
        journal.close()
        clearTimeout(deadline)
        process.exit(0)
      } catch {
        process.exit(1)
      }
    }
    process.once('SIGTERM', () => void shutdown('SIGTERM'))
    process.once('SIGINT', () => void shutdown('SIGINT'))
    process.stderr.write(
      `${JSON.stringify({ level: 'info', event: 'bridge_ready', port: config.port })}\n`
    )
  } catch (error) {
    await child.close().catch(() => undefined)
    journal.close()
    throw error
  }
}

void main().catch(() => {
  process.stderr.write(`${JSON.stringify({ level: 'error', event: 'bridge_start_failed' })}\n`)
  process.exit(1)
})
