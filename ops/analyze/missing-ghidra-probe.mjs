// Diagnostic bootstrap using the production classes, with no external network.
import { loadConfig } from '/opt/strad-bridge/dist/src/config.js'
import { prepareSpoolRoot } from '/opt/strad-bridge/dist/src/upload.js'
import { OperationJournal } from '/opt/strad-bridge/dist/src/journal.js'
import { RikuneChild } from '/opt/strad-bridge/dist/src/mcp-child.js'

process.umask(0o077)
let stage = 'config'
let child
let journal
try {
  const config = loadConfig()
  stage = 'spool'
  await prepareSpoolRoot(config.spoolRoot)
  stage = 'journal'
  journal = new OperationJournal(config.journalPath)
  stage = 'child_bootstrap'
  child = new RikuneChild(config, () => {})
  await child.start()
  console.log('MISSING_GHIDRA_BOOTSTRAP_UNEXPECTEDLY_READY')
  process.exitCode = 2
} catch (error) {
  let message = String(error.message)
  for (const value of Object.values(process.env)) {
    if (value && value.length >= 16) message = message.replaceAll(value, '[redacted]')
  }
  console.log('MISSING_GHIDRA_DIAGNOSTIC ' + JSON.stringify({ stage, message, code: error.code ?? null }))
  process.exitCode = 1
} finally {
  if (child) await child.close().catch(() => {})
  if (journal) journal.close()
}
