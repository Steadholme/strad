import { createHash } from 'node:crypto'

export const MODES = new Set(['deny', 'indeterminate', 'stale_digest', 'stale_version', 'stale_ttl', 'dependency_failure'])
export function decisionDigest(request, decision) {
  return createHash('sha256').update(JSON.stringify({
    domain: 'w33d.verdict.application-decision.v2', request,
    subject: decision.subject, resource: decision.resource, permission: decision.permission,
    decision: decision.decision, reason: decision.reason, evidence: decision.evidence,
    policy_version: decision.policy_version, subject_version: decision.subject_version,
    policy_epoch: decision.policy_epoch, issued_at: decision.issued_at, expires_at: decision.expires_at,
  })).digest('hex')
}

// Only refusal/corruption cases are supported. This helper can never turn a
// non-Allow decision into Allow, and is mounted only in closed acceptance.
export function injectDecisionFault(mode, request, original) {
  if (!MODES.has(mode)) throw new Error('Unknown closed decision fault')
  const originalDigest = decisionDigest(request, original)
  if (original.decision !== 'Allow' || original.decision_digest !== originalDigest ||
      original.decision_id !== 'dec_' + originalDigest.slice(0, 32)) {
    throw new Error('A real, coherent Allow is required before fault injection')
  }
  if (mode === 'dependency_failure') return { status: 503, body: { error: 'closed_dependency_failure' } }
  const decision = structuredClone(original)
  if (mode === 'deny') { decision.decision = 'Deny'; decision.reason = 'Closed refusal test'; decision.evidence = [] }
  if (mode === 'indeterminate') { decision.decision = 'Indeterminate'; decision.reason = 'Closed indeterminate test'; decision.evidence = [] }
  if (mode === 'stale_version') decision.policy_version = 0
  if (mode === 'stale_ttl') { decision.issued_at -= 60; decision.expires_at -= 60 }
  decision.decision_digest = decisionDigest(request, decision)
  decision.decision_id = 'dec_' + decision.decision_digest.slice(0, 32)
  if (mode === 'stale_digest') decision.decision_digest = (decision.decision_digest[0] === '0' ? '1' : '0') + decision.decision_digest.slice(1)
  return { status: 200, body: decision }
}
