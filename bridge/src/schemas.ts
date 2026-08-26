import { z } from 'zod'

const SAMPLE_ID = /^sha256:[0-9a-f]{64}$/
const SHA256 = /^[0-9a-f]{64}$/
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,239}$/
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const ARTIFACT_READ_MAX_BYTES = 256 * 1024
const safeText = (max: number) => z.string().trim().min(1).max(max)

const startSchema = z
  .object({
    action: z.literal('start'),
    sample_id: z.string().regex(SAMPLE_ID),
    goal: z.literal('static'),
    depth: z.literal('balanced'),
    backend_policy: z.literal('auto'),
    allow_transformations: z.literal(false),
    allow_live_execution: z.literal(false),
    force_refresh: z.literal(false),
    include_raw_result: z.literal(false),
  })
  .strict()

const promoteSchema = z
  .object({
    action: z.literal('promote'),
    plan_id: safeText(240),
    through_stage: z.literal('function_map'),
    allow_transformations: z.literal(false),
    allow_live_execution: z.literal(false),
    force_refresh: z.literal(false),
    include_raw_result: z.literal(false),
  })
  .strict()

const statusSchema = z
  .object({
    action: z.literal('status'),
    plan_id: safeText(240),
    include_raw_result: z.literal(false),
  })
  .strict()

const artifactSchema = z
  .object({
    sample_id: z.string().regex(SAMPLE_ID),
    artifact_id: safeText(240).optional(),
    artifact_type: safeText(240).optional(),
    path: safeText(2048).optional(),
    read_mode: z.enum(['profile', 'summary', 'content']),
  })
  .strict()
  .superRefine((value, context) => {
    const selectors = [value.artifact_id, value.artifact_type, value.path].filter(
      (item) => item !== undefined
    )
    if (selectors.length !== 1) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'Exactly one artifact selector is required',
      })
    }
  })
  .transform((value) => ({
    ...value,
    include_untracked_files: false,
    recursive: false,
    scan_roots: [],
    select_latest: true,
    include_content: value.read_mode !== 'profile',
    max_bytes: ARTIFACT_READ_MAX_BYTES,
    encoding: 'auto' as const,
    parse_json: false,
    ioc_highlights: false,
  }))

const attemptedActionSchema = z
  .object({
    tool: safeText(200),
    args_fingerprint: z.string().regex(SHA256),
    outcome: z.enum(['completed', 'failed', 'queued', 'skipped']),
    result_artifact_ids: z.array(safeText(200)).max(64),
    summary: safeText(1200).optional(),
  })
  .strict()

const checkpointSchema = z
  .object({
    sample_id: z.string().regex(SAMPLE_ID),
    case_id: z.string().regex(IDENTIFIER).optional(),
    parent_artifact_id: safeText(200).nullable(),
    session_tag: safeText(200).optional(),
    producer: z
      .object({ kind: z.literal('external_agent'), agent_name: safeText(200).optional() })
      .strict(),
    state: z
      .object({
        objective: safeText(2000),
        decisions: z.array(safeText(1200)).max(64),
        open_questions: z.array(safeText(1200)).max(64),
        attempted_actions: z.array(attemptedActionSchema).max(128),
        active_claim_ids: z.array(safeText(200)).max(256),
        pinned_artifact_ids: z.array(safeText(200)).max(128),
        next_actions: z.array(safeText(1200)).max(64),
      })
      .strict(),
  })
  .strict()

const contextPackSchema = z
  .object({
    sample_id: z.string().regex(SAMPLE_ID),
    goal: safeText(1000),
    token_budget: z.literal(8192),
    since_marker: safeText(4096).optional(),
    evidence_scope: z.literal('latest'),
    claim_scope: z.literal('latest'),
    include_case: z.literal(true),
    case_id: z.string().regex(IDENTIFIER),
  })
  .strict()

const sampleDeleteSchema = z
  .object({
    sample_id: z.string().regex(SAMPLE_ID),
    confirm_sha256: z.string().regex(SHA256),
    reason: safeText(500).optional(),
  })
  .strict()
  .superRefine((value, context) => {
    if (value.sample_id.slice('sha256:'.length) !== value.confirm_sha256) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['confirm_sha256'],
        message: 'Confirmation digest must match sample ID',
      })
    }
  })

const routeSchemas: Readonly<Record<string, z.ZodType>> = Object.freeze({
  '/internal/v1/workflows/start': startSchema,
  '/internal/v1/workflows/promote': promoteSchema,
  '/internal/v1/workflows/status': statusSchema,
  '/internal/v1/artifacts/read': artifactSchema,
  '/internal/v1/cases/checkpoint': checkpointSchema,
  '/internal/v1/context/pack': contextPackSchema,
  '/internal/v1/samples/delete': sampleDeleteSchema,
})

export function parseRouteBody(pathname: string, body: unknown): Record<string, unknown> {
  const schema = routeSchemas[pathname]
  if (!schema) throw new Error('route schema missing')
  return schema.parse(body) as Record<string, unknown>
}

const stageStatusResultSchema = z
  .object({
    stage: z.enum(['fast_profile', 'enrich_static', 'function_map']),
    status: safeText(64),
    execution_state: safeText(64).nullable().optional(),
    recovery_state: safeText(64),
    job_id: safeText(240).nullable().optional(),
  })
  .strict()

const artifactSelectorResultSchema = z
  .object({
    selector_id: safeText(512),
    sample_id: z.string().regex(SAMPLE_ID),
    artifact_id: safeText(512),
    artifact_type: safeText(512),
    path: z.string().min(1).max(4096),
    sha256: z.string().regex(SHA256).optional(),
    mime: z.string().min(1).max(256).nullable().optional(),
    stage: safeText(64).nullable(),
    source: z.enum(['stage', 'run']),
    suggested_read_mode: z.enum(['profile', 'summary', 'content']),
    read_args: z
      .object({
        sample_id: z.string().regex(SAMPLE_ID),
        artifact_id: safeText(512),
        read_mode: z.enum(['profile', 'summary', 'content']),
      })
      .strict(),
  })
  .strict()

const artifactSelectorSummaryResultSchema = z
  .object({
    total_artifact_refs: z.number().int().nonnegative(),
    selectable_artifact_refs: z.number().int().nonnegative(),
    selector_count: z.number().int().nonnegative().max(12),
    omitted_count: z.number().int().nonnegative(),
    latest_stage: safeText(64).nullable(),
    by_type: z.record(z.number().int().nonnegative()),
    by_stage: z.record(z.number().int().nonnegative()),
  })
  .strict()

const workflowResultSchema = z
  .object({
    result_mode: z.literal('workflow_run'),
    action: z.enum(['start', 'status', 'promote']),
    routed_tool: z.enum([
      'workflow.analyze.start',
      'workflow.analyze.status',
      'workflow.analyze.promote',
    ]),
    plan_id: safeText(240),
    current_stage: safeText(64).optional(),
    latest_stage: safeText(64).optional(),
    stage_statuses: z.array(stageStatusResultSchema).max(16).optional(),
    function_index_ready: z.boolean().optional(),
    artifact_selectors: z.array(artifactSelectorResultSchema).max(12).optional(),
    artifact_selector_summary: artifactSelectorSummaryResultSchema.optional(),
    recommended_workflow_tools: z.array(safeText(240)).max(64),
    next_actions: z.array(safeText(1000)).max(64),
    message: z.string().max(4096),
  })
  .passthrough()

const artifactReadResultSchema = z
  .object({
    sample_id: z.string().regex(SAMPLE_ID),
    tool_version: safeText(100),
    artifact: z
      .object({
        id: safeText(512),
        type: safeText(512),
        path: z.string().min(1).max(4096),
        sha256: z.string().regex(SHA256),
        mime: z.string().min(1).max(256).nullable(),
        created_at: z.string().datetime({ offset: true }),
      })
      .strict(),
    read_mode: z.enum(['profile', 'summary', 'content']),
    artifact_profile: z.record(z.unknown()).optional(),
    summary: z.record(z.unknown()).optional(),
    related_artifacts: z.array(z.record(z.unknown())).max(256).optional(),
    content: z.string().optional(),
    content_encoding: z.enum(['utf8', 'base64']).optional(),
    parsed_json: z.unknown().optional(),
    highlights: z
      .object({
        urls: z.array(z.string()).optional(),
        ip_addresses: z.array(z.string()).optional(),
        commands: z.array(z.string()).optional(),
        registry_keys: z.array(z.string()).optional(),
        pipes: z.array(z.string()).optional(),
      })
      .strict()
      .optional(),
    bytes_read: z.number().int().nonnegative(),
    total_size: z.number().int().nonnegative(),
    truncated: z.boolean(),
  })
  .strict()

const checkpointResultSchema = z
  .object({
    sample_id: z.string().regex(SAMPLE_ID),
    case_id: z.string().regex(IDENTIFIER),
    revision: z.number().int().positive(),
    parent_artifact_id: safeText(512).nullable(),
    artifact_role: z.literal('context_only'),
    state: z.record(z.unknown()),
    artifact: z
      .object({
        id: safeText(512),
        type: z.literal('analysis_case_state'),
        path: z.string().min(1).max(4096),
        sha256: z.string().regex(SHA256),
        mime: z.string().min(1).max(256).optional(),
      })
      .strict(),
    next_steps: z.array(safeText(1000)).max(64),
  })
  .strict()

const artifactPointerSchema = z
  .object({
    id: safeText(512),
    type: safeText(512).optional(),
    path: z.string().min(1).max(4096).optional(),
    sha256: z.string().regex(SHA256).optional(),
  })
  .strict()

const contextEvidenceSchema = z
  .object({ artifact_refs: z.array(artifactPointerSchema).max(256) })
  .passthrough()

const suggestedArtifactReadSchema = z
  .object({
    artifact_id: safeText(512),
    type: safeText(512).nullable(),
    path: z.string().min(1).max(4096).nullable(),
    sha256: z.string().regex(SHA256).nullable(),
    priority: z.number().int().min(1).max(4),
    reasons: z.array(safeText(1000)).max(64),
  })
  .strict()

const contextPackResultSchema = z
  .object({
    sample_id: z.string().regex(SAMPLE_ID),
    goal: z.string().min(1).max(1000),
    case_id: z.string().regex(IDENTIFIER).nullable(),
    primary_evidence: z.array(contextEvidenceSchema).max(1024),
    derived_evidence: z.array(contextEvidenceSchema).max(1024),
    claims: z.array(z.unknown()).max(1024),
    case_state: z.array(z.unknown()).max(1024),
    coverage_gaps: z.array(z.unknown()).max(1024),
    unresolved_questions: z.array(z.unknown()).max(1024),
    recent_changes: z.array(z.unknown()).max(1024),
    suggested_artifact_reads: z.array(suggestedArtifactReadSchema).max(1024),
    marker: safeText(4096),
    truncation_manifest: z
      .object({
        token_budget: z.literal(8192),
        estimated_tokens: z.number().int().nonnegative(),
        truncated: z.boolean(),
        budget_floor_exceeded: z.boolean(),
        sections: z.record(z.unknown()),
      })
      .strict(),
  })
  .strict()

const reclaimedSchema = z
  .object({
    files: z.number().int().nonnegative(),
    bytes: z.number().int().nonnegative(),
    db_rows: z.number().int().nonnegative(),
    kb_rows: z.number().int().nonnegative(),
    cache_entries: z.number().int().nonnegative(),
  })
  .strict()

const deleteResultSchema = z
  .object({
    sample_id: z.string().regex(SAMPLE_ID),
    outcome: z.enum(['deleted', 'already_absent']),
    deletion_id: z.string().regex(UUID).nullable(),
    reclaimed: reclaimedSchema,
    completed_at: z.string().datetime({ offset: true }),
  })
  .strict()
  .superRefine((value, context) => {
    if (
      (value.outcome === 'deleted' && value.deletion_id === null) ||
      (value.outcome === 'already_absent' && value.deletion_id !== null)
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['deletion_id'],
        message: 'deletion_id does not match delete outcome',
      })
    }
  })

function requireEqual(actual: unknown, expected: unknown, label: string): void {
  if (actual !== expected) throw new Error(`${label} differs from the bridge request`)
}

export function validateAndProjectBusinessResult(
  tool: string,
  args: Record<string, unknown>,
  value: unknown
): unknown {
  if (tool === 'workflow_run') {
    const parsed = workflowResultSchema.parse(value)
    requireEqual(parsed.action, args.action, 'workflow action')
    const routed = {
      start: 'workflow.analyze.start',
      status: 'workflow.analyze.status',
      promote: 'workflow.analyze.promote',
    }[parsed.action]
    requireEqual(parsed.routed_tool, routed, 'workflow routed tool')
    const selectors = (parsed.artifact_selectors ?? []).map((selector) => {
      requireEqual(selector.sample_id, selector.read_args.sample_id, 'selector sample ID')
      requireEqual(selector.artifact_id, selector.read_args.artifact_id, 'selector artifact ID')
      requireEqual(
        selector.suggested_read_mode,
        selector.read_args.read_mode,
        'selector read mode'
      )
      if (selector.stage === null && selector.source !== 'run') {
        throw new Error('stage artifact selector omitted its stage')
      }
      return {
        ...selector,
        sha256: selector.sha256 ?? null,
        mime: selector.mime ?? null,
        stage: selector.stage ?? 'run',
      }
    })
    return {
      plan_id: parsed.plan_id,
      stage_statuses: (parsed.stage_statuses ?? []).map((stage) => ({
        stage: stage.stage,
        status: stage.status,
        execution_state: stage.execution_state ?? null,
        recovery_state: stage.recovery_state,
        job_id: stage.job_id ?? null,
      })),
      function_index_ready: parsed.function_index_ready ?? false,
      current_stage: parsed.current_stage ?? null,
      latest_stage: parsed.latest_stage ?? null,
      artifact_selectors: selectors,
      artifact_selector_summary: parsed.artifact_selector_summary ?? null,
    }
  }
  if (tool === 'artifact_read') {
    const parsed = artifactReadResultSchema.parse(value)
    requireEqual(parsed.sample_id, args.sample_id, 'artifact sample ID')
    requireEqual(parsed.read_mode, args.read_mode, 'artifact read mode')
    if (parsed.bytes_read > parsed.total_size) throw new Error('artifact byte counts are invalid')
    return parsed
  }
  if (tool === 'analysis_case_checkpoint') {
    const parsed = checkpointResultSchema.parse(value)
    requireEqual(parsed.sample_id, args.sample_id, 'checkpoint sample ID')
    if (args.case_id !== undefined) requireEqual(parsed.case_id, args.case_id, 'checkpoint case ID')
    return { case_id: parsed.case_id, checkpoint_artifact_id: parsed.artifact.id }
  }
  if (tool === 'analysis_context_pack') {
    const parsed = contextPackResultSchema.parse(value)
    requireEqual(parsed.sample_id, args.sample_id, 'context sample ID')
    requireEqual(parsed.goal, args.goal, 'context goal')
    requireEqual(parsed.case_id, args.case_id, 'context case ID')
    if (parsed.truncation_manifest.estimated_tokens > 8192) {
      throw new Error('context pack exceeds its token budget')
    }
    return parsed
  }
  if (tool === 'sample_delete') {
    const parsed = deleteResultSchema.parse(value)
    requireEqual(parsed.sample_id, args.sample_id, 'deleted sample ID')
    return parsed
  }
  throw new Error('business result projection is missing')
}
