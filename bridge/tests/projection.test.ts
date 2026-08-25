import assert from 'node:assert/strict'
import test from 'node:test'

import { validateAndProjectBusinessResult } from '../src/schemas.js'


const sampleId = `sha256:${'a'.repeat(64)}`

test('workflow result is validated and projected to the exact unified bridge shape', () => {
  const result = validateAndProjectBusinessResult(
    'workflow_run',
    { action: 'status' },
    {
      result_mode: 'workflow_run',
      action: 'status',
      routed_tool: 'workflow.analyze.status',
      plan_id: 'plan_1',
      status: 'running',
      recommended_workflow_tools: [],
      next_actions: [],
      message: 'status',
      artifact_selectors: [
        {
          selector_id: 'selector_1',
          sample_id: sampleId,
          artifact_id: 'artifact_1',
          artifact_type: 'analysis_profile',
          path: 'artifacts/profile.json',
          sha256: 'b'.repeat(64),
          mime: 'application/json',
          stage: null,
          source: 'run',
          suggested_read_mode: 'summary',
          read_args: {
            sample_id: sampleId,
            artifact_id: 'artifact_1',
            read_mode: 'summary',
          },
        },
      ],
    }
  ) as Record<string, unknown>

  assert.deepEqual(Object.keys(result), [
    'plan_id',
    'stage_statuses',
    'function_index_ready',
    'current_stage',
    'latest_stage',
    'artifact_selectors',
    'artifact_selector_summary',
  ])
  assert.equal((result.artifact_selectors as Array<{ stage: string }>)[0]?.stage, 'run')
  assert.equal('status' in result, false)
})

test('workflow projection rejects discriminator and selector binding drift', () => {
  const base = {
    result_mode: 'workflow_run',
    action: 'start',
    routed_tool: 'workflow.analyze.start',
    plan_id: 'plan_1',
    recommended_workflow_tools: [],
    next_actions: [],
    message: 'start',
  }
  assert.throws(() =>
    validateAndProjectBusinessResult('workflow_run', { action: 'status' }, base)
  )
  assert.throws(() =>
    validateAndProjectBusinessResult(
      'workflow_run',
      { action: 'start' },
      {
        ...base,
        artifact_selectors: [
          {
            selector_id: 'selector_1',
            sample_id: sampleId,
            artifact_id: 'artifact_1',
            artifact_type: 'profile',
            path: 'profile.json',
            stage: 'fast_profile',
            source: 'stage',
            suggested_read_mode: 'profile',
            read_args: {
              sample_id: sampleId,
              artifact_id: 'different',
              read_mode: 'profile',
            },
          },
        ],
      }
    )
  )
})

test('checkpoint result projects only stable case identifiers', () => {
  const result = validateAndProjectBusinessResult(
    'analysis_case_checkpoint',
    { sample_id: sampleId },
    {
      sample_id: sampleId,
      case_id: 'case_1',
      revision: 1,
      parent_artifact_id: null,
      artifact_role: 'context_only',
      state: {},
      artifact: {
        id: 'artifact_case_1',
        type: 'analysis_case_state',
        path: 'cases/case_1.json',
        sha256: 'c'.repeat(64),
      },
      next_steps: [],
    }
  )
  assert.deepEqual(result, {
    case_id: 'case_1',
    checkpoint_artifact_id: 'artifact_case_1',
  })
})

test('artifact projection rejects unknown child fields at every frozen boundary', () => {
  const base = {
    sample_id: sampleId,
    tool_version: '1.3.0',
    artifact: {
      id: 'artifact_1',
      type: 'analysis_profile',
      path: 'artifacts/profile.json',
      sha256: 'b'.repeat(64),
      mime: 'application/json',
      created_at: '2026-08-23T00:00:00Z',
    },
    read_mode: 'summary',
    summary: {},
    bytes_read: 32,
    total_size: 32,
    truncated: false,
  }
  assert.doesNotThrow(() =>
    validateAndProjectBusinessResult(
      'artifact_read',
      { sample_id: sampleId, read_mode: 'summary' },
      base
    )
  )
  assert.throws(() =>
    validateAndProjectBusinessResult(
      'artifact_read',
      { sample_id: sampleId, read_mode: 'summary' },
      { ...base, unexpected_child_field: true }
    )
  )
  assert.throws(() =>
    validateAndProjectBusinessResult(
      'artifact_read',
      { sample_id: sampleId, read_mode: 'summary' },
      { ...base, artifact: { ...base.artifact, unexpected_child_field: true } }
    )
  )
})

test('delete result enforces outcome-specific deletion identity', () => {
  const base = {
    sample_id: sampleId,
    reclaimed: { files: 0, bytes: 0, db_rows: 0, kb_rows: 0, cache_entries: 0 },
    completed_at: '2026-08-23T00:00:00Z',
  }
  assert.doesNotThrow(() =>
    validateAndProjectBusinessResult(
      'sample_delete',
      { sample_id: sampleId },
      { ...base, outcome: 'already_absent', deletion_id: null }
    )
  )
  assert.throws(() =>
    validateAndProjectBusinessResult(
      'sample_delete',
      { sample_id: sampleId },
      { ...base, outcome: 'deleted', deletion_id: null }
    )
  )
})
