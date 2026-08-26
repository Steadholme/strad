'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..', '..');
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');
const JS = ['static/rikune.js', 'static/rikune-upload.js'];

test('no authority token is ever generated in the browser', () => {
  for (const f of JS) {
    const src = read(f);
    assert.doesNotMatch(src, /randomUUID/, `${f}: must not use crypto.randomUUID`);
    assert.doesNotMatch(src, /getRandomValues/, `${f}: must not use crypto.getRandomValues`);
    assert.doesNotMatch(src, /Math\.random/, `${f}: must not use Math.random`);
    assert.doesNotMatch(src, /\buuid\s*\(/, `${f}: must not call a uuid() generator`);
  }
});

test('every Idempotency-Key is read from a server-issued source', () => {
  // rikune.js: promote/delete/turn use formOpId(form) (the hidden operation_id).
  const core = read('static/rikune.js');
  const coreKeys = core.match(/'Idempotency-Key':\s*([a-zA-Z0-9_.]+)/g) || [];
  assert.ok(coreKeys.length >= 2, 'expected promote/turn Idempotency-Key usages');
  coreKeys.forEach((line) => assert.match(line, /idem\b/, `rikune.js Idempotency-Key must come from formOpId: ${line}`));
  // upload.js: create uses the hidden operationId; finalize/cancel use the server ids.
  const up = read('static/rikune-upload.js');
  assert.match(up, /'Idempotency-Key':\s*operationId\s*\}/, 'create must use the hidden operationId');
  assert.match(up, /'Idempotency-Key':\s*finalizeOp\s*\}/, 'finalize must use the server finalize id');
  assert.match(up, /'Idempotency-Key':\s*cancelOp\s*\}/, 'cancel must use the server cancel id');
  assert.match(up, /finalize_operation_id/, 'finalize id must be read from the response');
  assert.match(up, /cancel_operation_id/, 'cancel id must be read from the response');
});

test('no runtime inline styles (CSP style-src self)', () => {
  for (const f of JS) {
    const src = read(f);
    assert.doesNotMatch(src, /\.style\.[a-zA-Z]/, `${f}: must not write element.style.*`);
    assert.doesNotMatch(src, /\.style\.setProperty/, `${f}: must not use style.setProperty`);
    assert.doesNotMatch(src, /setAttribute\(\s*['"]style/, `${f}: must not set a style attribute`);
  }
});

test('upload progress is a native <progress> element driven by value', () => {
  const wb = read('templates/workbench.html');
  assert.match(wb, /<progress[^>]*data-wb-progress-el/, 'workbench must render <progress data-wb-progress-el>');
  assert.doesNotMatch(wb, /data-wb-progress-bar\b/, 'the old width-driven bar must be gone');
  const up = read('static/rikune-upload.js');
  assert.match(up, /progressEl\.value\s*=/, 'upload sets progress via progressEl.value');
});

test('templates bind endpoint-specific server-issued operation ids', () => {
  const detail = read('templates/detail.html');
  assert.match(detail, /data-wb-promote>[\s\S]*?name="operation_id" value="\{\{ promote_operation_id \}\}"/);
  assert.match(detail, /data-wb-delete>[\s\S]*?name="operation_id" value="\{\{ delete_operation_id \}\}"/);
  const conv = read('templates/conversation.html');
  assert.match(conv, /data-wb-new-session>[\s\S]*?value="\{\{ create_conversation_operation_id \}\}"/);
  assert.match(conv, /value="\{\{ persona_operation_id \}\}"/);
  assert.match(conv, /value="\{\{ turn_operation_id \}\}"/);
  assert.match(conv, /select[^>]*name="model"[^>]*data-wb-model-select/, 'conversation exposes a model selector');
  assert.match(conv, /value="\{\{ default_model \}\}"/, 'selector preserves the configured default without JavaScript');
  const wb = read('templates/workbench.html');
  assert.match(wb, /name="operation_id" value="\{\{ upload_create_operation_id \}\}"/);
  const list = read('templates/list.html');
  assert.match(list, /data-wb-data="quota"[^>]*>\{\{ quota_json \}\}/, 'list must expose quota_json');
});

test('live mutation forms no longer bind the generic {{ operation_id }}', () => {
  for (const f of ['templates/workbench.html', 'templates/detail.html', 'templates/conversation.html']) {
    assert.doesNotMatch(read(f), /name="operation_id" value="\{\{ operation_id \}\}"/, `${f}: still binds generic operation_id`);
  }
});

test('SSE reader enforces a buffer cap, watchdog, and scoped cursor', () => {
  const core = read('static/rikune.js');
  assert.match(core, /maxBuffer\s*\|\|\s*1048576/, 'a 1 MiB local buffer cap');
  assert.match(core, /idleMs\s*\|\|\s*45000/, 'a ~45s idle watchdog');
  assert.match(core, /new AbortController\(\)/, 'a fresh AbortController per connect');
  assert.match(core, /rikune\.sse\.lid\./, 'analysis-scoped Last-Event-ID cursor in sessionStorage');
});

test('conversation loads the authenticated model catalog and submits the selected model', () => {
  const core = read('static/rikune.js');
  assert.match(core, /\/api\/analyses\/'\s*\+\s*encodeURIComponent\(analysisId\)\s*\+\s*'\/models'/);
  assert.match(core, /model:\s*selectedModel/);
  assert.match(core, /var selectedModel = models\.indexOf\(previous\) >= 0 \? previous : '';/, 'a removed model never silently falls back');
  assert.match(core, /err\.code === 'invalid_model'[\s\S]*?modelSelect\.value = '';/, 'stale selections are cleared before refresh');
  assert.match(core, /The previous selection is unavailable\. Choose a model for this turn\./, 'missing selections require an explicit choice');
  assert.match(core, /removeChild\(optimisticUser\)/, 'rejected turns remove optimistic UI state');
  assert.match(core, /invalid_model:/, 'a stale selection has a stable safe error');
});
