'use strict';
const test = require('node:test');
const assert = require('node:assert');
const H = require('./harness');

const CREATE_OP = '11111111-1111-4111-8111-111111111111';
const FIN_OP = '22222222-2222-4222-8222-222222222222';
const CAN_OP = '33333333-3333-4333-8333-333333333333';
const RID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const AID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const STORE_KEY = 'rikune.upload.v1';

function makeFile(name, size) {
  return { name, size, slice: (s, e) => ({ arrayBuffer: () => Promise.resolve(new ArrayBuffer((e == null ? size : e) - (s || 0))) }) };
}

function buildForm() {
  const els = {};
  const hidden = H.el('input', { name: 'operation_id', value: CREATE_OP });
  els.file = H.el('input', { 'data-wb-file': '', id: 'wb-file', type: 'file' });
  els.size = H.el('input', { 'data-wb-total-bytes': '', name: 'total_bytes' });
  els.progress = H.el('div', { 'data-wb-progress': '' }); els.progress.hidden = true;
  els.progressEl = H.el('progress', { 'data-wb-progress-el': '', max: '100', value: '0' });
  els.pct = H.el('span', { 'data-wb-progress-pct': '' });
  els.bytes = H.el('span', { 'data-wb-progress-bytes': '' });
  els.pname = H.el('span', { 'data-wb-progress-name': '' });
  els.pstate = H.el('span', { 'data-wb-progress-state': '' });
  els.pid = H.el('span', { 'data-wb-progress-id': '' });
  els.cancel = H.el('button', { 'data-wb-cancel-upload': '', type: 'button' });
  const form = H.el('form', { 'data-wb-upload': '', action: '/api/analyses', method: 'post' }, [
    hidden, els.file, els.size,
    H.el('div', { 'data-wb-size-field': '' }),
    H.el('button', { 'data-wb-submit': '', type: 'submit' }),
    H.el('div', { 'data-wb-submit-row': '' }),
    H.el('label', { 'data-wb-drop': '' }),
    els.progress, els.progressEl, els.pct, els.bytes, els.pname, els.pstate, els.pid, els.cancel,
  ]);
  const errText = H.el('span', { 'data-wb-upload-error-text': '' });
  const errBox = H.el('div', { 'data-wb-upload-error': '' }, [errText]); errBox.hidden = true;
  const toasts = H.el('div', { 'data-wb-toasts': '' });
  els.form = form; els.errText = errText; els.errBox = errBox;
  return { form, els, bodyChildren: [form, errBox, toasts] };
}

// Build env, install globals, load both scripts. cfg supplies route responses.
function setup(cfg) {
  const built = buildForm();
  const calls = [];
  function fetchImpl(url, opts) {
    opts = opts || {};
    const method = (opts.method || 'GET').toUpperCase();
    calls.push({ url, method, headers: opts.headers || {}, body: opts.body });
    const u = String(url).split('?')[0];
    if (method === 'POST' && u === '/api/analyses') { cfg.createCalls = (cfg.createCalls || 0) + 1; return Promise.resolve(cfg.create ? cfg.create() : H.jsonResponse(201, { upload_id: RID, operation_id: CREATE_OP, finalize_operation_id: FIN_OP, cancel_operation_id: CAN_OP, analysis_location: '/analyses/' + AID })); }
    if (method === 'GET' && u === '/api/uploads/' + RID) { cfg.statusCalls = (cfg.statusCalls || 0) + 1; return Promise.resolve(cfg.status ? cfg.status() : H.jsonResponse(404, { error: { code: 'not_found' } })); }
    if (method === 'POST' && u === '/api/uploads/' + RID + '/chunks') { cfg.chunkCalls = (cfg.chunkCalls || 0) + 1; return cfg.chunk ? cfg.chunk() : Promise.resolve(H.noContentResponse()); }
    if (method === 'POST' && u === '/api/uploads/' + RID + '/finalize') { cfg.finalizeCalls = (cfg.finalizeCalls || 0) + 1; return Promise.resolve(H.jsonResponse(202, { analysis_id: AID, state: 'uploaded' })); }
    if (method === 'POST' && u === '/api/uploads/' + RID + '/cancel') { cfg.cancelCalls = (cfg.cancelCalls || 0) + 1; return Promise.resolve(H.jsonResponse(202, { upload_id: RID, state: 'cancelled' })); }
    return Promise.resolve(H.jsonResponse(404, { error: { code: 'not_found' } }));
  }
  const env = H.makeEnv({ page: 'workbench', href: 'https://rikune.example/', fetch: fetchImpl, bodyChildren: built.bodyChildren });
  if (cfg.persist) env.window.localStorage.setItem(STORE_KEY, JSON.stringify(cfg.persist));
  const restore = H.install(env);
  H.loadScript('rikune.js');
  H.loadScript('rikune-upload.js');
  return { env, calls, els: built.els, form: built.form, restore, cfg };
}

const find = (calls, method, includes) => calls.find((c) => c.method === method && c.url.split('?')[0].indexOf(includes) >= 0 && c.url.split('?')[0].endsWith(includes));
const findEndsWith = (calls, method, suffix) => calls.find((c) => c.method === method && c.url.split('?')[0].endsWith(suffix));

async function submit(ctx, file) {
  ctx.els.file.files = [file];
  ctx.form.dispatchEvent(H.makeEvent('submit'));
  await H.waitFor(() => ctx.env.location._assigned || ctx.els.errBox.hidden === false, 2000);
}

test('fresh upload: create uses the hidden operation_id, finalize/cancel use server ids', async () => {
  const ctx = setup({});
  try {
    await submit(ctx, makeFile('sample.bin', 100));
    const create = findEndsWith(ctx.calls, 'POST', '/api/analyses');
    const finalize = findEndsWith(ctx.calls, 'POST', '/finalize');
    assert.ok(create, 'a create call was made');
    assert.strictEqual(create.headers['Idempotency-Key'], CREATE_OP, 'create uses the hidden server operation_id');
    assert.ok(finalize, 'finalize was called');
    assert.strictEqual(finalize.headers['Idempotency-Key'], FIN_OP, 'finalize uses the server finalize id');
    assert.notStrictEqual(finalize.headers['Idempotency-Key'], CREATE_OP, 'finalize id != create id (no cross-op reuse)');
    assert.strictEqual(ctx.env.location._assigned, '/analyses/' + AID);
  } finally { ctx.restore(); }
});

test('fresh upload: progress uses <progress>.value, never an inline style', async () => {
  const ctx = setup({});
  try {
    await submit(ctx, makeFile('sample.bin', 100));
    assert.strictEqual(ctx.els.progressEl.value, 100, 'progress element value reaches 100');
    assert.strictEqual(ctx.els.progressEl.styleWrites.length, 0, 'no inline style writes on the progress element');
  } finally { ctx.restore(); }
});

test('fresh upload persists only {rid,name,size} — never file content', async () => {
  const ctx = setup({});
  try {
    await submit(ctx, makeFile('sample.bin', 100));
    const writes = ctx.env.window.localStorage._writes.filter((w) => w[0] === STORE_KEY);
    assert.ok(writes.length >= 1, 'the reservation id was persisted');
    const saved = JSON.parse(writes[writes.length - 1][1]);
    assert.deepStrictEqual(Object.keys(saved).sort(), ['name', 'rid', 'size']);
    assert.strictEqual(saved.rid, RID);
    assert.ok(!('content' in saved) && !('data' in saved) && !('bytes' in saved) && !('buffer' in saved));
  } finally { ctx.restore(); }
});

test('resume: matching file reuses the exact upload with no new analysis', async () => {
  const ctx = setup({
    persist: { rid: RID, name: 'sample.bin', size: 100 },
    status: () => H.jsonResponse(200, { state: 'uploading', total_bytes: 100, chunks: [], finalize_operation_id: FIN_OP, cancel_operation_id: CAN_OP, analysis_id: AID }),
  });
  try {
    await submit(ctx, makeFile('sample.bin', 100));
    assert.strictEqual(ctx.cfg.createCalls || 0, 0, 'NO new analysis created on resume');
    const finalize = findEndsWith(ctx.calls, 'POST', '/finalize');
    assert.ok(finalize && finalize.headers['Idempotency-Key'] === FIN_OP, 'resume finalizes with the server id');
    assert.strictEqual(ctx.env.location._assigned, '/analyses/' + AID);
  } finally { ctx.restore(); }
});

test('resume: already-committed chunks are skipped', async () => {
  const ctx = setup({
    persist: { rid: RID, name: 'sample.bin', size: 100 },
    status: () => H.jsonResponse(200, { state: 'uploading', total_bytes: 100, chunks: [{ chunk_index: 0 }], finalize_operation_id: FIN_OP, cancel_operation_id: CAN_OP, analysis_id: AID }),
  });
  try {
    await submit(ctx, makeFile('sample.bin', 100));
    assert.strictEqual(ctx.cfg.createCalls || 0, 0, 'no new analysis');
    assert.strictEqual(ctx.cfg.chunkCalls || 0, 0, 'the committed chunk was skipped');
    assert.ok(findEndsWith(ctx.calls, 'POST', '/finalize'));
  } finally { ctx.restore(); }
});

test('resume: missing upload (404) clears state and creates fresh', async () => {
  const ctx = setup({
    persist: { rid: RID, name: 'sample.bin', size: 100 },
    status: () => H.jsonResponse(404, { error: { code: 'not_found' } }),
  });
  try {
    await submit(ctx, makeFile('sample.bin', 100));
    assert.strictEqual(ctx.cfg.createCalls, 1, 'a fresh analysis was created after the missing upload');
  } finally { ctx.restore(); }
});

test('resume: terminal (cancelled) upload is not resumed', async () => {
  const ctx = setup({
    persist: { rid: RID, name: 'sample.bin', size: 100 },
    status: () => H.jsonResponse(200, { state: 'cancelled', total_bytes: 100, chunks: [], finalize_operation_id: FIN_OP, cancel_operation_id: CAN_OP, analysis_id: AID }),
  });
  try {
    await submit(ctx, makeFile('sample.bin', 100));
    assert.strictEqual(ctx.cfg.createCalls, 1, 'a cancelled upload triggers a fresh create, not a resume');
  } finally { ctx.restore(); }
});

test('resume: finalized upload redirects without re-uploading', async () => {
  const ctx = setup({
    persist: { rid: RID, name: 'sample.bin', size: 100 },
    status: () => H.jsonResponse(200, { state: 'finalized', analysis_id: AID, chunks: [] }),
  });
  try {
    await submit(ctx, makeFile('sample.bin', 100));
    assert.strictEqual(ctx.env.location._assigned, '/analyses/' + AID);
    assert.strictEqual(ctx.cfg.createCalls || 0, 0, 'no create');
    assert.strictEqual(ctx.cfg.finalizeCalls || 0, 0, 'no finalize');
    assert.strictEqual(ctx.cfg.chunkCalls || 0, 0, 'no chunk upload');
  } finally { ctx.restore(); }
});

test('resume: a different file (name/size) never adopts the saved upload', async () => {
  const ctx = setup({
    persist: { rid: RID, name: 'other.bin', size: 999 },
    status: () => H.jsonResponse(200, { state: 'uploading', total_bytes: 999, chunks: [], finalize_operation_id: FIN_OP, cancel_operation_id: CAN_OP, analysis_id: AID }),
  });
  try {
    await submit(ctx, makeFile('sample.bin', 100));
    assert.strictEqual(ctx.calls[0].url.split('?')[0], '/api/analyses', 'no status probe before create — resume was not attempted');
    assert.strictEqual(ctx.cfg.createCalls, 1, 'a fresh analysis is created for the new file');
  } finally { ctx.restore(); }
});

test('cancel sends the server cancel id (distinct from create and finalize)', async () => {
  let released = null;
  const ctx = setup({
    // Hang the chunk upload so the upload stays in-flight and cancel can fire.
    chunk: () => new Promise((r) => { released = r; }),
  });
  try {
    ctx.els.file.files = [makeFile('sample.bin', 100)];
    ctx.form.dispatchEvent(H.makeEvent('submit'));
    // Wait until the upload is in-flight (chunk requested), then cancel.
    await H.waitFor(() => (ctx.cfg.chunkCalls || 0) >= 1, 2000);
    ctx.els.cancel.dispatchEvent(H.makeEvent('click'));
    await H.waitFor(() => (ctx.cfg.cancelCalls || 0) >= 1, 2000);
    const cancel = findEndsWith(ctx.calls, 'POST', '/cancel');
    assert.ok(cancel, 'cancel was called');
    assert.strictEqual(cancel.headers['Idempotency-Key'], CAN_OP, 'cancel uses the server cancel id');
    assert.notStrictEqual(cancel.headers['Idempotency-Key'], CREATE_OP);
    assert.notStrictEqual(cancel.headers['Idempotency-Key'], FIN_OP);
  } finally { if (released) released(H.noContentResponse()); ctx.restore(); }
});
