'use strict';
const test = require('node:test');
const assert = require('node:assert');
const H = require('./harness');

const AID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const CID = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const PROMOTE_OP = '10000000-0000-4000-8000-000000000001';
const DELETE_OP = '20000000-0000-4000-8000-000000000002';
const TURN_OP = '30000000-0000-4000-8000-000000000003';

function recorder(routes) {
  const calls = [];
  function fetchImpl(url, opts) {
    opts = opts || {};
    const method = (opts.method || 'GET').toUpperCase();
    calls.push({ url, method, headers: opts.headers || {}, body: opts.body });
    const u = String(url).split('?')[0];
    const r = routes(u, method);
    return Promise.resolve(r || H.jsonResponse(404, { error: { code: 'not_found' } }));
  }
  fetchImpl.calls = calls;
  return fetchImpl;
}
const htmlResp = () => ({ ok: true, status: 200, headers: { get: (h) => (String(h).toLowerCase() === 'content-type' ? 'text/html' : null) }, text: () => Promise.resolve('<html></html>') });
const endsWith = (calls, method, suffix) => calls.find((c) => c.method === method && c.url.split('?')[0].endsWith(suffix));

// These flows fire a post-success SSR refresh (softRefreshDetail ~900ms / refreshComposerOp).
// This file runs in its own process, so we keep the browser shim installed and drain those
// timers once at the end rather than tearing globals down while async work is still in flight.
let lastRestore = null;
test.after(async () => { await new Promise((r) => setTimeout(r, 1300)); if (lastRestore) lastRestore(); });

test('promote and delete each send their own endpoint-specific server id', async () => {
  const promote = H.el('form', { 'data-wb-promote': '', method: 'post', action: '/api/analyses/' + AID + '/promote' }, [
    H.el('input', { name: 'operation_id', value: PROMOTE_OP }),
    H.el('button', { type: 'submit' }),
  ]);
  const del = H.el('form', { 'data-wb-delete': '', method: 'post', action: '/api/analyses/' + AID + '/delete' }, [
    H.el('input', { name: 'operation_id', value: DELETE_OP }),
    H.el('button', { type: 'submit' }),
  ]);
  const root = H.el('div', { class: 'wb-root' }, [promote, del]);
  const toasts = H.el('div', { 'data-wb-toasts': '' });
  const fetchImpl = recorder((u, m) => {
    if (m === 'POST' && u.endsWith('/promote')) return H.jsonResponse(202, { analysis_id: AID, state: 'analyzing' });
    if (m === 'POST' && u.endsWith('/delete')) return H.jsonResponse(202, { analysis_id: AID, state: 'delete_pending' });
    if (m === 'GET') return htmlResp();
    return null;
  });
  const env = H.makeEnv({ page: 'detail', href: 'https://rikune.example/analyses/' + AID, fetch: fetchImpl, bodyChildren: [root, toasts] });
  lastRestore = H.install(env);
  H.loadScript('rikune.js');
  promote.dispatchEvent(H.makeEvent('submit'));
  await H.waitFor(() => endsWith(fetchImpl.calls, 'POST', '/promote'));
  del.dispatchEvent(H.makeEvent('submit'));
  await H.waitFor(() => endsWith(fetchImpl.calls, 'POST', '/delete'));

  const p = endsWith(fetchImpl.calls, 'POST', '/promote');
  const d = endsWith(fetchImpl.calls, 'POST', '/delete');
  assert.strictEqual(p.headers['Idempotency-Key'], PROMOTE_OP, 'promote uses promote_operation_id');
  assert.strictEqual(d.headers['Idempotency-Key'], DELETE_OP, 'delete uses delete_operation_id');
  assert.notStrictEqual(p.headers['Idempotency-Key'], d.headers['Idempotency-Key'], 'no cross-operation id reuse');
});

test('a conversation turn sends the server-issued turn_operation_id and selected model', async () => {
  const hidden = H.el('input', { name: 'operation_id', value: TURN_OP });
  const textarea = H.el('textarea', { 'data-wb-message': '', name: 'message' });
  const seq = H.el('input', { 'data-wb-client-seq': '', name: 'client_seq', value: '1' });
  const model = H.el('select', { 'data-wb-model-select': '', name: 'model', value: 'glm-5.2' });
  model.value = 'glm-5.2';
  const modelStatus = H.el('span', { 'data-wb-model-status': '' });
  const send = H.el('button', { 'data-wb-send': '', type: 'submit' });
  const count = H.el('span', { 'data-wb-charcount': '' });
  const turnForm = H.el('form', { 'data-wb-turn': '', method: 'post', action: '/api/analyses/' + AID + '/conversations/' + CID + '/turns' }, [hidden, textarea, seq, model, modelStatus, count, send]);
  const thread = H.el('div', { 'data-wb-thread': '' });
  const threadEmpty = H.el('div', { 'data-wb-thread-empty': '' });
  const root = H.el('div', { class: 'wb-root' }, [thread, threadEmpty, turnForm]);
  root.dataset = { wbAnalysisId: AID, wbConversationId: CID };
  const toasts = H.el('div', { 'data-wb-toasts': '' });
  const fetchImpl = recorder((u, m) => {
    if (m === 'GET' && u.endsWith('/models')) return H.jsonResponse(200, { default_model: 'glm-5.2', models: ['glm-5.2', 'glm-4.7'] });
    if (m === 'POST' && u.endsWith('/turns')) return H.jsonResponse(202, { turn: { id: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd', state: 'pending' } });
    if (m === 'GET' && u.endsWith('/turns/dddddddd-dddd-4ddd-8ddd-dddddddddddd')) return H.jsonResponse(200, { turn: { state: 'completed' }, assistant: { content: 'done' } });
    if (m === 'GET') return htmlResp();
    return null;
  });
  const env = H.makeEnv({ page: 'conversation', href: 'https://rikune.example/analyses/' + AID + '/conversation?conversation_id=' + CID, fetch: fetchImpl, bodyChildren: [root, toasts] });
  lastRestore = H.install(env);
  H.loadScript('rikune.js');
  await H.waitFor(() => modelStatus.textContent === '2 models available');
  model.value = 'glm-4.7';
  textarea.value = 'What does this binary do?';
  turnForm.dispatchEvent(H.makeEvent('submit'));
  await H.waitFor(() => endsWith(fetchImpl.calls, 'POST', '/turns'));
  const t = endsWith(fetchImpl.calls, 'POST', '/turns');
  assert.strictEqual(t.headers['Idempotency-Key'], TURN_OP, 'turn uses turn_operation_id');
  assert.strictEqual(JSON.parse(t.body).model, 'glm-4.7', 'turn carries the fetched catalog selection');
  assert.notStrictEqual(t.headers['Idempotency-Key'], PROMOTE_OP);
  assert.notStrictEqual(t.headers['Idempotency-Key'], DELETE_OP);
});
