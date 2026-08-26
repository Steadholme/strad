'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const H = require('./harness');

const AID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const CID = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
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

// A conversation page seeded with a message list. Returns the live nodes and fetch.
function conversation(messages, assistantByTurn) {
  const messagesPre = H.el('pre', { id: 'wb-data-messages' });
  messagesPre.textContent = JSON.stringify(messages);
  const thread = H.el('div', { 'data-wb-thread': '' });
  const threadEmpty = H.el('div', { 'data-wb-thread-empty': '' });
  const hidden = H.el('input', { name: 'operation_id', value: TURN_OP });
  const textarea = H.el('textarea', { 'data-wb-message': '', name: 'message' });
  const seq = H.el('input', { 'data-wb-client-seq': '', name: 'client_seq', value: '2' });
  const model = H.el('select', { 'data-wb-model-select': '', name: 'model' }); model.value = 'glm-5.2';
  const send = H.el('button', { 'data-wb-send': '', type: 'submit' });
  const count = H.el('span', { 'data-wb-charcount': '' });
  const turnForm = H.el('form', { 'data-wb-turn': '', action: '/api/analyses/' + AID + '/conversations/' + CID + '/turns' }, [hidden, textarea, seq, model, send, count]);
  const root = H.el('div', { class: 'wb-root' }, [thread, threadEmpty, turnForm, messagesPre]);
  root.dataset = { wbAnalysisId: AID, wbConversationId: CID };
  const toasts = H.el('div', { 'data-wb-toasts': '' });
  const fetchImpl = recorder((u, m) => {
    if (m === 'GET' && u.endsWith('/models')) return H.jsonResponse(200, { default_model: 'glm-5.2', models: ['glm-5.2'] });
    if (m === 'GET' && u.indexOf('/turns/') >= 0) {
      const turnId = decodeURIComponent(u.slice(u.lastIndexOf('/turns/') + '/turns/'.length));
      if (Object.prototype.hasOwnProperty.call(assistantByTurn, turnId)) {
        return H.jsonResponse(200, { turn: { state: 'completed' }, assistant: { content: assistantByTurn[turnId] } });
      }
    }
    return null;
  });
  const env = H.makeEnv({ page: 'conversation', href: 'https://rikune.example/analyses/' + AID + '/conversation?conversation_id=' + CID, fetch: fetchImpl, bodyChildren: [root, toasts] });
  return { env, fetchImpl, thread };
}

test('a streaming SSR assistant message resumes polling its own turn and reuses its node', async () => {
  const T = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
  const ctx = conversation([
    { role: 'user', content: 'what is this', status: 'committed', turn_id: T, client_seq: 1 },
    { role: 'assistant', content: 'partial so far', status: 'streaming', turn_id: T },
  ], { [T]: 'final answer' });
  const restore = H.install(ctx.env);
  try {
    H.loadScript('rikune.js');
    const node = ctx.env.document.querySelector('[data-wb-streaming-turn="' + T + '"]');
    assert.ok(node, 'the in-flight assistant message is tagged for reuse');
    await H.waitFor(() => /final answer/.test(node.innerHTML || ''));
    assert.match(node.innerHTML, /final answer/, 'the existing node is updated in place with completed content');
    assert.strictEqual(ctx.thread.querySelectorAll('.wb-msg').length, 2, 'no duplicate assistant bubble is appended');
    const poll = ctx.fetchImpl.calls.find((c) => c.method === 'GET' && c.url.endsWith('/turns/' + T));
    assert.ok(poll, 'resumed polling the streaming turn by its own turn_id');
  } finally { restore(); }
});

test('legacy fallback: a trailing user turn still resumes with a fresh pending bubble', async () => {
  const T = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
  const ctx = conversation([
    { role: 'user', content: 'lonely question', status: 'committed', turn_id: T, client_seq: 1 },
  ], { [T]: 'the delayed answer' });
  const restore = H.install(ctx.env);
  try {
    H.loadScript('rikune.js');
    assert.strictEqual(ctx.env.document.querySelector('[data-wb-streaming-turn]'), null, 'no streaming node exists for a user-only tail');
    await H.waitFor(() => ctx.thread.querySelectorAll('.wb-msg').length === 2);
    const bubbles = ctx.thread.querySelectorAll('.wb-msg');
    await H.waitFor(() => /the delayed answer/.test(bubbles[bubbles.length - 1].innerHTML || ''));
    assert.match(bubbles[bubbles.length - 1].innerHTML, /the delayed answer/, 'the appended bubble is filled by the resumed poll');
    const poll = ctx.fetchImpl.calls.find((c) => c.method === 'GET' && c.url.endsWith('/turns/' + T));
    assert.ok(poll, 'polled the trailing user turn');
  } finally { restore(); }
});

test('two streaming assistants and a trailing user all resume without duplicate bubbles', async () => {
  const T1 = '11111111-1111-4111-8111-111111111111';
  const T2 = '22222222-2222-4222-8222-222222222222';
  const T3 = '33333333-3333-4333-8333-333333333333';
  const messages = [
    { role: 'user', content: 'first question', status: 'committed', turn_id: T1, client_seq: 1 },
    { role: 'assistant', content: 'first partial', status: 'streaming', turn_id: T1 },
    { role: 'user', content: 'second question', status: 'committed', turn_id: T2, client_seq: 2 },
    { role: 'assistant', content: 'second partial', status: 'streaming', turn_id: T2 },
    { role: 'user', content: 'third question', status: 'committed', turn_id: T3, client_seq: 3 },
  ];
  const ctx = conversation(messages, { [T1]: 'first final', [T2]: 'second final', [T3]: 'third final' });
  const restore = H.install(ctx.env);
  try {
    H.loadScript('rikune.js');
    const streaming = ctx.env.document.querySelectorAll('[data-wb-streaming-turn]');
    assert.strictEqual(streaming.length, 2, 'both SSR streaming bubbles are retained for in-place recovery');
    await H.waitFor(() => /first final/.test(streaming[0].innerHTML || ''));
    await H.waitFor(() => /second final/.test(streaming[1].innerHTML || ''));
    await H.waitFor(() => ctx.thread.querySelectorAll('.wb-msg').length === messages.length + 1);
    const bubbles = ctx.thread.querySelectorAll('.wb-msg');
    await H.waitFor(() => /third final/.test(bubbles[bubbles.length - 1].innerHTML || ''));

    assert.strictEqual(bubbles.length, 6, 'only the trailing user receives one new assistant bubble');
    const polls = ctx.fetchImpl.calls.filter((c) => c.method === 'GET' && c.url.indexOf('/turns/') >= 0);
    const counts = {};
    polls.forEach((call) => {
      const id = decodeURIComponent(call.url.slice(call.url.lastIndexOf('/turns/') + '/turns/'.length));
      counts[id] = (counts[id] || 0) + 1;
    });
    assert.deepStrictEqual(counts, { [T1]: 1, [T2]: 1, [T3]: 1 }, 'every unique pending turn is polled exactly once');
  } finally { restore(); }
});

test('duplicate streaming turn ids are deduplicated and lookup never interpolates a CSS selector', async () => {
  const T = '44444444-4444-4444-8444-444444444444';
  const ctx = conversation([
    { role: 'user', content: 'question', status: 'committed', turn_id: T, client_seq: 1 },
    { role: 'assistant', content: 'partial one', status: 'streaming', turn_id: T },
    { role: 'assistant', content: 'duplicate projection', status: 'streaming', turn_id: T },
  ], { [T]: 'final once' });
  const restore = H.install(ctx.env);
  try {
    H.loadScript('rikune.js');
    await H.waitFor(() => ctx.fetchImpl.calls.some((c) => c.method === 'GET' && c.url.endsWith('/turns/' + T)));
    await H.flush(3);
    const polls = ctx.fetchImpl.calls.filter((c) => c.method === 'GET' && c.url.endsWith('/turns/' + T));
    assert.strictEqual(polls.length, 1, 'one poll per unique turn_id');

    const core = fs.readFileSync(path.join(__dirname, '..', '..', 'static', 'rikune.js'), 'utf8');
    assert.match(core, /qa\('\[data-wb-streaming-turn\]'\)/, 'resume traverses marker nodes');
    assert.doesNotMatch(core, /q\('\[data-wb-streaming-turn="'\s*\+/, 'turn_id is never interpolated into a selector');
  } finally { restore(); }
});
