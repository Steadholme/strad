'use strict';
const test = require('node:test');
const assert = require('node:assert');
const H = require('./harness');

function abortErr() { const e = new Error('aborted'); e.name = 'AbortError'; return e; }

// A controllable SSE fetch: each connection exposes push()/finish() and rejects the
// pending read when its AbortSignal fires.
function makeSseFetch() {
  const conns = [];
  function fetchImpl(url, opts) {
    opts = opts || {};
    const enc = new TextEncoder();
    let queue = [];
    let waiter = null;
    let done = false;
    const conn = { url, opts, aborted: false };
    conn.push = (str) => { if (waiter) { const w = waiter; waiter = null; w.resolve({ done: false, value: enc.encode(str) }); } else queue.push(str); };
    conn.finish = () => { done = true; if (waiter) { const w = waiter; waiter = null; w.resolve({ done: true }); } };
    const reader = {
      read() {
        if (queue.length) return Promise.resolve({ done: false, value: enc.encode(queue.shift()) });
        if (done) return Promise.resolve({ done: true });
        return new Promise((resolve, reject) => { waiter = { resolve, reject }; });
      },
      cancel() { return Promise.resolve(); },
    };
    const signal = opts.signal;
    if (signal) {
      if (signal.aborted) return Promise.reject(abortErr());
      signal.addEventListener('abort', () => { conn.aborted = true; if (waiter) { const w = waiter; waiter = null; w.reject(abortErr()); } });
    }
    conns.push(conn);
    return Promise.resolve({ ok: true, status: 200, headers: { get: () => null }, body: { getReader: () => reader } });
  }
  fetchImpl.conns = conns;
  return fetchImpl;
}

function setup(sessionSeed) {
  const fetchImpl = makeSseFetch();
  const env = H.makeEnv({ page: '', fetch: fetchImpl });
  if (sessionSeed) for (const k of Object.keys(sessionSeed)) env.window.sessionStorage.setItem(k, sessionSeed[k]);
  const restore = H.install(env);
  H.loadScript('rikune.js');
  return { env, fetchImpl, restore, R: env.window.Rikune };
}

test('normal event: dispatched to onEvent and its id persists to the scoped cursor', async () => {
  const ctx = setup();
  try {
    const got = [];
    const conn = ctx.R.connectEvents('/events', { onEvent: (e) => got.push(e) }, { scope: 'A' });
    ctx.fetchImpl.conns[0].push('id: 9\ndata: {"type":"stage.finished"}\n\n');
    await H.waitFor(() => got.length >= 1);
    assert.deepStrictEqual(got[0], { type: 'stage.finished' });
    assert.strictEqual(ctx.env.window.sessionStorage.getItem('rikune.sse.lid.A'), '9');
    conn.close();
  } finally { ctx.restore(); }
});

test('resync event updates the scoped cursor to stream_head and calls onResync', async () => {
  const ctx = setup();
  try {
    const resyncs = [];
    const conn = ctx.R.connectEvents('/events', { onResync: (d) => resyncs.push(d) }, { scope: 'A' });
    ctx.fetchImpl.conns[0].push('event: resync\ndata: {"stream_head": 42}\n\n');
    await H.waitFor(() => resyncs.length >= 1);
    assert.strictEqual(resyncs[0].stream_head, 42);
    assert.strictEqual(ctx.env.window.sessionStorage.getItem('rikune.sse.lid.A'), '42');
    conn.close();
  } finally { ctx.restore(); }
});

test('a stored cursor replays as the Last-Event-ID header on connect', async () => {
  const ctx = setup({ 'rikune.sse.lid.A': '15' });
  try {
    const conn = ctx.R.connectEvents('/events', {}, { scope: 'A' });
    await H.waitFor(() => ctx.fetchImpl.conns.length >= 1);
    assert.strictEqual(ctx.fetchImpl.conns[0].opts.headers['Last-Event-ID'], '15');
    conn.close();
  } finally { ctx.restore(); }
});

test('cursors are analysis-scoped — analysis B never inherits analysis A', async () => {
  const ctx = setup();
  try {
    const a = ctx.R.connectEvents('/events', {}, { scope: 'A' });
    ctx.fetchImpl.conns[0].push('id: 7\ndata: {"type":"x"}\n\n');
    await H.waitFor(() => ctx.env.window.sessionStorage.getItem('rikune.sse.lid.A') === '7');
    a.close();
    const b = ctx.R.connectEvents('/events', {}, { scope: 'B' });
    await H.waitFor(() => ctx.fetchImpl.conns.length >= 2);
    const bConn = ctx.fetchImpl.conns[ctx.fetchImpl.conns.length - 1];
    assert.ok(!('Last-Event-ID' in bConn.opts.headers), 'B must not send A\'s cursor');
    assert.strictEqual(ctx.env.window.sessionStorage.getItem('rikune.sse.lid.B'), null);
    b.close();
  } finally { ctx.restore(); }
});

test('buffer cap: an oversized frame aborts the reader, clears the cursor, and asks for a resync', async () => {
  const ctx = setup({ 'rikune.sse.lid.A': '5' });
  try {
    const resyncs = [];
    const conn = ctx.R.connectEvents('/events', { onResync: (d) => resyncs.push(d) }, { scope: 'A', maxBuffer: 100 });
    await H.waitFor(() => ctx.fetchImpl.conns.length >= 1);
    ctx.fetchImpl.conns[0].push('x'.repeat(200)); // no newline → line buffer overflows the cap
    await H.waitFor(() => resyncs.length >= 1);
    assert.strictEqual(resyncs[0].reason, 'buffer_overflow');
    assert.strictEqual(ctx.env.window.sessionStorage.getItem('rikune.sse.lid.A'), null, 'cursor cleared on overflow');
    assert.strictEqual(ctx.fetchImpl.conns[0].aborted, true, 'the wedged reader was aborted');
    conn.close();
  } finally { ctx.restore(); }
});

test('watchdog: silence aborts the connection and reconnects with a fresh AbortController', async () => {
  const ctx = setup();
  try {
    H.resetAbortCount();
    const conn = ctx.R.connectEvents('/events', {}, { scope: 'A', idleMs: 25 });
    await H.waitFor(() => ctx.fetchImpl.conns.length >= 1);
    assert.strictEqual(H.getAbortCount(), 1, 'first connect made exactly one AbortController');
    // No traffic → the ~25ms watchdog aborts the current reader.
    await H.waitFor(() => ctx.fetchImpl.conns[0].aborted === true, 1000);
    // …and the loop reconnects (base backoff ~1s) with a brand-new controller.
    await H.waitFor(() => ctx.fetchImpl.conns.length >= 2, 3000);
    assert.strictEqual(H.getAbortCount(), 2, 'the reconnect used a fresh AbortController');
    conn.close();
  } finally { ctx.restore(); }
});
