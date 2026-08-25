'use strict';
const test = require('node:test');
const assert = require('node:assert');
const H = require('./harness');

test('list: storage tile is rendered from quota_json via <progress>.value (no inline style)', () => {
  const quotaPre = H.el('pre', { 'data-wb-data': 'quota', id: 'wb-data-quota' });
  quotaPre.textContent = JSON.stringify({ used_bytes: 2 * 1024 * 1024 * 1024, reserved_bytes: 0, byte_limit: 10 * 1024 * 1024 * 1024, analysis_count: 3, analysis_limit: 25 });
  const analysesPre = H.el('pre', { 'data-wb-data': 'analyses', id: 'wb-data-analyses' });
  analysesPre.textContent = '[]';
  const val = H.el('div', { 'data-wb-storage-value': '' });
  const meta = H.el('div', { 'data-wb-storage-meta': '' });
  const prog = H.el('progress', { 'data-wb-storage-progress': '', max: '100', value: '0' }); prog.hidden = true;
  const mount = H.el('div', { 'data-wb-analyses': '' });
  const emptyEl = H.el('div', { 'data-wb-analyses-empty': '' });
  const countEl = H.el('span', { 'data-wb-analysis-count': '' });
  const body = [
    mount, emptyEl, countEl, analysesPre,
    H.el('div', { 'data-wb-storage-stat': '' }, [val, meta, prog, quotaPre]),
    H.el('div', { 'data-wb-toasts': '' }),
  ];
  const env = H.makeEnv({ page: 'list', href: 'https://rikune.example/analyses', fetch: () => Promise.resolve(H.jsonResponse(404, {})), bodyChildren: body });
  const restore = H.install(env);
  try {
    H.loadScript('rikune.js');
    assert.strictEqual(val.textContent, '2.00 GiB', 'used bytes formatted');
    assert.strictEqual(meta.textContent, 'of 10.0 GiB used');
    assert.strictEqual(prog.value, 20, 'progress reflects 2/10 GiB = 20%');
    assert.strictEqual(prog.hidden, false, 'progress revealed');
    assert.strictEqual(prog.styleWrites.length, 0, 'no inline style writes on the storage progress');
  } finally { restore(); }
});
