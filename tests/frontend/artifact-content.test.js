'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const H = require('./harness');

const AID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

// A recording fetch: unmatched routes fall through to a 404 error envelope.
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
const contentCalls = (f) => f.calls.filter((c) => c.url.indexOf('/content') >= 0);
function inlinePayload(id, content) {
  const size = Buffer.byteLength(content, 'utf8');
  return {
    artifact: { id },
    content,
    content_state: 'inline_text',
    content_encoding: 'utf8',
    truncated: false,
    bytes_read: size,
    total_size: size,
  };
}

test('summary auto-renders server-verified artifact content fetched by the artifact id', async () => {
  const ART = '11111111-1111-4111-8111-111111111111';
  const UPSTREAM = 'upstream-must-not-be-used';
  const analysisPre = H.el('pre', { id: 'wb-data-analysis' });
  analysisPre.textContent = JSON.stringify({ id: AID, state: 'analyzed' });
  const artifactsPre = H.el('pre', { id: 'wb-data-artifacts' });
  artifactsPre.textContent = JSON.stringify([
    { id: ART, upstream_artifact_id: UPSTREAM, artifact_type: 'analysis-summary', artifact_ref: 'ref:summary', metadata: {}, mime: 'text/markdown' },
  ]);
  const mount = H.el('div', { 'data-wb-summary': '' });
  const empty = H.el('div', { 'data-wb-summary-empty': '' });
  const toasts = H.el('div', { 'data-wb-toasts': '' });
  const fetchImpl = recorder((u, m) => {
    if (m === 'GET' && u.endsWith('/artifacts/' + ART + '/content')) {
      return H.jsonResponse(200, inlinePayload(ART, '**Verified** summary body'));
    }
    return null;
  });
  const env = H.makeEnv({ page: 'detail', href: 'https://rikune.example/analyses/' + AID, fetch: fetchImpl, bodyChildren: [analysisPre, artifactsPre, mount, empty, toasts] });
  const restore = H.install(env);
  try {
    H.loadScript('rikune.js');
    await H.waitFor(() => /<strong>Verified<\/strong>/.test((mount.querySelector('.wb-summary-block') || {}).innerHTML || ''));
    const block = mount.querySelector('.wb-summary-block');
    assert.match(block.innerHTML, /<strong>Verified<\/strong> summary body/, 'renders fetched content through safe markdown');
    assert.strictEqual(block.getAttribute('aria-busy'), null, 'busy state cleared after load');
    assert.strictEqual(empty.hidden, true, 'empty state hidden once the summary renders');
    const cc = contentCalls(fetchImpl);
    assert.strictEqual(cc.length, 1, 'exactly one content fetch');
    assert.ok(cc[0].url.endsWith('/api/analyses/' + AID + '/artifacts/' + ART + '/content'), 'URL keyed by analysis id + artifact id');
    assert.ok(!fetchImpl.calls.some((c) => c.url.indexOf(UPSTREAM) >= 0), 'never fetched by the upstream selector');
  } finally { restore(); }
});

test('a verified binary summary uses fixed plain copy and never enters Markdown rendering', async () => {
  const ART = '12121212-1212-4212-8212-121212121212';
  const analysisPre = H.el('pre', { id: 'wb-data-analysis' });
  analysisPre.textContent = JSON.stringify({ id: AID, state: 'analyzed' });
  const artifactsPre = H.el('pre', { id: 'wb-data-artifacts' });
  artifactsPre.textContent = JSON.stringify([
    { id: ART, artifact_type: 'summary', artifact_ref: 'ref:binary-summary', metadata: {}, mime: 'application/octet-stream' },
  ]);
  const mount = H.el('div', { 'data-wb-summary': '' });
  const empty = H.el('div', { 'data-wb-summary-empty': '' });
  const fetchImpl = recorder((u, m) => {
    if (m === 'GET' && u.endsWith('/artifacts/' + ART + '/content')) {
      return H.jsonResponse(200, {
        artifact: { id: ART },
        content: null,
        content_state: 'binary',
        content_encoding: 'base64',
        truncated: false,
        bytes_read: 96,
        total_size: 96,
      });
    }
    return null;
  });
  const env = H.makeEnv({ page: 'detail', href: 'https://rikune.example/analyses/' + AID, fetch: fetchImpl, bodyChildren: [analysisPre, artifactsPre, mount, empty] });
  const restore = H.install(env);
  try {
    H.loadScript('rikune.js');
    const block = mount.querySelector('.wb-summary-block');
    await H.waitFor(() => /Verified binary artifact/.test(block.textContent || ''));
    assert.strictEqual(block.textContent, 'Verified binary artifact. Inline Markdown preview is unavailable.');
    assert.strictEqual(block.innerHTML, '', 'binary copy is assigned as plain text, not Markdown/HTML');
    assert.strictEqual(block.getAttribute('aria-busy'), null);
  } finally { restore(); }
});

test('a failed summary fetch degrades to safe, escaped fallback copy (no raw provider detail)', async () => {
  const ART = '11111111-1111-4111-8111-111111111111';
  const analysisPre = H.el('pre', { id: 'wb-data-analysis' });
  analysisPre.textContent = JSON.stringify({ id: AID, state: 'analyzed' });
  const artifactsPre = H.el('pre', { id: 'wb-data-artifacts' });
  artifactsPre.textContent = JSON.stringify([
    { id: ART, artifact_type: 'summary', artifact_ref: 'ref:summary', metadata: {}, mime: 'text/markdown' },
  ]);
  const mount = H.el('div', { 'data-wb-summary': '' });
  const empty = H.el('div', { 'data-wb-summary-empty': '' });
  const toasts = H.el('div', { 'data-wb-toasts': '' });
  const fetchImpl = recorder((u, m) => {
    if (m === 'GET' && u.endsWith('/content')) return H.jsonResponse(500, { error: { code: 'analyzer_unavailable', message: 'raw upstream trace' } });
    return null;
  });
  const env = H.makeEnv({ page: 'detail', href: 'https://rikune.example/analyses/' + AID, fetch: fetchImpl, bodyChildren: [analysisPre, artifactsPre, mount, empty, toasts] });
  const restore = H.install(env);
  try {
    H.loadScript('rikune.js');
    await H.waitFor(() => /could not be loaded/.test((mount.querySelector('.wb-summary-block') || {}).innerHTML || ''));
    const block = mount.querySelector('.wb-summary-block');
    assert.match(block.innerHTML, /The summary could not be loaded/, 'shows the safe fallback');
    assert.doesNotMatch(block.innerHTML, /raw upstream trace/, 'never surfaces raw provider detail');
    assert.strictEqual(block.getAttribute('aria-busy'), null, 'busy state cleared even on failure');
  } finally { restore(); }
});

test('evidence content loads lazily on expand, fetched by the artifact id', async () => {
  const EV = '22222222-2222-4222-8222-222222222222';
  const UPSTREAM = 'upstream-nope';
  const analysisPre = H.el('pre', { id: 'wb-data-analysis' });
  analysisPre.textContent = JSON.stringify({ id: AID, state: 'analyzed' });
  const artifactsPre = H.el('pre', { id: 'wb-data-artifacts' });
  artifactsPre.textContent = JSON.stringify([
    { id: EV, upstream_artifact_id: UPSTREAM, artifact_type: 'strings', artifact_ref: 'ref:ev1', metadata: { name: 'strings' }, mime: 'text/plain' },
  ]);
  const evMount = H.el('div', { 'data-wb-evidence': '' });
  const evEmpty = H.el('div', { 'data-wb-evidence-empty': '' });
  const cardBody = H.el('div', { class: 'card__body' }, [evMount, evEmpty]); // provides parentNode for the raw-data lookup
  const toasts = H.el('div', { 'data-wb-toasts': '' });
  const fetchImpl = recorder((u, m) => {
    if (m === 'GET' && u.endsWith('/artifacts/' + EV + '/content')) {
      return H.jsonResponse(200, inlinePayload(EV, 'string one\n\nstring two'));
    }
    return null;
  });
  const env = H.makeEnv({ page: 'detail', href: 'https://rikune.example/analyses/' + AID, fetch: fetchImpl, bodyChildren: [analysisPre, artifactsPre, cardBody, toasts] });
  const restore = H.install(env);
  try {
    H.loadScript('rikune.js');
    const det = evMount.querySelector('.wb-evi__reveal');
    assert.ok(det, 'each evidence row exposes a content disclosure');
    assert.strictEqual(contentCalls(fetchImpl).length, 0, 'lazy: nothing fetched before the row is expanded');
    const body = det.querySelector('.wb-evi__body');
    det.open = true;
    det.dispatchEvent(H.makeEvent('toggle'));
    await H.waitFor(() => /string one/.test(body.innerHTML || ''));
    assert.match(body.innerHTML, /string one/, 'renders fetched evidence content through safe markdown');
    const cc = contentCalls(fetchImpl);
    assert.strictEqual(cc.length, 1, 'fetched exactly once on expand');
    assert.ok(cc[0].url.endsWith('/api/analyses/' + AID + '/artifacts/' + EV + '/content'), 'keyed by analysis id + artifact id');
    assert.ok(!fetchImpl.calls.some((c) => c.url.indexOf(UPSTREAM) >= 0), 'never fetched by the upstream selector');
    // Collapsing then re-expanding must not refetch.
    det.open = false; det.dispatchEvent(H.makeEvent('toggle'));
    det.open = true; det.dispatchEvent(H.makeEvent('toggle'));
    await H.flush(3);
    assert.strictEqual(contentCalls(fetchImpl).length, 1, 'no refetch on re-expand');
  } finally { restore(); }
});

test('too-large evidence discloses that a complete hash check was not possible', async () => {
  const EV = '23232323-2323-4232-8232-232323232323';
  const analysisPre = H.el('pre', { id: 'wb-data-analysis' });
  analysisPre.textContent = JSON.stringify({ id: AID, state: 'analyzed' });
  const artifactsPre = H.el('pre', { id: 'wb-data-artifacts' });
  artifactsPre.textContent = JSON.stringify([
    { id: EV, artifact_type: 'strings', artifact_ref: 'ref:large', metadata: {}, mime: 'text/plain' },
  ]);
  const evMount = H.el('div', { 'data-wb-evidence': '' });
  const evEmpty = H.el('div', { 'data-wb-evidence-empty': '' });
  const cardBody = H.el('div', { class: 'card__body' }, [evMount, evEmpty]);
  const fetchImpl = recorder((u, m) => {
    if (m === 'GET' && u.endsWith('/artifacts/' + EV + '/content')) {
      return H.jsonResponse(200, {
        artifact: { id: EV },
        content: null,
        content_state: 'too_large',
        content_encoding: 'utf8',
        truncated: true,
        bytes_read: 2 * 1024 * 1024,
        total_size: 3 * 1024 * 1024,
      });
    }
    return null;
  });
  const env = H.makeEnv({ page: 'detail', href: 'https://rikune.example/analyses/' + AID, fetch: fetchImpl, bodyChildren: [analysisPre, artifactsPre, cardBody] });
  const restore = H.install(env);
  try {
    H.loadScript('rikune.js');
    const det = evMount.querySelector('.wb-evi__reveal');
    const body = det.querySelector('.wb-evi__body');
    det.open = true;
    det.dispatchEvent(H.makeEvent('toggle'));
    await H.waitFor(() => /exceeds the inline preview limit/.test(body.textContent || ''));
    assert.strictEqual(body.textContent, 'Artifact exceeds the inline preview limit; content was not rendered because a complete hash check was not possible. Size: 3.00 MiB.');
    assert.strictEqual(body.innerHTML, '', 'over-limit copy is assigned as plain text');
    assert.strictEqual(body.getAttribute('aria-busy'), null);
  } finally { restore(); }
});

test('unknown or malformed success payloads use the generic failure without provider detail', async (t) => {
  const cases = [
    {
      name: 'unknown state',
      payload(id) {
        return {
          artifact: { id }, content: '**provider secret**', content_state: 'provider_private',
          content_encoding: 'utf8', truncated: false, bytes_read: 19, total_size: 19,
        };
      },
    },
    {
      name: 'malformed binary content',
      payload(id) {
        return {
          artifact: { id }, content: '<script>provider trace</script>', content_state: 'binary',
          content_encoding: 'base64', truncated: false, bytes_read: 8, total_size: 8,
        };
      },
    },
    {
      name: 'missing exact-contract key',
      payload(id) {
        return {
          artifact: { id }, content: 'provider trace', content_state: 'inline_text',
          content_encoding: 'utf8', truncated: false, bytes_read: 14,
        };
      },
    },
  ];
  for (const [index, item] of cases.entries()) {
    await t.test(item.name, async () => {
      const ART = '34343434-3434-4343-8343-' + String(index + 1).padStart(12, '0');
      const analysisPre = H.el('pre', { id: 'wb-data-analysis' });
      analysisPre.textContent = JSON.stringify({ id: AID, state: 'analyzed' });
      const artifactsPre = H.el('pre', { id: 'wb-data-artifacts' });
      artifactsPre.textContent = JSON.stringify([{ id: ART, artifact_type: 'summary', artifact_ref: 'ref:bad', metadata: {} }]);
      const mount = H.el('div', { 'data-wb-summary': '' });
      const empty = H.el('div', { 'data-wb-summary-empty': '' });
      const fetchImpl = recorder((u, m) => (m === 'GET' && u.endsWith('/content')) ? H.jsonResponse(200, item.payload(ART)) : null);
      const env = H.makeEnv({ page: 'detail', href: 'https://rikune.example/analyses/' + AID, fetch: fetchImpl, bodyChildren: [analysisPre, artifactsPre, mount, empty] });
      const restore = H.install(env);
      try {
        H.loadScript('rikune.js');
        const block = mount.querySelector('.wb-summary-block');
        await H.waitFor(() => /summary could not be loaded/.test(block.innerHTML || ''));
        assert.match(block.innerHTML, /The summary could not be loaded/);
        assert.doesNotMatch(block.innerHTML, /provider|script|trace|secret/i, 'provider-controlled detail is not rendered');
        assert.strictEqual(block.getAttribute('aria-busy'), null);
      } finally { restore(); }
    });
  }
});

test('artifact content is addressed only by {analysisId, artifactId} — no client path or upstream selector', () => {
  const core = fs.readFileSync(path.join(__dirname, '..', '..', 'static', 'rikune.js'), 'utf8');
  assert.match(core, /\/artifacts\/'\s*\+\s*encodeURIComponent\(artifactId\)\s*\+\s*'\/content'/, 'the content URL is built from the artifact id');
  assert.match(core, /function fetchArtifactContent\(analysisId, artifactId\)/, 'a single helper owns the content URL construction');
});
