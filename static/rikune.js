/* Rikune Workbench — progressive enhancement.
 * No inline scripts/styles (CSP default-src 'self'). All data arrives via
 * server-escaped <pre data-wb-data> islands whose textContent the HTML parser
 * entity-decodes back to valid JSON. The page is fully usable without this file:
 * navigation, CSS-driven section tabs, and every mutation form work on their own.
 */
(function () {
  'use strict';

  var CSRF_COOKIE = '__Host-csrf';

  function q(sel, root) { return (root || document).querySelector(sel); }
  function qa(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }

  function cookie(name) {
    var parts = ('; ' + document.cookie).split('; ' + name + '=');
    if (parts.length === 2) return parts.pop().split(';').shift();
    return '';
  }
  function csrfToken() {
    var c = cookie(CSRF_COOKIE);
    if (c) return c;
    var f = q('input[name="csrf_token"]');
    return f ? f.value : '';
  }
  // Authority tokens (Idempotency-Key / operation_id) are always server-issued: read
  // from a form's hidden operation_id field. They are never generated in the browser.
  function formOpId(form) {
    if (!form) return '';
    var el = form.querySelector('input[name="operation_id"]');
    return el && el.value ? el.value : '';
  }
  function escapeHtml(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#x27;');
  }
  function jsonFrom(sel) {
    var el = q(sel);
    if (!el) return null;
    var text = el.textContent;
    if (!text || !text.trim()) return null;
    try { return JSON.parse(text); } catch (e) { return null; }
  }
  function fmtBytes(n) {
    n = Number(n) || 0;
    var u = ['B', 'KiB', 'MiB', 'GiB', 'TiB'], i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (i === 0 ? n : (n < 10 ? n.toFixed(2) : n.toFixed(1))) + ' ' + u[i];
  }
  function fmtDate(s) {
    if (!s) return '—';
    var d = new Date(s);
    if (isNaN(d.getTime())) return String(s);
    try {
      return d.toLocaleString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    } catch (e) { return d.toISOString(); }
  }
  function daysUntil(s) {
    var d = new Date(s);
    if (isNaN(d.getTime())) return null;
    return Math.max(0, Math.ceil((d.getTime() - Date.now()) / 86400000));
  }
  function statusTone(state) {
    switch (state) {
      case 'analyzed': return { tone: 'ok', label: 'Analyzed' };
      case 'degraded': return { tone: 'warn', label: 'Partial results' };
      case 'failed': return { tone: 'down', label: 'Failed' };
      case 'analyzing': case 'promoting': return { tone: 'info', label: 'Analyzing' };
      case 'starting': return { tone: 'info', label: 'Starting' };
      case 'start_uncertain': return { tone: 'info', label: 'Recovering' };
      case 'uploaded': return { tone: 'info', label: 'Uploaded' };
      case 'uploading': return { tone: 'neutral', label: 'Uploading' };
      case 'created': return { tone: 'neutral', label: 'Queued' };
      case 'delete_pending': case 'deleting': return { tone: 'neutral', label: 'Deleting' };
      case 'deleted': return { tone: 'neutral', label: 'Deleted' };
      default: return { tone: 'neutral', label: state || 'Unknown' };
    }
  }

  var toastRegion;
  function toast(message, kind) {
    if (!toastRegion) toastRegion = q('[data-wb-toasts]');
    if (!toastRegion) { return; }
    var el = document.createElement('div');
    el.className = 'toast' + (kind === 'error' ? ' toast--err' : '');
    el.setAttribute('role', kind === 'error' ? 'alert' : 'status');
    el.textContent = message;
    toastRegion.appendChild(el);
    requestAnimationFrame(function () { el.classList.add('is-in'); });
    setTimeout(function () {
      el.classList.remove('is-in');
      setTimeout(function () { if (el.parentNode) el.parentNode.removeChild(el); }, 220);
    }, 5200);
  }

  // Safe error text: never surface raw provider/internal detail; use the server's
  // safe message when present, else a code-mapped fallback.
  var ERROR_TEXT = {
    quota_exceeded: 'Not enough storage space. Free up space by deleting old analyses.',
    rate_limited: 'You have reached the usage limit for now. Please wait before trying again.',
    file_too_large: 'The file exceeds 500 MiB.',
    unknown_file_type: 'This file type is not supported.',
    chunk_conflict: 'The upload got out of sync. Please retry the upload.',
    idempotency_mismatch: 'This action was already submitted differently. Reload and try again.',
    state_conflict: 'This action conflicts with the current state. Reload and try again.',
    forbidden: 'The request could not be verified. Reload the page and try again.',
    not_found: 'This item was not found.',
    invalid_upload: 'The upload is invalid.',
    invalid_request: 'The request is invalid.',
    invalid_model: 'That AI model is no longer available. Choose another model and try again.',
    authorization_unavailable: 'Service is temporarily unavailable. Please try again shortly.',
    analyzer_unavailable: 'The analyzer is temporarily unavailable. Please try again shortly.',
    assistant_unavailable: 'The AI is unavailable right now. Please try again shortly.'
  };
  function errorText(code, message) {
    if (message && typeof message === 'string') return message;
    return ERROR_TEXT[code] || 'Something went wrong. Please try again.';
  }

  // fetch a private JSON API; throws {code,message,status,retryable}
  function api(method, url, body, extraHeaders) {
    var headers = { 'Accept': 'application/json', 'X-CSRF-Token': csrfToken() };
    var opts = { method: method, headers: headers, credentials: 'same-origin' };
    if (body !== undefined && body !== null) {
      headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    if (extraHeaders) { for (var k in extraHeaders) headers[k] = extraHeaders[k]; }
    return fetch(url, opts).then(function (res) {
      var ct = res.headers.get('content-type') || '';
      if (res.ok) {
        if (ct.indexOf('application/json') >= 0) return res.json();
        return { location: res.headers.get('Location') };
      }
      return res.json().catch(function () { return {}; }).then(function (payload) {
        var err = (payload && payload.error) || {};
        var e = new Error(errorText(err.code, err.message));
        e.code = err.code; e.status = res.status; e.retryable = !!err.retryable;
        throw e;
      });
    });
  }

  // ---- minimal, safe markdown ----------------------------------------------
  var UNCITED = '未引用的模型解释';
  function inlineMd(text, analysisId) {
    var out = escapeHtml(text);
    out = out.replace(/`([^`]+)`/g, function (m, c) { return '<code>' + c + '</code>'; });
    out = out.replace(/\*\*([^*]+)\*\*/g, function (m, c) { return '<strong>' + c + '</strong>'; });
    out = out.replace(/\[ref:([a-z0-9_-]{1,240})\]/g, function (m, id) {
      var href = '/analyses/' + encodeURIComponent(analysisId || '') + '/evidence?highlight=' + encodeURIComponent(id);
      return '<a class="wb-cite" href="' + href + '" aria-label="View evidence: ' + id + '">' + id + '</a>';
    });
    out = out.replace(/_([^_]+)_/g, function (m, c) {
      if (c === UNCITED) return '<span class="wb-uncited">' + UNCITED + '</span>';
      return '<em>' + c + '</em>';
    });
    return out;
  }
  function renderMarkdown(md, analysisId) {
    var paras = String(md == null ? '' : md).split(/\n{2,}/);
    return paras.map(function (p) {
      var t = p.trim();
      if (!t) return '';
      if (/^#{1,6}\s/.test(t)) return '<p class="wb-md-h">' + inlineMd(t.replace(/^#{1,6}\s/, ''), analysisId) + '</p>';
      if (/^[-*]\s/.test(t)) {
        var items = t.split(/\n/).map(function (l) { return '<li>' + inlineMd(l.replace(/^[-*]\s/, ''), analysisId) + '</li>'; });
        return '<ul class="wb-md-ul">' + items.join('') + '</ul>';
      }
      return '<p>' + inlineMd(t, analysisId).replace(/\n/g, '<br>') + '</p>';
    }).join('');
  }

  window.Rikune = {
    q: q, qa: qa, csrfToken: csrfToken, formOpId: formOpId, escapeHtml: escapeHtml,
    jsonFrom: jsonFrom, fmtBytes: fmtBytes, fmtDate: fmtDate, daysUntil: daysUntil,
    statusTone: statusTone, toast: toast, api: api, errorText: errorText,
    renderMarkdown: renderMarkdown, connectEvents: connectEvents
  };

  // ---- shared UI: tab roving, confirm focus ---------------------------------
  function initTabs() {
    qa('[role="tablist"]').forEach(function (list) {
      var tabs = qa('[role="tab"]', list);
      // Link-tabs on the detail page: mark the tab matching the current section.
      var root = list.closest('.wb-root');
      var section = root ? root.getAttribute('data-section') : null;
      if (section) {
        tabs.forEach(function (t) {
          if (t.getAttribute('data-tab') === section) { t.setAttribute('aria-current', 'page'); t.classList.add('is-active'); }
        });
      }
      tabs.forEach(function (t) {
        var active = t.getAttribute('aria-current') === 'page' || t.classList.contains('is-active');
        t.setAttribute('tabindex', active ? '0' : '-1');
      });
      if (!tabs.some(function (t) { return t.getAttribute('tabindex') === '0'; }) && tabs[0]) {
        tabs[0].setAttribute('tabindex', '0');
      }
      list.addEventListener('keydown', function (e) {
        var i = tabs.indexOf(document.activeElement);
        if (i < 0) return;
        var j = null;
        if (e.key === 'ArrowRight' || e.key === 'ArrowDown') j = (i + 1) % tabs.length;
        else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') j = (i - 1 + tabs.length) % tabs.length;
        else if (e.key === 'Home') j = 0;
        else if (e.key === 'End') j = tabs.length - 1;
        if (j !== null) { e.preventDefault(); tabs[j].focus(); }
      });
    });
  }
  function initConfirmDetails() {
    qa('details.wb-confirm').forEach(function (d) {
      d.addEventListener('toggle', function () {
        if (d.open) {
          var focusable = q('button, a, input', d.querySelector('.wb-confirm__panel'));
          if (focusable) focusable.focus();
          document.addEventListener('keydown', esc);
        } else {
          document.removeEventListener('keydown', esc);
        }
      });
      function esc(e) { if (e.key === 'Escape') { d.open = false; var s = q('summary', d); if (s) s.focus(); } }
    });
  }

  // ---- LIST -----------------------------------------------------------------
  // Storage tile from the server quota projection (quota_json). Uses the native
  // <progress> value — no runtime inline style.
  function renderQuota() {
    var quota = jsonFrom('#wb-data-quota');
    if (!quota) return;
    var used = (Number(quota.used_bytes) || 0) + (Number(quota.reserved_bytes) || 0);
    var limit = Number(quota.byte_limit) || 0;
    var valEl = q('[data-wb-storage-value]');
    var metaEl = q('[data-wb-storage-meta]');
    var prog = q('[data-wb-storage-progress]');
    if (valEl) valEl.textContent = fmtBytes(used);
    if (metaEl && limit) metaEl.textContent = 'of ' + fmtBytes(limit) + ' used';
    if (prog && limit > 0) {
      var pct = Math.min(100, Math.round((used / limit) * 100));
      prog.value = pct;
      prog.hidden = false;
      prog.setAttribute('aria-label', 'Storage used: ' + pct + '%');
    }
  }
  function initList() {
    renderQuota();
    var data = jsonFrom('#wb-data-analyses');
    var mount = q('[data-wb-analyses]');
    var raw = q('[data-wb-rawdata]');
    var empty = q('[data-wb-analyses-empty]');
    var count = q('[data-wb-analysis-count]');
    if (!Array.isArray(data) || !mount) return;
    if (count) count.textContent = String(data.length);
    if (data.length === 0) {
      if (empty) empty.hidden = false;
      if (raw) raw.hidden = true;
      mount.hidden = true;
      return;
    }
    var ul = document.createElement('ul');
    ul.className = 'wb-alist';
    data.forEach(function (a) {
      var st = statusTone(a.state);
      var days = daysUntil(a.retention_until);
      var sample = a.sample_id ? (a.sample_id.slice(0, 18) + '…') : '—';
      var li = document.createElement('li');
      li.className = 'wb-alist__row';
      var link = document.createElement('a');
      link.className = 'wb-alist__main';
      link.href = '/analyses/' + encodeURIComponent(a.id);
      var name = document.createElement('span');
      name.className = 'wb-alist__name mono';
      name.textContent = a.display_name || a.id;
      var meta = document.createElement('span');
      meta.className = 'wb-alist__meta';
      meta.textContent = st.label + ' · ' + sample + ' · ' + (days != null ? days + 'd left' : '—');
      link.appendChild(name); link.appendChild(meta);
      var pill = document.createElement('span');
      pill.className = 'pill pill-' + st.tone;
      if (st.tone !== 'neutral') { var dot = document.createElement('span'); dot.className = 'dot dot-' + st.tone; pill.appendChild(dot); }
      pill.appendChild(document.createTextNode(st.label));
      li.appendChild(link); li.appendChild(pill);
      ul.appendChild(li);
    });
    mount.replaceChildren(ul);
    mount.hidden = false;
    if (raw) raw.hidden = true;
    if (empty) empty.hidden = true;
  }

  // ---- DETAIL ---------------------------------------------------------------
  function renderDetail(analysis, artifacts) {
    if (!analysis) return;
    var st = statusTone(analysis.state);
    var pill = q('[data-wb-status-pill]');
    if (pill) {
      pill.className = 'pill pill-' + st.tone;
      var dot = q('[data-wb-status-dot]', pill);
      if (dot) dot.className = 'dot' + (st.tone !== 'neutral' ? ' dot-' + st.tone : '');
      var lab = q('[data-wb-status-label]', pill);
      if (lab) lab.textContent = st.label;
    }
    var days = daysUntil(analysis.retention_until);
    var ret = q('[data-wb-retention]');
    if (ret) ret.textContent = days != null ? (days + ' days remaining' + (days <= 7 ? ' · expiring soon' : '')) : '';
    setField('state', st.label);
    setField('sample_id', analysis.sample_id || '—');
    setField('created_at', fmtDate(analysis.created_at));
    setField('retention_until', days != null ? (days + ' days remaining') : fmtDate(analysis.retention_until));

    var deg = q('[data-wb-degraded-banner]');
    if (deg) deg.hidden = analysis.state !== 'degraded';
    var rec = q('[data-wb-recovering-banner]');
    if (rec) rec.hidden = analysis.state !== 'start_uncertain';

    renderSummary(analysis, artifacts);
    renderEvidence(analysis, artifacts);
    renderStages(analysis);
  }
  function setField(name, value) {
    var el = q('[data-wb-field="' + name + '"]');
    if (el) el.textContent = value;
  }
  // Fetch one artifact's server-verified content by its own server-issued id. The URL is
  // keyed only by {analysisId, artifactId}: never a client-supplied path and never the
  // upstream analyzer selector, so the browser cannot reach outside the owner scope.
  function fetchArtifactContent(analysisId, artifactId) {
    return api('GET', '/api/analyses/' + encodeURIComponent(analysisId) +
      '/artifacts/' + encodeURIComponent(artifactId) + '/content');
  }
  var ARTIFACT_CONTENT_KEYS = [
    'artifact', 'bytes_read', 'content', 'content_encoding', 'content_state',
    'total_size', 'truncated'
  ];
  var BINARY_ARTIFACT_COPY = 'Verified binary artifact. Inline Markdown preview is unavailable.';
  var LARGE_ARTIFACT_COPY = 'Artifact exceeds the inline preview limit; content was not rendered because a complete hash check was not possible.';
  function exactArtifactContent(payload, artifactId) {
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) throw new Error('artifact content contract');
    var keys = Object.keys(payload).sort();
    if (keys.length !== ARTIFACT_CONTENT_KEYS.length || keys.some(function (key, i) {
      return key !== ARTIFACT_CONTENT_KEYS[i];
    })) throw new Error('artifact content contract');
    if (!payload.artifact || typeof payload.artifact !== 'object' || Array.isArray(payload.artifact) ||
      payload.artifact.id !== artifactId) throw new Error('artifact content contract');
    if (typeof payload.truncated !== 'boolean' ||
      !Number.isSafeInteger(payload.bytes_read) || payload.bytes_read < 0 ||
      !Number.isSafeInteger(payload.total_size) || payload.total_size < 0 ||
      payload.bytes_read > payload.total_size) throw new Error('artifact content contract');

    if (payload.content_state === 'inline_text' && payload.content_encoding === 'utf8' &&
      typeof payload.content === 'string' && payload.truncated === false &&
      payload.bytes_read === payload.total_size) {
      return { kind: 'markdown', content: payload.content };
    }
    if (payload.content_state === 'binary' && payload.content_encoding === 'base64' &&
      payload.content === null && payload.truncated === false &&
      payload.bytes_read === payload.total_size) {
      return { kind: 'plain', content: BINARY_ARTIFACT_COPY };
    }
    if (payload.content_state === 'too_large' &&
      (payload.content_encoding === 'utf8' || payload.content_encoding === 'base64') &&
      payload.content === null && payload.truncated === true &&
      payload.bytes_read < payload.total_size) {
      return { kind: 'plain', content: LARGE_ARTIFACT_COPY + ' Size: ' + fmtBytes(payload.total_size) + '.' };
    }
    throw new Error('artifact content contract');
  }
  function renderVerifiedArtifactContent(node, payload, artifactId, analysisId) {
    var view = exactArtifactContent(payload, artifactId);
    if (view.kind === 'markdown') {
      node.innerHTML = renderMarkdown(view.content, analysisId);
      return;
    }
    // Binary and over-limit states use fixed plain text. No provider-controlled value
    // enters innerHTML; only a bounded, non-negative safe-integer size is formatted.
    node.innerHTML = '';
    node.textContent = view.content;
  }
  function renderSummary(analysis, artifacts) {
    var mount = q('[data-wb-summary]');
    var empty = q('[data-wb-summary-empty]');
    if (!mount) return;
    var summary = (artifacts || []).filter(function (a) { return /summ/i.test(a.artifact_type || ''); });
    if (!summary.length) {
      mount.hidden = true;
      if (empty) empty.hidden = false;
      return;
    }
    var frag = document.createElement('div');
    var pending = summary.map(function (a) {
      var block = document.createElement('div');
      block.className = 'wb-summary-block';
      block.setAttribute('aria-busy', 'true');
      block.innerHTML = renderMarkdown('_Loading summary…_', analysis.id);
      frag.appendChild(block);
      return { artifact: a, block: block };
    });
    mount.replaceChildren(frag);
    mount.hidden = false;
    if (empty) empty.hidden = true;
    // The summary is the server-verified artifact content, fetched automatically by the
    // artifact's own id and rendered through the same safe markdown pipeline.
    pending.forEach(function (item) {
      if (!item.artifact.id) {
        item.block.innerHTML = renderMarkdown('_The summary could not be loaded. Refresh to try again._', analysis.id);
        item.block.removeAttribute('aria-busy');
        return;
      }
      fetchArtifactContent(analysis.id, item.artifact.id)
        .then(function (payload) {
          renderVerifiedArtifactContent(item.block, payload, item.artifact.id, analysis.id);
          item.block.removeAttribute('aria-busy');
        })
        .catch(function () {
          item.block.innerHTML = renderMarkdown('_The summary could not be loaded. Refresh to try again._', analysis.id);
          item.block.removeAttribute('aria-busy');
        });
    });
  }
  function renderEvidence(analysis, artifacts) {
    var mount = q('[data-wb-evidence]');
    var empty = q('[data-wb-evidence-empty]');
    var raw = mount ? mount.parentNode.querySelector('.wb-rawdata') : null;
    if (!mount) return;
    if (!Array.isArray(artifacts) || artifacts.length === 0) {
      mount.hidden = true;
      if (empty) empty.hidden = false;
      return;
    }
    var analysisId = analysis && analysis.id;
    var groups = {};
    artifacts.forEach(function (a) { var t = a.artifact_type || 'other'; (groups[t] = groups[t] || []).push(a); });
    var wrap = document.createElement('div');
    var highlight = new URLSearchParams(location.search).get('highlight');
    Object.keys(groups).sort().forEach(function (t) {
      var h = document.createElement('h3'); h.className = 'eyebrow'; h.textContent = t + ' (' + groups[t].length + ')';
      wrap.appendChild(h);
      var ul = document.createElement('ul'); ul.className = 'wb-evi';
      groups[t].forEach(function (a) {
        var refId = (a.artifact_ref || '').replace(/^ref:/, '');
        var li = document.createElement('li'); li.className = 'wb-evi__item';
        li.id = 'ev-' + refId;
        var ref = document.createElement('div'); ref.className = 'wb-evi__ref'; ref.textContent = a.artifact_ref || '';
        var title = document.createElement('div'); title.className = 'wb-evi__title';
        title.textContent = (a.metadata && (a.metadata.name || a.metadata.title)) || refId || a.upstream_artifact_id;
        var meta = document.createElement('div'); meta.className = 'wb-evi__meta';
        meta.textContent = (a.metadata && (a.metadata.description || a.metadata.summary)) || (a.mime || '');
        li.appendChild(ref); li.appendChild(title); if (meta.textContent) li.appendChild(meta);
        if (analysisId && a.id) li.appendChild(evidenceReveal(analysisId, a.id));
        if (highlight && refId === highlight) { li.classList.add('is-highlight'); }
        ul.appendChild(li);
      });
      wrap.appendChild(ul);
    });
    mount.replaceChildren(wrap);
    mount.hidden = false;
    if (empty) empty.hidden = true;
    if (raw) raw.open = false;
    if (highlight) {
      var target = q('#ev-' + (window.CSS && CSS.escape ? CSS.escape(highlight) : highlight));
      if (target) { target.scrollIntoView({ block: 'center' }); }
    }
  }
  // Lazily-loaded evidence content: a native disclosure that fetches the artifact's
  // server-verified content only when first expanded, and only once. Keyed by the
  // artifact's own id — never a client-supplied path or the upstream selector.
  function evidenceReveal(analysisId, artifactId) {
    var det = document.createElement('details'); det.className = 'wb-evi__reveal';
    var sum = document.createElement('summary'); sum.textContent = 'View content'; det.appendChild(sum);
    var body = document.createElement('div'); body.className = 'wb-evi__body'; det.appendChild(body);
    det.addEventListener('toggle', function () {
      if (!det.open || det.getAttribute('data-wb-loaded')) return;
      det.setAttribute('data-wb-loaded', '1');
      body.setAttribute('aria-busy', 'true');
      fetchArtifactContent(analysisId, artifactId)
        .then(function (payload) {
          renderVerifiedArtifactContent(body, payload, artifactId, analysisId);
          body.removeAttribute('aria-busy');
        })
        .catch(function () {
          det.removeAttribute('data-wb-loaded');   // allow a retry on the next expand
          body.innerHTML = renderMarkdown('_The evidence content could not be loaded. Try again._', analysisId);
          body.removeAttribute('aria-busy');
        });
    });
    return det;
  }
  var STAGE_STEPS = ['fast_profile', 'enrich_static', 'function_map'];
  function renderStages(analysis) {
    var mount = q('[data-wb-stages]');
    if (!mount) return;
    var latestIdx = STAGE_STEPS.indexOf(analysis.latest_stage);
    var currentIdx = STAGE_STEPS.indexOf(analysis.current_stage);
    var ul = document.createElement('ul'); ul.className = 'wb-stagelist';
    STAGE_STEPS.forEach(function (s, i) {
      var cls = 'wb-stage--wait', mark = '○';
      if (analysis.state === 'analyzed' || (latestIdx >= 0 && i <= latestIdx)) { cls = 'wb-stage--done'; mark = '✓'; }
      if (currentIdx === i && analysis.state !== 'analyzed') { cls = 'wb-stage--run'; mark = '⟳'; }
      if (analysis.state === 'failed') { cls = 'wb-stage--fail'; mark = '✕'; }
      var li = document.createElement('li'); li.className = 'wb-stage ' + cls;
      var ico = document.createElement('span'); ico.className = 'wb-stage__ico'; ico.setAttribute('aria-hidden', 'true'); ico.textContent = mark;
      var name = document.createElement('span'); name.className = 'wb-stage__name'; name.textContent = s.replace(/_/g, ' ');
      li.appendChild(ico); li.appendChild(name);
      ul.appendChild(li);
    });
    mount.replaceChildren(ul);
    mount.hidden = false;
  }
  function appendEvent(evt) {
    var line = q('[data-wb-events]');
    if (!line) return;
    var payload = evt.payload || {};
    var li = document.createElement('li'); li.className = 'eventline__item';
    var dot = document.createElement('span'); dot.className = 'eventline__dot'; dot.setAttribute('aria-hidden', 'true');
    var time = document.createElement('div'); time.className = 'eventline__time'; time.textContent = fmtDate(evt.created_at);
    var title = document.createElement('div'); title.className = 'eventline__title'; title.textContent = (evt.type || 'event').replace(/[._]/g, ' ');
    li.appendChild(dot); li.appendChild(time); li.appendChild(title);
    if (payload.message || payload.stage) {
      var body = document.createElement('div'); body.className = 'eventline__body';
      body.textContent = payload.message || String(payload.stage);
      li.appendChild(body);
    }
    line.insertBefore(li, line.firstChild);
    while (line.children.length > 40) line.removeChild(line.lastChild);
  }

  var refreshTimer = null;
  function softRefreshDetail() {
    if (refreshTimer) return;
    refreshTimer = setTimeout(function () {
      refreshTimer = null;
      fetch(location.href, { credentials: 'same-origin', headers: { 'Accept': 'text/html' } })
        .then(function (r) { return r.ok ? r.text() : null; })
        .then(function (html) {
          if (!html) return;
          var doc = new DOMParser().parseFromString(html, 'text/html');
          var a = doc.querySelector('#wb-data-analysis');
          var ev = doc.querySelector('#wb-data-artifacts');
          var analysis = a ? safeParse(a.textContent) : null;
          var artifacts = ev ? safeParse(ev.textContent) : [];
          if (analysis) renderDetail(analysis, artifacts);
          refreshFormOps(doc);
        })
        .catch(function () { });
    }, 900);
  }
  function safeParse(t) { try { return JSON.parse(t); } catch (e) { return null; } }
  // Copy freshly server-issued operation ids from an SSR render into the live forms so
  // a repeated mutation always sends a new, server-issued token — never a client one.
  // Each form keeps its own endpoint-specific id (promote/delete/turn/etc.).
  function refreshFormOps(doc) {
    ['data-wb-promote', 'data-wb-delete', 'data-wb-turn', 'data-wb-new-session', 'data-wb-persona-form'].forEach(function (attr) {
      var live = q('form[' + attr + '] input[name="operation_id"]');
      var fresh = doc.querySelector('form[' + attr + '] input[name="operation_id"]');
      if (live && fresh && fresh.value) live.value = fresh.value;
    });
  }

  function initDetail() {
    var root = q('.wb-root');
    var analysis = jsonFrom('#wb-data-analysis');
    var artifacts = jsonFrom('#wb-data-artifacts') || [];
    var rawA = q('[data-wb-rawdata]');
    if (rawA) rawA.open = false;
    if (analysis) renderDetail(analysis, artifacts);
    wireMutationForms();
    if (root && root.dataset.wbEventsUrl && analysis && !isTerminal(analysis.state)) {
      var conn = connectEvents(root.dataset.wbEventsUrl, {
        onEvent: function (evt) { appendEvent(evt); softRefreshDetail(); },
        onResync: function () { softRefreshDetail(); }
      }, { scope: analysis.id });
      window.addEventListener('beforeunload', function () { conn.close(); });
    }
  }
  function isTerminal(state) { return state === 'analyzed' || state === 'failed' || state === 'deleted' || state === 'degraded'; }

  // Enhance promote/delete/cancel forms: async submit + toast, no full reload flash.
  function wireMutationForms() {
    qa('form[data-wb-promote], form[data-wb-delete]').forEach(function (form) {
      form.addEventListener('submit', function (e) {
        if (!form.getAttribute('action')) return;
        // Idempotency-Key = the server-issued, endpoint-specific operation id in this
        // form's hidden field (promote_operation_id / delete_operation_id). If it is
        // missing we do NOT invent one — let the native form POST carry the field.
        var idem = formOpId(form);
        if (!idem) return;
        e.preventDefault();
        var btn = form.querySelector('button[type="submit"]');
        if (btn) btn.setAttribute('aria-busy', 'true');
        api('POST', form.getAttribute('action'), {}, { 'Idempotency-Key': idem })
          .then(function (res) {
            if (form.hasAttribute('data-wb-delete')) { location.href = '/analyses'; return; }
            // A repeat promote needs a fresh server-issued id: adopt the one the
            // mutation returned, else the next SSR render supplies it.
            if (res && res.next_operation_id) { var f = form.querySelector('input[name="operation_id"]'); if (f) f.value = res.next_operation_id; }
            toast('Promoting to a deeper stage…');
            softRefreshDetail();
            if (btn) btn.removeAttribute('aria-busy');
          })
          .catch(function (err) {
            if (btn) btn.removeAttribute('aria-busy');
            toast(err.message, 'error');
          });
      });
    });
  }

  // ---- CONVERSATION ---------------------------------------------------------
  function initConversation() {
    var root = q('.wb-root');
    var analysisId = root ? root.dataset.wbAnalysisId : '';
    var selectedCid = root ? root.dataset.wbConversationId : '';
    var sessions = jsonFrom('#wb-data-conversations') || [];
    var messages = jsonFrom('#wb-data-messages') || [];
    renderSessions(sessions, selectedCid, analysisId);
    renderThread(messages, analysisId);
    enhancePersona();
    loadModels(analysisId);
    wireComposer(analysisId, selectedCid, messages);
    var selectNote = q('[data-wb-select-note]');
    if (selectNote) selectNote.hidden = !!selectedCid;
    // If a session is selected but empty, the persona/composer forms are usable.
    qa('.wb-rawdata').forEach(function (d) { d.open = false; });
  }
  function renderSessions(sessions, selectedCid, analysisId) {
    var mount = q('[data-wb-sessions]');
    var empty = q('[data-wb-sessions-empty]');
    if (!mount) return;
    if (!sessions.length) { mount.hidden = true; if (empty) empty.hidden = false; return; }
    var ul = document.createElement('ul'); ul.className = 'wb-convlist';
    sessions.forEach(function (c) {
      var li = document.createElement('li');
      var a = document.createElement('a');
      a.href = '/analyses/' + encodeURIComponent(analysisId) + '/conversation?conversation_id=' + encodeURIComponent(c.id);
      if (c.id === selectedCid) { a.className = 'is-active'; a.setAttribute('aria-current', 'true'); }
      a.textContent = c.title || 'Session';
      var meta = document.createElement('span'); meta.className = 'muted';
      meta.textContent = personaLabel(c.persona_id) + ' · ' + fmtDate(c.updated_at);
      a.appendChild(meta);
      li.appendChild(a);
      ul.appendChild(li);
    });
    mount.replaceChildren(ul);
    mount.hidden = false;
    if (empty) empty.hidden = true;
  }
  function personaLabel(id) {
    return ({
      'binary-analyst': 'General analyst', 'malware-analyst': 'Malware triage',
      'reverse-engineer': 'Vulnerability researcher', 'incident-responder': 'Incident responder',
      'custom': 'Custom'
    })[id] || id || '';
  }
  function renderThread(messages, analysisId) {
    var mount = q('[data-wb-thread]');
    var empty = q('[data-wb-thread-empty]');
    if (!mount) return;
    if (!messages.length) { if (empty) empty.hidden = false; return; }
    if (empty) empty.hidden = true;
    var frag = document.createDocumentFragment();
    messages.forEach(function (m) { frag.appendChild(messageEl(m, analysisId)); });
    mount.replaceChildren(frag);
    mount.scrollTop = mount.scrollHeight;
  }
  function messageEl(m, analysisId) {
    var el = document.createElement('div');
    el.className = 'wb-msg wb-msg--' + (m.role === 'user' ? 'user' : 'assistant');
    // Tag an in-flight (SSR-projected) assistant turn so a refresh can find and reuse
    // this exact node instead of appending a duplicate pending bubble.
    if (m.role === 'assistant' && m.status === 'streaming' && m.turn_id) el.setAttribute('data-wb-streaming-turn', m.turn_id);
    if (m.role === 'assistant') el.innerHTML = renderMarkdown(m.content, analysisId);
    else { var p = document.createElement('p'); p.textContent = m.content; el.appendChild(p); }
    if (m.status && m.status !== 'complete' && m.status !== 'committed') {
      var meta = document.createElement('div'); meta.className = 'wb-msg__meta'; meta.textContent = m.status;
      el.appendChild(meta);
    }
    return el;
  }
  function enhancePersona() {
    qa('select[data-wb-persona-select]').forEach(function (sel) {
      var form = sel.closest('form');
      // Only the persona-update form accepts custom_persona. The create-session
      // form has no such field, so a custom selection there would fail validation.
      if (!form || !form.hasAttribute('data-wb-persona-form')) return;
      if (!q('option[value="custom"]', sel)) {
        var opt = document.createElement('option'); opt.value = 'custom'; opt.textContent = 'Custom…'; sel.appendChild(opt);
      }
      var ta = q('textarea[name="custom_persona"]', form);
      if (!ta) {
        ta = document.createElement('textarea');
        ta.name = 'custom_persona'; ta.className = 'textarea'; ta.maxLength = 2000; ta.rows = 3;
        ta.placeholder = 'Describe the persona…'; ta.hidden = true;
        ta.setAttribute('aria-label', 'Custom persona');
        sel.parentNode.insertBefore(ta, sel.nextSibling);
      }
      function sync() { ta.hidden = sel.value !== 'custom'; if (ta.hidden) ta.value = ''; }
      sel.addEventListener('change', sync); sync();
    });
  }
  function loadModels(analysisId) {
    var select = q('[data-wb-model-select]');
    var status = q('[data-wb-model-status]');
    if (!select || !analysisId) return;
    select.setAttribute('aria-busy', 'true');
    if (status) status.textContent = 'Loading available models…';
    api('GET', '/api/analyses/' + encodeURIComponent(analysisId) + '/models')
      .then(function (payload) {
        var models = payload && Array.isArray(payload.models) ? payload.models : [];
        var defaultModel = payload && typeof payload.default_model === 'string' ? payload.default_model : select.value;
        if (!models.length) throw new Error('No AI models are currently available.');
        var previous = select.value;
        var selectedModel = models.indexOf(previous) >= 0 ? previous : '';
        var frag = document.createDocumentFragment();
        if (!selectedModel) {
          var placeholder = document.createElement('option');
          placeholder.value = '';
          placeholder.textContent = 'Choose a model…';
          placeholder.disabled = true;
          placeholder.selected = true;
          frag.appendChild(placeholder);
        }
        models.forEach(function (model) {
          var option = document.createElement('option');
          option.value = model;
          option.textContent = model === defaultModel ? model + ' (default)' : model;
          frag.appendChild(option);
        });
        select.replaceChildren(frag);
        select.value = selectedModel;
        if (status) status.textContent = selectedModel
          ? models.length + (models.length === 1 ? ' model available' : ' models available')
          : 'The previous selection is unavailable. Choose a model for this turn.';
      })
      .catch(function () {
        if (status) status.textContent = 'The model list could not be revalidated. Try again shortly.';
      })
      .then(function () { select.removeAttribute('aria-busy'); });
  }
  function wireComposer(analysisId, selectedCid, messages) {
    var form = q('form[data-wb-turn]');
    if (!form) return;
    var textarea = q('[data-wb-message]', form);
    var count = q('[data-wb-charcount]', form);
    var seqInput = q('[data-wb-client-seq]', form);
    var modelSelect = q('[data-wb-model-select]', form);
    var maxSeq = 0;
    messages.forEach(function (m) { if (m.client_seq && m.client_seq > maxSeq) maxSeq = m.client_seq; });
    if (seqInput && (!seqInput.value || seqInput.value === '{{ next_client_seq }}')) seqInput.value = String(maxSeq + 1);
    if (textarea && count) {
      textarea.addEventListener('input', function () {
        count.textContent = textarea.value.length + ' / 8192';
        count.classList.toggle('is-near', textarea.value.length > 7000);
        count.classList.toggle('is-over', textarea.value.length > 8192);
      });
      textarea.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); form.requestSubmit ? form.requestSubmit() : form.submit(); }
      });
    }
    if (!selectedCid) { return; } // No session selected: leave native POST (will guide via error)
    form.addEventListener('submit', function (e) {
      // Idempotency-Key = the server-issued turn_operation_id in the hidden field; no
      // client-invented token. If it is missing, let the native POST carry the field.
      var idem = formOpId(form);
      if (!idem) return;
      e.preventDefault();
      var msg = textarea ? textarea.value.trim() : '';
      if (!msg) return;
      var selectedModel = modelSelect ? modelSelect.value : '';
      if (!selectedModel) {
        if (modelSelect) modelSelect.focus();
        toast('Choose an available AI model before sending.', 'error');
        return;
      }
      var clientSeq = Number(seqInput ? seqInput.value : maxSeq + 1) || (maxSeq + 1);
      var thread = q('[data-wb-thread]');
      var empty = q('[data-wb-thread-empty]'); if (empty) empty.hidden = true;
      var optimisticUser = messageEl({ role: 'user', content: msg, status: 'committed', client_seq: clientSeq }, analysisId);
      if (thread) thread.appendChild(optimisticUser);
      var pending = messageEl({ role: 'assistant', content: '_Working…_', status: 'generating' }, analysisId);
      if (thread) { thread.appendChild(pending); thread.scrollTop = thread.scrollHeight; }
      var send = q('[data-wb-send]', form); if (send) send.setAttribute('aria-busy', 'true');
      api('POST', form.getAttribute('action'), { client_seq: clientSeq, message: msg, model: selectedModel }, { 'Idempotency-Key': idem })
        .then(function (res) {
          if (textarea) { textarea.value = ''; if (count) count.textContent = '0 / 8192'; }
          maxSeq = clientSeq; if (seqInput) seqInput.value = String(maxSeq + 1);
          // Each turn needs a fresh server-issued operation id: adopt the one the turn
          // response returns, else refresh it from the conversation's SSR render.
          var liveOp = form.querySelector('input[name="operation_id"]');
          if (res && res.next_operation_id && liveOp) liveOp.value = res.next_operation_id;
          else refreshComposerOp(form);
          var loc = res && (res.location || (res.turn && ('/api/analyses/' + analysisId + '/conversations/' + selectedCid + '/turns/' + res.turn.id)));
          pollTurn(loc, pending, analysisId, send);
        })
        .catch(function (err) {
          if (send) send.removeAttribute('aria-busy');
          if (optimisticUser.parentNode) optimisticUser.parentNode.removeChild(optimisticUser);
          if (pending.parentNode) pending.parentNode.removeChild(pending);
          if (empty && thread && !thread.children.length) empty.hidden = false;
          if (err.code === 'invalid_model') {
            if (modelSelect) modelSelect.value = '';
            loadModels(analysisId);
          }
          toast(err.message, 'error');
        });
    });
    // Recovery: resume every SSR-projected streaming assistant and a trailing user turn
    // that still has no assistant reply.
    resumePending(analysisId, selectedCid, messages);
  }
  // Pull a fresh server-issued turn operation id from the conversation's SSR render
  // into the composer, so the next turn never reuses or invents a token.
  function refreshComposerOp(form) {
    fetch(location.href, { credentials: 'same-origin', headers: { 'Accept': 'text/html' } })
      .then(function (r) { return r.ok ? r.text() : null; })
      .then(function (html) {
        if (!html) return;
        var doc = new DOMParser().parseFromString(html, 'text/html');
        var fresh = doc.querySelector('form[data-wb-turn] input[name="operation_id"]');
        var live = form.querySelector('input[name="operation_id"]');
        if (fresh && live && fresh.value) live.value = fresh.value;
      })
      .catch(function () { });
  }
  function pollTurn(url, pendingEl, analysisId, sendBtn) {
    if (!url) { if (sendBtn) sendBtn.removeAttribute('aria-busy'); return; }
    var tries = 0;
    (function poll() {
      tries++;
      fetch(url, { credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (data) {
          if (!data) throw new Error('poll');
          var turn = data.turn || {};
          var assistant = data.assistant;
          if (turn.state === 'completed' || turn.state === 'partial') {
            if (assistant) pendingEl.innerHTML = renderMarkdown(assistant.content, analysisId);
            if (turn.state === 'partial') { var m = document.createElement('div'); m.className = 'wb-msg__meta'; m.textContent = 'partial'; pendingEl.appendChild(m); }
            if (sendBtn) sendBtn.removeAttribute('aria-busy');
            return;
          }
          if (turn.state === 'failed' || turn.state === 'cancelled') {
            pendingEl.innerHTML = renderMarkdown('_The AI assistant is temporarily unavailable. Your message was saved — try again._', analysisId);
            if (sendBtn) sendBtn.removeAttribute('aria-busy');
            return;
          }
          if (tries < 150) setTimeout(poll, 1200);
          else if (sendBtn) sendBtn.removeAttribute('aria-busy');
        })
        .catch(function () { if (tries < 150) setTimeout(poll, 2000); else if (sendBtn) sendBtn.removeAttribute('aria-busy'); });
    })();
  }
  function resumePending(analysisId, selectedCid, messages) {
    if (!messages.length) return;
    var last = messages[messages.length - 1];
    if (!last) return;
    var turnUrl = '/api/analyses/' + encodeURIComponent(analysisId) + '/conversations/' +
      encodeURIComponent(selectedCid) + '/turns/';
    var streamingNodes = qa('[data-wb-streaming-turn]');
    var polledTurns = Object.create(null);
    var assistantTurns = Object.create(null);

    messages.forEach(function (message) {
      if (!message || message.role !== 'assistant' || !message.turn_id) return;
      var turnId = String(message.turn_id);
      assistantTurns[turnId] = true;
      if (message.status !== 'streaming' || polledTurns[turnId]) return;
      // Compare attributes while traversing known marker nodes. Never interpolate a
      // server value into a CSS selector, so a malformed id cannot inject a selector.
      var node = streamingNodes.find(function (candidate) {
        return candidate.getAttribute('data-wb-streaming-turn') === turnId;
      });
      if (!node) return;
      polledTurns[turnId] = true;
      pollTurn(turnUrl + encodeURIComponent(turnId), node, analysisId, null);
    });

    // Legacy fallback: a trailing user turn whose assistant reply never arrived — append
    // one fresh pending bubble and poll it even when older assistants are still streaming.
    if (last.role === 'user' && last.turn_id) {
      var trailingTurnId = String(last.turn_id);
      if (assistantTurns[trailingTurnId] || polledTurns[trailingTurnId]) return;
      var thread = q('[data-wb-thread]');
      var pending = messageEl({ role: 'assistant', content: '_Resuming…_', status: 'generating' }, analysisId);
      if (thread) thread.appendChild(pending);
      polledTurns[trailingTurnId] = true;
      pollTurn(turnUrl + encodeURIComponent(trailingTurnId), pending, analysisId, null);
    }
  }

  // ---- CONTEXT PREVIEW ------------------------------------------------------
  function initContext() {
    var ctx = jsonFrom('#wb-data-context');
    var mount = q('[data-wb-context]');
    var empty = q('[data-wb-context-empty]');
    var raw = q('.wb-rawdata');
    if (!mount) return;
    var items = ctx && (ctx.items || (ctx.context && ctx.context.items));
    if (ctx == null || (Array.isArray(items) && !items.length)) {
      if (empty) empty.hidden = false;
      return;
    }
    if (Array.isArray(items)) {
      var ul = document.createElement('ul'); ul.className = 'wb-evi';
      items.forEach(function (it) {
        var li = document.createElement('li'); li.className = 'wb-evi__item';
        var ref = document.createElement('div'); ref.className = 'wb-evi__ref';
        ref.textContent = it.ref || it.id || it.kind || '';
        var body = document.createElement('div'); body.className = 'wb-evi__meta';
        body.textContent = it.text || it.summary || it.label || JSON.stringify(it);
        li.appendChild(ref); li.appendChild(body);
        ul.appendChild(li);
      });
      mount.replaceChildren(ul);
      mount.hidden = false;
      if (raw) raw.open = false;
    }
  }

  // ---- SSE reader (manual: Last-Event-ID / resync / heartbeat / buffer cap) --
  // opts: { scope, idleMs, maxBuffer }. `scope` namespaces the Last-Event-ID cursor
  // per analysis in sessionStorage so a cursor never leaks across analyses. The reader
  // caps its local line buffer, reconnects on silence, and uses a fresh AbortController
  // for every connection so a wedged or oversized stream self-heals.
  function connectEvents(url, handlers, opts) {
    opts = opts || {};
    var IDLE_MS = opts.idleMs || 45000;         // reconnect after this much silence
    var MAX_BUF = opts.maxBuffer || 1048576;    // 1 MiB local line-buffer cap
    var LID_KEY = opts.scope ? ('rikune.sse.lid.' + opts.scope) : null;
    var stopped = false, backoff = 1000;
    var ctrl = null, watchdog = null;

    function loadLid() {
      if (!LID_KEY) return null;
      try { return sessionStorage.getItem(LID_KEY) || null; } catch (e) { return null; }
    }
    function saveLid(id) {
      if (!LID_KEY) return;
      try { if (id == null) sessionStorage.removeItem(LID_KEY); else sessionStorage.setItem(LID_KEY, String(id)); } catch (e) { }
    }
    var lastId = loadLid();

    function clearWatchdog() { if (watchdog) { clearTimeout(watchdog); watchdog = null; } }
    function armWatchdog() { clearWatchdog(); watchdog = setTimeout(function () { abortCurrent(); }, IDLE_MS); }
    function abortCurrent() { if (ctrl) { try { ctrl.abort(); } catch (e) { } } }

    function dispatch(ev) {
      if (ev.id) { lastId = ev.id; saveLid(lastId); }
      if (ev.event === 'resync') {
        var d = safeParse(ev.data) || {};
        if (d.stream_head != null) { lastId = String(d.stream_head); saveLid(lastId); }
        if (handlers.onResync) handlers.onResync(d);
        return;
      }
      var data = safeParse(ev.data);
      if (data && handlers.onEvent) handlers.onEvent(data);
    }

    // Buffer overrun: drop the scoped cursor, ask the caller to reload from SSR truth,
    // and reconnect fresh so one oversized frame can't wedge the stream.
    function overflowResync() {
      lastId = null; saveLid(null);
      if (handlers.onResync) handlers.onResync({ reason: 'buffer_overflow' });
      abortCurrent();
    }

    function readStream() {
      ctrl = new AbortController();               // a fresh controller per connect
      var headers = { 'Accept': 'text/event-stream' };
      if (lastId) headers['Last-Event-ID'] = String(lastId);
      return fetch(url, { headers: headers, credentials: 'same-origin', signal: ctrl.signal }).then(function (res) {
        if (!res.ok || !res.body) throw new Error('sse ' + res.status);
        var reader = res.body.getReader(), dec = new TextDecoder(), buf = '';
        var ev = { id: null, event: 'message', data: '' };
        armWatchdog();
        function pump() {
          return reader.read().then(function (r) {
            if (r.done) return;
            armWatchdog();                          // any chunk (incl. :heartbeat) = liveness
            buf += dec.decode(r.value, { stream: true });
            if (buf.length > MAX_BUF) { overflowResync(); return; }
            var idx;
            while ((idx = buf.indexOf('\n')) >= 0) {
              var line = buf.slice(0, idx).replace(/\r$/, '');
              buf = buf.slice(idx + 1);
              if (line === '') {
                if (ev.data !== '' || ev.event !== 'message') dispatch(ev);
                ev = { id: null, event: 'message', data: '' };
                continue;
              }
              if (line.charAt(0) === ':') continue;   // comment / heartbeat
              var c = line.indexOf(':'), field = line, val = '';
              if (c >= 0) { field = line.slice(0, c); val = line.slice(c + 1); if (val.charAt(0) === ' ') val = val.slice(1); }
              if (field === 'id') ev.id = val;
              else if (field === 'event') ev.event = val;
              else if (field === 'data') ev.data = ev.data ? ev.data + '\n' + val : val;
            }
            backoff = 1000;
            return pump();
          });
        }
        return pump();
      });
    }
    (function loop() {
      if (stopped) return;
      readStream().then(function () {
        clearWatchdog();
        if (!stopped) setTimeout(loop, backoff);
      }).catch(function (e) {
        clearWatchdog();
        if (stopped) return;
        // AbortError = an intentional watchdog/overflow reconnect: retry on base backoff.
        if (e && e.name === 'AbortError') { setTimeout(loop, backoff); return; }
        setTimeout(loop, backoff);
        backoff = Math.min(backoff * 2, 15000);
      });
    })();
    return { close: function () { stopped = true; clearWatchdog(); abortCurrent(); } };
  }

  // ---- boot -----------------------------------------------------------------
  function boot() {
    initTabs();
    initConfirmDetails();
    var page = document.body.getAttribute('data-wb-page');
    if (page === 'list') initList();
    else if (page === 'detail') initDetail();
    else if (page === 'conversation') initConversation();
    else if (page === 'context-preview') initContext();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
