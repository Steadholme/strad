/* Rikune Workbench — durable resumable upload (workbench page).
 * Depends on window.Rikune (rikune.js loads first). Without JavaScript the plain
 * multipart form still submits to POST /api/analyses through the same server-side
 * upload state machine, carrying the server-issued operation_id form field.
 *
 * Authority tokens are never invented in the browser. The create Idempotency-Key is
 * the server-issued hidden operation_id (upload_create_operation_id); finalize and
 * cancel use the server-issued finalize_operation_id / cancel_operation_id returned
 * by create and status — the backend rejects anything but those exact ids. The only
 * thing persisted for cross-reload resume is {rid,name,size}; never any file bytes.
 */
(function () {
  'use strict';
  var R = window.Rikune || {};
  var CHUNK = 8388608;          // 8 MiB — frozen chunk size
  var MAX_BYTES = 524288000;    // 500 MiB
  var STORE_KEY = 'rikune.upload.v1';
  var TERMINAL = { finalized: 1, cancelled: 1, expired: 1 };

  function q(sel, root) { return (root || document).querySelector(sel); }
  function csrf() { return R.csrfToken ? R.csrfToken() : ''; }
  function toast(m, k) { if (R.toast) R.toast(m, k); }

  var form = q('form[data-wb-upload]');
  if (!form) return;

  var fileInput = q('[data-wb-file]', form);
  var sizeInput = q('[data-wb-total-bytes]', form);
  var sizeField = q('[data-wb-size-field]', form);
  var submitBtn = q('[data-wb-submit]', form);
  var submitRow = q('[data-wb-submit-row]', form);
  var dropZone = q('[data-wb-drop]', form);
  var progress = q('[data-wb-progress]', form);
  var progressEl = q('[data-wb-progress-el]', form);   // native <progress>
  var progressPct = q('[data-wb-progress-pct]', form);
  var progressBytes = q('[data-wb-progress-bytes]', form);
  var progressName = q('[data-wb-progress-name]', form);
  var progressState = q('[data-wb-progress-state]', form);
  var progressId = q('[data-wb-progress-id]', form);
  var cancelBtn = q('[data-wb-cancel-upload]', form);
  var errorBox = q('[data-wb-upload-error]');
  var errorText = q('[data-wb-upload-error-text]');

  // { rid, size, name, cancelled, finalizeOp, cancelOp }
  var active = null;

  // JS enhancement: hide the manual byte-size field; fill it from the file.
  if (sizeField) sizeField.hidden = true;
  if (fileInput) {
    fileInput.addEventListener('change', function () {
      var f = fileInput.files && fileInput.files[0];
      if (f && sizeInput) sizeInput.value = String(f.size);
      hideError();
    });
  }

  // The server-issued create operation id is the hidden operation_id form field. We
  // never invent it; a full page reload asks the server for a fresh one.
  function createOperationId() {
    var el = q('input[name="operation_id"]', form);
    return el && el.value ? el.value : '';
  }

  function showError(msg) {
    if (errorBox && errorText) { errorText.textContent = ' ' + msg; errorBox.hidden = false; }
    else toast(msg, 'error');
  }
  function hideError() { if (errorBox) errorBox.hidden = true; }

  function setBusy(on) {
    if (submitBtn) { if (on) submitBtn.setAttribute('aria-busy', 'true'); else submitBtn.removeAttribute('aria-busy'); }
  }
  function setProgress(uploaded, total, label) {
    var pct = total > 0 ? Math.min(100, Math.round((uploaded / total) * 100)) : 0;
    // Native <progress> value is a DOM property, not an inline style, so it stays
    // within CSP style-src 'self' — no runtime `style="width:..."`.
    if (progressEl) progressEl.value = pct;
    if (progressPct) progressPct.textContent = pct + '%';
    if (progressBytes && R.fmtBytes) progressBytes.textContent = R.fmtBytes(uploaded) + ' / ' + R.fmtBytes(total);
    if (label && progressState) progressState.textContent = label;
  }
  function enterUploading(name, rid, total) {
    if (progress) progress.hidden = false;
    if (submitRow) submitRow.hidden = true;
    if (dropZone) dropZone.setAttribute('aria-disabled', 'true');
    if (progressName) progressName.textContent = name;
    if (progressId) progressId.textContent = rid;
    setProgress(0, total, 'Uploading');
  }
  function leaveUploading() {
    if (progress) progress.hidden = true;
    if (submitRow) submitRow.hidden = false;
    if (dropZone) dropZone.removeAttribute('aria-disabled');
    setBusy(false);
    active = null;
  }

  function sha256Hex(buffer) {
    return crypto.subtle.digest('SHA-256', buffer).then(function (digest) {
      var b = new Uint8Array(digest), hex = '';
      for (var i = 0; i < b.length; i++) hex += b[i].toString(16).padStart(2, '0');
      return hex;
    });
  }

  function createAnalysis(file, operationId) {
    return R.api('POST', '/api/analyses',
      { filename: file.name, total_bytes: file.size },
      { 'Idempotency-Key': operationId });
  }
  function fetchStatus(rid) {
    return fetch('/api/uploads/' + encodeURIComponent(rid), { credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
      .then(function (r) { return r.ok ? r.json() : null; })
      .catch(function () { return null; });
  }
  function putChunk(rid, index, file) {
    var start = index * CHUNK;
    var end = Math.min(start + CHUNK, file.size);
    var blob = file.slice(start, end);
    return blob.arrayBuffer().then(function (buf) {
      return sha256Hex(buf).then(function (hex) {
        return fetch('/api/uploads/' + encodeURIComponent(rid) + '/chunks', {
          method: 'POST', credentials: 'same-origin', body: buf,
          headers: {
            'Content-Type': 'application/octet-stream',
            'Content-Range': 'bytes ' + start + '-' + (end - 1) + '/' + file.size,
            'X-Chunk-SHA256': hex,
            'X-CSRF-Token': csrf()
          }
        }).then(function (res) {
          if (res.status === 204) return end;
          return res.json().catch(function () { return {}; }).then(function (p) {
            var err = (p && p.error) || {};
            var e = new Error(R.errorText ? R.errorText(err.code, err.message) : 'Upload failed.');
            e.code = err.code; throw e;
          });
        });
      });
    });
  }
  // finalize/cancel authority tokens are server-issued and endpoint-specific; the
  // backend rejects anything but the exact operation id it issued for this upload.
  function finalize(rid, finalizeOp) {
    return R.api('POST', '/api/uploads/' + encodeURIComponent(rid) + '/finalize', {}, { 'Idempotency-Key': finalizeOp });
  }
  function cancel(rid, cancelOp) {
    return R.api('POST', '/api/uploads/' + encodeURIComponent(rid) + '/cancel', {}, { 'Idempotency-Key': cancelOp }).catch(function () { });
  }
  function opsFrom(source) {
    if (!source) return { finalizeOp: null, cancelOp: null };
    return { finalizeOp: source.finalize_operation_id || null, cancelOp: source.cancel_operation_id || null };
  }

  function run(file, rid, committed) {
    var chunkCount = Math.ceil(file.size / CHUNK);
    var i = 0, uploaded = 0;
    function next() {
      if (active && active.cancelled) return Promise.resolve(null);
      if (i >= chunkCount) return Promise.resolve('done');
      var idx = i++;
      if (committed && committed.has(idx)) {
        uploaded = Math.min(file.size, (idx + 1) * CHUNK);
        setProgress(uploaded, file.size);
        return next();
      }
      return putChunk(rid, idx, file).then(function (endByte) {
        uploaded = endByte;
        setProgress(uploaded, file.size);
        return next();
      });
    }
    return next();
  }

  // Only {rid,name,size} is persisted — never any file content.
  function persist(rid, file) {
    try { localStorage.setItem(STORE_KEY, JSON.stringify({ rid: rid, name: file.name, size: file.size })); } catch (e) { }
  }
  function loadPersist() {
    try {
      var raw = localStorage.getItem(STORE_KEY);
      if (!raw) return null;
      var v = JSON.parse(raw);
      if (!v || typeof v.rid !== 'string' || !v.rid || typeof v.name !== 'string' || typeof v.size !== 'number') return null;
      return { rid: v.rid, name: v.name, size: v.size };
    } catch (e) { return null; }
  }
  function clearPersist() { try { localStorage.removeItem(STORE_KEY); } catch (e) { } }

  function committedFrom(status) {
    var set = new Set();
    if (status && Array.isArray(status.chunks)) status.chunks.forEach(function (c) { set.add(c.chunk_index); });
    return set;
  }

  // Resume the exact prior upload for this file when possible. Resolves to:
  //   {rid,status}  → resume this upload (skip already-committed chunks)
  //   'redirect'    → the prior upload already finalized; navigated to its analysis
  //   null          → no valid prior upload; caller creates a fresh one
  function tryResume(file) {
    var saved = loadPersist();
    if (!saved || saved.name !== file.name || saved.size !== file.size) return Promise.resolve(null);
    return fetchStatus(saved.rid).then(function (status) {
      if (!status) { clearPersist(); return null; }                          // missing / not found
      if (status.state === 'finalized') {
        clearPersist();
        window.location.assign(status.analysis_id ? ('/analyses/' + status.analysis_id) : '/analyses');
        return 'redirect';
      }
      if (TERMINAL[status.state] || status.error_code) { clearPersist(); return null; }   // dead upload
      if (typeof status.total_bytes === 'number' && status.total_bytes !== file.size) { clearPersist(); return null; }
      return { rid: saved.rid, status: status };
    });
  }

  function driveToFinish(file, rid, status, created) {
    var createdOps = opsFrom(created);
    var statusOps = opsFrom(status);
    active = {
      rid: rid, size: file.size, name: file.name, cancelled: false,
      finalizeOp: createdOps.finalizeOp || statusOps.finalizeOp || null,
      cancelOp: createdOps.cancelOp || statusOps.cancelOp || null
    };
    enterUploading(file.name, rid, file.size);
    return run(file, rid, committedFrom(status)).then(function (result) {
      if (result === null) return;   // cancelled
      if (progressState) progressState.textContent = 'Finishing';
      return finalizeUpload(rid, created, status);
    });
  }

  function finalizeUpload(rid, created, status) {
    var known = active && active.finalizeOp;
    var ensured = known
      ? Promise.resolve(known)
      : fetchStatus(rid).then(function (s) { return s && s.finalize_operation_id; });
    return ensured.then(function (op) {
      if (!op) throw new Error('This upload cannot be finished right now. Reload and try again.');
      return finalize(rid, op).then(function (res) {
        clearPersist();
        var loc = (res && res.analysis_id && ('/analyses/' + res.analysis_id))
          || (created && created.analysis_location)
          || (status && status.analysis_id && ('/analyses/' + status.analysis_id))
          || '/analyses';
        window.location.assign(loc);
      });
    });
  }

  function startFresh(file) {
    var operationId = createOperationId();
    if (!operationId) {
      showError('The page is missing its security token. Reload and try again.');
      leaveUploading();
      return Promise.resolve();
    }
    return createAnalysis(file, operationId).then(function (created) {
      var rid = created.upload_id;
      persist(rid, file);
      // Fresh upload: fetch status to learn committed chunks (none yet) and, if the
      // create body omitted them, the server-issued finalize/cancel operation ids.
      return fetchStatus(rid).then(function (status) {
        return driveToFinish(file, rid, status, created);
      });
    }, function (err) {
      if (err && (err.code === 'idempotency_mismatch' || err.code === 'state_conflict')) {
        // The page's create id was already used for a different file. Do not invent a
        // new one — a reload issues a fresh server operation id.
        clearPersist();
        showError('This upload was already started for a different file. Reload the page to upload another file.');
        leaveUploading();
        return;
      }
      throw err;
    });
  }

  function start(file) {
    hideError();
    if (!file) { showError('Choose a file to upload.'); return; }
    if (file.size <= 0) { showError('The file is empty.'); return; }
    if (file.size > MAX_BYTES) { showError('The file exceeds 500 MiB.'); return; }
    if (!(window.crypto && crypto.subtle)) {
      // No SubtleCrypto (insecure context): fall back to the plain multipart submit,
      // which carries the server-issued operation_id form field.
      if (sizeInput) sizeInput.value = String(file.size);
      form.submit();
      return;
    }
    setBusy(true);
    tryResume(file).then(function (resume) {
      if (resume === 'redirect') return;
      if (resume) return driveToFinish(file, resume.rid, resume.status, null);
      return startFresh(file);
    }).catch(function (err) {
      leaveUploading();
      showError(err && err.message ? err.message : 'Upload failed. Please try again.');
    });
  }

  form.addEventListener('submit', function (e) {
    // Progressive enhancement: intercept only when we can run the chunked flow.
    if (!(window.fetch && window.Promise)) return; // let native multipart submit
    e.preventDefault();
    var file = fileInput && fileInput.files && fileInput.files[0];
    start(file);
  });

  if (cancelBtn) {
    cancelBtn.addEventListener('click', function () {
      if (!active) return;
      active.cancelled = true;
      var rid = active.rid;
      var known = active.cancelOp;
      if (progressState) progressState.textContent = 'Cancelling';
      var ensured = known
        ? Promise.resolve(known)
        : fetchStatus(rid).then(function (s) { return s && s.cancel_operation_id; });
      ensured.then(function (op) {
        if (!op) { clearPersist(); leaveUploading(); return; }
        return cancel(rid, op).then(function () {
          clearPersist();
          leaveUploading();
          toast('Upload cancelled.');
        });
      });
    });
  }
})();
