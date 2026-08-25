'use strict';
/* Minimal browser-shim harness for the Rikune Workbench static JS.
 *
 * The production files (static/rikune.js, static/rikune-upload.js) are plain browser
 * IIFEs with no module exports. We install a small fake DOM + fake network on the
 * real global (so WebCrypto / TextDecoder / typed arrays stay same-realm), then run
 * each file with vm.runInThisContext. Tests drive real submit events and SSE chunks
 * and assert on the fakes. No third-party dependency — Node built-ins only.
 */
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');

const STATIC_DIR = path.resolve(__dirname, '..', '..', 'static');

// ---- tiny selector matcher (tag / #id / .class / [attr] / [attr="v"], comma groups) ----
function matchOne(el, sel) {
  if (!el || el.nodeType === 3) return false;
  let s = String(sel).trim();
  const tag = /^[a-zA-Z][\w-]*/.exec(s);
  if (tag) {
    if (el.tagName !== tag[0].toUpperCase()) return false;
    s = s.slice(tag[0].length);
  }
  const re = /#([\w-]+)|\.([\w-]+)|\[([\w:-]+)(?:=("?)([^"\]]*)\4)?\]/g;
  let m;
  while ((m = re.exec(s))) {
    if (m[1]) { if ((el.attributes.id || '') !== m[1]) return false; }
    else if (m[2]) { if (!el.classList.contains(m[2])) return false; }
    else if (m[3]) {
      const has = Object.prototype.hasOwnProperty.call(el.attributes, m[3]);
      if (m[5] === undefined) { if (!has) return false; }
      else if (String(el.attributes[m[3]]) !== m[5]) return false;
    }
  }
  return true;
}
function qsa(root, selector, first) {
  const groups = String(selector).split(',').map((x) => x.trim()).filter(Boolean);
  const out = [];
  (function walk(node) {
    for (const child of node.children || []) {
      if (groups.some((g) => matchOne(child, g))) { out.push(child); if (first) return true; }
      if (walk(child)) return true;
    }
    return false;
  })(root);
  return out;
}

function makeClassList(el) {
  return {
    add(...c) { c.forEach((x) => el._classes.add(x)); },
    remove(...c) { c.forEach((x) => el._classes.delete(x)); },
    toggle(c, on) { const has = el._classes.has(c); const want = on === undefined ? !has : !!on; if (want) el._classes.add(c); else el._classes.delete(c); return want; },
    contains(c) { return el._classes.has(c); },
    get value() { return [...el._classes].join(' '); },
  };
}

class El {
  constructor(tag) {
    this.tagName = String(tag || 'div').toUpperCase();
    this.nodeType = 1;
    this.attributes = {};
    this.children = [];
    this.parentNode = null;
    this._listeners = {};
    this._classes = new Set();
    this.classList = makeClassList(this);
    this.styleWrites = [];
    this.style = new Proxy({}, { set: (t, k, v) => { t[k] = v; this.styleWrites.push([k, v]); return true; }, get: (t, k) => t[k] });
    this.value = '';
    this.textContent = '';
    this.hidden = false;
    this.open = false;
    this.files = null;
    this.dataset = {};
  }
  setAttribute(k, v) { this.attributes[k] = String(v); }
  getAttribute(k) { return Object.prototype.hasOwnProperty.call(this.attributes, k) ? this.attributes[k] : null; }
  removeAttribute(k) { delete this.attributes[k]; }
  hasAttribute(k) { return Object.prototype.hasOwnProperty.call(this.attributes, k); }
  get id() { return this.attributes.id || ''; }
  set id(v) { this.attributes.id = String(v); }
  get className() { return this.classList.value; }
  set className(v) { this._classes = new Set(); this.classList = makeClassList(this); String(v || '').split(/\s+/).filter(Boolean).forEach((c) => this._classes.add(c)); }
  set innerHTML(v) { this._innerHTML = v; this.children = []; }
  get innerHTML() { return this._innerHTML || ''; }
  appendChild(c) { c.parentNode = this; this.children.push(c); return c; }
  insertBefore(c, ref) { c.parentNode = this; const i = this.children.indexOf(ref); if (i < 0) this.children.push(c); else this.children.splice(i, 0, c); return c; }
  removeChild(c) { const i = this.children.indexOf(c); if (i >= 0) this.children.splice(i, 1); c.parentNode = null; return c; }
  replaceChildren(...n) { this.children = []; n.forEach((x) => this.appendChild(x)); }
  addEventListener(t, fn) { (this._listeners[t] = this._listeners[t] || []).push(fn); }
  removeEventListener(t, fn) { const a = this._listeners[t]; if (a) { const i = a.indexOf(fn); if (i >= 0) a.splice(i, 1); } }
  dispatchEvent(ev) { ev.target = ev.target || this; (this._listeners[ev.type] || []).slice().forEach((fn) => fn(ev)); return !ev.defaultPrevented; }
  get firstChild() { return this.children[0] || null; }
  get lastChild() { return this.children[this.children.length - 1] || null; }
  closest(sel) { let n = this; while (n) { if (matchOne(n, sel)) return n; n = n.parentNode; } return null; }
  querySelector(sel) { return qsa(this, sel, true)[0] || null; }
  querySelectorAll(sel) { return qsa(this, sel, false); }
  focus() {}
  scrollIntoView() {}
  get scrollHeight() { return 0; }
  set scrollTop(_) {}
  requestSubmit() { this.dispatchEvent(makeEvent('submit')); }
  submit() { this._nativeSubmitted = true; }
}

function makeEvent(type) {
  return { type, defaultPrevented: false, preventDefault() { this.defaultPrevented = true; }, key: undefined };
}

// build an element tree from a spec: el(tag, attrs, [children|text])
function el(tag, attrs, kids) {
  const node = new El(tag);
  if (attrs) for (const k of Object.keys(attrs)) {
    if (k === 'class') node.className = attrs[k];
    else if (k === 'value') node.value = attrs[k];
    else if (k === 'text') node.textContent = attrs[k];
    else node.setAttribute(k, attrs[k]);
  }
  if (typeof kids === 'string') node.textContent = kids;
  else if (Array.isArray(kids)) kids.forEach((c) => node.appendChild(c));
  return node;
}

function makeStorage() {
  const map = new Map();
  const writes = [];
  return {
    getItem: (k) => (map.has(k) ? map.get(k) : null),
    setItem: (k, v) => { map.set(k, String(v)); writes.push([k, String(v)]); },
    removeItem: (k) => { map.delete(k); },
    clear: () => map.clear(),
    _map: map,
    _writes: writes,
  };
}

// A response builder for the fake fetch.
function jsonResponse(status, body, location) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (h) => (String(h).toLowerCase() === 'content-type' ? 'application/json' : (String(h).toLowerCase() === 'location' ? (location || null) : null)) },
    json: () => Promise.resolve(body),
    text: () => Promise.resolve(JSON.stringify(body)),
  };
}
function noContentResponse() {
  return { ok: true, status: 204, headers: { get: () => null }, json: () => Promise.resolve({}), text: () => Promise.resolve('') };
}

// Counting AbortController so tests can prove a fresh controller per connect.
let abortCount = 0;
class CountingAbortController extends AbortController {
  constructor() { super(); abortCount += 1; }
}

// Fake DOMParser producing an El tree with querySelector — good enough for op-id refresh.
class FakeDOMParser {
  parseFromString(html) {
    const root = new El('#document');
    const forms = FakeDOMParser._forms || [];
    forms.forEach((f) => root.appendChild(f));
    root._html = html;
    return root;
  }
}

function install(env) {
  const saved = {};
  const keys = ['window', 'document', 'localStorage', 'sessionStorage', 'location', 'fetch', 'AbortController', 'DOMParser', 'requestAnimationFrame'];
  keys.forEach((k) => { saved[k] = Object.getOwnPropertyDescriptor(globalThis, k); });
  globalThis.window = env.window;
  globalThis.document = env.document;
  globalThis.localStorage = env.window.localStorage;
  globalThis.sessionStorage = env.window.sessionStorage;
  globalThis.location = env.window.location;
  globalThis.fetch = env.window.fetch;
  globalThis.AbortController = CountingAbortController;
  globalThis.DOMParser = FakeDOMParser;
  globalThis.requestAnimationFrame = env.window.requestAnimationFrame;
  return function restore() {
    keys.forEach((k) => {
      if (saved[k]) Object.defineProperty(globalThis, k, saved[k]);
      else delete globalThis[k];
    });
  };
}

function makeEnv(opts) {
  opts = opts || {};
  const body = el('body', { 'data-wb-page': opts.page || '' }, opts.bodyChildren || []);
  const location = { href: opts.href || 'https://rikune.example/', _assigned: null, assign(u) { this._assigned = u; } };
  const window = {
    CSS: { escape: (s) => String(s) },
    Promise,
    crypto: globalThis.crypto,
    localStorage: makeStorage(),
    sessionStorage: makeStorage(),
    location,
    fetch: opts.fetch,
    requestAnimationFrame: (fn) => setTimeout(fn, 0),
    addEventListener() {},
    removeEventListener() {},
  };
  window.window = window;
  const document = {
    body,
    cookie: opts.cookie || '',
    readyState: 'complete',
    activeElement: null,
    createElement: (t) => new El(t),
    createTextNode: (t) => { const n = new El('#text'); n.nodeType = 3; n.textContent = t; return n; },
    createDocumentFragment: () => new El('#fragment'),
    querySelector: (s) => qsa(body, s, true)[0] || null,
    querySelectorAll: (s) => qsa(body, s, false),
    addEventListener() {},
    removeEventListener() {},
  };
  window.fetch = opts.fetch;
  return { window, document, location, body };
}

function loadScript(name) {
  const src = fs.readFileSync(path.join(STATIC_DIR, name), 'utf8');
  vm.runInThisContext(src, { filename: `static/${name}` });
}

function resetAbortCount() { abortCount = 0; }
function getAbortCount() { return abortCount; }

function flush(times) {
  times = times || 1;
  let p = Promise.resolve();
  for (let i = 0; i < times; i++) p = p.then(() => new Promise((r) => setImmediate(r)));
  return p;
}
async function waitFor(cond, timeoutMs) {
  const deadline = Date.now() + (timeoutMs || 1500);
  while (!cond()) {
    if (Date.now() > deadline) throw new Error('waitFor: condition not met in time');
    await new Promise((r) => setImmediate(r));
  }
}

module.exports = {
  El, el, makeEvent, makeEnv, install, loadScript, STATIC_DIR,
  jsonResponse, noContentResponse, makeStorage, matchOne, qsa,
  FakeDOMParser, resetAbortCount, getAbortCount, flush, waitFor,
};
