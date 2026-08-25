'use strict';
const test = require('node:test');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const STATIC = path.resolve(__dirname, '..', '..', 'static');

// `node --check` on every shipped script — parses without executing.
for (const f of ['rikune.js', 'rikune-upload.js']) {
  test(`node --check ${f}`, () => {
    execFileSync(process.execPath, ['--check', path.join(STATIC, f)], { stdio: 'pipe' });
  });
}
