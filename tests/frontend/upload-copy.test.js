'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..', '..');
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');

// The only cross-reload resume path (rikune-upload.js tryResume) matches a persisted
// {rid,name,size} against a re-selected file on the workbench page — there is no resume
// affordance on the Analyses page. The recovery copy must reflect that exact behavior.
test('upload recovery copy tells the user to reselect the exact same file on this page', () => {
  const wb = read('templates/workbench.html');
  assert.match(wb, /reselect the exact same file on this page to resume/, 'copy matches the tryResume behavior');
  assert.doesNotMatch(wb, /resume from the Analyses page/, 'the inaccurate Analyses-page copy is gone');
});
