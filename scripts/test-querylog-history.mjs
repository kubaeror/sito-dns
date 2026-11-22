#!/usr/bin/env node
// Executable DOM/JS regression test for the query-log history controls.
//
// The repository has no browser test harness, so this script runs the real
// static/app.js in a Node `vm` context with a tiny fake DOM. It simulates the
// HTMX events in the same shape htmx 2.0.4 dispatches (notably: beforeSwap is
// dispatched on the swap target, so `detail.elt` is #query-table-body for every
// rows response). That shape is what catches the Load-older-cancels-itself bug.
//
// Run from the repository root: node scripts/test-querylog-history.mjs

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const appPath =
  process.env.SITO_APP_JS ||
  path.join(repoRoot, 'crates/sito-api/static/app.js');
const appSource = fs.readFileSync(appPath, 'utf8');

let activeDocument = null;

class FakeElement {
  constructor(tagName, id = '', attributes = {}) {
    this.tagName = tagName.toUpperCase();
    this.id = id;
    this.attributes = new Map();
    this.dataset = {};
    this.children = [];
    this.parent = null;
    this.disabled = false;
    for (const [name, value] of Object.entries(attributes)) {
      this.setAttribute(name, value);
    }
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
    if (name.startsWith('data-')) {
      const property = name
        .slice(5)
        .replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
      this.dataset[property] = String(value);
    }
  }

  hasAttribute(name) {
    return this.attributes.has(name);
  }

  getAttribute(name) {
    return this.attributes.has(name) ? this.attributes.get(name) : null;
  }

  appendChild(child) {
    if (child.parent) child.parent.removeChild(child);
    child.parent = this;
    this.children.push(child);
    return child;
  }

  removeChild(child) {
    const index = this.children.indexOf(child);
    if (index >= 0) this.children.splice(index, 1);
    child.parent = null;
  }

  remove() {
    if (this.parent) this.parent.removeChild(this);
  }

  contains(node) {
    if (node === this) return true;
    return this.children.some((child) => child.contains(node));
  }

  focus() {
    if (activeDocument) activeDocument.activeElement = this;
  }

  descendants() {
    const result = [];
    for (const child of this.children) {
      result.push(child, ...child.descendants());
    }
    return result;
  }

  matches(selector) {
    const match = /^([a-zA-Z0-9]*)\[([^=\]]+)\]$/.exec(selector);
    if (!match) return false;
    const [, tagName, attribute] = match;
    if (tagName && this.tagName !== tagName.toUpperCase()) return false;
    return this.hasAttribute(attribute);
  }

  querySelectorAll(selector) {
    return this.descendants().filter((element) => element.matches(selector));
  }

  querySelector(selector) {
    return this.querySelectorAll(selector)[0] || null;
  }
}

class FakeDocument {
  constructor() {
    this.listeners = new Map();
    this.root = new FakeElement('html', '__document_root__');
    this.activeElement = null;
  }

  addEventListener(type, listener) {
    const listeners = this.listeners.get(type) || [];
    listeners.push(listener);
    this.listeners.set(type, listeners);
  }

  fire(type, detail = {}) {
    const event = {
      type,
      detail,
      defaultPrevented: false,
      preventDefault() {
        this.defaultPrevented = true;
      },
    };
    for (const listener of this.listeners.get(type) || []) {
      listener(event);
    }
    return event;
  }

  getElementById(id) {
    return this.root.descendants().find((element) => element.id === id) || null;
  }

  querySelector(selector) {
    return this.root.querySelector(selector);
  }

  querySelectorAll(selector) {
    return this.root.querySelectorAll(selector);
  }
}

function installControls(document, historyMode) {
  const old = document.getElementById('query-history-controls');
  if (old) old.remove();

  const controls = new FakeElement('div', 'query-history-controls', {
    'data-history-mode': historyMode ? 'true' : 'false',
  });
  controls.appendChild(
    new FakeElement('button', '', { 'data-querylog-load-older': '' }),
  );
  if (historyMode) {
    controls.appendChild(
      new FakeElement('button', '', { 'data-querylog-back-live': '' }),
    );
  }
  document.root.appendChild(controls);
  return controls;
}

function row(key, text) {
  const element = new FakeElement('tr', `query-${key}`, {
    'data-querylog-row-key': key,
  });
  element.textContent = text;
  return element;
}

const document = new FakeDocument();
activeDocument = document;

const tbody = new FakeElement('tbody', 'query-table-body');
document.root.appendChild(tbody);
let controls = installControls(document, false);

const sandbox = { document, console };
vm.createContext(sandbox);
vm.runInContext(appSource, sandbox, { filename: 'app.js' });

const beforeRequest = (elt, xhr) =>
  document.fire('htmx:beforeRequest', { elt, target: tbody, xhr });
const beforeSwap = (xhr) =>
  document.fire('htmx:beforeSwap', {
    elt: tbody, // htmx dispatches on the swap target for every rows response.
    target: tbody,
    xhr,
    shouldSwap: true,
  });
const afterRequest = (xhr) =>
  document.fire('htmx:afterRequest', { elt: tbody, target: tbody, xhr });

// ---------------------------------------------------------------------------
// 1. Critical regression: Load older's own response must swap into tbody.
// ---------------------------------------------------------------------------
{
  controls = installControls(document, false);
  const loadOlder = controls.querySelector('[data-querylog-load-older]');
  const loadXhr = {};

  const request = beforeRequest(loadOlder, loadXhr);
  assert.equal(request.defaultPrevented, false);
  assert.equal(controls.dataset.historyMode, 'true', 'Load older enters history');

  const swap = beforeSwap(loadXhr);
  assert.equal(
    swap.detail.shouldSwap,
    true,
    'Load older response must not be mistaken for the 3 s poll',
  );

  tbody.appendChild(row('id-1', 'older'));
  document.fire('htmx:afterSwap', { elt: tbody, target: tbody });
  assert.equal(
    tbody.querySelectorAll('tr[data-querylog-row-key]').length,
    1,
    'older rows are appended',
  );

  // The OOB controls response replaces the controls and history stays on.
  const oldControls = controls;
  const oldLoadOlder = loadOlder;
  oldLoadOlder.focus();
  document.fire('htmx:oobBeforeSwap', { target: oldControls });
  controls = installControls(document, true);
  document.fire('htmx:oobAfterSwap', { target: controls });
  assert.equal(controls.dataset.historyMode, 'true');
  assert.equal(
    document.activeElement,
    controls.querySelector('[data-querylog-load-older]'),
    'focus moves to the replacement Load older control',
  );

  document.fire('htmx:afterSettle', { elt: tbody, target: tbody });
  afterRequest(loadXhr);
}

// ---------------------------------------------------------------------------
// 2. A poll already in flight when history starts is dropped.
// ---------------------------------------------------------------------------
{
  controls = installControls(document, false);
  const pollXhr = {};
  const pollRequest = beforeRequest(tbody, pollXhr);
  assert.equal(pollRequest.defaultPrevented, false, 'live polling is allowed');

  const loadOlder = controls.querySelector('[data-querylog-load-older]');
  const loadXhr = {};
  beforeRequest(loadOlder, loadXhr);

  const stalePollSwap = beforeSwap(pollXhr);
  assert.equal(
    stalePollSwap.detail.shouldSwap,
    false,
    'an in-flight poll response must not replace history rows',
  );

  const loadSwap = beforeSwap(loadXhr);
  assert.equal(
    loadSwap.detail.shouldSwap,
    true,
    'the concurrent Load older response still swaps',
  );

  afterRequest(pollXhr);
  const freshPollSwap = beforeSwap(pollXhr);
  assert.equal(
    freshPollSwap.detail.shouldSwap,
    true,
    'the poll XHR is forgotten once its request completed',
  );
  afterRequest(loadXhr);
}

// ---------------------------------------------------------------------------
// 3. New polls are paused while history mode is active.
// ---------------------------------------------------------------------------
{
  controls = installControls(document, true);
  const suppressed = beforeRequest(tbody, {});
  assert.equal(
    suppressed.defaultPrevented,
    true,
    'the 3 s poll is cancelled while browsing history',
  );
}

// ---------------------------------------------------------------------------
// 4. A filter change is not cancelled and its response resets live mode.
// ---------------------------------------------------------------------------
{
  controls = installControls(document, true);
  const filterInput = new FakeElement('input', 'domain-search');
  document.root.appendChild(filterInput);
  const filterXhr = {};

  const request = beforeRequest(filterInput, filterXhr);
  assert.equal(request.defaultPrevented, false);
  assert.equal(beforeSwap(filterXhr).detail.shouldSwap, true);

  // The cursor-less filter response carries live-mode OOB controls.
  controls = installControls(document, false);
  assert.equal(controls.dataset.historyMode, 'false');

  // Polling resumes after the filter response.
  const resumed = beforeRequest(tbody, {});
  assert.equal(resumed.defaultPrevented, false, 'filter change resumes polling');
  afterRequest(filterXhr);
}

// ---------------------------------------------------------------------------
// 5. Back to live clears history and resumes polling.
// ---------------------------------------------------------------------------
{
  controls = installControls(document, true);
  const back = controls.querySelector('[data-querylog-back-live]');
  const backXhr = {};
  const request = beforeRequest(back, backXhr);
  assert.equal(request.defaultPrevented, false);
  assert.equal(controls.dataset.historyMode, 'false', 'Back to live clears history');
  assert.equal(beforeSwap(backXhr).detail.shouldSwap, true);

  controls = installControls(document, false);
  const poll = beforeRequest(tbody, {});
  assert.equal(poll.defaultPrevented, false, 'Back to live resumes polling');
  afterRequest(backXhr);
}

// ---------------------------------------------------------------------------
// 6. A failed Load older from live mode does not leave polling paused behind
//    controls that have no Back to live button.
// ---------------------------------------------------------------------------
{
  controls = installControls(document, false);
  const loadOlder = controls.querySelector('[data-querylog-load-older]');
  beforeRequest(loadOlder, {});
  assert.equal(controls.dataset.historyMode, 'true');
  document.fire('htmx:responseError', { elt: loadOlder, xhr: {} });
  assert.equal(
    controls.dataset.historyMode,
    'false',
    'a failed first history load reverts to live mode',
  );
  const resumed = beforeRequest(tbody, {});
  assert.equal(resumed.defaultPrevented, false, 'polling resumes after the failure');
}
{
  // A failure while already in history mode keeps history (Back to live exists).
  controls = installControls(document, true);
  const loadOlder = controls.querySelector('[data-querylog-load-older]');
  beforeRequest(loadOlder, {});
  document.fire('htmx:sendError', { elt: loadOlder, xhr: {} });
  assert.equal(controls.dataset.historyMode, 'true');
}

// ---------------------------------------------------------------------------
// 7. Duplicate appended rows are removed by row key.
// ---------------------------------------------------------------------------
{
  tbody.children.length = 0;
  tbody.appendChild(row('id-9', 'first'));
  tbody.appendChild(row('id-9', 'duplicate'));
  document.fire('htmx:afterSwap', { elt: tbody, target: tbody });
  const remaining = tbody.querySelectorAll('tr[data-querylog-row-key]');
  assert.equal(remaining.length, 1, 'repeated pages do not duplicate rows');
  assert.equal(remaining[0].textContent, 'first');
}

console.log('query-log history DOM tests passed');
