// Check explicit credential access and prevent accidental persistence of a viewed key.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const script = fs.readFileSync(path.join(__dirname, '../sitewatcher/webapp/static/sitewatcher/key_visibility.js'), 'utf8');
function page(present = true) {
  const requests = [];
  const handlers = {};
  const field = {type: 'password', value: '', name: 'virustotal_api_key', events: {},
    addEventListener(name, callback) { this.events[name] = callback; },
    removeAttribute(name) { if (name === 'name') this.name = ''; },
    form: {querySelector: () => ({value: 'synthetic-csrf'})}};
  const toggle = {hidden: true, dataset: {showLabel: 'Show', hideLabel: 'Hide', errorLabel: 'Unavailable'}, attrs: {},
    addEventListener(name, callback) { this[name] = callback; },
    setAttribute(name, value) { this.attrs[name] = value; }};
  const notice = {textContent: ''};
  const container = {dataset: {keyPresent: String(present)},
    querySelector: selector => selector === 'input' ? field : selector === '[data-key-visibility]' ? toggle : notice};
  const document = {hidden: false, querySelector: () => container,
    addEventListener(name, callback) { handlers[name] = callback; }};
  vm.runInNewContext(script, {document, AbortController, URLSearchParams,
    window: {addEventListener(name, callback) { handlers[name] = callback; }},
    fetch: (url, options) => new Promise(resolve => requests.push({url, options, resolve})),
  });
  const respond = (key, ok = true) => requests.at(-1).resolve({ok, json: async () => ({key})});
  return {field, toggle, notice, requests, handlers, document, respond};
}
(async () => {
  let p = page();
  assert.equal(p.requests.length, 0, 'page load must not reveal a key');
  assert.equal(p.toggle.hidden, false);
  let click = p.toggle.click();
  assert.equal(p.requests[0].url, '/settings');
  assert.equal(p.requests[0].options.method, 'POST');
  assert.equal(p.requests[0].options.cache, 'no-store');
  assert.deepEqual([...p.requests[0].options.body.keys()], ['action', 'csrfmiddlewaretoken']);
  p.respond('synthetic-key');
  await click;
  assert.equal(p.field.value, 'synthetic-key');
  assert.equal(p.field.type, 'text');
  assert.equal(p.field.name, '', 'viewed key must not be submitted by Save settings');
  await p.toggle.click();
  assert.equal(p.field.value, '');
  assert.equal(p.field.type, 'password');
  assert.equal(p.field.name, 'virustotal_api_key');
  click = p.toggle.click();
  p.respond('synthetic-key');
  await click;
  p.field.value = 'edited-replacement';
  p.field.events.input();
  await p.toggle.click();
  assert.equal(p.field.name, 'virustotal_api_key');
  assert.equal(p.field.value, 'edited-replacement', 'hiding must retain explicit edits');

  p = page();
  click = p.toggle.click();
  p.document.hidden = true;
  p.handlers.visibilitychange();
  assert.equal(p.requests[0].options.signal.aborted, true);
  p.respond('must-not-appear');
  await click;
  assert.equal(p.field.value, '');
  assert.equal(p.field.type, 'password', 'late response must not expose a hidden credential');
  p.document.hidden = false;
  click = p.toggle.click();
  p.respond('error-must-not-appear', false);
  await click;
  assert.equal(p.field.value, '');
  assert.equal(p.notice.textContent, 'Unavailable');
  assert.equal(p.notice.hidden, false);

  p = page(false);
  p.field.value = 'newly-typed-key';
  await p.toggle.click();
  assert.equal(p.requests.length, 0, 'newly entered key requires no server access');
  assert.equal(p.field.type, 'text');
  p.handlers.pagehide();
  assert.equal(p.field.type, 'password');
  assert.equal(p.field.value, 'newly-typed-key');
  console.log('Key visibility: explicit CSRF POST, no automatic reveal/save, edit retention, hide/abort cleanup and safe errors passed.');
})().catch(error => { console.error(error); process.exitCode = 1; });
