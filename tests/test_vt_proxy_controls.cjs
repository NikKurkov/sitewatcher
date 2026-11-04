const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const script = fs.readFileSync(require('node:path').join(__dirname,
  '../sitewatcher/webapp/static/sitewatcher/vt_proxy.js'), 'utf8');
const input = {value: 'unsaved-private-url', disabled: false};
const toggle = {checked: false, events: {}, attrs: {},
  addEventListener(name, fn) { this.events[name] = fn; },
  setAttribute(name, value) { this.attrs[name] = value; }};
const fields = {hidden: false, querySelectorAll: () => [input]};
vm.runInNewContext(script, {document: {querySelector(selector) {
  return selector === '[data-vt-proxy-toggle]' ? toggle : fields;
}}});
assert.equal(fields.hidden, true);
assert.equal(input.disabled, true);
toggle.checked = true;
toggle.events.change();
assert.equal(fields.hidden, false);
assert.equal(input.disabled, false);
assert.equal(toggle.attrs['aria-expanded'], 'true');
toggle.checked = false;
toggle.events.change();
assert.equal(fields.hidden, true);
assert.equal(input.value, 'unsaved-private-url');
assert.equal(input.disabled, true);
console.log('VirusTotal proxy checkbox: visibility, disabled fields and retained edits PASS');
