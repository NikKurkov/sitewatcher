// Exercise disclosure persistence, empty groups and bulk selection without DOM dependencies.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const script = fs.readFileSync(path.join(__dirname,
  '../sitewatcher/webapp/static/sitewatcher/domain_groups.js'), 'utf8');
function element(dataset = {}) {
  return {dataset, hidden: false, events: {}, attrs: {}, checked: false,
    addEventListener(type, fn) { this.events[type] = fn; },
    setAttribute(name, value) { this.attrs[name] = value; },
    getAttribute(name) { return this.attrs[name]; },
    fire(type) { this.events[type]?.({preventDefault() {}}); },
    querySelector() { return null; }, querySelectorAll() { return []; }};
}
function page({filtered = false, stored = '{"0":false,"1":false}', readOnly = false,
               storageFailure = false} = {}) {
  const data = new Map([['owner-1', stored]]);
  const selections = ['a.example', 'b.example'].map(value => Object.assign(element(), {value}));
  const rows = selections.map(input => Object.assign(element({groupId: '0'}), {
    querySelector: selector => selector === '[data-domain-select]' ? input : null}));
  const empty = element({groupId: '1'});
  const buttons = [element(), element()];
  const groupSelect = [element(), element()];
  const headers = buttons.map((button, i) => Object.assign(element({domainGroup: String(i)}), {
    querySelector: selector => selector === '[data-group-toggle]' ? button : groupSelect[i]}));
  const table = element({groupFiltered: String(filtered), groupStorageKey: 'owner-1'});
  table.querySelectorAll = selector => ({'tbody[data-domain-name]': rows,
    'tbody[data-group-id]': [...rows, empty], '[data-domain-group]': headers,
    '[data-domain-selection], [data-group-selection]': []}[selector] || []);
  const fields = {'[data-selected-domains]': element(), '[data-selected-count]': element({template:'Selected: {count}'}),
    '[data-move-submit]': element(), '[data-selection-clear]': element()};
  const form = Object.assign(element(), {querySelector: selector => fields[selector]});
  const expand = element(), collapse = element();
  const document = {querySelector: selector => ({'[data-domain-groups]': table,
    '[data-groups-expand]': expand, '[data-groups-collapse]': collapse,
    '[data-bulk-move]': readOnly ? null : form}[selector] || null)};
  vm.runInNewContext(script, {document, localStorage: {
    getItem(key) { if (storageFailure) throw new Error('Disabled'); return data.get(key); },
    setItem(key, value) { if (storageFailure) throw new Error('Disabled'); data.set(key, value); },
  }});
  return {data, rows, empty, buttons, groupSelect, selections, fields, form, expand, collapse};
}
let p = page();
assert.equal(p.rows[0].hidden, true);
assert.equal(p.empty.hidden, true, 'collapsed empty groups hide their content too');
p.buttons[1].fire('click');
assert.equal(p.empty.hidden, false);
assert.equal(JSON.parse(p.data.get('owner-1'))['1'], true);
p.expand.fire('click');
assert.equal(p.rows.every(row => !row.hidden), true);
p.collapse.fire('click');
assert.equal(p.rows.every(row => row.hidden), true);
p = page({filtered: true});
assert.equal(p.rows.every(row => !row.hidden), true);
assert.equal(p.empty.hidden, false);
p.collapse.fire('click');
assert.equal(p.data.get('owner-1'), '{"0":false,"1":false}', 'filters do not replace saved open state');
p = page({stored: 'broken JSON', storageFailure: true, readOnly: true});
assert.equal(p.rows[0].hidden, false);
p.collapse.fire('click');
assert.equal(p.empty.hidden, true);
p = page();
p.selections[0].checked = true;
p.selections[0].fire('change');
assert.equal(p.form.hidden, false);
assert.equal(p.fields['[data-selected-domains]'].value, '["a.example"]');
assert.equal(p.groupSelect[0].indeterminate, true);
p.groupSelect[0].checked = true;
p.groupSelect[0].fire('change');
assert.equal(p.fields['[data-selected-domains]'].value, '["a.example","b.example"]');
assert.equal(p.groupSelect[1].disabled, true);
p.fields['[data-selection-clear]'].fire('click');
assert.equal(p.form.hidden, true);
assert.equal(p.fields['[data-move-submit]'].disabled, true);
console.log('Groups: empty disclosure, persisted/filtered state, unavailable storage and bulk selection passed.');
