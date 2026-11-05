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
               storageFailure = false, single = false} = {}) {
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
    'tbody[data-group-id]': [...rows, empty], '[data-domain-group]': single ? [] : headers,
    '[data-domain-selection], [data-group-selection]': []}[selector] || []);
  buttons.forEach((button, index) => {
    button.closest = selector => selector === '[data-group-toggle]' ? button : headers[index];
    button.fire = () => table.events.click({target: button});
  });
  const fields = {'[data-selected-domains]': element(), '[data-selected-count]': element({template:'Selected: {count}'}),
    '[data-move-submit]': element(), '[data-selection-clear]': element()};
  const form = Object.assign(element(), {querySelector: selector => fields[selector]});
  const expand = element(), collapse = element(), selectVisible = element();
  const document = {querySelector: selector => ({'[data-domain-groups]': table,
    '[data-groups-expand]': expand, '[data-groups-collapse]': collapse,
    '[data-select-visible]': single ? selectVisible : null,
    '[data-bulk-move]': readOnly ? null : form}[selector] || null)};
  vm.runInNewContext(script, {document, localStorage: {
    getItem(key) { if (storageFailure) throw new Error('Disabled'); return data.get(key); },
    setItem(key, value) { if (storageFailure) throw new Error('Disabled'); data.set(key, value); },
  }});
  return {data, table, rows, empty, buttons, groupSelect, selections, fields, form, expand, collapse, selectVisible};
}
let p = page();
assert.equal(p.rows[0].hidden, true);
assert.equal(p.empty.hidden, true, 'collapsed empty groups hide their content too');
p.buttons[1].fire('click');
assert.equal(p.empty.hidden, false);
assert.equal(JSON.parse(p.data.get('owner-1'))['1'], true);
p = page({filtered: true});
assert.equal(p.rows.every(row => !row.hidden), true);
assert.equal(p.empty.hidden, false);
p.buttons[0].fire('click');
assert.equal(p.data.get('owner-1'), '{"0":false,"1":false}', 'filters do not replace saved open state');
p = page({stored: 'broken JSON', storageFailure: true, readOnly: true});
assert.equal(p.rows[0].hidden, false);
p.buttons[1].fire('click');
assert.equal(p.empty.hidden, true);
console.log('Groups: empty disclosure, persisted/filtered state and unavailable storage passed.');

p = page({single: true});
assert.equal(p.rows.every(row => !row.hidden), true, 'single group ignores old collapsed preference');
const formScript = fs.readFileSync(path.join(__dirname, '../sitewatcher/webapp/static/sitewatcher/group_form.js'), 'utf8');
const select = Object.assign(element(), {value: '0'});
let focuses = 0;
const input = Object.assign(element(), {focus() { focuses++; }});
const field = Object.assign(element(), {querySelector: () => input});
vm.runInNewContext(formScript, {document: {querySelector: s => s === '#group_id' ? select : field}});
assert.equal(field.hidden, true);
assert.equal(input.disabled, true);
select.value = 'new';
select.fire('change');
assert.equal(field.hidden, false);
assert.equal(input.required, true);
assert.equal(input.disabled, false);
assert.equal(focuses, 1);
input.value = 'Draft group';
select.value = '0';
select.fire('change');
assert.equal(field.hidden, true);
assert.equal(input.disabled, true);
select.value = 'new';
select.fire('change');
assert.equal(input.value, 'Draft group');
console.log('Single-group display and inline new-group field focus/validation/draft retention passed.');

p = page({stored: '{"0":true,"1":true}'});
p.rows[0].dataset.groupId = '1';
p.buttons[0].fire('click');
assert.equal(p.rows[0].hidden, false, 'source collapse does not hide a transferred row');
p.buttons[1].fire('click');
assert.equal(p.rows[0].hidden, true, 'target collapse includes transferred rows');
console.log('Dynamic membership: source/target disclosure follows moved rows.');
