// Exercise the shipped browser script without a browser or third-party DOM library.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const script = fs.readFileSync(path.join(__dirname,
  '../sitewatcher/webapp/static/sitewatcher/theme.js'), 'utf8');
const focusKey = 'sitewatcher_filter_focus';

function page(saved = null) {
  const events = {};
  const timers = new Map();
  const storage = new Map(saved ? [[focusKey, JSON.stringify(saved)]] : []);
  const disclosure = {open: false};
  const fields = {};
  const document = {
    activeElement: null,
    addEventListener() {},
    querySelector: () => null,
    querySelectorAll: selector => selector === '.filter-form, .history-filters' ? [form] : [],
    getElementById: id => fields[id],
  };
  let submissions = 0;
  let nextTimer = 0;
  const form = {
    contains: field => Object.values(fields).includes(field),
    addEventListener: (name, handler) => { events[name] = handler; },
    requestSubmit: () => { submissions++; events.submit(); },
  };
  for (const [id, type, value] of [
    ['q', 'search', 'example'], ['status', 'select-one', 'warn'],
    ['id_history_from', 'date', '2026-11-03'],
  ]) {
    fields[id] = {id, type, value, selectionStart: 3,
      closest: () => type === 'date' ? disclosure : null,
      focus() { document.activeElement = this; },
      setSelectionRange(start, end) { this.selection = [start, end]; },
    };
  }
  document.activeElement = fields.q;
  vm.runInNewContext(script, {document, location: {pathname: '/'},
    sessionStorage: {getItem: key => storage.get(key) ?? null,
      setItem: (key, value) => storage.set(key, value), removeItem: key => storage.delete(key)},
    setTimeout: (callback, delay) => { timers.set(++nextTimer, {callback, delay}); return nextTimer; },
    clearTimeout: id => timers.delete(id),
  });
  return {fields, storage, disclosure, events, timers, document,
    submissions: () => submissions,
    flush: () => { const callbacks = [...timers.values()]; timers.clear(); callbacks.forEach(({callback}) => callback()); },
  };
}

let p = page();
p.events.input({target: p.fields.q});
p.fields.q.value = 'example.org';
p.events.input({target: p.fields.q});
assert.equal(p.submissions(), 0);
assert.equal(p.timers.size, 1);
assert.equal([...p.timers.values()][0].delay, 400);
p.flush();
assert.equal(p.submissions(), 1);
assert.equal(JSON.parse(p.storage.get(focusKey)).value, 'example.org');

p = page();
p.events.input({target: p.fields.q});
p.document.activeElement = p.fields.status;
p.events.change({target: p.fields.status});
assert.equal(p.submissions(), 1);
assert.equal(p.timers.size, 0);
p.flush();
assert.equal(p.submissions(), 1);

p = page();
p.events.input({target: p.fields.q});
p.events.compositionstart();
assert.equal(p.timers.size, 0);
p.events.input({target: p.fields.q, isComposing: true});
assert.equal(p.timers.size, 0);
p.events.compositionend({target: p.fields.q});
p.flush();
assert.equal(p.submissions(), 1);
p.events.change({target: p.fields.id_history_from});
assert.equal(p.submissions(), 2);
p.events.input({target: p.fields.q});
p.events.submit();
assert.equal(p.timers.size, 0);

p = page({id: 'q', value: 'example', path: '/', cursor: 4});
assert.deepEqual(p.fields.q.selection, [4, 4]);
assert.equal(p.storage.has(focusKey), false);
p = page({id: 'id_history_from', value: '2026-11-03', path: '/', cursor: null});
assert.equal(p.disclosure.open, true);
assert.equal(p.document.activeElement, p.fields.id_history_from);
p = page({id: 'q', value: 'different query', path: '/', cursor: 4});
assert.equal(p.fields.q.selection, undefined);
console.log('Automatic filters: debounce, immediate changes, IME, focus and disclosure restoration passed.');
