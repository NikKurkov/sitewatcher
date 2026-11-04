// Exercise the shipped browser script without a browser or third-party DOM library.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const script = fs.readFileSync(path.join(__dirname,
  '../sitewatcher/webapp/static/sitewatcher/theme.js'), 'utf8');
const focusKey = 'sitewatcher_filter_focus';

function page(saved = null, external = false) {
  const events = {};
  const timers = new Map();
  const storage = new Map(saved ? [[focusKey, JSON.stringify(saved)]] : []);
  const disclosure = {open: false};
  const fields = {};
  const document = {
    activeElement: null,
    addEventListener() {},
    querySelector: () => null,
    querySelectorAll: selector => selector === '.filter-form, .history-filters' ? [form]
      : selector === '[form="domain-filters"]' && external ? [fields.status] : [],
    getElementById: id => fields[id],
  };
  let submissions = 0;
  let nextTimer = 0;
  const form = {
    id: external ? 'domain-filters' : '',
    contains: field => Object.values(fields).includes(field) && !(external && field === fields.status),
    addEventListener: (name, handler) => { events[name] = handler; },
    requestSubmit: () => { submissions++; events.submit(); },
  };
  for (const [id, type, value] of [
    ['q', 'search', 'example'], ['status', 'select-one', 'warn'],
    ['id_history_from', 'date', '2026-11-03'],
  ]) {
    fields[id] = {id, type, value, selectionStart: 3, form, events: {},
      addEventListener(name, handler) { this.events[name] = handler; },
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
p = page(null, true);
p.document.activeElement = p.fields.status;
p.fields.status.events.change({target: p.fields.status});
assert.equal(p.submissions(), 1, 'associated controls outside the form still submit immediately');
assert.equal(JSON.parse(p.storage.get(focusKey)).id, 'status');
p = page();
p.events.input({target: p.fields.q});
p.events.submit();
assert.equal(p.timers.size, 0);
assert.equal(JSON.parse(p.storage.get(focusKey)).id, 'q', 'native Enter also remembers focus');
console.log('Automatic filters: debounce, external form controls, Enter, IME, focus and disclosure restoration passed.');

function refreshPage(tagName, stored, sceneOpen = false) {
  const values = new Map([['refresh', stored]]);
  const attributes = {'aria-pressed': 'true'};
  const handlers = {};
  const option = {hidden: true};
  const control = {tagName, checked: true, dataset: {enabledLabel: 'Disable', disabledLabel: 'Enable'},
    getAttribute: name => attributes[name], setAttribute: (name, value) => { attributes[name] = value; },
    addEventListener: (name, fn) => { handlers[name] = fn; }};
  const refresh = {querySelector: selector => selector === '[data-refresh-enabled]' ? control : option};
  let interval;
  let reloads = 0;
  vm.runInNewContext(script, {
    document: {hidden: false, activeElement: {matches: () => false}, addEventListener() {},
      querySelector: selector => selector === '[data-auto-refresh]' ? refresh
        : selector === '[data-live-activity]:not([hidden])' && sceneOpen ? {} : null,
      querySelectorAll: () => []},
    sessionStorage: {getItem: key => values.get(key) ?? null,
      setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key)},
    location: {pathname: '/', reload: () => { reloads++; }},
    setInterval: fn => { interval = fn; },
  });
  return {control, option, handlers, attributes, values, tick: () => interval(), reloads: () => reloads};
}

let refresh = refreshPage('BUTTON', 'off');
assert.equal(refresh.option.hidden, false);
assert.equal(refresh.attributes['aria-pressed'], 'false');
assert.equal(refresh.control.title, 'Enable');
refresh.tick();
assert.equal(refresh.reloads(), 0);
refresh.handlers.click();
assert.equal(refresh.attributes['aria-pressed'], 'true');
assert.equal(refresh.control.title, 'Disable');
assert.equal(refresh.values.get('refresh'), 'on');
refresh.tick();
assert.equal(refresh.reloads(), 1);
refresh = refreshPage('INPUT', 'on');
assert.equal(refresh.control.checked, true);
refresh.tick();
assert.equal(refresh.reloads(), 1);
refresh.control.checked = false;
refresh.handlers.change();
refresh.tick();
assert.equal(refresh.values.get('refresh'), 'off');
assert.equal(refresh.reloads(), 1);
refresh = refreshPage('BUTTON', 'on', true);
refresh.tick();
assert.equal(refresh.reloads(), 0, 'The open signal room must survive automatic refresh');
console.log('Header refresh toggle and public-page checkbox preserve saved state and refresh behavior.');

// Settings and edit pages reveal navigation only: no live fetch or refresh timer.
for (const storageFails of [false, true]) {
  const events = {};
  const values = new Map();
  const link = {hidden: true, addEventListener: (name, handler) => { events[name] = handler; }};
  vm.runInNewContext(script, {
    document: {addEventListener() {}, querySelector: () => null,
      querySelectorAll: selector => selector === '[data-activity-navigation]' ? [link] : []},
    sessionStorage: {getItem: () => null, removeItem() {}},
    localStorage: {setItem: (key, value) => {
      if (storageFails) throw new Error('Storage blocked');
      values.set(key, value);
    }},
    setInterval: () => { throw new Error('Form pages must not refresh automatically'); },
    fetch: () => { throw new Error('Form pages must not poll activity'); },
  });
  assert.equal(link.hidden, false);
  events.click();
  assert.equal(values.get('sitewatcher_live_activity'), storageFails ? undefined : 'on');
}
console.log('Shared toolbar: live navigation remembers the panel without form refresh or polling.');

// Run navigation round trips against the actual shipped script and storage format.
function disclosurePage(storage, {scope = 'owner-1', pathname = '/', activeInput = false,
  dragging = false, missing = false} = {}) {
  const handlers = {};
  const windowEvents = {};
  const rowEvents = {};
  const buttonEvents = {};
  let interval;
  let reloads = 0;
  let scroll;
  const panel = {hidden: true};
  const attrs = {'aria-controls': 'panel-1', 'aria-expanded': 'false'};
  const button = {hidden: true, id: 'toggle-1', matches: () => false,
    getAttribute: key => attrs[key], setAttribute: (key, value) => { attrs[key] = value; },
    addEventListener: (key, fn) => { buttonEvents[key] = fn; },
    click: () => buttonEvents.click(), focus: () => { document.activeElement = button; },
    closest: selector => selector === '[data-domain-key]' ? domain : null};
  const nested = {open: false};
  const domain = {dataset: {domainKey: '1'},
    querySelector: selector => selector === '[data-domain-toggle]' ? button : null,
    querySelectorAll: selector => selector === 'details' ? [nested] : [button]};
  const row = {addEventListener: (key, fn) => { rowEvents[key] = fn; }, querySelector: () => button};
  const root = {dataset: {disclosureScope: scope}, contains: target => target === button,
    querySelectorAll: selector => selector === '[data-domain-key]' ? (missing ? [] : [domain])
      : selector === '[data-domain-toggle]' ? (missing ? [] : [button])
      : selector === '[data-domain-summary]' ? [row] : []};
  const enabled = {tagName: 'INPUT', checked: true, addEventListener() {}};
  const refresh = {querySelector: selector => selector === '[data-refresh-enabled]' ? enabled : {}};
  const document = {hidden: false, activeElement: {matches: () => activeInput},
    addEventListener: (key, fn) => { handlers[key] = fn; },
    querySelector: selector => selector === '[data-disclosure-scope]' ? root
      : selector === '[data-auto-refresh]' ? refresh
      : selector.includes('data-dragging') && dragging ? {} : null,
    querySelectorAll: () => [],
    getElementById: id => missing ? null : id === 'panel-1' ? panel : id === 'toggle-1' ? button : null};
  vm.runInNewContext(script, {document,
    window: {scrollX: 12, scrollY: 340, scrollTo: (x, y) => { scroll = [x, y]; },
      addEventListener: (key, fn) => { windowEvents[key] = fn; }},
    location: {pathname, reload: () => { reloads++; }},
    sessionStorage: {getItem: key => storage.get(key) ?? null,
      setItem: (key, value) => storage.set(key, value), removeItem: key => storage.delete(key)},
    setInterval: fn => { interval = fn; }});
  return {button, attrs, panel, nested, rowEvents, handlers, windowEvents, document,
    tick: () => interval(), reloads: () => reloads, scroll: () => scroll};
}
const savedDisclosures = new Map();
let disclosure = disclosurePage(savedDisclosures);
assert.equal(disclosure.button.hidden, false);
disclosure.button.click();
disclosure.nested.open = true;
disclosure.button.focus();
disclosure.tick();
assert.equal(disclosure.reloads(), 1, 'Reading open details permits an actual native reload');
assert.equal(disclosure.panel.hidden, false);
disclosure = disclosurePage(savedDisclosures);
assert.equal(disclosure.attrs['aria-expanded'], 'true');
assert.equal(disclosure.panel.hidden, false);
assert.equal(disclosure.nested.open, true);
assert.equal(disclosure.document.activeElement, disclosure.button);
assert.deepEqual(disclosure.scroll(), [12, 340]);
disclosure.rowEvents.click({target: {closest: () => ({})}});
assert.equal(disclosure.attrs['aria-expanded'], 'true', 'Interactive descendants do not toggle rows');
disclosure.rowEvents.click({target: {closest: () => null}});
assert.equal(disclosure.attrs['aria-expanded'], 'false', 'Text and empty row areas toggle');
disclosure.windowEvents.pagehide();
assert.equal(disclosurePage(savedDisclosures).panel.hidden, true, 'Manual navigation captures closed state');
for (const options of [{scope: 'owner-2'}, {pathname: '/public/other/'}, {missing: true}]) {
  assert.equal(disclosurePage(savedDisclosures, options).panel.hidden, true);
}
for (const options of [{activeInput: true}, {dragging: true}]) {
  const busy = disclosurePage(new Map(), options);
  busy.tick();
  assert.equal(busy.reloads(), 0);
}
disclosure = disclosurePage(new Map());
disclosure.handlers.input({target: {matches: () => true}});
disclosure.tick();
assert.equal(disclosure.reloads(), 0, 'Unsaved input blocks refresh after leaving the field');
console.log('Domain disclosures: native refresh, navigation, nested state, scroll, focus, scope and interaction guards passed.');
