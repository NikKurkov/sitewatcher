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

function refreshPage(stored, {sceneOpen = false, tooltipOpen = false, hidden = false, selected = false} = {}) {
  const values = new Map([['refresh', stored]]);
  let interval;
  let reloads = 0;
  vm.runInNewContext(script, {
    document: {hidden, activeElement: {matches: () => false}, addEventListener() {},
      querySelector: selector => selector === '[data-auto-refresh]' ? {}
        : selector === '[data-live-activity]:not([hidden])' && sceneOpen ? {}
        : selector === '[data-domain-select]:checked' && selected ? {}
        : selector.includes('.chart-tooltip') && tooltipOpen ? {} : null,
      querySelectorAll: () => []},
    sessionStorage: {getItem: key => values.get(key) ?? null},
    location: {pathname: '/', reload: () => { reloads++; }},
    setInterval: (fn, delay) => { assert.equal(delay, 60000); interval = fn; },
  });
  return {tick: () => interval(), reloads: () => reloads};
}

for (const stored of ['off', 'on', null]) {
  const refresh = refreshPage(stored);
  refresh.tick();
  assert.equal(refresh.reloads(), 1, 'Refresh stays on even with an old disabled preference');
}
for (const options of [{sceneOpen: true}, {tooltipOpen: true}, {hidden: true}, {selected: true}]) {
  const refresh = refreshPage('on', options);
  refresh.tick();
  assert.equal(refresh.reloads(), 0, 'Active reading and hidden pages defer refresh');
}
console.log('Always-on refresh ignores old toggles and protects active reading.');

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
  const nameEvents = {};
  const nameAttrs = {};
  const name = {setAttribute: (key, value) => { nameAttrs[key] = value; },
    addEventListener: (key, fn) => { nameEvents[key] = fn; },
    click: () => nameEvents.click({preventDefault() {}})};
  const domain = {dataset: {domainKey: '1'},
    querySelector: selector => selector === '[data-domain-toggle]' ? button
      : selector === '.domain-name' ? name : null,
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
  return {button, attrs, panel, nested, nameEvents, nameAttrs, rowEvents, handlers, windowEvents, document,
    tick: () => interval(), reloads: () => reloads, scroll: () => scroll};
}
const nameDisclosure = disclosurePage(new Map());
let nameNavigationPrevented = false;
nameDisclosure.nameEvents.click({preventDefault() { nameNavigationPrevented = true; }});
assert.equal(nameNavigationPrevented, true);
assert.equal(nameDisclosure.attrs['aria-expanded'], 'true');
assert.equal(nameDisclosure.nameAttrs['aria-expanded'], 'true');
nameDisclosure.nameEvents.keydown({key: ' ', preventDefault() {}});
assert.equal(nameDisclosure.attrs['aria-expanded'], 'false', 'Space activates the domain disclosure');
nameDisclosure.nameEvents.click({ctrlKey: true, preventDefault() { throw Error('Modified navigation must remain native'); }});
assert.equal(nameDisclosure.attrs['aria-expanded'], 'false');
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

// A chart can be inspected by time column, touch, and a single keyboard tab stop.
{
  const svgEvents = {}, documentEvents = {};
  const tooltip = {hidden: true, style: {}, offsetWidth: 120, offsetHeight: 25};
  let document;
  const points = [0, 20, 100].map((x) => {
    const events = {}, classes = new Set();
    const dot = {getAttribute: key => key === 'cx' ? x : 10,
      getBoundingClientRect: () => ({left: x, top: 40, bottom: 44, width: 4})};
    const point = {events, tabIndex: x === 0 ? 0 : -1,
      querySelector: () => dot,
      getAttribute: () => `Time ${x}: 100 ms`,
      classList: {add: name => classes.add(name), remove: name => classes.delete(name)},
      addEventListener: (name, fn) => { events[name] = fn; },
      closest: () => point,
      focus: () => {
        document.activeElement?.events?.blur();
        document.activeElement = point;
        events.focus();
      }};
    return point;
  });
  const svg = {addEventListener: (name, fn) => { svgEvents[name] = fn; },
    getScreenCTM: () => ({a: 1, b: 0, c: 0, d: 1, e: 0, f: 0}),
    contains: target => points.includes(target)};
  const chart = {querySelector: selector => selector === 'svg' ? svg : tooltip,
    querySelectorAll: () => points,
    getBoundingClientRect: () => ({left: 0, top: 0, width: 300}),
    contains: target => points.includes(target) || target === svg};
  document = {activeElement: null, addEventListener: (name, fn) => { documentEvents[name] = fn; },
    querySelector: () => null,
    querySelectorAll: selector => selector === '.response-chart' ? [chart] : []};
  vm.runInNewContext(script, {document, window: {addEventListener() {}}});
  svgEvents.pointermove({clientX: 20, clientY: 400});
  assert.equal(tooltip.textContent, 'Time 20: 100 ms');
  svgEvents.pointermove({clientX: 60, clientY: 10});
  assert.equal(tooltip.hidden, true, 'A long gap must not select a remote measurement');
  svgEvents.pointerdown({clientX: 100, pointerType: 'touch'});
  svgEvents.pointerleave({pointerType: 'touch'});
  assert.equal(tooltip.hidden, false, 'A touch tooltip survives lifting the finger');
  points[0].focus();
  points[0].events.keydown({key: 'ArrowRight', preventDefault() {}});
  assert.equal(document.activeElement, points[1]);
  assert.equal(points.filter(point => point.tabIndex === 0).length, 1);
  points[1].events.keydown({key: 'End', preventDefault() {}});
  assert.equal(document.activeElement, points[2]);
  points[2].events.keydown({key: 'Home', preventDefault() {}});
  assert.equal(document.activeElement, points[0]);
  documentEvents.keydown({key: 'Escape'});
  assert.equal(tooltip.hidden, true);
  svgEvents.pointerdown({clientX: 20, pointerType: 'touch'});
  documentEvents.pointerdown({target: {}});
  assert.equal(tooltip.hidden, true, 'Tapping outside dismisses the chart tooltip');
}
console.log('Chart inspection: time columns, missing intervals, touch, arrows, Home/End and dismissal passed.');

// The browser owns click/tap toggling and Escape/outside dismissal of native popovers.
// Our enhancement only opens them for mouse hover and visible keyboard focus.
{
  let open = false;
  let keyboardFocus = false;
  const triggerEvents = {};
  const tooltipEvents = {};
  const windowEvents = {};
  const tooltip = {
    style: {}, offsetWidth: 80, offsetHeight: 28,
    matches: () => open,
    showPopover() { open = true; },
    hidePopover() { open = false; },
    addEventListener(name, handler) { tooltipEvents[name] = handler; },
  };
  const trigger = {
    getAttribute: () => 'response-window-one.example-15',
    getBoundingClientRect: () => ({left: 290, top: 80}),
    matches: () => keyboardFocus,
    addEventListener(name, handler) { triggerEvents[name] = handler; },
  };
  const document = {
    addEventListener() {}, querySelector: () => null,
    querySelectorAll: selector => selector === '.chart-window-value' ? [trigger] : [],
    getElementById: () => tooltip,
  };
  vm.runInNewContext(script, {document, location: {pathname: '/'},
    window: {innerWidth: 320, addEventListener(name, handler) { windowEvents[name] = handler; }},
    sessionStorage: {getItem: () => null}, setTimeout, clearTimeout,
  });
  triggerEvents.pointerenter({pointerType: 'touch'});
  triggerEvents.focus();
  assert.equal(open, false, 'Touch relies on native click instead of opening twice');
  triggerEvents.pointerenter({pointerType: 'mouse'});
  assert.equal(open, true);
  assert.equal(tooltip.style.left, '232px', 'Keep the tooltip within the viewport');
  assert.equal(tooltip.style.top, '46px');
  triggerEvents.pointerleave({pointerType: 'mouse'});
  assert.equal(open, false);
  keyboardFocus = true;
  triggerEvents.focus();
  assert.equal(open, true);
  triggerEvents.pointerleave({pointerType: 'mouse'});
  assert.equal(open, true, 'Keyboard focus keeps the period visible');
  triggerEvents.blur();
  assert.equal(open, false);
  // Native tap opens the popover, then the toggle event positions it.
  open = true;
  triggerEvents.pointerleave({pointerType: 'touch'});
  assert.equal(open, true, 'Touch pointerleave must not dismiss a newly tapped value');
  tooltipEvents.toggle({newState: 'open'});
  assert.equal(tooltip.style.left, '232px');
  windowEvents.scroll();
  assert.equal(open, false);
}
console.log('Response averages: native touch popovers, mouse hover, keyboard focus and viewport positioning passed.');

// Switching to private access omits the public address without losing its draft.
{
  let change;
  const input = {value: 'shop-health', disabled: false};
  const mode = {value: 'public', disabled: false, addEventListener: (_, handler) => {change = handler;}};
  const address = {hidden: false, querySelector: () => input};
  const form = {querySelector: selector => selector === '[name="access_mode"]' ? mode : address};
  const document = {addEventListener() {}, querySelectorAll: () => [],
    querySelector: selector => selector === '.status-page-form' ? form : null};
  vm.runInNewContext(script, {document, window: {addEventListener() {}}});
  assert.equal(address.hidden, false);
  mode.value = 'private'; change();
  assert.equal(address.hidden, true);
  assert.equal(input.disabled, true);
  mode.value = 'public'; change();
  assert.equal(address.hidden, false);
  assert.equal(input.disabled, false);
  assert.equal(input.value, 'shop-health');
}
console.log('Status-page access: hide private address and preserve its draft passed.');
