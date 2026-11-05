// Exercise the shipped drag handlers with controlled requests and a small DOM boundary.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const script = fs.readFileSync(path.join(__dirname,
  '../sitewatcher/webapp/static/sitewatcher/domain_order.js'), 'utf8');

function page() {
  const classes = () => {
    const values = new Set();
    return {add: (...names) => names.forEach(name => values.add(name)),
      remove: (...names) => names.forEach(name => values.delete(name)),
      contains: name => values.has(name),
      toggle(name, enabled) { if (enabled) values.add(name); else values.delete(name); }};
  };
  const events = {};
  const storage = new Map([['groups-owner', JSON.stringify({'1': true, '2': false})]]);
  const requests = [];
  let reloads = 0;
  const table = {
    dataset: {saved: 'Order saved', failed: 'Order failed', group: 'Favorites stay first',
      moveFailed: 'Group move failed', saving: 'Saving', moved: 'Moved', moveChanged: 'Changed', dropTarget: 'Move to {group}', groupStorageKey: 'groups-owner'},
    attributes: {}, children: [],
    setAttribute(name, value) { this.attributes[name] = value; },
    addEventListener(name, handler) {
      const previous = events[name];
      events[name] = event => { previous?.(event); handler(event); };
    },
    dispatchEvent(event) { events[event.type]?.(event); },
    contains(node) { return this.children.includes(node); },
    replaceChildren(...nodes) { this.children = nodes; },
    insertBefore(node, reference) {
      this.children.splice(this.children.indexOf(node), 1);
      const index = reference === null ? this.children.length : this.children.indexOf(reference);
      assert.notEqual(index, -1, 'Insertion reference belongs to the table');
      this.children.splice(index, 0, node);
    },
  };
  function node(kind, groupId, domainName, favorite = false) {
    const item = {kind, dataset: domainName ? {domainName, groupId, favorite: String(favorite)}
      : kind === 'header' ? {domainGroup: groupId} : {groupId},
      classList: classes(), hidden: false,
      matches: selector => selector === 'tbody' || selector === 'tbody[data-domain-name]' && Boolean(domainName),
      querySelector(selector) {
        if (selector === '[data-domain-drag]') return handles.find(h => h.row === this);
        if (selector === '.group-name') return {textContent: 'Group '+groupId};
        return this.button;
      },
      focus() {}, scrollIntoView() {},
      remove() { table.children = table.children.filter(item => item !== this); },
      closest(selector) {
        if (selector === 'tbody[data-domain-name]') return domainName ? this : null;
        if (selector === '[data-domain-group], tbody[data-group-id]') return this;
        return null;
      },
      getBoundingClientRect: () => ({top: 0, bottom: 100, height: 100}),
    };
    item.button = {attrs: {}, setAttribute(k,v) { this.attrs[k]=v; },
      getAttribute(k) { return this.attrs[k]; }};
    Object.defineProperty(item, 'isConnected', {get: () => table.children.includes(item)});
    Object.defineProperty(item, 'nextElementSibling', {
      get: () => table.children[table.children.indexOf(item) + 1] || null,
    });
    return item;
  }
  const firstHeader = node('header', '1');
  const a = node('row', '1', 'a.example');
  const b = node('row', '1', 'b.example');
  const favorite = node('row', '1', 'favorite.example', true);
  const secondHeader = node('header', '2');
  const c = node('row', '2', 'c.example');
  const emptyHeader = node('header', '3');
  const emptyBody = node('empty', '3');
  table.children = [firstHeader, a, b, favorite, secondHeader, c, emptyHeader, emptyBody];
  const handles = [a, b, favorite, c].map(row => ({
    draggable: true, events: {}, setAttribute() {}, focus() {}, scrollIntoView() {},
    closest: selector => selector === '[data-domain-drag]' ? handles.find(h => h.row === row) : row,
    addEventListener(name, handler) { this.events[name] = handler; }, row,
  }));
  const message = {textContent: '', classList: classes()};
  table.querySelector = () => ({value: 'csrf-fixture'});
  table.querySelectorAll = selector => selector === '[data-domain-drag]' ? handles
    : selector === '[data-domain-group]' ? table.children.filter(n => n.kind === 'header')
    : selector === 'tbody[data-group-id]' ? table.children.filter(n => n.kind !== 'header') : [];

  const context = {
    document: {
      querySelector: selector => ['[data-domain-order]', '[data-domain-groups]'].includes(selector)
        ? table : selector === '[data-domain-move-dialog]' ? null : message,
      addEventListener() {}, body: {append() {}},
      createElement(tag) {
        if (tag !== 'template') return {remove() {}};
        return {innerHTML: '', content: {querySelector() {
          const [kind, id] = this.owner.innerHTML.replace('<table>', '').replace('</table>', '').split(':');
          return node(kind, id);
        }}, set innerHTML(value) { this._html=value; this.content.owner=this; }, get innerHTML() { return this._html; }};
      },
    },
    window: {matchMedia: () => ({matches: true}), scrollTo() {}, scrollBy() {}, scrollX: 0, scrollY: 0},
    innerHeight: 900,
    setTimeout: () => 1, clearTimeout() {}, requestAnimationFrame: () => 1, cancelAnimationFrame() {},
    CustomEvent: class { constructor(type, {detail}) { this.type=type; this.detail=detail; } },
    URLSearchParams,
    fetch(url, options) {
      return new Promise((resolve, reject) => requests.push({url, options, resolve, reject}));
    },
    localStorage: {getItem: key => storage.get(key) ?? null,
      setItem: (key, value) => storage.set(key, value)},
    location: {reload: () => { reloads++; }},
  };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname,
    '../sitewatcher/webapp/static/sitewatcher/domain_groups.js'), 'utf8'), context);
  vm.runInNewContext(script, context);
  function event(target, clientY = 75) {
    return {target, clientY, prevented: false,
      preventDefault() { this.prevented = true; },
      dataTransfer: {setData() {}, dropEffect: ''}};
  }
  function drag(row, target) {
    events.dragstart(event(handles.find(handle => handle.row === row)));
    const over = event(target);
    events.dragover(over);
    events.drop(event(target));
    return over;
  }
  return {table, a, b, c, favorite, firstHeader, secondHeader, emptyHeader, emptyBody,
    handles, storage, message, requests, drag, reloads: () => reloads};
}
const flush = () => new Promise(resolve => setImmediate(resolve));
const confirmed = (p, target) => ({ok: true, redirected: false, json: async () => ({saved: true,
  membership: {'a.example': Number(target), 'b.example': 1, 'favorite.example': 1, 'c.example': 2},
  order: ['favorite.example', 'b.example', 'a.example', 'c.example'],
  groups: [1,2,3].map(id => ({id,
    total: Object.values({'a': Number(target), 'b':1, 'favorite':1, 'c':2}).filter(g => g===id).length,
    heading: 'header:'+id, empty: 'empty:'+id})),
})});

(async () => {
  // Headers also represent collapsed groups; empty bodies and target rows use the same move.
  for (const [targetName, expectedGroup] of [
    ['secondHeader', '2'], ['c', '2'], ['emptyHeader', '3'], ['emptyBody', '3'],
  ]) {
    const p = page();
    const before = [...p.table.children];
    const over = p.drag(p.a, p[targetName]);
    assert.equal(over.prevented, true);
    assert.equal(over.dataTransfer.dropEffect, 'move');
    assert.equal(p.requests.length, 1);
    p.drag(p.b, p.emptyHeader);
    assert.equal(p.requests.length, 1, 'A pending transfer blocks competing moves');
    const request = p.requests[0];
    assert.equal(request.url, '/settings/groups');
    assert.equal(request.options.method, 'POST');
    assert.equal(request.options.credentials, 'same-origin');
    assert.equal(request.options.headers.Accept, 'application/json');
    assert.equal(request.options.headers['X-CSRFToken'], 'csrf-fixture');
    assert.deepEqual([...request.options.body], [
      ['operation', 'move'], ['group_id', expectedGroup], ['original_group_id', '1'], ['domains', '["a.example"]'],
    ]);
    assert.deepEqual(p.table.children, before, 'Keep every row and header until confirmed');
    assert.equal(p.reloads(), 0);
    assert.equal(p.storage.get('groups-owner'), '{"1":true,"2":false}');
    assert.equal(p.table.attributes['aria-busy'], 'true');
    assert.ok(p.handles.every(handle => !handle.draggable));
    request.resolve(confirmed(p, expectedGroup));
    await flush();
    assert.equal(p.reloads(), 0, 'Never navigate after a confirmed transfer');
    assert.equal(p.a.dataset.groupId, expectedGroup);
    assert.equal(p.a.hidden, false, 'Destination is opened after save');
    assert.ok(p.table.children.includes(p.a), 'Existing row, chart and listeners are retained');
    assert.equal(p.table.children.filter(n => n === p.a).length, 1);
    const state = JSON.parse(p.storage.get('groups-owner'));
    assert.equal(state[expectedGroup], true, 'Open the destination after the confirmed transfer');
    assert.equal(state['1'], true, 'Retain the other group states');
    assert.equal(p.table.attributes['aria-busy'], 'false');
    assert.ok(p.handles.every(handle => handle.draggable));
  }

  for (const failure of ['network', 'http', 'redirect', 'unconfirmed', 'invalid-json']) {
    const p = page();
    const before = [...p.table.children];
    p.drag(p.a, p.secondHeader);
    if (failure === 'network') p.requests[0].reject(new Error('Offline'));
    else p.requests[0].resolve({
      ok: failure !== 'http', redirected: failure === 'redirect',
      json: async () => {
        if (failure === 'invalid-json') throw new Error('Invalid response');
        return {saved: failure !== 'unconfirmed'};
      },
    });
    await flush();
    assert.equal(p.requests[1].url, '/settings/groups', 'Ambiguous writes use a read-back, never a second POST');
    assert.equal(p.requests[1].options.method, undefined);
    p.requests[1].reject(new Error('Read-back unavailable'));
    await flush();
    assert.deepEqual(p.table.children, before, `${failure}: keep original groups and rows`);
    assert.equal(p.reloads(), 0);
    assert.equal(p.storage.get('groups-owner'), '{"1":true,"2":false}');
    assert.equal(p.message.textContent, 'Group move failed');
    assert.equal(p.message.classList.contains('domain-order-error'), true);
    assert.equal(p.message.classList.contains('sr-only'), false);
    assert.equal(p.a.classList.contains('domain-is-moving'), false);
    assert.ok(p.handles.every(handle => handle.draggable));
  }

  {
    const p = page();
    const before = [...p.table.children];
    const over = p.drag(p.a, p.favorite);
    assert.equal(over.prevented, false, 'Same-group favorites remain a separate ordering section');
    assert.equal(over.dataTransfer.dropEffect, 'none');
    assert.equal(p.requests.length, 0);
    assert.deepEqual(p.table.children, before);
    assert.equal(p.message.textContent, 'Favorites stay first');
  }

  {
    const p = page();
    const before = [...p.table.children];
    p.drag(p.a, p.b);
    assert.equal(p.requests[0].url, '/domains/reorder', 'Within-group drop still saves display order');
    assert.deepEqual(JSON.parse(p.requests[0].options.body.get('order')),
      ['b.example', 'a.example', 'favorite.example', 'c.example']);
    assert.equal(p.table.children[0], p.firstHeader);
    assert.equal(p.table.children[4], p.secondHeader);
    p.requests[0].resolve({ok: false});
    await flush();
    assert.deepEqual(p.table.children, before, 'Failed reorder restores headers and empty group bodies');
    assert.equal(p.message.textContent, 'Order failed');
    assert.equal(p.reloads(), 0);
  }
  {
    const p = page();
    p.drag(p.a, p.secondHeader);
    p.requests[0].reject(new Error('Response lost after commit'));
    await flush();
    assert.equal(p.requests.length, 2);
    p.requests[1].resolve(confirmed(p, '2'));
    await flush();
    assert.equal(p.a.dataset.groupId, '2', 'Read-back confirms a committed move without repeating POST');
    assert.equal(p.message.textContent, 'Moved');
    assert.equal(p.reloads(), 0);
    const empty = p.table.children.find(node => node.kind === 'header' && node.dataset.domainGroup === '3');
    p.drag(p.a, empty);
    assert.equal(p.requests[2].options.body.get('original_group_id'), '2');
    p.requests[2].resolve(confirmed(p, '3'));
    await flush();
    assert.equal(p.a.dataset.groupId, '3');
    assert.equal(p.a.hidden, false);
    assert.equal(p.requests.filter(r => r.options.method === 'POST').length, 2);
    assert.equal(p.reloads(), 0);
  }

  console.log('Domain drag: cross-group confirmation, persistence, failure recovery, favorites and header rollback passed.');
})().catch(error => { console.error(error); process.exitCode = 1; });
