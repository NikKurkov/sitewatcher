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
      moveFailed: 'Group move failed', groupStorageKey: 'groups-owner'},
    attributes: {}, children: [],
    setAttribute(name, value) { this.attributes[name] = value; },
    addEventListener(name, handler) { events[name] = handler; },
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
      classList: classes(),
      matches: selector => selector === 'tbody[data-domain-name]' && Boolean(domainName),
      closest(selector) {
        if (selector === 'tbody[data-domain-name]') return domainName ? this : null;
        if (selector === '[data-domain-group], tbody[data-group-id]') return this;
        return null;
      },
      getBoundingClientRect: () => ({top: 0, height: 100}),
    };
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
  table.querySelectorAll = () => handles;
  vm.runInNewContext(script, {
    document: {querySelector: selector => selector === '[data-domain-order]' ? table : message},
    URLSearchParams,
    fetch(url, options) {
      return new Promise((resolve, reject) => requests.push({url, options, resolve, reject}));
    },
    localStorage: {getItem: key => storage.get(key) ?? null,
      setItem: (key, value) => storage.set(key, value)},
    location: {reload: () => { reloads++; }},
  });
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
const confirmed = {ok: true, redirected: false, json: async () => ({saved: true})};

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
    const request = p.requests[0];
    assert.equal(request.url, '/settings/groups');
    assert.equal(request.options.method, 'POST');
    assert.equal(request.options.credentials, 'same-origin');
    assert.equal(request.options.headers.Accept, 'application/json');
    assert.equal(request.options.headers['X-CSRFToken'], 'csrf-fixture');
    assert.deepEqual([...request.options.body], [
      ['operation', 'move'], ['group_id', expectedGroup], ['domains', '["a.example"]'],
    ]);
    assert.deepEqual(p.table.children, before, 'Keep every row and header until confirmed');
    assert.equal(p.reloads(), 0);
    assert.equal(p.storage.get('groups-owner'), '{"1":true,"2":false}');
    assert.equal(p.table.attributes['aria-busy'], 'true');
    assert.ok(p.handles.every(handle => !handle.draggable));
    request.resolve(confirmed);
    await flush();
    assert.equal(p.reloads(), 1);
    const state = JSON.parse(p.storage.get('groups-owner'));
    assert.equal(state[expectedGroup], true, 'Open the destination after the confirmed reload');
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
  console.log('Domain drag: cross-group confirmation, persistence, failure recovery, favorites and header rollback passed.');
})().catch(error => { console.error(error); process.exitCode = 1; });
