// Run the shipped activity controller with a minimal DOM and controlled network/timers.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../sitewatcher/webapp/static/sitewatcher/activity.js'), 'utf8');

function page({saved = 'off', reduced = false} = {}) {
  const timers = new Map();
  const requests = [];
  const animations = [];
  const handlers = {};
  const stored = new Map([['sitewatcher_live_activity', saved]]);
  let timerId = 0;
  function node(tag = 'div') {
    return {tag, children: [], dataset: {}, style: {}, hidden: false, attrs: {}, clientWidth: 310,
      setAttribute(key, value) { this.attrs[key] = value; },
      append(...items) { for (const item of items) { item.remove(); item.parent = this; this.children.push(item); } },
      remove() { if (this.parent) this.parent.children = this.parent.children.filter(item => item !== this); },
      getAnimations() { return []; },
      animate(frames, options) { animations.push({frames, options}); },
      addEventListener(name, callback) { this[name] = callback; },
    };
  }
  const list = node('ol');
  const notice = node();
  const toggle = node('button');
  toggle.dataset = {enabledLabel: 'Hide', disabledLabel: 'Show'};
  const panel = node('section');
  panel.dataset = {timezone: 'UTC', running: 'Running', milliseconds: 'ms', interrupted: 'Interrupted', idle: 'Idle',
    waiting: 'Waiting', unavailable: 'Unavailable'};
  panel.querySelector = selector => selector === '[data-activity-lanes]' ? list : notice;
  const document = {hidden: false, documentElement: {lang: 'en'},
    querySelector: selector => selector === '[data-live-activity]' ? panel : toggle,
    createElement: node, addEventListener(name, callback) { handlers[name] = callback; }};
  vm.runInNewContext(source, {document, Intl, AbortController, encodeURIComponent,
    window: {matchMedia: () => ({matches: reduced, addEventListener() {}}), addEventListener() {}},
    localStorage: {getItem: key => stored.get(key), setItem: (key, value) => stored.set(key, value)},
    setTimeout: (callback, delay) => { timers.set(++timerId, {callback, delay}); return timerId; },
    clearTimeout: id => timers.delete(id),
    fetch: (url, options) => new Promise(resolve => requests.push({url, options, resolve})),
  });
  const flush = async () => { for (let i = 0; i < 8; i++) await Promise.resolve(); };
  const respond = async (events, ok = true) => {
    requests.at(-1).resolve({ok, json: async () => ({events})});
    await flush();
  };
  const tick = () => { const entries = [...timers.values()]; timers.clear(); entries.forEach(({callback}) => callback()); };
  return {panel, toggle, list, notice, document, timers, requests, animations, handlers, respond, tick, stored};
}
const event = (id, phase = 'finished') => ({id, domain: '<script>.example', label: 'TLS certificate',
  phase, status: phase === 'running' ? 'UNKNOWN' : 'OK', status_label: 'Healthy',
  started_at: '2026-11-03T13:00:00Z', finished_at: phase === 'running' ? null : '2026-11-03T13:00:01Z',
  elapsed_ms: phase === 'running' ? null : 1000});
(async () => {
  let p = page();
  assert.equal(p.requests.length, 0);
  assert.equal(p.panel.hidden, true);
  p.toggle.click();
  assert.equal(p.requests.length, 1);
  assert.equal(p.requests[0].url, '/api/activity');
  await p.respond([event(1)]);
  assert.equal(p.animations.length, 0, 'baseline must not replay old checks');
  assert.equal(p.list.children[0].children[0].children[1].textContent, '<script>.example');
  assert.equal(p.timers.size, 1);
  assert.equal([...p.timers.values()][0].delay, 2000);
  p.tick();
  await p.respond([event(1), event(2, 'running')]);
  assert.equal(p.animations.length, 1);
  p.tick();
  await p.respond([event(1), event(2)]);
  assert.equal(p.animations.length, 2, 'completion returns signal');
  p.tick();
  await p.respond([event(1), event(2)]);
  assert.equal(p.animations.length, 2, 'same completion must not replay');
  p.tick();
  const inflight = p.requests.at(-1);
  p.toggle.click();
  assert.equal(inflight.options.signal.aborted, true);
  assert.equal(p.timers.size, 0);
  await p.respond([event(3)]);
  assert.equal(p.timers.size, 0, 'late response cannot restart disabled polling');
  assert.equal(p.stored.get('sitewatcher_live_activity'), 'off');

  p = page({saved: 'on', reduced: true});
  await p.respond([]);
  p.tick();
  await p.respond(Array.from({length: 100}, (_, i) => event(i)));
  assert.equal(p.list.children.length, 6, 'bursts remain bounded');
  assert.equal(p.animations.length, 0, 'reduced motion keeps real data without animation');
  p.tick();
  p.document.hidden = true;
  p.handlers.visibilitychange();
  assert.equal(p.requests.at(-1).options.signal.aborted, true);
  assert.equal(p.timers.size, 0);
  p.document.hidden = false;
  p.handlers.visibilitychange();
  await p.respond([], false);
  assert.equal(p.notice.textContent, 'Unavailable');
  assert.equal(p.timers.size, 1, 'temporary failures reconnect without overlapping requests');
  console.log('Live activity: optional polling, lifecycle signals, deduplication, hidden/disabled cancellation, reduced motion and bounded bursts passed.');
})().catch(error => { console.error(error); process.exitCode = 1; });
