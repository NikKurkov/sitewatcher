// Execute the shipped SVG scene with a fake DOM, independent animation clock and network.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../sitewatcher/webapp/static/sitewatcher/activity.js'), 'utf8');
const epoch = Date.parse('2026-11-03T13:00:00Z');

function page({saved = 'on', reduced = false, width = 1000, publicView = false} = {}) {
  const timers = new Map();
  const frames = new Map();
  const requests = [];
  const stored = new Map([['sitewatcher_live_activity', saved], ['sitewatcher_public_live_activity', saved]]);
  const handlers = {};
  const windowHandlers = {};
  const mediaHandlers = {};
  let sequence = 0;
  let now = 0;
  let wallTime = epoch;
  let resize;
  function node(tag = 'div') {
    const classes = new Set();
    const listeners = {};
    const element = {tag, children: [], dataset: {}, style: {}, hidden: false, attrs: {},
      clientWidth: width, clientHeight: 100, scrollTop: 0, offsetHeight: 20, value: 'slow',
      classList: {
        add(...names) { names.forEach(name => classes.add(name)); },
        remove(...names) { names.forEach(name => classes.delete(name)); },
        toggle(name, force) {
          const present = force === undefined ? !classes.has(name) : force;
          if (present) classes.add(name); else classes.delete(name);
          return present;
        },
        contains(name) { return classes.has(name); },
      },
      setAttribute(key, value) { this.attrs[key] = String(value); },
      getAttribute(key) { return this.attrs[key] ?? null; },
      append(...items) {
        for (let item of items) {
          if (typeof item === 'string') item = Object.assign(node('#text'), {textContent: item});
          item.remove();
          item.parentNode = this;
          this.children.push(item);
        }
      },
      remove() {
        if (this.parentNode) {
          this.parentNode.children = this.parentNode.children.filter(item => item !== this);
          this.parentNode = null;
        }
      },
      replaceChildren(...items) {
        for (const child of [...this.children]) child.remove();
        this._text = '';
        this.append(...items);
      },
      addEventListener(name, callback) { listeners[name] = callback; },
      dispatch(name) { listeners[name]?.(); },
      click() { this.dispatch('click'); },
      focus() {},
    };
    Object.defineProperties(element, {
      firstElementChild: {get() { return this.children[0]; }},
      textContent: {
        get() { return (this._text || '') + this.children.map(child => child.textContent).join(''); },
        set(value) { this.replaceChildren(); this._text = String(value); },
      },
      innerHTML: {set() { throw new Error('Activity output must use text nodes, never innerHTML'); }},
      scrollHeight: {get() { return this.children.reduce((height, child) => height + Math.max(20, child.scrollHeight), 0); }},
    });
    return element;
  }
  const selectors = ['activity-scene', 'scene-links', 'scene-nodes', 'scene-pulses', 'scene-hub',
    'activity-status', 'scene-mode', 'scene-empty', 'scene-overflow', 'scene-pause', 'scene-speed',
    'scene-replay', 'scene-fullscreen', 'activity-console', 'console-scroll', 'console-follow',
    'activity-accessible', 'domain-map', 'map-count', 'map-detail', 'map-unpin', 'scene-sent', 'scene-returned', 'scene-active', 'console-count', 'scene-pause-label', 'critical-panel', 'critical-list', 'critical-count', 'critical-connection'];
  const elements = Object.fromEntries(selectors.map(name => [name, node(name === 'activity-scene' ? 'svg' : 'div')]));
  const get = name => elements[name];
  get('console-scroll').append(get('activity-console'));
  get('scene-pause').dataset = {pauseLabel: 'Pause', resumeLabel: 'Resume'};
  const toggle = node('button');
  toggle.dataset = {enabledLabel: 'Hide', disabledLabel: 'Show'};
  const panel = node('section');
  panel.dataset = {timezone: 'UTC', running: 'Running', milliseconds: 'ms', interrupted: 'Interrupted',
    idle: 'Idle', waiting: 'Waiting', unavailable: 'Unavailable', reducedLabel: 'Reduced motion',
    pausedLabel: 'Paused', mixedLabel: 'Mixed', recordedLabel: 'Recorded', liveLabel: 'Live',
    pinnedLabel: 'Pinned', selectLabel: 'Select a domain', selectedLabel: 'Selected domain', logOnly: 'Log only', newEvents: 'New events', followLabel: 'Follow'};
  if (publicView) Object.assign(panel.dataset, {publicActivity: 'true', activityEndpoint: 'activity'});
  panel.querySelector = selector => elements[selector.slice(6, -1)] || null;
  const document = {hidden: false, documentElement: {lang: 'en'}, body: node('body'),
    querySelector: selector => selector === '[data-live-activity]' ? panel : toggle,
    createElement: node, createElementNS: (_, tag) => node(tag),
    addEventListener(name, callback) { handlers[name] = callback; }};
  const media = {matches: reduced, addEventListener(name, callback) { mediaHandlers[name] = callback; }};
  class ClockDate extends Date { static now() { return wallTime; } }
  vm.runInNewContext(source, {document, Intl, Date: ClockDate, AbortController, encodeURIComponent,
    window: {matchMedia: () => media, addEventListener(name, callback) { windowHandlers[name] = callback; }},
    ResizeObserver: class { constructor(callback) { this.callback = callback; resize = callback; } observe() { this.callback(); } },
    localStorage: {getItem: key => stored.get(key), setItem: (key, value) => stored.set(key, value)},
    setTimeout: (callback, delay) => { timers.set(++sequence, {callback, delay}); return sequence; },
    clearTimeout: id => timers.delete(id),
    requestAnimationFrame: callback => { frames.set(++sequence, callback); return sequence; },
    cancelAnimationFrame: id => frames.delete(id),
    fetch: (url, options) => new Promise((resolve, reject) => requests.push({url, options, resolve, reject})),
  });
  const flush = async () => { for (let i = 0; i < 10; i++) await Promise.resolve(); };
  const respond = async (events, {ok = true, redirected = false, request = requests.at(-1),
    status = 200, incidents = [], domains = [...new Set(events.map(event => event.domain))].sort().map(name => ({name, status: 'UNKNOWN', label: '', status_label: 'No data'}))} = {}) => {
    request.resolve({ok, redirected, status, json: async () => ({events, domains, critical_incidents: incidents})});
    await flush();
  };
  const poll = () => {
    const entry = [...timers].find(([, timer]) => timer.delay === 2000);
    assert.ok(entry, 'a single future poll must exist');
    timers.delete(entry[0]);
    entry[1].callback();
  };
  const frame = (delta = 40) => {
    now += delta;
    wallTime += delta;
    const pending = [...frames.values()];
    frames.clear();
    pending.forEach(callback => callback(now));
  };
  const advance = milliseconds => { for (let elapsed = 0; elapsed < milliseconds; elapsed += 40) frame(40); };
  const count = name => Number(get(`scene-${name}`).textContent);
  const pulses = () => get('scene-pulses').children;
  const position = () => {
    assert.ok(pulses().length, 'a visible flight must exist');
    // Trail circles, aura, then the rectangular head; inspect actual SVG coordinates.
    const transform = pulses()[0].children.find(child => child.tag === 'rect').getAttribute('transform');
    return transform.match(/translate\(([-\d.]+) ([-\d.]+)\)/).slice(1).map(Number);
  };
  return {panel, toggle, get, document, timers, frames, requests, stored, media,
    respond, flush, poll, frame, advance, count, pulses, position,
    visibility(hidden) { document.hidden = hidden; handlers.visibilitychange(); },
    reduced(value) { media.matches = value; mediaHandlers.change(); },
    resize(width) { get('activity-scene').clientWidth = width; resize(); },
    pagehide() { windowHandlers.pagehide(); }};
}
const event = (id, phase = 'finished', extra = {}) => ({id, domain: `site-${id}.example`, label: 'TLS certificate',
  phase, status: phase === 'running' ? 'UNKNOWN' : 'OK', status_label: 'Healthy',
  started_at: '2026-11-03T13:00:00Z', finished_at: phase === 'running' ? null : '2026-11-03T13:00:01Z',
  elapsed_ms: phase === 'running' ? null : 1000, ...extra});

async function journey() {
  const p = page({saved: 'off'});
  assert.equal(p.requests.length, 0);
  assert.equal(p.panel.hidden, true);
  p.toggle.click();
  assert.equal(p.requests.length, 1);
  assert.equal(p.requests[0].url, '/api/activity');
  assert.equal(p.requests[0].options.credentials, 'same-origin');
  await p.respond([event(1, 'running')]);
  p.frame();
  const start = p.position()[0];
  p.advance(1960);
  const halfway = p.position()[0];
  assert.ok(halfway > start + 100 && halfway < 700, 'slow outbound takes seconds, following the SVG curve');
  assert.equal(p.count('returned'), 0);
  p.advance(2200);
  const destination = p.position()[0];
  assert.ok(destination > 700, 'outbound reaches the remote station');
  p.advance(10000);
  assert.equal(p.position()[0], destination, 'a running check waits at its station until a finish event');
  assert.equal(p.count('returned'), 0, 'elapsed animation time cannot invent a completed check');
  assert.equal(p.frames.size, 0, 'waiting running checks do not burn animation frames');
  p.poll();
  await p.respond([event(1)]);
  p.frame();
  p.advance(2400);
  assert.ok(p.position()[0] < destination && p.position()[0] > start + 100, 'completion travels back slowly');
  assert.equal(p.count('returned'), 0);
  p.advance(2400);
  assert.equal(p.count('returned'), 1);
  assert.equal(p.pulses().length, 0);
  assert.equal(p.get('activity-console').children.length, 2, 'running and completion are distinct log entries');
  p.poll();
  await p.respond([event(1)]);
  p.advance(6000);
  assert.equal(p.count('sent'), 1, 'duplicate completion does not launch another journey');
  assert.equal(p.get('activity-console').children.length, 2, 'duplicate completion does not repeat in console');
}

async function pausedPolling() {
  const p = page();
  await p.respond([event(1, 'running')]);
  p.frame();
  p.advance(1000);
  const before = p.position();
  p.get('scene-pause').click();
  assert.equal(p.frames.size, 0);
  assert.equal(p.get('scene-mode').textContent, 'Paused');
  p.advance(10000);
  assert.deepEqual(p.position(), before, 'pause freezes the visual clock');
  p.poll();
  await p.respond([event(1), event(2, 'running')]);
  assert.equal(p.requests.length, 2, 'pause retains network polling');
  assert.equal(p.get('activity-console').children.length, 3, 'console receives real events while visual clock is paused');
  assert.deepEqual(p.position(), before);
  p.get('scene-pause').click();
  p.frame();
  p.advance(1000);
  assert.ok(p.position()[0] > before[0], 'resume continues without catching up in one frame');
  p.get('scene-speed').value = 'slower';
  p.get('scene-speed').dispatch('change');
  assert.equal(p.stored.get('sitewatcher_scene_speed'), 'slower');
}

async function burstAndConsole() {
  const p = page();
  await p.respond([]);
  p.get('console-scroll').scrollTop = 0;
  p.get('console-scroll').dispatch('scroll');
  p.poll();
  await p.respond(Array.from({length: 130}, (_, index) => event(index + 1)));
  assert.equal(p.get('activity-console').children.length, 100, 'console is bounded');
  assert.equal(p.get('console-count').textContent, '100');
  assert.ok(p.get('scene-nodes').children.length <= 6, 'stations are bounded');
  assert.equal(p.get('activity-accessible').children.length, 6);
  assert.equal(p.get('scene-overflow').hidden, false, 'excess visuals remain represented by log-only counter');
  let maxFlights = 0;
  for (let i = 0; i < 1000; i++) {
    p.frame();
    maxFlights = Math.max(maxFlights, p.pulses().length);
  }
  assert.ok(maxFlights <= 3, 'wide scene bounds concurrent flights');
  assert.ok(p.count('sent') <= 6, 'a burst leaves only a bounded visual backlog');
  assert.equal(p.count('sent'), p.count('returned'));
  assert.equal(p.pulses().length, 0);
  p.get('console-scroll').scrollTop = 0;
  p.get('console-scroll').dispatch('scroll');
  const top = p.get('console-scroll').scrollTop;
  p.poll();
  await p.respond([event(200)]);
  assert.equal(p.get('console-follow').textContent, 'New events: 1');
  assert.equal(p.get('console-scroll').scrollTop, top, 'reading old console output does not jump to the end');
  p.get('console-follow').click();
  assert.equal(p.get('console-follow').textContent, 'Follow');
  assert.equal(p.get('console-scroll').scrollTop, p.get('console-scroll').scrollHeight);

  const compact = page({width: 600});
  await compact.respond(Array.from({length: 20}, (_, index) => event(index)));
  assert.equal(compact.panel.dataset.sceneLayout, 'compact');
  for (let i = 0; i < 200; i++) {
    compact.frame();
    assert.ok(compact.pulses().length <= 2, 'compact scene bounds concurrent flights');
    assert.ok(compact.get('scene-nodes').children.length <= 4);
  }
}

async function reducedMotionAndSafety() {
  const p = page({reduced: true});
  const unsafe = '<img src=x onerror=alert(1)>.example';
  const label = '<script>alert(2)</script>';
  await p.respond([event(1, 'running', {domain: unsafe, label})]);
  assert.equal(p.frames.size, 0);
  assert.equal(p.pulses().length, 0);
  assert.equal(p.get('scene-mode').textContent, 'Reduced motion');
  assert.equal(p.get('scene-pause').disabled, true);
  assert.equal(p.get('scene-speed').disabled, true);
  const row = p.get('activity-console').children[0];
  assert.ok(row.textContent.includes(unsafe) && row.textContent.includes(label));
  const domainLink = row.children.find(child => child.tag === 'a');
  assert.ok(row.children.some(child => child.className === 'console-check'), 'check has its own field');
  assert.ok(row.children.some(child => child.className === 'console-duration'), 'duration has its own field');
  assert.equal(domainLink.href, `/domains/history?domain=${encodeURIComponent(unsafe)}`);
  assert.ok(p.get('activity-accessible').textContent.includes(unsafe));
  assert.ok(p.get('domain-map').children[0].attrs['aria-label'].includes(unsafe), 'static map retains full domain as accessible text');
  p.poll();
  await p.respond([event(1, 'finished', {domain: unsafe, label})]);
  assert.equal(p.get('activity-console').children.length, 2);
  assert.equal(p.pulses().length, 0, 'reduced motion still consumes completion data');
  assert.equal(p.get('scene-replay').disabled, true, 'reduced motion disables recorded animation replay');

  const live = page();
  await live.respond([event(1, 'running')]);
  live.frame();
  assert.equal(live.pulses().length, 1);
  live.reduced(true);
  assert.equal(live.frames.size, 0);
  assert.equal(live.pulses().length, 0, 'changing reduced motion clears in-flight visuals');
  live.poll();
  await live.respond([event(1)]);
  assert.equal(live.get('activity-console').children.length, 2, 'changing reduced motion preserves polling');
  assert.equal(live.get('scene-replay').disabled, true);
  live.reduced(false);
  assert.equal(live.get('scene-replay').disabled, false, 'replay becomes available when motion is enabled again');
}

async function missingRunningRetiresWithoutResponse() {
  const p = page();
  await p.respond([event(1, 'running'), event(2, 'running'), event(3, 'running')]);
  p.frame();
  assert.equal(p.count('sent'), 1, 'one running flight launched while two remain queued');
  assert.equal(p.get('activity-console').children.length, 3);
  p.poll();
  await p.respond([]);
  assert.equal(p.get('activity-accessible').children.length, 0, 'absent records leave the accessible snapshot');
  assert.equal(p.get('activity-status').textContent, 'Waiting');
  p.advance(6000);
  assert.equal(p.pulses().length, 0, 'a missing running flight fades and frees its slot');
  assert.equal(p.count('active'), 0);
  assert.equal(p.count('sent'), 1, 'absent queued running checks are never launched');
  assert.equal(p.count('returned'), 0, 'a vanished running event cannot fabricate a response');
  assert.equal(p.get('activity-console').children.length, 3, 'retiring visuals cannot fabricate console events');
  assert.equal(p.get('scene-replay').disabled, true, 'no stale completion remains available for replay');
  p.poll();
  await p.respond([event(4, 'running')]);
  p.frame();
  assert.equal(p.count('active'), 1, 'the retired flight no longer holds scene capacity');
  assert.equal(p.count('sent'), 2);
}

async function cancellationAndFailures() {
  const p = page();
  const first = p.requests[0];
  p.toggle.click();
  assert.equal(first.options.signal.aborted, true);
  assert.equal(p.frames.size, 0);
  assert.equal(p.timers.size, 0);
  await p.respond([event(1)], {request: first});
  assert.equal(p.timers.size, 0, 'late disabled response cannot restart polling');
  assert.equal(p.get('activity-console').children.length, 0);
  assert.equal(p.stored.get('sitewatcher_live_activity'), 'off');
  p.toggle.click();
  const second = p.requests.at(-1);
  p.visibility(true);
  assert.equal(second.options.signal.aborted, true);
  assert.equal(p.frames.size, 0);
  assert.equal(p.timers.size, 0);
  p.visibility(false);
  const current = p.requests.at(-1);
  assert.notEqual(current, second);
  await p.respond([event(999)], {request: second});
  assert.equal(p.get('activity-console').children.length, 0, 'hidden request cannot overwrite a resumed session');
  await p.respond([], {ok: false, request: current});
  assert.equal(p.get('activity-status').textContent, 'Unavailable');
  assert.equal(p.timers.size, 1, 'failure schedules one retry');
  p.poll();
  await p.respond([], {redirected: true});
  assert.equal(p.get('activity-status').textContent, 'Unavailable', 'authentication redirects are not activity data');
  assert.equal(p.timers.size, 1);
  p.poll();
  const pending = p.requests.at(-1);
  p.pagehide();
  assert.equal(pending.options.signal.aborted, true);
  assert.equal(p.timers.size, 0);
  assert.equal(p.frames.size, 0);
}

async function pinnedCardSurvivesResize() {
  const p = page();
  const domains = [1, 2, 3, 4].map(id => ({name: `site-${id}.example`, status: 'OK', label: '', status_label: 'Healthy'}));
  await p.respond([event(1, 'running'), event(2, 'running'), event(3, 'running')], {domains});
  p.get('domain-map').children[3].click();
  p.advance(3100);
  assert.equal(p.count('active'), 3);
  p.resize(350);
  assert.equal(p.get('scene-nodes').children.length, 4);
  assert.ok(p.get('scene-nodes').children.some(node => node.dataset.pinned === 'true'), 'selected idle domain survives resizing three active journeys to mobile');
  for (const node of p.get('scene-nodes').children) assert.ok(!node.attrs.transform.includes('undefined'));
}

async function domainMapAndRetirement() {
  const p = page();
  const domains = Array.from({length: 50}, (_, i) => ({name: `map-${String(i).padStart(2, '0')}.example`, status: 'OK', label: 'TLS certificate', status_label: 'Healthy'}));
  await p.respond([], {domains});
  assert.equal(p.get('domain-map').children.length, 50, 'all domains exist even with no recent events');
  assert.equal(p.get('scene-nodes').children.length, 0, 'idle map does not fill large cards');
  const first = p.get('domain-map').children[0];
  first.dispatch('mouseenter');
  const description = p.get('map-detail').textContent;
  p.poll();
  await p.respond([], {domains});
  assert.equal(p.get('map-detail').textContent, description, 'polling does not erase the hovered domain details');
  first.click();
  assert.equal(first.attrs['aria-pressed'], 'true');
  assert.equal(p.get('scene-nodes').children.length, 1, 'pin reveals an idle domain without inventing a probe');
  assert.equal(p.count('sent'), 0);
  p.poll();
  await p.respond([event(8, 'finished', {domain: domains[1].name})], {domains});
  p.advance(12500);
  assert.equal(p.count('returned'), 1);
  assert.equal(p.get('scene-nodes').children.length, 1, 'finished card collapses; pinned card remains');
  assert.equal(p.get('domain-map').children[0], first, 'polling preserves button identity and keyboard focus');
  first.click();
  p.advance(3000);
  assert.equal(p.get('scene-nodes').children.length, 0, 'unpin releases the idle card');
  p.poll();
  await p.respond([], {domains: domains.slice(1)});
  assert.equal(p.get('domain-map').children.length, 49, 'deleted domain leaves the map');
  assert.equal(first.parentNode, null);
  p.reduced(true);
  p.get('domain-map').children[0].click();
  assert.equal(p.get('scene-nodes').children.length, 1);
  p.get('map-unpin').click();
  assert.equal(p.get('scene-nodes').children.length, 0, 'reduced motion unpins immediately without an animation clock');
  p.get('domain-map').children[0].click();
  p.poll();
  await p.respond([], {domains: domains.slice(2)});
  assert.equal(p.get('scene-nodes').children.length, 0, 'deleting a selected domain removes its static card');
}

async function publicActivityScope() {
  const p = page({publicView: true});
  assert.equal(p.requests[0].url, 'activity', 'capability endpoint is relative; token is never copied into markup/storage');
  assert.equal(p.requests[0].options.credentials, 'omit');
  assert.equal(p.requests[0].options.referrerPolicy, 'no-referrer');
  await p.respond([event('opaque-first')]);
  const row = p.get('activity-console').children[0];
  assert.equal(row.children[2].children.some(child => child.tag === 'a'), false, 'public console has no owner-history links');
  p.poll();
  await p.respond([event('opaque-second')]);
  assert.equal(p.get('activity-console').children.length, 1, 'removing publication also removes old console entries');
  p.advance(1000);
  p.poll();
  await p.respond([], {ok: false, status: 404});
  assert.equal(p.get('domain-map').children.length, 0, 'revoked link clears the map');
  assert.equal(p.get('activity-console').children.length, 0, 'revoked link clears the console');
  assert.equal(p.pulses().length, 0);
  p.toggle.click();
  assert.equal(p.stored.get('sitewatcher_public_live_activity'), 'off');
  assert.equal(p.stored.get('sitewatcher_live_activity'), 'on', 'public and owner toggles have independent preferences');
  p.toggle.click();
  const stale = p.requests.at(-1);
  p.toggle.click();
  p.toggle.click();
  await p.respond([event('current')]);
  await p.respond([], {ok: false, status: 404, request: stale});
  assert.equal(p.get('domain-map').children.length, 1, 'a late revoked response cannot clear a newer live session');
  assert.equal(p.get('activity-console').children.length, 1);
}

(async () => {
  for (const test of [publicActivityScope, domainMapAndRetirement, pinnedCardSurvivesResize, journey, pausedPolling, burstAndConsole, reducedMotionAndSafety, missingRunningRetiresWithoutResponse, cancellationAndFailures]) {
    await test();
    console.log(`Live activity: ${test.name} passed`);
  }
})().catch(error => { console.error(error); process.exitCode = 1; });

(async () => {
  const p = page();
  const incidents = [{domain: '<script>.example', paused: false, checks: [
    {name: 'http_basic', label: 'HTTP unavailable', opened_at: '2026-11-03T12:00:00Z', status: 'CRIT', stale: false},
    {name: 'tls_cert', label: 'TLS certificate', opened_at: '2026-11-03T12:05:00Z', status: 'UNKNOWN', stale: true},
  ]}];
  await p.respond([], {incidents});
  assert.equal(p.get('critical-panel').hidden, false);
  assert.equal(p.get('critical-count').textContent, '2');
  assert.equal(p.get('critical-list').children.length, 1);
  const row = p.get('critical-list').children[0];
  assert.ok(row.textContent.includes('<script>.example'), 'domain is displayed as text');
  p.get('scene-pause').click();
  p.get('scene-replay').click();
  assert.equal(p.get('critical-list').children[0], row, 'animation controls do not clear incidents');
  p.poll();
  await p.respond([], {ok: false});
  assert.equal(p.get('critical-panel').hidden, false);
  assert.equal(p.get('critical-list').children[0], row, 'failed transport retains incident rows');
  assert.equal(p.get('critical-connection').hidden, false);
  p.poll();
  await p.respond([], {incidents});
  assert.equal(p.get('critical-list').children[0], row, 'stable updates preserve reading and disclosure');
  assert.equal(p.get('critical-connection').hidden, true);
  p.poll();
  await p.respond([]);
  assert.equal(p.get('critical-panel').hidden, true, 'only a successful authoritative snapshot clears it');
  console.log('Critical panel: grouped stable DOM, safe text, pause/replay and failed transport retention passed.');
})().catch(error => { console.error(error); process.exitCode = 1; });
