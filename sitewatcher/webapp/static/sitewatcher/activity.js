// Activity is read-only: opening this view never starts a website check.
(() => {
  const panel = document.querySelector('[data-live-activity]');
  const toggle = document.querySelector('[data-activity-toggle]');
  if (!panel || !toggle) return;
  const list = panel.querySelector('[data-activity-lanes]');
  const notice = panel.querySelector('[data-activity-status]');
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
  const storageKey = 'sitewatcher_live_activity';
  let enabled = false;
  let timer;
  let pending;
  let previous = null;
  const lanes = new Map();
  const clock = new Intl.DateTimeFormat(document.documentElement.lang, {
    timeZone: panel.dataset.timezone, hour: '2-digit', minute: '2-digit', second: '2-digit',
  });

  const stop = () => {
    clearTimeout(timer);
    pending?.abort();
    pending = null;
    for (const lane of lanes.values()) lane.ball.getAnimations().forEach(animation => animation.cancel());
  };
  const makeLane = (event) => {
    const row = document.createElement('li');
    row.className = 'activity-lane';
    const heading = document.createElement('div');
    heading.className = 'activity-lane-heading';
    const label = document.createElement('span');
    label.textContent = event.label;
    const domain = document.createElement('a');
    domain.href = `/domains/history?domain=${encodeURIComponent(event.domain)}`;
    domain.textContent = event.domain;
    const state = document.createElement('span');
    state.className = 'activity-result';
    const time = document.createElement('time');
    heading.append(label, domain, state, time);
    const track = document.createElement('div');
    track.className = 'activity-track';
    track.setAttribute('aria-hidden', 'true');
    const origin = document.createElement('span');
    origin.className = 'activity-origin';
    origin.textContent = '◉';
    const wire = document.createElement('span');
    wire.className = 'activity-wire';
    const ball = document.createElement('span');
    ball.className = 'activity-ball';
    wire.append(ball);
    const server = document.createElement('span');
    server.className = 'activity-server';
    // A server icon built locally; all event strings are assigned with textContent.
    server.textContent = '▤';
    track.append(origin, wire, server);
    row.append(heading, track);
    return {row, state, time, wire, ball};
  };
  const phase = event => event.phase === 'running' ? 'running' : `${event.phase}:${event.status}`;
  const render = (events) => {
    const selected = [...events].sort((a, b) =>
      Number(b.phase === 'running') - Number(a.phase === 'running') || b.id - a.id).slice(0, 6);
    const ids = new Set(selected.map(event => event.id));
    for (const [id, lane] of lanes) {
      if (!ids.has(id)) { lane.row.remove(); lanes.delete(id); }
    }
    for (const event of selected) {
      let lane = lanes.get(event.id);
      if (!lane) { lane = makeLane(event); lanes.set(event.id, lane); }
      list.append(lane.row);
      const running = event.phase === 'running';
      const result = running ? 'running' : ['OK', 'WARN', 'CRIT'].includes(event.status)
        ? event.status.toLowerCase() : 'unknown';
      lane.row.dataset.state = result;
      lane.state.textContent = running ? panel.dataset.running : event.phase === 'interrupted'
        ? panel.dataset.interrupted : event.status_label;
      if (event.elapsed_ms !== null && !running) lane.state.textContent += ` · ${event.elapsed_ms} ${panel.dataset.milliseconds}`;
      const stamp = event.finished_at || event.started_at;
      lane.time.dateTime = stamp;
      lane.time.textContent = clock.format(new Date(stamp));
      const distance = Math.max(0, lane.wire.clientWidth - 10);
      lane.ball.style.transform = `translateX(${running ? distance : 0}px)`;
      const changed = previous !== null && previous.get(event.id) !== phase(event);
      if (!changed) continue;
      lane.ball.getAnimations().forEach(animation => animation.cancel());
      if (reducedMotion.matches || event.phase === 'interrupted') continue;
      const at = pixels => ({transform: `translateX(${pixels}px)`});
      const frames = running ? [at(0), at(distance)] : previous.has(event.id)
        ? [at(distance), at(0)] : [at(0), at(distance), at(0)];
      lane.ball.animate(frames, {duration: !running && !previous.has(event.id) ? 1300 : 650,
        easing: 'ease-in-out'});
    }
    previous = new Map(events.map(event => [event.id, phase(event)]));
    const runningCount = events.filter(event => event.phase === 'running').length;
    notice.textContent = runningCount ? `${panel.dataset.running}: ${runningCount}`
      : events.length ? panel.dataset.idle : panel.dataset.waiting;
  };
  const poll = async () => {
    if (!enabled || document.hidden || pending) return;
    const controller = new AbortController();
    pending = controller;
    try {
      const response = await fetch('/api/activity', {
        credentials: 'same-origin', cache: 'no-store', signal: controller.signal,
        headers: {Accept: 'application/json'},
      });
      if (!response.ok || response.redirected) throw new Error('Activity unavailable');
      const payload = await response.json();
      if (pending === controller && enabled && !document.hidden) render(payload.events);
    } catch (error) {
      if (pending === controller && error.name !== 'AbortError') notice.textContent = panel.dataset.unavailable;
    } finally {
      if (pending === controller) {
        pending = null;
        if (enabled && !document.hidden) timer = setTimeout(poll, 2000);
      }
    }
  };
  const setEnabled = (value) => {
    enabled = value;
    panel.hidden = !value;
    toggle.setAttribute('aria-pressed', String(value));
    toggle.title = value ? toggle.dataset.enabledLabel : toggle.dataset.disabledLabel;
    stop();
    if (value) {
      previous = null;
      poll();
    }
  };
  toggle.hidden = false;
  toggle.addEventListener('click', () => {
    setEnabled(!enabled);
    try { localStorage.setItem(storageKey, enabled ? 'on' : 'off'); } catch {}
  });
  document.addEventListener('visibilitychange', () => {
    stop();
    if (enabled && !document.hidden) { previous = null; poll(); }
  });
  window.addEventListener('pagehide', stop);
  reducedMotion.addEventListener('change', () => {
    for (const lane of lanes.values()) lane.ball.getAnimations().forEach(animation => animation.cancel());
  });
  try { setEnabled(localStorage.getItem(storageKey) === 'on'); } catch { setEnabled(false); }
})();
