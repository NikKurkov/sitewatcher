// A slow visual clock follows real check events; it never starts or delays monitoring.
(() => {
  const panel = document.querySelector('[data-live-activity]');
  const toggle = document.querySelector('[data-activity-toggle]');
  if (!panel || !toggle) return;
  const find = selector => panel.querySelector(selector);
  const svg = find('[data-activity-scene]');
  const canvas = find('[data-scene-scroll]') || svg;
  const links = find('[data-scene-links]');
  const stations = find('[data-scene-nodes]');
  const particles = find('[data-scene-pulses]');
  const hub = find('[data-scene-hub]');
  const notice = find('[data-activity-status]');
  const mode = find('[data-scene-mode]');
  const empty = find('[data-scene-empty]');
  const overflow = find('[data-scene-overflow]');
  const pause = find('[data-scene-pause]');
  const speed = find('[data-scene-speed]');
  const replay = find('[data-scene-replay]');
  const expand = find('[data-scene-fullscreen]');
  const log = find('[data-activity-console]');
  const scroll = find('[data-console-scroll]');
  const follow = find('[data-console-follow]');
  const accessible = find('[data-activity-accessible]');
  const domainMap = find('[data-domain-map]');
  const mapDetail = find('[data-map-detail]');
  const unpin = find('[data-map-unpin]');
  const criticalPanel = find('[data-critical-panel]');
  const criticalList = find('[data-critical-list]');
  const criticalCount = find('[data-critical-count]');
  const criticalConnection = find('[data-critical-connection]');
  const incidentRows = new Map();
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)');
  const publicView = panel.dataset.publicActivity === 'true';
  const storageKey = publicView ? 'sitewatcher_public_live_activity' : 'sitewatcher_live_activity';
  const speedKey = 'sitewatcher_scene_speed';
  const routeView = !publicView && window.SiteWatcherRouteView
    ? new window.SiteWatcherRouteView(panel, changeRouteView) : null;
  const clock = new Intl.DateTimeFormat(document.documentElement.lang, {
    timeZone: panel.dataset.timezone, hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
  const records = new Map();
  const nodes = new Map();
  const roster = new Map();
  let selectedName = null;
  let inspectedName = null;
  const logged = new Map();
  let queue = [];
  let flights = [];
  let enabled = false;
  let paused = false;
  let looping = false;
  let following = true;
  let unread = 0;
  let skipped = 0;
  let sent = 0;
  let returned = 0;
  let baseline = false;
  let compact = false;
  let timer;
  let loopTimer;
  let request;
  let frame;
  let lastFrame;
  let visualTime = 0;
  let nextLaunch = 0;
  let dialog;
  let placeholder;
  let pageScroll = 0;
  let oldOverflow = '';
  let lastMetrics = '';

  const ns = (tag, attrs = {}, text = '') => {
    const element = document.createElementNS('http://www.w3.org/2000/svg', tag);
    for (const [name, value] of Object.entries(attrs)) element.setAttribute(name, value);
    if (text) element.textContent = text;
    return element;
  };
  const level = event => event.phase === 'running' ? 'running'
    : ['OK', 'WARN', 'CRIT'].includes(event.status) ? event.status.toLowerCase() : 'unknown';
  const signature = event => `${event.phase}:${event.status}`;
  const stamp = event => event.finished_at || event.started_at;
  const recent = () => [...records.values()].sort((a, b) =>
    Date.parse(stamp(b)) - Date.parse(stamp(a)) || String(b.id).localeCompare(String(a.id), 'en', {numeric: true}));
  const stateText = event => event.phase === 'running' ? panel.dataset.running
    : event.phase === 'interrupted' ? panel.dataset.interrupted : event.status_label;
  const legDuration = flight => {
    const base = ({slower: 7000, slow: 4000, normal: 2000})[speed.value] || 4000;
    const points = nodes.get(flight.event.domain)?.route.points;
    return base * (points ? Math.max(1, (points.length - 1) / 3) : 1);
  };
  const capacity = () => compact ? 2 : 3;
  const pinned = domain => selectedName === domain || flights.some(flight => flight.event.domain === domain);
  const point = (route, t) => {
    const p = Math.max(0, Math.min(1, t));
    if (route.points) {
      const offset = p * (route.points.length - 1);
      const index = Math.min(route.points.length - 2, Math.floor(offset));
      const a = route.points[index], b = route.points[index + 1];
      return {x: a.x + (b.x - a.x) * (offset - index), y: a.y + (b.y - a.y) * (offset - index)};
    }
    const q = 1 - p;
    return {
      x: q ** 3 * route.x1 + 3 * q ** 2 * p * route.c1 + 3 * q * p ** 2 * route.c2 + p ** 3 * route.x2,
      y: q ** 3 * route.y1 + 3 * q ** 2 * p * route.y1 + 3 * q * p ** 2 * route.y2 + p ** 3 * route.y2,
    };
  };
  const updateCounters = () => {
    const recorded = flights.some(item => item.recorded) || queue.some(item => item.recorded);
    const live = flights.some(item => !item.recorded) || queue.some(item => !item.recorded);
    const label = reduced.matches ? panel.dataset.reducedLabel : paused ? panel.dataset.pausedLabel
      : recorded ? live ? panel.dataset.mixedLabel : panel.dataset.recordedLabel : panel.dataset.liveLabel;
    const metrics = `${sent}:${returned}:${flights.length}:${skipped}:${label}`;
    if (metrics === lastMetrics) return;
    lastMetrics = metrics;
    find('[data-scene-sent]').textContent = String(sent);
    find('[data-scene-returned]').textContent = String(returned);
    find('[data-scene-active]').textContent = String(flights.length);
    overflow.hidden = skipped === 0;
    overflow.textContent = `${panel.dataset.logOnly}: ${skipped}`;
    mode.textContent = label;
    mode.dataset.mode = recorded ? 'recorded' : 'live';
  };
  const updateFollow = () => {
    follow.setAttribute('aria-pressed', String(following));
    follow.textContent = unread ? `${panel.dataset.newEvents}: ${unread}` : panel.dataset.followLabel;
    find('[data-console-count]').textContent = String(log.children.length);
  };
  const appendLog = event => {
    const key = `${event.id}:${signature(event)}`;
    if (logged.has(key)) return;
    logged.set(key, true);
    while (logged.size > 300) logged.delete(logged.keys().next().value);
    const row = document.createElement('li');
    row.dataset.domain = event.domain;
    row.dataset.level = level(event);
    const time = document.createElement('time');
    time.dateTime = stamp(event);
    time.textContent = clock.format(new Date(stamp(event)));
    const state = document.createElement('span');
    state.className = 'console-status';
    state.dataset.level = level(event);
    state.textContent = event.phase === 'running' ? '→' : event.phase === 'interrupted' ? '×' : '←';
    const check = document.createElement('span');
    check.className = 'console-check';
    check.textContent = event.label;
    const domain = document.createElement(publicView ? 'span' : 'a');
    domain.className = 'console-domain';
    if (!publicView) domain.href = `/domains/history?domain=${encodeURIComponent(event.domain)}`;
    domain.textContent = event.domain;
    const result = document.createElement('span');
    result.className = 'console-result';
    result.dataset.level = level(event);
    result.textContent = stateText(event);
    const duration = document.createElement('span');
    duration.className = 'console-duration';
    duration.textContent = event.elapsed_ms !== null && event.phase === 'finished'
      ? `${event.elapsed_ms} ${panel.dataset.milliseconds}` : '—';
    for (const field of [check, domain, result, duration]) field.title = field.textContent;
    row.append(time, check, domain, state, result, duration);
    const oldHeight = scroll.scrollHeight;
    const oldTop = scroll.scrollTop;
    log.append(row);
    while (log.children.length > 100) log.firstElementChild.remove();
    if (following) scroll.scrollTop = scroll.scrollHeight;
    else {
      scroll.scrollTop = Math.max(0, oldTop - Math.max(0, oldHeight + row.offsetHeight - scroll.scrollHeight));
      unread = Math.min(100, unread + 1);
    }
    updateFollow();
  };

  const mapDescription = item => `${item.name} · ${item.label ? item.label + ' — ' : ''}${item.status_label}`;
  const snapshotEvent = item => ({domain: item.name, label: item.label || panel.dataset.selectedLabel,
    status: item.status, status_label: item.status_label, phase: 'snapshot'});
  const describeMap = () => {
    const item = roster.get(inspectedName);
    mapDetail.textContent = item ? mapDescription(item)
      : selectedName ? `${panel.dataset.pinnedLabel}: ${selectedName}` : panel.dataset.selectLabel;
  };
  const paintMap = () => {
    const running = new Set([...records.values()].filter(event => event.phase === 'running').map(event => event.domain));
    for (const item of roster.values()) {
      item.button.dataset.level = running.has(item.name) ? 'running' : level(snapshotEvent(item));
      item.button.classList.toggle('is-open', nodes.has(item.name));
      item.button.setAttribute('aria-pressed', String(selectedName === item.name));
      const description = running.has(item.name) ? `${item.name} · ${panel.dataset.running}` : mapDescription(item);
      if (item.button.title !== description) item.button.title = description;
      item.button.setAttribute('aria-label', item.button.title);
    }
    unpin.hidden = !selectedName;
    describeMap();
  };
  const selectDomain = name => {
    const previous = nodes.get(selectedName);
    selectedName = selectedName === name ? null : name;
    routeView?.select(selectedName);
    inspectedName = null;
    if (previous && !pinned(previous.domain)) {
      if (reduced.matches) removeNode(previous);
      else previous.retireAt = visualTime + 1600;
    }
    if (selectedName && roster.has(selectedName)) {
      const active = flights.find(item => item.event.domain === selectedName);
      const node = ensureNode(active ? active.event : snapshotEvent(roster.get(selectedName)));
      if (node) { node.retireAt = undefined; node.group.classList.remove('is-leaving'); }
    }
    nodes.forEach(node => { node.group.dataset.pinned = String(node.domain === selectedName); });
    empty.hidden = records.size > 0 || nodes.size > 0;
    paintMap();
    wake();
  };
  const reconcileMap = domains => {
    const names = new Set(domains.map(item => item.name));
    for (const [name, item] of roster) {
      if (!names.has(name)) {
        item.button.remove();
        roster.delete(name);
        if (selectedName === name) selectedName = null;
        for (const flight of [...flights]) if (flight.event.domain === name) removeFlight(flight);
        queue = queue.filter(item => item.event.domain !== name);
        const node = nodes.get(name);
        if (node) removeNode(node);
      }
    }
    for (const item of domains) {
      const old = roster.get(item.name);
      if (old) { Object.assign(old, item); continue; }
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'activity-map-dot';
      button.dataset.domain = item.name;
      button.addEventListener('click', () => selectDomain(item.name));
      const describe = () => { inspectedName = item.name; describeMap(); };
      const restore = () => { inspectedName = null; describeMap(); };
      button.addEventListener('mouseenter', describe);
      button.addEventListener('focus', describe);
      button.addEventListener('mouseleave', restore);
      button.addEventListener('blur', restore);
      domainMap.append(button);
      roster.set(item.name, {...item, button});
    }
    find('[data-map-count]').textContent = String(roster.size);
    describeMap();
  };
  const removeNode = node => {
    node.group.remove();
    node.path.remove();
    nodes.delete(node.domain);
    roster.get(node.domain)?.button.classList.remove('is-open');
    empty.hidden = records.size > 0 || nodes.size > 0;
  };

  const layoutNode = node => {
    const ys = compact ? [96, 245, 395, 544] : [85, 171, 257, 343, 429, 515];
    const focused = routeView?.active && node.domain === selectedName ? routeView.geometry : null;
    const center = focused ? focused.hub : compact ? {x: 80, y: 320, scale: .65} : {x: 170, y: 300, scale: 1};
    const x = focused ? focused.target.x : compact ? 350 : 730;
    const y = focused ? focused.target.y : ys[node.slot];
    const start = center.x + 95 * center.scale;
    const end = x - 20;
    node.route = {x1: start, y1: center.y, x2: end, y2: y,
      c1: start + (end - start) * .46, c2: start + (end - start) * .54};
    if (focused) {
      node.route.points = focused.points;
      node.path.setAttribute('d', focused.points.map((p, i) => `${i ? 'L' : 'M'}${p.x} ${p.y}`).join(' '));
      node.path.setAttribute('stroke-dasharray', roster.get(node.domain)?.route?.result?.reached ? '' : '5 6');
    } else {
      node.path.setAttribute('d', `M${start} ${center.y}C${node.route.c1} ${center.y} ${node.route.c2} ${y} ${end} ${y}`);
      node.path.setAttribute('stroke-dasharray', '');
    }
    node.group.setAttribute('transform', `translate(${x} ${y})`);
    node.body.setAttribute('y', compact ? -48 : -31);
    node.body.setAttribute('height', compact ? 100 : 62);
    node.name.setAttribute('y', compact ? -18 : -11);
    node.meta.setAttribute('y', compact ? 9 : 8);
    node.state.setAttribute('y', compact ? 35 : 25);
    node.dot.setAttribute('cy', compact ? -36 : -19);
    hub.setAttribute('transform', `translate(${center.x} ${center.y}) scale(${center.scale})`);
  };
  const updateNode = (node, event) => {
    node.last = event;
    node.touched = Date.parse(stamp(event)) || visualTime;
    node.group.dataset.pinned = String(node.domain === selectedName);
    node.group.dataset.level = level(event);
    node.meta.textContent = routeView?.active && event.domain === selectedName
      ? routeView.geometry.destination_ip || event.label
      : compact && event.label.length > 24 ? event.label.slice(0, 23) + '…' : event.label;
    node.state.textContent = stateText(event);
    const max = compact ? 18 : 29;
    node.name.textContent = event.domain.length > max
      ? event.domain.slice(0, max - 7) + '…' + event.domain.slice(-6) : event.domain;
    node.title.textContent = `${event.domain} · ${event.label} · ${stateText(event)}`;
  };
  const ensureNode = event => {
    if (nodes.has(event.domain)) {
      const node = nodes.get(event.domain);
      updateNode(node, event);
      return node;
    }
    const order = compact ? [1, 2, 0, 3] : [2, 3, 1, 4, 0, 5];
    let slot = order.find(index => ![...nodes.values()].some(node => node.slot === index));
    if (slot === undefined) {
      const oldest = [...nodes.values()].filter(node => !pinned(node.domain))
        .sort((a, b) => a.touched - b.touched)[0];
      if (!oldest) return null;
      slot = oldest.slot;
      removeNode(oldest);
    }
    const path = ns('path', {class: 'scene-link'});
    const group = ns('g', {class: 'scene-node'});
    const title = ns('title');
    const name = ns('text', {class: 'scene-node-name', x: 16, y: -10});
    const meta = ns('text', {class: 'scene-node-meta', x: 16, y: 12});
    const state = ns('text', {class: 'scene-node-status', x: 16, y: 30});
    const body = ns('rect', {class: 'scene-node-body', x: 0, y: -31, width: 245, height: 62, rx: 5});
    const dot = ns('circle', {class: 'scene-node-dot', cx: 228, cy: -19, r: 3});
    const content = ns('g', {class: 'scene-node-content'});
    group.append(title, content);
    content.append(body,
      ns('rect', {class: 'scene-node-paddle', x: -22, y: -22, width: 5, height: 44, rx: 1}),
      dot, name, meta, state);
    group.addEventListener('click', () => selectDomain(event.domain));
    links.append(path);
    stations.append(group);
    const node = {domain: event.domain, slot, group, path, title, name, meta, state, body, dot, touched: visualTime};
    nodes.set(event.domain, node);
    layoutNode(node);
    updateNode(node, event);
    return node;
  };
  const drawFlight = flight => {
    const node = nodes.get(flight.event.domain);
    if (!node) return;
    const p = flight.phase === 'out' ? flight.progress : flight.phase === 'back' ? 1 - flight.progress : 1;
    const here = point(node.route, p);
    const near = point(node.route, p + (flight.phase === 'back' ? -.01 : .01));
    const angle = Math.atan2(near.y - here.y, near.x - here.x) * 180 / Math.PI;
    const color = flight.phase === 'back' ? level(flight.event) : 'running';
    flight.head.dataset.level = color;
    flight.head.setAttribute('transform', `translate(${here.x} ${here.y}) rotate(${angle})`);
    flight.label.setAttribute('opacity', p > .78 ? '0' : '1');
    flight.label.setAttribute('transform', `translate(${here.x} ${here.y - (compact ? 20 : 15)})`);
    flight.glow.dataset.level = color;
    flight.glow.setAttribute('cx', here.x);
    flight.glow.setAttribute('cy', here.y);
    flight.impact.setAttribute('cx', node.route.x2);
    flight.impact.setAttribute('cy', node.route.y2);
    flight.impact.setAttribute('r', String(5 + Math.min(1, flight.dwell / 700) * 22));
    flight.impact.setAttribute('opacity', flight.phase === 'wait' ? String(.65 * (1 - Math.min(1, flight.dwell / 700))) : '0');
    flight.group.setAttribute('opacity', flight.phase === 'fade' ? String(1 - flight.progress) : '1');
    flight.trail.forEach((dot, index) => {
      const position = point(node.route, p + (flight.phase === 'back' ? 1 : -1) * (index + 1) * .014);
      dot.dataset.level = color;
      dot.setAttribute('cx', position.x);
      dot.setAttribute('cy', position.y);
      dot.setAttribute('opacity', flight.phase === 'wait' ? '0' : String(.25 - index * .035));
    });
  };
  const removeFlight = flight => {
    flight.group.remove();
    flights = flights.filter(item => item !== flight);
    const node = nodes.get(flight.event.domain);
    if (node) {
      node.group.classList.toggle('is-active', flights.some(item => item.event.domain === node.domain));
      if (selectedName !== node.domain && !pinned(node.domain)) node.retireAt = visualTime + 2400;
    }
    paintMap();
  };
  const enqueue = (event, recorded = false) => {
    if (routeView?.active && event.domain !== selectedName) return;
    if (flights.some(item => item.event.id === event.id) || queue.some(item => item.event.id === event.id)) return;
    if (reduced.matches) return;
    const item = {event, recorded};
    if (recorded) queue.push(item);
    else {
      const position = queue.findIndex(value => value.recorded);
      queue.splice(position < 0 ? queue.length : position, 0, item);
    }
    if (queue.length > 6) {
      // The console remains immediate; visuals sample bursts rather than falling minutes behind.
      const drop = queue.findIndex(value => value.recorded);
      queue.splice(drop < 0 ? 0 : drop, 1);
      skipped++;
    }
  };
  const fillReplay = () => {
    const completed = recent().filter(event => event.phase === 'finished'
      && (!routeView?.active || event.domain === selectedName)).slice(0, routeView?.active ? 3 : 6).reverse();
    completed.forEach(event => enqueue(event, true));
    updateCounters();
    wake();
  };
  const launch = item => {
    const node = ensureNode(item.event);
    if (!node) return false;
    node.retireAt = undefined;
    node.group.classList.remove('is-leaving');
    const group = ns('g');
    const trail = Array.from({length: 6}, () => ns('circle', {class: 'scene-pulse', r: 2.5}));
    const glow = ns('circle', {class: 'scene-pulse scene-pulse-aura', r: 12, opacity: .12});
    const head = ns('rect', {class: 'scene-pulse', x: -7, y: -3, width: 14, height: 6, rx: 1});
    const label = ns('text', {class: 'scene-pulse-label', 'text-anchor': 'middle'}, item.event.label);
    const impact = ns('circle', {class: 'scene-impact', r: 5, opacity: 0});
    group.append(impact, ...trail, glow, head, label);
    particles.append(group);
    const flight = {...item, phase: 'out', progress: 0, group, head, glow, trail, label, impact, dwell: 0};
    flights.push(flight);
    node.group.classList.add('is-active');
    sent++;
    paintMap();
    drawFlight(flight);
    updateCounters();
    return true;
  };
  function tick(now) {
    frame = null;
    if (!enabled || document.hidden || paused || reduced.matches) return;
    if (lastFrame !== undefined && now - lastFrame < 30) { frame = requestAnimationFrame(tick); return; }
    const delta = lastFrame === undefined ? 0 : Math.min(80, now - lastFrame);
    lastFrame = now;
    visualTime += delta;
    for (const node of [...nodes.values()]) {
      if (!pinned(node.domain) && node.retireAt !== undefined) {
        node.group.classList.toggle('is-leaving', visualTime >= node.retireAt - 500);
        if (visualTime >= node.retireAt) removeNode(node);
      }
    }
    if (queue.length && flights.length < capacity() && visualTime >= nextLaunch) {
      const item = queue.shift();
      if (launch(item)) nextLaunch = visualTime + 1400;
      else queue.unshift(item);
    }
    for (const flight of [...flights]) {
      if (flight.phase === 'out' || flight.phase === 'back') {
        flight.progress = Math.min(1, flight.progress + delta / legDuration(flight));
        if (flight.progress === 1) {
          if (flight.phase === 'back') { returned++; removeFlight(flight); continue; }
          flight.phase = 'wait';
          flight.progress = 0;
        }
      } else if (flight.phase === 'wait') {
        flight.dwell += delta;
        if (flight.event.phase !== 'running' && flight.dwell >= 500) {
          flight.phase = flight.event.phase === 'finished' ? 'back' : 'fade';
          flight.progress = 0;
        }
      } else if (flight.phase === 'fade') {
        flight.progress = Math.min(1, flight.progress + delta / 900);
        if (flight.progress === 1) { removeFlight(flight); continue; }
      }
      drawFlight(flight);
    }
    updateCounters();
    routeView?.step(flights);
    const moving = flights.some(flight => flight.phase !== 'wait' || flight.event.phase !== 'running');
    const retiring = [...nodes.values()].some(node => !pinned(node.domain) && node.retireAt !== undefined);
    if (moving || retiring || queue.length && flights.length < capacity()) frame = requestAnimationFrame(tick);
    else {
      lastFrame = undefined;
      if (looping && !flights.length && !queue.length && recent().some(event => event.phase === 'finished')) {
        clearTimeout(loopTimer);
        loopTimer = setTimeout(fillReplay, 1800);
      }
    }
  }
  function wake() {
    if (enabled && !paused && !document.hidden && !reduced.matches && (frame === undefined || frame === null)) {
      lastFrame = undefined;
      if (!flights.length) nextLaunch = visualTime;
      frame = requestAnimationFrame(tick);
    }
  }
  const layout = () => {
    routeView?.resize(canvas.clientWidth);
    const focused = routeView?.active ? routeView.geometry : null;
    const next = focused ? focused.compact : canvas.clientWidth < 620;
    svg.style.width = focused ? '100%' : '';
    svg.style.height = focused ? `${focused.compact ? 400 : 420}px` : '';
    if (compact !== next) {
      compact = next;
      // Slots are stable within each layout; pin active domains before rebuilding on resize.
      const selected = [...flights.map(item => item.event),
        ...(selectedName && roster.has(selectedName) ? [snapshotEvent(roster.get(selectedName))] : []),
        ...[...nodes.values()].map(node => node.last)];
      const deadlines = new Map([...nodes.values()].map(node => [node.domain, node.retireAt]));
      nodes.clear();
      links.replaceChildren();
      stations.replaceChildren();
      for (const event of selected) {
        if (!nodes.has(event.domain) && nodes.size < (compact ? 4 : 6)) {
          const node = ensureNode(event);
          node.retireAt = deadlines.get(event.domain);
          node.group.classList.toggle('is-active', flights.some(item => item.event.domain === event.domain));
        }
      }
    }
    panel.dataset.sceneLayout = compact ? 'compact' : 'wide';
    svg.setAttribute('viewBox', focused ? `0 0 ${focused.width} ${focused.height}`
      : compact ? '0 0 620 640' : '0 0 1000 600');
    if (selectedName && roster.has(selectedName) && !nodes.has(selectedName)) {
      ensureNode(snapshotEvent(roster.get(selectedName)));
    }
    nodes.forEach(node => { layoutNode(node); updateNode(node, node.last); });
    flights.forEach(drawFlight);
    if (following) scroll.scrollTop = scroll.scrollHeight;
    paintMap();
  };
  function changeRouteView() {
    if (frame !== undefined && frame !== null) cancelAnimationFrame(frame);
    frame = undefined;
    lastFrame = undefined;
    clearTimeout(loopTimer);
    flights.forEach(flight => flight.group.remove());
    flights = [];
    queue = [];
    nodes.clear();
    links.replaceChildren();
    stations.replaceChildren();
    sent = returned = skipped = 0;
    canvas.scrollLeft = 0;
    layout();
    updateCounters();
    if (enabled) fillReplay();
  }
  const render = (events, domains) => {
    const initial = !baseline;
    reconcileMap(domains);
    routeView?.update(domains, selectedName);
    if (publicView) {
      for (const row of [...log.children]) if (!roster.has(row.dataset.domain)) row.remove();
      unread = Math.min(unread, log.children.length);
      updateFollow();
    }
    const visibleIds = new Set(events.map(event => event.id));
    // A bounded feed can lose an unfinished probe. Retire its picture without fabricating a response.
    for (const flight of flights) {
      if (flight.event.phase === 'running' && !visibleIds.has(flight.event.id)) {
        flight.event = {...flight.event, phase: 'interrupted', status: 'UNKNOWN'};
      }
    }
    queue = queue.filter(item => item.event.phase !== 'running' || visibleIds.has(item.event.id));
    for (const id of records.keys()) if (!visibleIds.has(id)) records.delete(id);
    for (const event of events) {
      const old = records.get(event.id);
      const changed = !old || signature(old) !== signature(event);
      records.delete(event.id);
      records.set(event.id, event);
      for (const item of [...queue, ...flights]) if (item.event.id === event.id) item.event = event;
      if (!initial && changed) {
        appendLog(event);
        const age = Date.now() - Date.parse(stamp(event));
        enqueue(event, age > 15000 || age < -30000);
      }
    }
    while (records.size > 100) {
      const removable = [...records.keys()].find(id => !flights.some(item => item.event.id === id));
      records.delete(removable);
    }
    const ordered = recent();
    if (initial) {
      ordered.slice(0, 40).reverse().forEach(appendLog);
      ordered.filter(event => event.phase === 'running').slice(0, 3).reverse().forEach(event => enqueue(event));
      ordered.filter(event => event.phase === 'finished').slice(0, 6).reverse().forEach(event => enqueue(event, true));
      baseline = true;
    }
    // Keep active stations in place. Fill empty slots; rotate idle stations only for new journeys.
    const displayed = new Set();
    for (const event of ordered) {
      if (displayed.has(event.domain)) continue;
      displayed.add(event.domain);
      const active = flights.find(item => item.event.domain === event.domain);
      if (nodes.has(event.domain)) updateNode(nodes.get(event.domain), active ? active.event : event);

    }
    if (selectedName && roster.has(selectedName)) {
      const active = flights.find(item => item.event.domain === selectedName);
      ensureNode(active ? active.event : snapshotEvent(roster.get(selectedName)));
    }
    paintMap();
    accessible.replaceChildren();
    ordered.slice(0, 6).forEach(event => {
      const item = document.createElement('li');
      item.textContent = `${event.domain}: ${event.label} — ${stateText(event)}`;
      accessible.append(item);
    });
    empty.hidden = records.size > 0 || nodes.size > 0;
    replay.disabled = reduced.matches || !ordered.some(event => event.phase === 'finished');
    const waiting = ordered.filter(event => event.phase === 'running').length;
    const status = waiting ? `${panel.dataset.running}: ${waiting}`
      : records.size ? panel.dataset.idle : panel.dataset.waiting;
    if (notice.textContent !== status) notice.textContent = status;
    updateCounters();
    wake();
  };
  const renderIncidents = incidents => {
    if (publicView || !criticalPanel || !Array.isArray(incidents)) return;
    const create = (tag, className, text = '') => {
      const element = document.createElement(tag);
      element.className = className;
      element.textContent = text;
      return element;
    };
    const names = new Set(incidents.map(item => item.domain));
    for (const [name, row] of incidentRows) {
      if (!names.has(name)) { row.element.remove(); incidentRows.delete(name); }
    }
    let count = 0;
    for (const incident of incidents) {
      let row = incidentRows.get(incident.domain);
      if (!row) {
        const element = create('li', 'activity-critical-domain');
        const details = create('details', '');
        details.open = true;
        const summary = create('summary', '');
        const name = create('span', 'activity-critical-name', incident.domain);
        const total = create('span', 'activity-critical-domain-count');
        summary.append(name, total);
        const list = create('ul', 'activity-critical-checks');
        details.append(summary, list);
        element.append(details);
        criticalList.append(element);
        row = {element, list, total, checks: new Map()};
        incidentRows.set(incident.domain, row);
      }
      const checks = new Set(incident.checks.map(check => check.name));
      for (const [name, check] of row.checks) {
        if (!checks.has(name)) { check.element.remove(); row.checks.delete(name); }
      }
      row.total.textContent = String(incident.checks.length);
      for (const check of incident.checks) {
        let item = row.checks.get(check.name);
        if (!item) {
          const element = create('li', '');
          const link = create('a', 'activity-critical-link');
          link.href = `/domains/history?domain=${encodeURIComponent(incident.domain)}`;
          const time = create('time', 'activity-critical-age');
          const state = create('span', 'activity-critical-state');
          element.append(link, time, state);
          row.list.append(element);
          item = {element, link, time, state};
          row.checks.set(check.name, item);
        }
        item.link.textContent = check.label;
        const raw = check.opened_at.replace(' ', 'T');
        const date = new Date(/(?:Z|[+-]\d{2}:?\d{2})$/.test(raw) ? raw : raw + 'Z');
        const minutes = Math.max(0, Math.floor((Date.now() - date.getTime()) / 60000));
        item.time.textContent = `${minutes} ${criticalPanel.dataset.minutes}`;
        item.time.dateTime = date.toISOString();
        item.time.title = new Intl.DateTimeFormat(document.documentElement.lang, {
          timeZone: panel.dataset.timezone, dateStyle: 'medium', timeStyle: 'short',
        }).format(date);
        item.state.textContent = incident.paused ? criticalPanel.dataset.paused
          : check.stale || check.status !== 'CRIT' ? criticalPanel.dataset.awaiting : '';
        item.state.hidden = !item.state.textContent;
      }
      count += incident.checks.length;
    }
    if (criticalCount.textContent !== String(count)) criticalCount.textContent = String(count);
    criticalConnection.hidden = true;
    criticalPanel.hidden = count === 0;
    panel.dataset.hasCritical = String(count > 0);
  };
  const poll = async () => {
    if (!enabled || document.hidden || request) return;
    const controller = new AbortController();
    request = controller;
    try {
      const response = await fetch(panel.dataset.activityEndpoint || '/api/activity', {
        credentials: publicView ? 'omit' : 'same-origin', referrerPolicy: 'no-referrer', cache: 'no-store',
        signal: controller.signal, headers: {Accept: 'application/json'}});
      if (!response.ok || response.redirected) {
        if (publicView && response.status === 404 && request === controller
            && enabled && !document.hidden) render([], []);
        throw new Error('Activity unavailable');
      }
      const data = await response.json();
      if (!publicView && criticalPanel && !Array.isArray(data.critical_incidents)) {
        throw new Error('Incident state unavailable');
      }
      if (request === controller && enabled && !document.hidden) {
        render(data.events, data.domains);
        renderIncidents(data.critical_incidents);
      }
    } catch (error) {
      if (request === controller && error.name !== 'AbortError') {
        notice.textContent = panel.dataset.unavailable;
        if (criticalConnection) criticalConnection.hidden = false;
      }
    } finally {
      if (request === controller) {
        request = null;
        if (enabled && !document.hidden) timer = setTimeout(poll, 2000);
      }
    }
  };
  const stop = () => {
    clearTimeout(timer);
    clearTimeout(loopTimer);
    request?.abort();
    request = null;
    if (frame !== undefined && frame !== null) cancelAnimationFrame(frame);
    frame = undefined;
    lastFrame = undefined;
  };
  const closeExpanded = () => {
    if (!dialog) return;
    const container = dialog;
    dialog = null;
    panel.classList.remove('is-expanded');
    placeholder.parentNode.insertBefore(panel, placeholder);
    placeholder.remove();
    container.remove();
    document.body.style.overflow = oldOverflow;
    expand.title = expand.dataset.enterLabel;
    expand.setAttribute('aria-label', expand.title);
    window.scrollTo(0, pageScroll);
    expand.focus({preventScroll: true});
    layout();
  };
  const setEnabled = value => {
    enabled = value;
    panel.hidden = !value;
    toggle.setAttribute('aria-pressed', String(value));
    toggle.title = value ? toggle.dataset.enabledLabel : toggle.dataset.disabledLabel;
    stop();
    if (value) { layout(); poll(); wake(); }
    else {
      if (dialog) dialog.close();
      flights.forEach(item => item.group.remove());
      flights = [];
      queue = [];
      records.clear();
      logged.clear();
      nodes.clear();
      roster.clear();
      selectedName = inspectedName = null;
      routeView?.reset();
      domainMap.replaceChildren();
      find('[data-map-count]').textContent = '0';
      mapDetail.textContent = panel.dataset.selectLabel;
      unpin.hidden = true;
      links.replaceChildren();
      stations.replaceChildren();
      log.replaceChildren();
      baseline = false;
      sent = returned = skipped = unread = 0;
      following = true;
      updateFollow();
      updateCounters();
    }
  };
  unpin.addEventListener('click', () => selectDomain(selectedName));
  toggle.hidden = false;
  toggle.addEventListener('click', () => {
    setEnabled(!enabled);
    try { localStorage.setItem(storageKey, enabled ? 'on' : 'off'); } catch {}
  });
  pause.addEventListener('click', () => {
    paused = !paused;
    pause.setAttribute('aria-pressed', String(paused));
    find('[data-scene-pause-label]').textContent = paused ? pause.dataset.resumeLabel : pause.dataset.pauseLabel;
    panel.dataset.paused = String(paused);
    if (paused) { if (frame !== undefined && frame !== null) cancelAnimationFrame(frame); frame = undefined; clearTimeout(loopTimer); }
    else wake();
    updateCounters();
  });
  speed.addEventListener('change', () => {
    try { localStorage.setItem(speedKey, speed.value); } catch {}
  });
  replay.setAttribute('aria-pressed', 'false');
  replay.addEventListener('click', () => {
    looping = !looping;
    replay.setAttribute('aria-pressed', String(looping));
    clearTimeout(loopTimer);
    if (looping) fillReplay();
    else { queue = queue.filter(item => !item.recorded); updateCounters(); }
  });
  scroll.addEventListener('scroll', () => {
    following = scroll.scrollHeight - scroll.scrollTop - scroll.clientHeight < 28;
    if (following) unread = 0;
    updateFollow();
  });
  follow.addEventListener('click', () => {
    following = true;
    unread = 0;
    scroll.scrollTop = scroll.scrollHeight;
    updateFollow();
  });
  expand.addEventListener('click', () => {
    if (dialog) { dialog.close(); return; }
    const container = document.createElement('dialog');
    if (typeof container.showModal !== 'function') return;
    container.className = 'activity-dialog';
    container.setAttribute('aria-labelledby', 'live-checks-title');
    placeholder = document.createComment('live-checks');
    panel.parentNode.insertBefore(placeholder, panel);
    pageScroll = window.scrollY;
    oldOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    document.body.append(container);
    container.append(panel);
    dialog = container;
    container.addEventListener('close', closeExpanded);
    container.showModal();
    panel.classList.add('is-expanded');
    expand.title = expand.dataset.exitLabel;
    expand.setAttribute('aria-label', expand.title);
    expand.focus({preventScroll: true});
    layout();
  });
  document.addEventListener('visibilitychange', () => {
    stop();
    if (enabled && !document.hidden) { poll(); wake(); }
  });
  window.addEventListener('pagehide', () => { stop(); if (dialog) dialog.close(); });
  reduced.addEventListener('change', () => {
    panel.dataset.reducedMotion = String(reduced.matches);
    pause.disabled = reduced.matches;
    speed.disabled = reduced.matches;
    replay.disabled = reduced.matches || !recent().some(event => event.phase === 'finished');
    if (reduced.matches) {
      if (frame !== undefined && frame !== null) cancelAnimationFrame(frame);
      frame = undefined;
      flights.forEach(item => item.group.remove());
      flights = [];
      queue = [];
      for (const node of [...nodes.values()]) {
        node.group.classList.remove('is-active');
        if (node.domain !== selectedName) removeNode(node);
      }
      paintMap();
    }
    updateCounters();
    wake();
  });
  new ResizeObserver(layout).observe(canvas);
  panel.dataset.reducedMotion = String(reduced.matches);
  pause.disabled = reduced.matches;
  speed.disabled = reduced.matches;
  try { if (['slower', 'slow', 'normal'].includes(localStorage.getItem(speedKey))) speed.value = localStorage.getItem(speedKey); } catch {}
  try { setEnabled(localStorage.getItem(storageKey) === 'on'); } catch { setEnabled(false); }
})();
