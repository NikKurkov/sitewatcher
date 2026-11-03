// Private workspace only. Cached UDP observations never change check status.
(() => {
  const svgElement = (tag, attrs = {}, text = '') => {
    const node = document.createElementNS('http://www.w3.org/2000/svg', tag);
    for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
    node.textContent = text;
    return node;
  };
  window.SiteWatcherRouteView = class {
    constructor(panel, onChange) {
      this.panel = panel;
      this.onChange = onChange;
      this.controls = panel.querySelector('[data-route-controls]');
      this.svg = panel.querySelector('[data-activity-scene]');
      this.scroll = panel.querySelector('[data-scene-scroll]');
      this.domains = new Map();
      this.selectedName = null;
      this.desired = false;
      this.following = true;
      this.active = false;
      this.geometry = null;
      this.signature = '';
      this.busy = false;
      this.saveGeneration = 0;
      this.message = '';
      this.paddles = [];
      this.group = svgElement('g', {'data-route-hops': '', class: 'scene-route-hops'});
      const nodes = this.svg?.querySelector('[data-scene-nodes]');
      if (nodes) nodes.before(this.group);
      this.find('[data-route-refresh]')?.addEventListener('click', () => this.save('refresh'));
      this.find('[data-route-disable]')?.addEventListener('click', () => this.save('disable'));
      this.find('[data-route-toggle]')?.addEventListener('click', () => {
        this.desired = !this.desired;
        this.following = true;
        this.render();
      });
      this.find('[data-route-follow]')?.addEventListener('click', () => {
        this.following = true;
        this.paintFollow();
      });
      const suspend = () => {
        this.following = false;
        this.paintFollow();
      };
      this.scroll?.addEventListener('wheel', suspend, {passive: true});
      this.scroll?.addEventListener('touchstart', suspend, {passive: true});
      this.scroll?.addEventListener('pointerdown', suspend, {passive: true});
      this.scroll?.addEventListener('keydown', event => {
        if (['ArrowLeft', 'ArrowRight', 'Home', 'End', 'PageUp', 'PageDown'].includes(event.key)) suspend();
      });
      this.paintControls();
    }
    find(selector) { return this.controls?.querySelector(selector); }
    text(key) { return this.controls?.dataset[key] || ''; }
    update(domains, selectedName) {
      this.domains = new Map(domains.map(item => [item.name, item]));
      this.message = '';
      this.selectedName = selectedName || null;
      this.render();
    }
    select(name) {
      if (this.selectedName !== name) this.message = '';
      this.selectedName = name || null;
      this.following = true;
      this.render();
    }
    reset() {
      this.saveGeneration++;
      this.busy = false;
      this.selectedName = null;
      this.domains.clear();
      this.desired = false;
      this.following = true;
      this.message = '';
      this.render();
      if (this.scroll) this.scroll.scrollLeft = 0;
    }
    route() { return this.domains.get(this.selectedName)?.route; }
    hops() {
      const hops = this.route()?.result?.hops;
      if (!Array.isArray(hops) || !hops.length || hops.length > 24) return [];
      // Reject a malformed cache rather than drawing a plausible synthetic route.
      if (!hops.every(hop => Number.isInteger(hop.ttl) && hop.ttl > 0
          && hop.ttl <= 24 && (hop.ip === null || typeof hop.ip === 'string'))) return [];
      if (!hops.every((hop, index) => !index || hop.ttl > hops[index - 1].ttl)) return [];
      return hops;
    }
    render() {
      const route = this.route();
      const hops = this.hops();
      const active = Boolean(this.desired && this.selectedName && hops.length && this.svg);
      const result = route?.result;
      const signature = active ? JSON.stringify([this.selectedName, result]) : '';
      const changed = this.active !== active || this.signature !== signature;
      const previousGeometry = this.geometrySignature || '';
      this.active = active;
      this.signature = signature;
      this.panel.dataset.routeActive = String(active);
      if (changed) {
        this.geometry = null;
        this.group.replaceChildren();
        this.paddles = [];
        if (active) this.draw(hops, result);
      }
      this.paintControls();
      this.paintList(hops, result);
      this.geometrySignature = this.active ? JSON.stringify([this.selectedName, this.geometry]) : '';
      if (previousGeometry !== this.geometrySignature) this.onChange?.();
    }
    draw(hops, result) {
      // A responding destination belongs to the existing domain card, not a second router.
      const routers = result.reached && hops.at(-1).ip === result.destination_ip
        ? hops.slice(0, -1) : hops;
      const hub = {x: 110, y: 200, scale: .7};
      const points = [{x: hub.x + 95 * hub.scale, y: hub.y}];
      routers.forEach((hop, index) => {
        const x = 360 + index * 320;
        const y = hub.y;
        points.push({x, y});
        const group = svgElement('g', {class: 'scene-route-hop', transform: `translate(${x} ${y})`});
        if (!hop.ip) group.classList.add('is-silent');
        const ip = hop.ip || '*';
        const rtt = typeof hop.rtt_ms === 'number' && Number.isFinite(hop.rtt_ms)
          ? `${hop.rtt_ms.toFixed(1)} ${this.text('ms')}` : this.text('noResponse');
        group.append(
          svgElement('title', {}, `${this.text('hop')} ${hop.ttl}: ${ip} ${hop.hostname || ''} · ${rtt}`),
          svgElement('rect', {class: 'scene-route-paddle', x: -3, y: -24, width: 6, height: 48, rx: 2}),
          svgElement('text', {class: 'scene-route-ttl', y: -43, 'text-anchor': 'middle'}, String(hop.ttl)),
          svgElement('text', {class: 'scene-route-ip', y: 53, 'text-anchor': 'middle'}, ip),
          svgElement('text', {class: 'scene-route-ptr', y: 75, 'text-anchor': 'middle'},
            hop.hostname?.length > 30 ? `${hop.hostname.slice(0, 27)}…` : hop.hostname || ''),
          svgElement('text', {class: 'scene-route-rtt', y: 96, 'text-anchor': 'middle'}, rtt)
        );
        this.group.append(group);
        this.paddles.push(group);
      });
      const target = {x: 380 + routers.length * 320, y: hub.y};
      points.push({x: target.x - 20, y: target.y});
      this.geometry = {width: target.x + 300, height: 420, hub, target, points,
        destination_ip: result.destination_ip || null};
    }
    paintControls() {
      const route = this.route();
      const selected = Boolean(this.selectedName && this.domains.has(this.selectedName));
      const readOnly = this.panel.dataset.routeReadOnly === 'true';
      const pending = ['queued', 'running'].includes(route?.state);
      const refresh = this.find('[data-route-refresh]');
      if (refresh) {
        refresh.disabled = !selected || readOnly || this.busy || pending;
        refresh.textContent = this.busy ? this.text('pending')
          : this.text(route?.enabled ? 'refresh' : 'enable');
      }
      const disable = this.find('[data-route-disable]');
      if (disable) disable.disabled = !selected || !route?.enabled || readOnly || this.busy;
      const toggle = this.find('[data-route-toggle]');
      if (toggle) {
        toggle.disabled = !selected;
        toggle.setAttribute('aria-pressed', String(this.desired));
      }
      const domain = this.find('[data-route-domain]');
      if (domain) domain.textContent = selected ? this.selectedName : '';
      const state = this.find('[data-route-state]');
      let description = !selected ? this.text('select') : this.text('empty');
      if (selected && route) {
        const partial = route.result && (!route.result.reached || route.result.truncated);
        description = this.text(partial && route.state === 'ready' ? 'partial' : route.state);
        if (!route.enabled && route.state !== 'disabled') description += ` · ${this.text('disabled')}`;
      }
      if (state) state.textContent = this.message || description;
      this.paintFollow();
    }
    paintFollow() {
      const button = this.find('[data-route-follow]');
      if (!button) return;
      button.hidden = !this.active;
      button.setAttribute('aria-pressed', String(this.following));
      button.textContent = this.text(this.following ? 'follow' : 'followPaused');
    }
    paintList(hops, result) {
      const details = this.find('[data-route-details]');
      const list = this.find('[data-route-list]');
      if (details) details.hidden = !hops.length;
      if (!list) return;
      const signature = JSON.stringify([this.selectedName, result]);
      if (this.listSignature === signature) return;
      this.listSignature = signature;
      list.replaceChildren();
      for (const hop of hops) {
        const row = document.createElement('li');
        row.value = hop.ttl;
        const ip = document.createElement('code');
        ip.textContent = hop.ip || '*';
        row.append(ip);
        if (hop.hostname) row.append(` — ${hop.hostname}`);
        row.append(typeof hop.rtt_ms === 'number' && Number.isFinite(hop.rtt_ms)
          ? ` · ${hop.rtt_ms.toFixed(1)} ${this.text('ms')}` : ` · ${this.text('noResponse')}`);
        list.append(row);
      }
      const captured = this.find('[data-route-captured]');
      if (captured) {
        const date = new Date(result?.captured_at);
        captured.textContent = Number.isNaN(date.getTime()) ? ''
          : `${this.text('captured')}: ${date.toLocaleString(document.documentElement.lang || undefined,
            {timeZone: this.panel.dataset.timezone || undefined})}`;
      }
    }
    async save(action) {
      const domain = this.selectedName;
      if (!domain || this.busy || this.panel.dataset.routeReadOnly === 'true') return;
      const csrf = document.querySelector('input[name=csrfmiddlewaretoken]')?.value;
      if (!csrf) { this.message = this.text('failed'); this.paintControls(); return; }
      const generation = ++this.saveGeneration;
      this.busy = true;
      this.message = '';
      this.paintControls();
      try {
        const response = await fetch('/domains/route', {
          method: 'POST', credentials: 'same-origin',
          headers: {'X-CSRFToken': csrf, 'Content-Type': 'application/x-www-form-urlencoded'},
          body: new URLSearchParams({domain, action}),
        });
        const saved = response.ok && (await response.json()).saved === true;
        if (generation !== this.saveGeneration) return;
        if (this.selectedName === domain) {
          this.message = this.text(saved ? action === 'disable' ? 'stopped' : 'saved'
            : response.status === 409 ? 'conflict' : 'failed');
          if (saved) {
            const item = this.domains.get(domain);
            if (item) item.route = {...item.route, enabled: action !== 'disable',
              state: action === 'disable' ? 'disabled' : 'queued'};
            if (action === 'refresh') this.desired = true;
          }
        }
      } catch (_) {
        if (generation === this.saveGeneration && this.selectedName === domain) {
          this.message = this.text('failed');
        }
      } finally {
        if (generation === this.saveGeneration) {
          this.busy = false;
          this.render();
        }
      }
    }
    step(flights) {
      if (!this.active || !this.geometry) return;
      const flight = flights.find(item => item.event.domain === this.selectedName);
      const progress = flight ? Math.max(0, Math.min(1, flight.phase === 'out'
        ? flight.progress : flight.phase === 'back' ? 1 - flight.progress : 1)) : null;
      const segments = this.geometry.points.length - 1;
      this.paddles.forEach((paddle, index) => {
        paddle.classList.toggle('is-traversed', progress !== null && progress * segments >= index + 1);
        paddle.classList.toggle('is-current', progress !== null
          && Math.abs(progress * segments - index - 1) < .16);
      });
      if (!this.following || progress === null || !this.scroll || !this.svg) return;
      const offset = progress * segments;
      const index = Math.min(segments - 1, Math.floor(offset));
      const start = this.geometry.points[index];
      const end = this.geometry.points[index + 1];
      const x = start.x + (end.x - start.x) * (offset - index);
      const scale = this.svg.getBoundingClientRect().width / this.geometry.width;
      const target = Math.max(0, x * scale - this.scroll.clientWidth * .5);
      this.scroll.scrollLeft += (target - this.scroll.scrollLeft) * .12;
    }
  };
})();
