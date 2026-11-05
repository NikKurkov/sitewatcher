// Change the theme without discarding an unsaved form; native GET works without JS.
document.addEventListener('submit', (event) => {
  if (!event.target.matches('.theme-controls')) return;
  event.preventDefault();
  const button = event.target.querySelector('.theme-switch');
  const mode = button.value;
  document.documentElement.dataset.theme = mode;
  document.cookie = `sitewatcher_theme=${mode}; Path=/; Max-Age=31536000; SameSite=Strict`;
  button.setAttribute('aria-checked', String(mode === 'dark'));
  button.value = mode === 'dark' ? 'light' : 'dark';
  button.title = mode === 'dark' ? button.dataset.lightTitle : button.dataset.darkTitle;
});

// Owner-only link fields support clipboard copying and manual selection.
document.addEventListener('click', async (event) => {
  const button = event.target.closest('.copy-public-link');
  if (!button) return;
  const input = document.getElementById(button.dataset.copyTarget);
  const status = button.parentElement.querySelector('[data-copy-status]');
  input.focus();
  input.select();
  try {
    await navigator.clipboard.writeText(input.value);
    status.textContent = button.dataset.copySuccess;
  } catch {
    status.textContent = button.dataset.copyFailure;
  }
});

// Native navigation preserves domain disclosures without replacing initialized DOM.
const disclosureRoot = document.querySelector('[data-disclosure-scope]');
let saveDisclosureState = () => {};
if (disclosureRoot) {
  const stateKey = 'sitewatcher_disclosures';
  // Hash the address so a publication bearer URL is never copied into storage.
  let addressHash = 2166136261;
  let addressHash2 = 5381;
  for (const character of location.pathname) {
    addressHash = Math.imul(addressHash ^ character.charCodeAt(0), 16777619);
    addressHash2 = Math.imul(addressHash2, 33) ^ character.charCodeAt(0);
  }
  const scope = `${disclosureRoot.dataset.disclosureScope}:${addressHash >>> 0}:${addressHash2 >>> 0}`;
  const domains = [...disclosureRoot.querySelectorAll('[data-domain-key]')];
  const toggles = [...disclosureRoot.querySelectorAll('[data-domain-toggle]')];
  const panelFor = (button) => document.getElementById(button.getAttribute('aria-controls'));
  const nameFor = (button) => button.closest('[data-domain-key]')?.querySelector('.domain-name');
  const setOpen = (button, open) => {
    const panel = panelFor(button);
    if (!panel) return;
    panel.hidden = !open;
    button.setAttribute('aria-expanded', String(open));
    nameFor(button)?.setAttribute('aria-expanded', String(open));
  };
  toggles.forEach((button) => {
    button.hidden = false;
    button.addEventListener('click', () => {
      setOpen(button, button.getAttribute('aria-expanded') !== 'true');
    });
    const name = nameFor(button);
    if (name) {
      name.setAttribute('role', 'button');
      name.setAttribute('aria-controls', button.getAttribute('aria-controls'));
      name.setAttribute('aria-expanded', button.getAttribute('aria-expanded'));
      name.addEventListener('click', (event) => {
        if (event.ctrlKey || event.metaKey || event.shiftKey || event.altKey || event.button > 0) return;
        event.preventDefault();
        button.click();
      });
      name.addEventListener('keydown', (event) => {
        if (event.key !== ' ') return;
        event.preventDefault();
        name.click();
      });
    }
  });
  disclosureRoot.querySelectorAll('[data-domain-summary]').forEach((row) => {
    row.addEventListener('click', (event) => {
      if (event.target.closest('a,button,form,input,select,textarea,details,summary,label,[contenteditable],[role="button"],[data-status-preview]')) return;
      const button = row.querySelector('[data-domain-toggle]');
      if (button) button.click();
    });
  });
  const focusable = 'a,button,input,select,textarea,summary,[tabindex]';
  const readStates = () => {
    try {
      const states = JSON.parse(sessionStorage.getItem(stateKey));
      return Array.isArray(states) ? states.filter((entry) => entry &&
        typeof entry.scope === 'string' && Date.now() - entry.time < 86400000) : [];
    } catch { return []; }
  };
  const saved = readStates().find((entry) => entry.scope === scope);
  if (saved) {
    domains.forEach((domain) => {
      const open = Array.isArray(saved.open) && saved.open.includes(domain.dataset.domainKey);
      const button = domain.querySelector('[data-domain-toggle]');
      const details = domain.querySelector('[data-domain-disclosure]');
      if (button) setOpen(button, open);
      if (details) details.open = open;
      domain.querySelectorAll('details').forEach((nested, index) => {
        if (nested !== details && Array.isArray(saved.nested)) {
          nested.open = saved.nested.some((item) => item.key === domain.dataset.domainKey && item.index === index);
        }
      });
    });
    const focus = saved.focus;
    if (focus) {
      const domain = domains.find((item) => item.dataset.domainKey === focus.key);
      const target = focus.id ? document.getElementById(focus.id)
        : domain?.querySelectorAll(focusable)[focus.index];
      if (target && disclosureRoot.contains(target) && !target.closest('[hidden]')) {
        target.focus({preventScroll: true});
      }
    }
    if (Number.isFinite(saved.x) && Number.isFinite(saved.y)) {
      window.scrollTo(saved.x, saved.y);
      window.addEventListener('pageshow', () => window.scrollTo(saved.x, saved.y), {once: true});
    }
  }
  saveDisclosureState = () => {
    const open = [];
    const nested = [];
    domains.forEach((domain) => {
      const button = domain.querySelector('[data-domain-toggle]');
      const details = domain.querySelector('[data-domain-disclosure]');
      if (button?.getAttribute('aria-expanded') === 'true' || details?.open) open.push(domain.dataset.domainKey);
      domain.querySelectorAll('details').forEach((item, index) => {
        if (item !== details && item.open) nested.push({key: domain.dataset.domainKey, index});
      });
    });
    const active = document.activeElement;
    const domain = active?.closest('[data-domain-key]');
    let focus = null;
    if (active && disclosureRoot.contains(active)) {
      if (active.id) focus = {id: active.id};
      else if (domain) focus = {key: domain.dataset.domainKey,
        index: [...domain.querySelectorAll(focusable)].indexOf(active)};
    }
    const state = {scope, time: Date.now(), open, nested, focus, x: window.scrollX, y: window.scrollY};
    try {
      sessionStorage.setItem(stateKey, JSON.stringify([
        ...readStates().filter((entry) => entry.scope !== scope).slice(-7), state,
      ]));
    } catch {}
  };
  window.addEventListener('pagehide', saveDisclosureState);
  window.addEventListener('beforeunload', saveDisclosureState);
}

// Submit native GET filters automatically, keeping focus across the resulting navigation.
const filterFocusKey = 'sitewatcher_filter_focus';
try {
  const saved = JSON.parse(sessionStorage.getItem(filterFocusKey));
  sessionStorage.removeItem(filterFocusKey);
  const field = saved && document.getElementById(saved.id);
  if (field && saved.path === location.pathname && field.value === saved.value) {
    const disclosure = field.closest('details');
    if (disclosure) disclosure.open = true;
    field.focus();
    if (field.type === 'search' && saved.cursor !== null) {
      field.setSelectionRange(saved.cursor, saved.cursor);
    }
  }
} catch {}

document.querySelectorAll('.filter-form, .history-filters').forEach((form) => {
  let timer;
  const apply = () => {
    clearTimeout(timer);
    form.requestSubmit();
  };
  const search = (event) => {
    if (event.target.type !== 'search') return;
    clearTimeout(timer);
    if (!event.isComposing) timer = setTimeout(apply, 400);
  };
  const targets = [form, ...(form.id ? document.querySelectorAll(`[form="${form.id}"]`) : [])];
  targets.forEach((target) => {
    target.addEventListener('input', search);
    target.addEventListener('compositionstart', () => clearTimeout(timer));
    target.addEventListener('compositionend', search);
    target.addEventListener('change', (event) => {
      if (event.target.type !== 'search') apply();
    });
  });
  form.addEventListener('submit', () => {
    clearTimeout(timer);
    const field = document.activeElement;
    if ((form.contains(field) || field?.form === form) && field.id) {
      try {
        sessionStorage.setItem(filterFocusKey, JSON.stringify({
          id: field.id, value: field.value, path: location.pathname,
          cursor: field.type === 'search' ? field.selectionStart : null,
        }));
      } catch {}
    }
  });
});

// Other owner pages open the overview's saved live panel without polling from a form.
document.querySelectorAll('[data-activity-navigation]').forEach((link) => {
  link.hidden = false;
  link.addEventListener('click', () => {
    try { localStorage.setItem('sitewatcher_live_activity', 'on'); } catch {}
  });
});

// Refresh read pages while readers keep disclosures open; defer active edits and dragging.
const refresh = document.querySelector('[data-auto-refresh]');
if (refresh) {
  let draft = false;
  document.addEventListener('input', (event) => {
    const editable = 'input:not([type=hidden]):not([type=checkbox]):not([type=radio]),'
      + 'textarea,[contenteditable]';
    if (event.target.matches(editable)) {
      draft = true;
    }
  });
  const filters = document.querySelector('.filter-form');
  if (filters) {
    [filters, ...filters.elements].forEach((target) => {
      target.addEventListener('input', () => { draft = true; });
      target.addEventListener('change', () => { draft = true; });
    });
  }
  setInterval(() => {
    if (!document.hidden && !draft
        && !document.querySelector('[data-live-activity]:not([hidden])')
        && !document.querySelector('.domains-table[aria-busy=true], .domains-table[data-dragging=true]')
        && !document.querySelector('[data-domain-move-dialog][open], .domains-table[data-move-cooldown]')
        && !document.querySelector('.status-tooltip:not([hidden]), .chart-tooltip:not([hidden]), .chart-window-tooltip:popover-open')
        && !document.activeElement.matches('input,select,textarea,[contenteditable]')) {
      saveDisclosureState();
      location.reload();
    }
  }, 60000);
}

// Keep tooltip text tied to the saved bucket, for pointer and keyboard navigation.
document.querySelectorAll('.response-chart').forEach((chart) => {
  const tooltip = chart.querySelector('.chart-tooltip');
  if (!tooltip) return;
  const svg = chart.querySelector('svg');
  const points = [...chart.querySelectorAll('.chart-point')].map((point) => {
    const dot = point.querySelector('.chart-dot');
    return {point, x: Number(dot.getAttribute('cx')), y: Number(dot.getAttribute('cy'))};
  });
  let active = null;
  const show = (point, reposition = false) => {
    if (point === active && !reposition) return;
    active?.classList.remove('is-active');
    active = point;
    tooltip.hidden = !point;
    if (!point) return;
    point.classList.add('is-active');
    tooltip.textContent = point.getAttribute('aria-label');
    const bounds = chart.getBoundingClientRect();
    const dot = point.querySelector('.chart-dot').getBoundingClientRect();
    const left = dot.left + dot.width / 2 - bounds.left - tooltip.offsetWidth / 2;
    tooltip.style.left = `${Math.max(8, Math.min(left, bounds.width - tooltip.offsetWidth - 8))}px`;
    const above = dot.top - bounds.top - tooltip.offsetHeight - 10;
    tooltip.style.top = `${above >= 0 ? above : dot.bottom - bounds.top + 10}px`;
  };
  // Follow the nearest time column, without bridging a long measurement gap.
  const inspect = (event) => {
    const matrix = svg.getScreenCTM();
    if (!matrix) return;
    let nearest = null;
    let distance = 18;
    for (const {point, x, y} of points) {
      const dx = matrix.a * x + matrix.c * y + matrix.e - event.clientX;
      const candidate = Math.abs(dx);
      if (candidate < distance) { nearest = point; distance = candidate; }
    }
    show(nearest);
  };
  svg.addEventListener('pointermove', inspect);
  svg.addEventListener('pointerdown', inspect);
  svg.addEventListener('pointerleave', (event) => {
    if (event.pointerType === 'touch') return;
    show(svg.contains(document.activeElement)
      ? document.activeElement.closest('.chart-point') : null);
  });
  points.forEach(({point}, index) => {
    point.addEventListener('focus', () => {
      points.forEach(({point: other}) => { other.tabIndex = other === point ? 0 : -1; });
      show(point);
    });
    point.addEventListener('blur', () => show(null));
    point.addEventListener('keydown', (event) => {
      const target = {ArrowLeft: index - 1, ArrowRight: index + 1,
        Home: 0, End: points.length - 1}[event.key];
      if (target === undefined) return;
      event.preventDefault();
      points[Math.max(0, Math.min(target, points.length - 1))].point.focus();
    });
  });
  const restoredPoint = document.activeElement?.closest('.chart-point');
  if (restoredPoint && chart.contains(restoredPoint)) show(restoredPoint);
  document.addEventListener('keydown', (event) => {
    if (active && event.key === 'Escape') show(null);
  });
  document.addEventListener('pointerdown', (event) => {
    if (!chart.contains(event.target)) show(null);
  });
  window.addEventListener('resize', () => { if (active) show(active, true); });
});

// Fixed positioning keeps status details outside the table's clipped scroll area.
document.querySelectorAll('[data-status-preview]').forEach((preview) => {
  const trigger = preview.querySelector('[data-status-trigger]');
  const tooltip = preview.querySelector('.status-tooltip');
  let closeTimer;
  const hide = () => { clearTimeout(closeTimer); tooltip.hidden = true; };
  const show = () => {
    clearTimeout(closeTimer);
    tooltip.hidden = false;
    const bounds = trigger.getBoundingClientRect();
    const left = Math.min(bounds.left, window.innerWidth - tooltip.offsetWidth - 12);
    tooltip.style.left = `${Math.max(12, left)}px`;
    const below = bounds.bottom + 8;
    const top = below + tooltip.offsetHeight <= window.innerHeight - 12
      ? below : bounds.top - tooltip.offsetHeight - 8;
    tooltip.style.top = `${Math.max(12, top)}px`;
  };
  preview.addEventListener('pointerenter', show);
  preview.addEventListener('pointerleave', () => {
    closeTimer = setTimeout(() => {
      if (!preview.contains(document.activeElement)) hide();
    }, 150);
  });
  preview.addEventListener('focusin', show);
  preview.addEventListener('focusout', (event) => {
    if (!preview.contains(event.relatedTarget)) hide();
  });
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && !tooltip.hidden) {
      if (tooltip.contains(document.activeElement)) trigger.focus();
      hide();
    }
  });
  window.addEventListener('resize', hide);
  window.addEventListener('scroll', (event) => {
    if (!tooltip.contains(event.target)) hide();
  }, {capture: true, passive: true});
});

// Native popovers provide tap toggling, outside dismissal and Escape for averages.
document.querySelectorAll('.chart-window-value').forEach((trigger) => {
  const tooltip = document.getElementById(trigger.getAttribute('popovertarget'));
  if (!tooltip?.showPopover) return;
  const hide = () => { if (tooltip.matches(':popover-open')) tooltip.hidePopover(); };
  const show = () => {
    if (!tooltip.matches(':popover-open')) tooltip.showPopover();
    const bounds = trigger.getBoundingClientRect();
    tooltip.style.left = `${Math.max(8, Math.min(bounds.left, window.innerWidth - tooltip.offsetWidth - 8))}px`;
    tooltip.style.top = `${Math.max(8, bounds.top - tooltip.offsetHeight - 6)}px`;
  };
  tooltip.addEventListener('toggle', (event) => { if (event.newState === 'open') show(); });
  trigger.addEventListener('pointerenter', (event) => { if (event.pointerType === 'mouse') show(); });
  trigger.addEventListener('pointerleave', (event) => {
    if (event.pointerType === 'mouse' && !trigger.matches(':focus-visible')) hide();
  });
  trigger.addEventListener('focus', () => { if (trigger.matches(':focus-visible')) show(); });
  trigger.addEventListener('blur', hide);
  window.addEventListener('resize', hide);
  window.addEventListener('scroll', hide, {capture: true, passive: true});
});

// Public page addresses are editable only in public mode.
const statusPageForm = document.querySelector('.status-page-form');
if (statusPageForm) {
  const mode = statusPageForm.querySelector('[name="access_mode"]');
  const address = statusPageForm.querySelector('.status-page-address');
  const updateAddress = () => {
    address.hidden = mode.value !== 'public';
    address.querySelector('input').disabled = address.hidden || mode.disabled;
  };
  mode.addEventListener('change', updateAddress);
  updateAddress();
}
