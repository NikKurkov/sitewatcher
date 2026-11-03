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
});

// The full bearer link is available only in the immediate publication response.
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

// Refresh only read pages, preserving scroll and never interrupting a draft or disclosure.
const refresh = document.querySelector('[data-auto-refresh]');
if (refresh) {
  const enabled = refresh.querySelector('[data-refresh-enabled]');
  refresh.querySelector('[data-refresh-option]').hidden = false;
  const isToggle = enabled.tagName === 'BUTTON';
  const isEnabled = () => isToggle ? enabled.getAttribute('aria-pressed') === 'true' : enabled.checked;
  const setEnabled = (value) => {
    if (isToggle) {
      enabled.setAttribute('aria-pressed', String(value));
      enabled.title = value ? enabled.dataset.enabledLabel : enabled.dataset.disabledLabel;
    } else {
      enabled.checked = value;
    }
  };
  try { setEnabled(sessionStorage.getItem('refresh') !== 'off'); } catch {}
  enabled.addEventListener(isToggle ? 'click' : 'change', () => {
    const value = isToggle ? !isEnabled() : enabled.checked;
    setEnabled(value);
    try { sessionStorage.setItem('refresh', value ? 'on' : 'off'); } catch {}
  });
  let draft = false;
  const filters = document.querySelector('.filter-form');
  if (filters) {
    [filters, ...filters.elements].forEach((target) => {
      target.addEventListener('input', () => { draft = true; });
      target.addEventListener('change', () => { draft = true; });
    });
  }
  setInterval(() => {
    if (isEnabled() && !document.hidden && !draft && !document.querySelector('details[open]')
        && !document.querySelector('.status-tooltip:not([hidden])')
        && !document.activeElement.matches('input,select,textarea,button,[contenteditable]')) {
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
  // Compare in screen pixels so dense or narrow charts still select the nearest dot.
  svg.addEventListener('pointermove', (event) => {
    const matrix = svg.getScreenCTM();
    if (!matrix) return;
    let nearest = null;
    let distance = 18;
    for (const {point, x, y} of points) {
      const dx = matrix.a * x + matrix.c * y + matrix.e - event.clientX;
      const dy = matrix.b * x + matrix.d * y + matrix.f - event.clientY;
      const candidate = Math.hypot(dx, dy);
      if (candidate < distance) { nearest = point; distance = candidate; }
    }
    show(nearest);
  });
  svg.addEventListener('pointerleave', () => {
    show(svg.contains(document.activeElement)
      ? document.activeElement.closest('.chart-point') : null);
  });
  points.forEach(({point}) => {
    point.addEventListener('focus', () => show(point));
    point.addEventListener('blur', () => show(null));
  });
  document.addEventListener('keydown', (event) => {
    if (active && event.key === 'Escape') show(null);
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
