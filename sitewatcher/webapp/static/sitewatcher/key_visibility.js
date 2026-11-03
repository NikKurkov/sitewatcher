// Fetch a configured key only on an explicit owner click; viewing never resaves it.
(() => {
  const container = document.querySelector('[data-key-field]');
  if (!container) return;
  const field = container.querySelector('input');
  const toggle = container.querySelector('[data-key-visibility]');
  const notice = container.querySelector('[data-key-status]');
  const form = field.form;
  const originalName = field.name;
  if (container.dataset.keyPresent === 'true') field.placeholder = '••••••••••••';
  let showingSaved = false;
  let pending;
  const hide = () => {
    pending?.abort();
    pending = null;
    if (showingSaved) {
      field.value = '';
      field.name = originalName;
      showingSaved = false;
    }
    field.type = 'password';
    toggle.setAttribute('aria-pressed', 'false');
    toggle.title = toggle.dataset.showLabel;
    toggle.setAttribute('aria-label', toggle.title);
  };
  toggle.hidden = false;
  field.addEventListener('input', () => {
    // Editing is an explicit replacement. A merely revealed value has no form name.
    field.name = originalName;
    showingSaved = false;
  });
  toggle.addEventListener('click', async () => {
    if (field.type === 'text') { hide(); return; }
    notice.textContent = '';
    notice.hidden = true;
    if (!field.value && container.dataset.keyPresent === 'true') {
      const controller = new AbortController();
      pending = controller;
      toggle.disabled = true;
      try {
        const response = await fetch('/settings', {
          method: 'POST', credentials: 'same-origin', cache: 'no-store',
          signal: controller.signal,
          body: new URLSearchParams({action: 'reveal_virustotal_key',
            csrfmiddlewaretoken: form.querySelector('[name=csrfmiddlewaretoken]').value}),
        });
        if (!response.ok || response.redirected) throw new Error('Key unavailable');
        const data = await response.json();
        if (pending !== controller || controller.signal.aborted) return;
        if (!field.value) {
          field.value = data.key;
          field.removeAttribute('name');
          showingSaved = true;
        }
      } catch (error) {
        if (pending === controller && error.name !== 'AbortError') {
          notice.textContent = toggle.dataset.errorLabel;
          notice.hidden = false;
        }
        return;
      } finally {
        if (pending === controller) pending = null;
        toggle.disabled = false;
      }
    }
    field.type = 'text';
    toggle.setAttribute('aria-pressed', 'true');
    toggle.title = toggle.dataset.hideLabel;
    toggle.setAttribute('aria-label', toggle.title);
  });
  document.addEventListener('visibilitychange', () => { if (document.hidden) hide(); });
  window.addEventListener('pagehide', hide);
})();
