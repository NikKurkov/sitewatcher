// The checkbox changes field visibility; persistence still requires Save settings.
(() => {
  const toggle = document.querySelector('[data-vt-proxy-toggle]');
  const fields = document.querySelector('[data-vt-proxy-fields]');
  if (!toggle || !fields) return;
  const update = () => {
    fields.hidden = !toggle.checked;
    for (const input of fields.querySelectorAll('input')) input.disabled = !toggle.checked;
    toggle.setAttribute('aria-expanded', String(toggle.checked));
  };
  toggle.addEventListener('change', update);
  update();
})();
