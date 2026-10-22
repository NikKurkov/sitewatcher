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
    status.textContent = 'Public link copied.';
  } catch {
    status.textContent = 'Link selected. Press Ctrl+C or use your device’s Copy action.';
  }
});
