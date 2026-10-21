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
