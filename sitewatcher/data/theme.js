// Progressive enhancement: change the theme without discarding an unsaved form.
document.addEventListener('click', (event) => {
  const link = event.target.closest('.theme-controls a[data-theme-choice]');
  if (!link || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
  const mode = link.dataset.themeChoice;
  if (!['light', 'dark', 'system'].includes(mode)) return;
  event.preventDefault();
  document.documentElement.dataset.theme = mode;
  document.cookie = `sitewatcher_theme=${mode}; Path=/; Max-Age=31536000; SameSite=Strict`;
  document.querySelectorAll('.theme-controls a').forEach((item) => {
    if (item === link) item.setAttribute('aria-current', 'true');
    else item.removeAttribute('aria-current');
  });
});
