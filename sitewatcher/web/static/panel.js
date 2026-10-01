(() => {
  const root = document.documentElement;
  document.querySelectorAll('[data-theme-toggle]').forEach(button => {
    button.addEventListener('click', () => {
      const theme = root.dataset.theme === 'dark' ? 'light' : 'dark';
      root.dataset.theme = theme;
      try { localStorage.setItem('sitewatcher-theme', theme); } catch (_) {}
    });
  });

  const menu = document.querySelector('[data-menu-toggle]');
  if (menu) {
    menu.addEventListener('click', () => {
      const open = document.body.classList.toggle('nav-open');
      menu.setAttribute('aria-expanded', String(open));
      menu.setAttribute('aria-label', open ? 'Close navigation' : 'Open navigation');
    });
    document.addEventListener('keydown', event => {
      if (event.key === 'Escape') {
        document.body.classList.remove('nav-open');
        menu.setAttribute('aria-expanded', 'false');
      }
    });
  }

  document.querySelectorAll('form[data-confirm]').forEach(form => {
    form.addEventListener('submit', event => {
      if (!window.confirm(form.dataset.confirm)) event.preventDefault();
    });
  });

  const refreshSeconds = Number(document.body.dataset.autoRefresh || 0);
  if (refreshSeconds) {
    window.setInterval(() => {
      const focused = document.activeElement;
      const editing = focused && focused.matches('input, textarea, select, [contenteditable="true"]');
      if (document.visibilityState === 'visible' && !editing) window.location.reload();
    }, refreshSeconds * 1000);
  }
})();
