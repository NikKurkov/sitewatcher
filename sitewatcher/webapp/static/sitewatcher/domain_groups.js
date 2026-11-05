// Persist group disclosure independently for each signed-in workspace.
(() => {
  const table = document.querySelector('[data-domain-groups]');
  if (!table) return;
  const filtered = table.dataset.groupFiltered === 'true';
  const key = table.dataset.groupStorageKey;
  let saved = {};
  try {
    const value = JSON.parse(localStorage.getItem(key) || '{}');
    if (value && typeof value === 'object' && !Array.isArray(value)) saved = value;
  } catch { /* Unavailable storage must never prevent access to domains. */ }
  const allBodies = [...table.querySelectorAll('tbody[data-group-id]')];
  const groups = [...table.querySelectorAll('[data-domain-group]')].map(header => ({
    header,
    id: header.dataset.domainGroup,
    button: header.querySelector('[data-group-toggle]'),
    rows: allBodies.filter(row => row.dataset.groupId === header.dataset.domainGroup),
  }));
  const setOpen = (group, open, persist = false) => {
    group.button.setAttribute('aria-expanded', String(open));
    group.rows.forEach(row => { row.hidden = !open; });
    if (persist && !filtered) {
      saved[group.id] = open;
      try { localStorage.setItem(key, JSON.stringify(saved)); } catch { /* Optional preference. */ }
    }
  };
  groups.forEach(group => {
    setOpen(group, filtered || saved[group.id] !== false);
    group.button.addEventListener('click', () => {
      setOpen(group, group.button.getAttribute('aria-expanded') !== 'true', true);
    });
  });
})();
