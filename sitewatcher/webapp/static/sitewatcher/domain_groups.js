// Resolve membership at the time of each toggle: rows can move without navigation.
(() => {
  const table = document.querySelector('[data-domain-groups]');
  if (!table) return;
  const filtered = table.dataset.groupFiltered === 'true';
  const key = table.dataset.groupStorageKey;
  let saved = {};
  try {
    const value = JSON.parse(localStorage.getItem(key) || '{}');
    if (value && typeof value === 'object' && !Array.isArray(value)) saved = value;
  } catch { /* Optional preference. */ }
  const headers = () => [...table.querySelectorAll('[data-domain-group]')];
  const setOpen = (header, open, persist = false) => {
    const id = header.dataset.domainGroup;
    header.querySelector('[data-group-toggle]').setAttribute('aria-expanded', String(open));
    table.querySelectorAll('tbody[data-group-id]').forEach(row => {
      if (row.dataset.groupId === id) row.hidden = !open;
    });
    if (persist && !filtered) {
      saved[id] = open;
      try { localStorage.setItem(key, JSON.stringify(saved)); } catch { /* Optional preference. */ }
    }
  };
  headers().forEach(header => setOpen(header, filtered || saved[header.dataset.domainGroup] !== false));
  table.addEventListener('click', event => {
    const button = event.target.closest('[data-group-toggle]');
    if (button) setOpen(button.closest('[data-domain-group]'),
      button.getAttribute('aria-expanded') !== 'true', true);
  });
  table.addEventListener('sitewatcher:group-open', event => {
    const header = headers().find(item => item.dataset.domainGroup === String(event.detail.id));
    if (header) setOpen(header, event.detail.open, event.detail.persist);
  });
  table.addEventListener('sitewatcher:groups-updated', event => {
    headers().forEach(header => setOpen(header,
      header.querySelector('[data-group-toggle]').getAttribute('aria-expanded') === 'true'));
    const header = headers().find(item => item.dataset.domainGroup === String(event.detail.open));
    if (header) setOpen(header, true, true);
  });
})();
