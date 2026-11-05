// Group disclosure and explicit bulk selection, scoped to the signed-in workspace.
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
  const allRows = [...table.querySelectorAll('tbody[data-domain-name]')];
  const allBodies = [...table.querySelectorAll('tbody[data-group-id]')];
  const groups = [...table.querySelectorAll('[data-domain-group]')].map(header => ({
    header,
    id: header.dataset.domainGroup,
    button: header.querySelector('[data-group-toggle]'),
    rows: allBodies.filter(row => row.dataset.groupId === header.dataset.domainGroup),
    selection: header.querySelector('[data-group-select]'),
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
  for (const [selector, open] of [['[data-groups-expand]', true], ['[data-groups-collapse]', false]]) {
    const button = document.querySelector(selector);
    if (!button) continue;
    button.hidden = false;
    button.addEventListener('click', () => groups.forEach(group => setOpen(group, open, true)));
  }
  const form = document.querySelector('[data-bulk-move]');
  if (!form) return;
  const selections = allRows.map(row => row.querySelector('[data-domain-select]')).filter(Boolean);
  if (!selections.length) return;
  const selectedInput = form.querySelector('[data-selected-domains]');
  const count = form.querySelector('[data-selected-count]');
  const submit = form.querySelector('[data-move-submit]');
  const update = () => {
    const selected = selections.filter(input => input.checked).map(input => input.value);
    selectedInput.value = JSON.stringify(selected);
    count.textContent = count.dataset.template.replace('{count}', String(selected.length));
    submit.disabled = selected.length === 0 || selected.length > 1000;
    form.hidden = selected.length === 0;
    groups.forEach(group => {
      if (!group.selection) return;
      const inputs = group.rows.map(row => row.querySelector('[data-domain-select]')).filter(Boolean);
      const checked = inputs.filter(input => input.checked).length;
      group.selection.checked = inputs.length > 0 && checked === inputs.length;
      group.selection.indeterminate = checked > 0 && checked < inputs.length;
      group.selection.disabled = inputs.length === 0;
    });
  };
  table.querySelectorAll('[data-domain-selection], [data-group-selection]').forEach(label => {
    label.hidden = false;
  });
  selections.forEach(input => input.addEventListener('change', update));
  groups.forEach(group => group.selection?.addEventListener('change', () => {
    group.rows.forEach(row => {
      const input = row.querySelector('[data-domain-select]');
      if (input) input.checked = group.selection.checked;
    });
    update();
  }));
  form.querySelector('[data-selection-clear]')?.addEventListener('click', () => {
    selections.forEach(input => { input.checked = false; });
    update();
  });
  form.addEventListener('submit', event => {
    update();
    if (submit.disabled) event.preventDefault();
  });
  update();
})();
