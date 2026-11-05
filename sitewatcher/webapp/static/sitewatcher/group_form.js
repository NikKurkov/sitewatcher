// Progressive enhancement: group creation is still validated with the domain on the server.
(() => {
  const select = document.querySelector('#group_id');
  const field = document.querySelector('[data-new-group-field]');
  const input = field?.querySelector('input');
  if (!select || !field || !input) return;
  const update = focus => {
    const creating = select.value === 'new';
    field.hidden = !creating;
    input.disabled = !creating;
    input.required = creating;
    if (creating && focus) input.focus();
  };
  select.addEventListener('change', () => update(true));
  update(false);
})();
