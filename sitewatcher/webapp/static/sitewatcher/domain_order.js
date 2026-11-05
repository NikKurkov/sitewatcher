// Native drag-and-drop changes display order only; monitoring settings are untouched.
(() => {
  const table = document.querySelector('[data-domain-order]');
  if (!table) return;
  const body = table;
  const token = table.querySelector('[name=csrfmiddlewaretoken]');
  const message = document.querySelector('[data-order-status]');
  const handles = [...table.querySelectorAll('[data-domain-drag]')];
  if (!token || !handles.length) return;
  const rows = () => [...body.children].filter(node => node.matches('tbody[data-domain-name]'));
  const rowOf = target => target.closest('tbody[data-domain-name]');
  const sameGroup = (a, b) => a.dataset.favorite === b.dataset.favorite && a.dataset.groupId === b.dataset.groupId;
  let source = null;
  let marked = null;
  let pending = false;
  const announce = (text, error = false) => {
    if (message.textContent !== text) message.textContent = text;
    message.classList.toggle('sr-only', !error);
    message.classList.toggle('domain-order-error', error);
  };
  const clearMarker = () => {
    marked?.classList.remove('domain-drop-before', 'domain-drop-after');
    marked = null;
  };
  const endDrag = () => {
    clearMarker();
    source?.classList.remove('domain-is-dragging');
    source = null;
    table.dataset.dragging = 'false';
  };
  const save = async before => {
    const current = rows();
    const previousRows = before.filter(node => node.matches('tbody[data-domain-name]'));
    if (current.every((row, index) => row === previousRows[index])) return;
    pending = true;
    table.setAttribute('aria-busy', 'true');
    handles.forEach(handle => { handle.draggable = false; handle.setAttribute('aria-disabled', 'true'); });
    try {
      const response = await fetch('/domains/reorder', {
        method: 'POST', credentials: 'same-origin', cache: 'no-store',
        headers: {'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
          'X-CSRFToken': token.value, Accept: 'application/json'},
        body: new URLSearchParams({order: JSON.stringify(current.map(row => row.dataset.domainName))}),
      });
      if (!response.ok || response.redirected || !(await response.json()).saved) throw new Error('Order not confirmed');
      announce(table.dataset.saved);
    } catch {
      body.replaceChildren(...before);
      announce(table.dataset.failed, true);
    } finally {
      pending = false;
      table.setAttribute('aria-busy', 'false');
      handles.forEach(handle => { handle.draggable = true; handle.setAttribute('aria-disabled', 'false'); });
    }
  };
  handles.forEach(handle => {
    handle.hidden = false;
    handle.addEventListener('keydown', event => {
      if (!event.altKey || !['ArrowUp', 'ArrowDown'].includes(event.key)) return;
      event.preventDefault();
      if (pending || source) return;
      const before = [...body.children];
      const row = rowOf(handle);
      const domainRows = rows();
      const index = domainRows.indexOf(row);
      const neighbor = domainRows[index + (event.key === 'ArrowUp' ? -1 : 1)];
      if (!neighbor) return;
      if (!sameGroup(neighbor, row)) { announce(table.dataset.group); return; }
      body.insertBefore(row, event.key === 'ArrowUp' ? neighbor : neighbor.nextElementSibling);
      handle.focus({preventScroll: true});
      handle.scrollIntoView({block: 'nearest'});
      save(before);
    });
  });
  table.addEventListener('dragstart', event => {
    const handle = event.target.closest('[data-domain-drag]');
    if (!handle) return;
    if (pending) { event.preventDefault(); return; }
    source = rowOf(handle);
    source.classList.add('domain-is-dragging');
    table.dataset.dragging = 'true';
    event.dataTransfer.effectAllowed = 'move';
    event.dataTransfer.setData('text/plain', source.dataset.domainName);
  });
  table.addEventListener('dragover', event => {
    if (!source) return;
    const target = rowOf(event.target);
    clearMarker();
    if (!target || target === source || !sameGroup(target, source)) {
      event.dataTransfer.dropEffect = 'none';
      return;
    }
    event.preventDefault();
    event.dataTransfer.dropEffect = 'move';
    const bounds = target.getBoundingClientRect();
    target.classList.add(event.clientY < bounds.top + bounds.height / 2 ? 'domain-drop-before' : 'domain-drop-after');
    marked = target;
  });
  table.addEventListener('drop', event => {
    if (!source) return;
    event.preventDefault();
    const target = rowOf(event.target);
    if (target && target !== source && sameGroup(target, source)) {
      const before = [...body.children];
      const bounds = target.getBoundingClientRect();
      body.insertBefore(source, event.clientY < bounds.top + bounds.height / 2 ? target : target.nextElementSibling);
      endDrag();
      save(before);
    } else {
      if (target && !sameGroup(target, source)) announce(table.dataset.group);
      endDrag();
    }
  });
  table.addEventListener('dragend', endDrag);
})();
