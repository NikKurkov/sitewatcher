// Move existing rows after server confirmation, retaining charts, details and listeners.
(() => {
  const table = document.querySelector('[data-domain-order]');
  if (!table) return;
  const token = table.querySelector('[name=csrfmiddlewaretoken]');
  const message = document.querySelector('[data-order-status]');
  const handles = [...table.querySelectorAll('[data-domain-drag]')];
  if (!token || !handles.length) return;
  const rows = () => [...table.children].filter(node => node.matches('tbody[data-domain-name]'));
  const headers = () => [...table.querySelectorAll('[data-domain-group]')];
  const rowOf = target => target.closest('tbody[data-domain-name]');
  const groupOf = target => {
    const node = target.closest('[data-domain-group], tbody[data-group-id]');
    return node ? node.dataset.domainGroup ?? node.dataset.groupId : null;
  };
  const sameGroup = (a, b) => a.dataset.favorite === b.dataset.favorite && a.dataset.groupId === b.dataset.groupId;
  const reduced = () => window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const emit = (name, detail) => table.dispatchEvent(new CustomEvent(name, {detail}));
  const dialog = document.querySelector('[data-domain-move-dialog]');
  const select = dialog?.querySelector('select');
  const confirm = dialog?.querySelector('[data-move-confirm]');
  let dialogRow = null;
  let source = null;
  let marked = null;
  let pending = false;
  let ghost = null;
  let hoverTimer = null;
  let scrollFrame = null;
  let pointerY = null;
  let noticeTimer = null;
  let cooldownTimer = null;
  let ignoreClickUntil = 0;
  const previewOpen = new Set();
  const announce = (text, error = false, saving = false) => {
    clearTimeout(noticeTimer);
    if (message.textContent !== text) message.textContent = text;
    message.classList.remove('sr-only');
    message.classList.add('domain-order-notice');
    message.classList.toggle('domain-order-error', error);
    message.classList.toggle('is-saving', saving);
    if (dialog?.open) {
      const status = dialog.querySelector('[data-move-status]');
      status.textContent = text;
      status.hidden = false;
      status.classList.toggle('domain-move-dialog-error', error);
    }
    if (!error && !saving) noticeTimer = setTimeout(() => message.classList.add('sr-only'), 5000);
  };
  const busy = value => {
    pending = value;
    clearTimeout(cooldownTimer);
    table.dataset.moveCooldown = 'true';
    if (!value) cooldownTimer = setTimeout(() => { delete table.dataset.moveCooldown; }, 5000);
    table.setAttribute('aria-busy', String(value));
    handles.forEach(handle => {
      handle.draggable = !value;
      handle.setAttribute('aria-disabled', String(value));
    });
    if (dialog) {
      confirm.disabled = value || !dialogRow || select.value === dialogRow.dataset.groupId;
      dialog.querySelector('[data-move-cancel]').disabled = value;
      select.disabled = value;
    }
  };
  const clearMarker = () => {
    clearTimeout(hoverTimer);
    hoverTimer = null;
    marked?.classList.remove('domain-drop-before', 'domain-drop-after', 'domain-drop-group');
    marked = null;
  };
  const endDrag = (keepOpen = null) => {
    clearMarker();
    if (scrollFrame !== null) cancelAnimationFrame(scrollFrame);
    scrollFrame = null;
    pointerY = null;
    source?.classList.remove('domain-is-dragging');
    source = null;
    ghost?.remove();
    ghost = null;
    previewOpen.forEach(id => {
      if (id !== keepOpen) emit('sitewatcher:group-open', {id, open: false, persist: false});
    });
    previewOpen.clear();
    table.dataset.dragging = 'false';
    ignoreClickUntil = Date.now() + 200;
  };
  const edgeScroll = () => {
    if (!source) return;
    if (pointerY !== null) {
      const margin = 80;
      const delta = pointerY < margin ? -Math.min(18, (margin - pointerY) / 4)
        : pointerY > innerHeight - margin ? Math.min(18, (pointerY - innerHeight + margin) / 4) : 0;
      if (delta) window.scrollBy(0, delta);
    }
    scrollFrame = requestAnimationFrame(edgeScroll);
  };
  const request = async (url, options = {}) => {
    const response = await fetch(url, {credentials: 'same-origin', cache: 'no-store',
      signal: globalThis.AbortSignal?.timeout(15000), ...options});
    if (!response.ok || response.redirected) throw new Error('Request not confirmed');
    return response.json();
  };
  const parseBody = html => {
    const template = document.createElement('template');
    template.innerHTML = `<table>${html}</table>`;
    const node = template.content.querySelector('tbody');
    if (!node) throw new Error('Invalid group response');
    return node;
  };
  const applyGroups = async (payload, moved) => {
    if (!payload.saved || !Array.isArray(payload.groups) || !Array.isArray(payload.order)
        || !payload.membership || typeof payload.membership !== 'object') {
      throw new Error('Missing membership confirmation');
    }
    const current = rows();
    const oldOpen = new Map(headers().map(header => [header.dataset.domainGroup,
      header.querySelector('[data-group-toggle]').getAttribute('aria-expanded')]));
    // Validate and prepare all server-rendered fragments before changing the live DOM.
    const fragments = payload.groups.map(group => {
      const header = parseBody(group.heading);
      const empty = parseBody(group.empty);
      if (header.dataset.domainGroup !== String(group.id)
          || empty.dataset.groupId !== String(group.id)) throw new Error('Mismatched group response');
      header.querySelector('[data-group-toggle]').setAttribute('aria-expanded', oldOpen.get(String(group.id)) ?? 'true');
      return {group, header, empty};
    });
    const groupIds = new Set(fragments.map(item => String(item.group.id)));
    if (current.some(row => Object.hasOwn(payload.membership, row.dataset.domainName)
        && !groupIds.has(String(payload.membership[row.dataset.domainName])))) {
      throw new Error('Missing destination group');
    }
    const positions = new Map(reduced() ? [] : current.filter(row => !row.hidden)
      .map(row => [row, row.getBoundingClientRect().top]));
    const rank = new Map(payload.order.map((name, index) => [name, index]));
    const ordered = current.filter(row => Object.hasOwn(payload.membership, row.dataset.domainName))
      .sort((a, b) => rank.get(a.dataset.domainName) - rank.get(b.dataset.domainName));
    const nodes = [...table.children].filter(node => !node.matches('tbody'));
    const destination = payload.membership[moved.dataset.domainName];
    for (const {group, header, empty} of fragments) {
      const members = ordered.filter(row => String(payload.membership[row.dataset.domainName]) === String(group.id));
      if (table.dataset.groupFiltered === 'true' && !members.length) continue;
      if (fragments.length > 1) nodes.push(header);
      members.forEach(row => {
        row.dataset.groupId = String(group.id);
        if (fragments.length === 1) row.hidden = false;
      });
      nodes.push(...members);
      if (!members.length && group.total === 0) nodes.push(empty);
    }
    const scrollX = window.scrollX, scrollY = window.scrollY;
    table.replaceChildren(...nodes);
    if (select) select.replaceChildren(...fragments.map(({group, header}) => {
      const option = document.createElement('option');
      option.value = String(group.id);
      option.textContent = header.querySelector('.group-name').textContent;
      return option;
    }));
    emit('sitewatcher:groups-updated', {open: destination});
    window.scrollTo(scrollX, scrollY);
    if (moved.isConnected) {
      const handle = moved.querySelector('[data-domain-drag]');
      handle.focus({preventScroll: true});
      const bounds = moved.getBoundingClientRect();
      if (bounds.top < 16 || bounds.bottom > innerHeight - 80) {
        moved.scrollIntoView({block: 'nearest', behavior: 'instant'});
      }
      moved.classList.remove('domain-move-arrived');
      // Animation restarts on repeated moves without replacing initialized content.
      void moved.offsetHeight;
      moved.classList.add('domain-move-arrived');
    }
    const animations = [];
    if (!reduced()) positions.forEach((top, row) => {
      if (row.hidden || !row.isConnected || !row.animate) return;
      const delta = top - row.getBoundingClientRect().top;
      if (delta && Math.abs(delta) < innerHeight) animations.push(row.animate([
        {transform: `translateY(${delta}px)`}, {transform: 'translateY(0)'},
      ], {duration: 220, easing: 'cubic-bezier(.2,.7,.2,1)'}).finished.catch(() => {}));
    });
    await Promise.all(animations);
    return destination;
  };
  const save = async before => {
    const current = rows();
    const previousRows = before.filter(node => node.matches('tbody[data-domain-name]'));
    if (current.every((row, index) => row === previousRows[index])) return;
    busy(true);
    try {
      const data = await request('/domains/reorder', {
        method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
          'X-CSRFToken': token.value, Accept: 'application/json'},
        body: new URLSearchParams({order: JSON.stringify(current.map(row => row.dataset.domainName))}),
      });
      if (!data.saved) throw new Error('Order not confirmed');
      announce(table.dataset.saved);
    } catch {
      table.replaceChildren(...before);
      announce(table.dataset.failed, true);
    } finally { busy(false); }
  };
  const moveGroup = async (row, groupId) => {
    if (pending || String(groupId) === row.dataset.groupId) return;
    const original = row.dataset.groupId;
    busy(true);
    announce(table.dataset.saving, false, true);
    row.classList.add('domain-is-moving');
    let snapshot = null;
    try {
      snapshot = await request('/settings/groups', {
        method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
          'X-CSRFToken': token.value, Accept: 'application/json'},
        body: new URLSearchParams({operation: 'move', group_id: groupId, original_group_id: original,
          domains: JSON.stringify([row.dataset.domainName])}),
      });
      if (!snapshot.saved || !snapshot.membership) throw new Error('Move not confirmed');
    } catch {
      // A lost POST response is not proof of rollback. Read state; never repeat the write.
      try { snapshot = await request('/settings/groups', {headers: {Accept: 'application/json'}}); }
      catch { snapshot = null; }
    }
    try {
      if (!snapshot?.saved || !snapshot.membership) throw new Error('No authoritative state');
      if (dialog?.open) dialog.close();
      const destination = await applyGroups(snapshot, row);
      if (String(destination) === String(groupId)) announce(table.dataset.moved);
      else if (String(destination) !== original) announce(table.dataset.moveChanged, true);
      else announce(table.dataset.moveFailed, true);
    } catch {
      announce(table.dataset.moveFailed, true);
    } finally {
      row.classList.remove('domain-is-moving');
      busy(false);
    }
  };
  if (dialog) {
    dialog.querySelector('[data-move-cancel]').addEventListener('click', () => dialog.close());
    dialog.addEventListener('cancel', event => { if (pending) event.preventDefault(); });
    select.addEventListener('change', () => { confirm.disabled = select.value === dialogRow?.dataset.groupId; });
    dialog.querySelector('form').addEventListener('submit', event => {
      event.preventDefault();
      if (dialogRow) moveGroup(dialogRow, select.value);
    });
  }
  handles.forEach(handle => {
    handle.hidden = false;
    handle.addEventListener('click', () => {
      if (!dialog || select.options.length < 2 || pending || source || Date.now() < ignoreClickUntil) return;
      dialogRow = rowOf(handle);
      dialog.querySelector('[data-move-domain]').textContent = dialogRow.dataset.domainName;
      select.value = dialogRow.dataset.groupId;
      confirm.disabled = true;
      dialog.querySelector('[data-move-status]').hidden = true;
      dialog.showModal();
      select.focus();
    });
    handle.addEventListener('keydown', event => {
      if (!event.altKey || !['ArrowUp', 'ArrowDown'].includes(event.key)) return;
      event.preventDefault();
      if (pending || source) return;
      const before = [...table.children];
      const row = rowOf(handle);
      const domainRows = rows();
      const index = domainRows.indexOf(row);
      const neighbor = domainRows[index + (event.key === 'ArrowUp' ? -1 : 1)];
      if (!neighbor) return;
      if (!sameGroup(neighbor, row)) { announce(table.dataset.group); return; }
      table.insertBefore(row, event.key === 'ArrowUp' ? neighbor : neighbor.nextElementSibling);
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
    ghost = document.createElement('div');
    ghost.className = 'domain-drag-preview';
    ghost.textContent = source.dataset.domainName;
    document.body.append(ghost);
    event.dataTransfer.setDragImage?.(ghost, 20, 20);
    scrollFrame = requestAnimationFrame(edgeScroll);
  });
  document.addEventListener('dragover', event => {
    if (!source) return;
    pointerY = event.clientY;
    if (!table.contains(event.target)) clearMarker();
  });
  table.addEventListener('dragover', event => {
    if (!source) return;
    const target = rowOf(event.target);
    const groupId = groupOf(event.target);
    if (groupId !== null && groupId !== source.dataset.groupId) {
      event.preventDefault();
      event.dataTransfer.dropEffect = 'move';
      const node = event.target.closest('[data-domain-group], tbody[data-group-id]');
      if (marked !== node) {
        clearMarker();
        marked = node;
        marked.classList.add('domain-drop-group');
        const header = headers().find(item => item.dataset.domainGroup === groupId);
        const name = header?.querySelector('.group-name')?.textContent;
        if (name) announce(table.dataset.dropTarget.replace('{group}', name));
        if (header?.querySelector('[data-group-toggle]').getAttribute('aria-expanded') === 'false') {
          hoverTimer = setTimeout(() => {
            previewOpen.add(groupId);
            emit('sitewatcher:group-open', {id: groupId, open: true, persist: false});
          }, 600);
        }
      }
      return;
    }
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
    const groupId = groupOf(event.target);
    if (groupId !== null && groupId !== source.dataset.groupId) {
      const row = source;
      endDrag(groupId);
      moveGroup(row, groupId);
      return;
    }
    const target = rowOf(event.target);
    if (target && target !== source && sameGroup(target, source)) {
      const before = [...table.children];
      const bounds = target.getBoundingClientRect();
      table.insertBefore(source, event.clientY < bounds.top + bounds.height / 2 ? target : target.nextElementSibling);
      endDrag();
      save(before);
    } else {
      if (target && !sameGroup(target, source)) announce(table.dataset.group);
      endDrag();
    }
  });
  table.addEventListener('dragend', () => {
    endDrag();
    if (!pending) message.classList.add('sr-only');
  });
})();
