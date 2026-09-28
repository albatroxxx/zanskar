// Per-OS command tabs on the install page. Each [data-tabs] holds a list of
// [role=tab] buttons and matching [data-panel] blocks; the chosen tab is
// remembered so every block on the page follows the same choice.
document.querySelectorAll('[data-tabs]').forEach(group => {
  const tabs = group.querySelectorAll('[role=tab]');
  const show = key => {
    tabs.forEach(t => t.setAttribute('aria-selected', String(t.dataset.tab === key)));
    group.querySelectorAll('[data-panel]').forEach(p => { p.hidden = p.dataset.panel !== key; });
  };
  tabs.forEach(t => t.addEventListener('click', () => {
    try { localStorage.setItem('zanskar-os', t.dataset.tab); } catch { /* private mode */ }
    show(t.dataset.tab);
    document.querySelectorAll('[data-tabs]').forEach(other => {
      if (other === group) return;
      other.querySelectorAll('[role=tab]').forEach(x => x.setAttribute('aria-selected', String(x.dataset.tab === t.dataset.tab)));
      other.querySelectorAll('[data-panel]').forEach(p => { p.hidden = p.dataset.panel !== t.dataset.tab; });
    });
  }));
  let remembered = null;
  try { remembered = localStorage.getItem('zanskar-os'); } catch { /* private mode */ }
  if (remembered && group.querySelector(`[data-tab="${remembered}"]`)) show(remembered);
});
