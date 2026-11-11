(function () {
  const form      = document.getElementById('scanForm');
  const launchBtn = document.getElementById('launchBtn');
  const summary   = document.getElementById('selSummary');
  const demoBtn   = document.getElementById('demoBtn');
  const demoForm  = document.getElementById('demoForm');

  if (!form) return;

  /* card click toggles checkbox + selected class */
  form.querySelectorAll('.sel-card').forEach(card => {
    card.addEventListener('click', () => {
      const cb = card.querySelector('input[type=checkbox]');
      cb.checked = !cb.checked;
      card.classList.toggle('selected', cb.checked);
      update();
    });
  });

  function checked(name) {
    return [...form.querySelectorAll(`input[name=${name}]:checked`)]
      .map(el => el.closest('.sel-card').querySelector('.card-name').textContent.trim());
  }

  function update() {
    const tgts  = checked('targets');
    const tools = checked('tools');
    const ok = tgts.length > 0 && tools.length > 0;
    launchBtn.disabled = !ok;

    if (ok) {
      summary.innerHTML = `<strong>${tgts.join(', ')}</strong> &middot; ${tools.join(', ')}`;
    } else if (tgts.length === 0) {
      summary.textContent = tgts.length === 0 && tools.length === 0
        ? (document.documentElement.lang === 'fr'
            ? 'Sélectionne au moins une cible et un outil'
            : 'Select at least one target and one tool')
        : (document.documentElement.lang === 'fr'
            ? 'Sélectionne au moins une cible'
            : 'Select at least one target');
    } else {
      summary.textContent = document.documentElement.lang === 'fr'
        ? 'Sélectionne au moins un outil'
        : 'Select at least one tool';
    }
  }

  /* prevent double-submit */
  form.addEventListener('submit', e => {
    if (launchBtn.disabled) { e.preventDefault(); return; }
    launchBtn.disabled = true;
    launchBtn.textContent = '…';
  });

  /* demo button: submit the hidden demo form */
  if (demoBtn && demoForm) {
    demoBtn.addEventListener('click', () => {
      demoBtn.textContent = '…';
      demoBtn.disabled = true;
      demoForm.submit();
    });
  }
})();
