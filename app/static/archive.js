/* Archive: preview switching, keyboard navigation and scale-to-fit. */
(function () {
  var list = document.getElementById('run-list');
  if (!list) return;
  function $(id) { return document.getElementById(id); }
  function show(a) {
    var d = a.dataset;
    list.querySelectorAll('.run-item.selected').forEach(function (x) { x.classList.remove('selected'); });
    a.classList.add('selected');
    $('pv-title').textContent = d.title;
    $('pv-period').textContent = d.period;
    $('pv-meta').textContent = d.meta;
    var chip = $('pv-status'); chip.textContent = d.status; chip.className = 'chip ' + d.status;
    var open = $('pv-open'), pdf = $('pv-pdf'), frame = $('pv-frame'), err = $('pv-error');
    open.hidden = !d.html; if (d.html) { open.href = d.html; }
    pdf.hidden = !d.pdf; if (d.pdf) { pdf.href = d.pdf; }
    err.hidden = !d.error; err.textContent = d.error || '';
    var warn = $('pv-warning'); warn.hidden = !d.warning; warn.textContent = d.warning || '';
    $('pv-running').hidden = d.status !== 'running';
    $('pv-stage').hidden = !d.html;
    if (d.html) { if (frame.getAttribute('src') !== d.html) { frame.setAttribute('src', d.html); } } else { frame.removeAttribute('src'); }
    fit();
    if (window.history && history.replaceState) { history.replaceState(null, '', a.href); }
  }
  list.addEventListener('click', function (e) {
    var a = e.target.closest('.run-item');
    if (!a || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) { return; }
    e.preventDefault(); show(a);
  });
  document.addEventListener('keydown', function (e) {
    if (e.metaKey || e.ctrlKey || e.altKey || (e.target.closest && e.target.closest('input, select, textarea'))) { return; }
    var dir = (e.key === 'ArrowDown' || e.key === 'j') ? 1 : ((e.key === 'ArrowUp' || e.key === 'k') ? -1 : 0);
    if (!dir) { return; }
    var items = Array.prototype.slice.call(list.querySelectorAll('.run-item'));
    var i = items.findIndex(function (x) { return x.classList.contains('selected'); });
    var next = items[Math.min(items.length - 1, Math.max(0, i + dir))];
    if (next) { e.preventDefault(); show(next); next.scrollIntoView({ block: 'nearest' }); next.focus({ preventScroll: true }); }
  });
  // Reports are laid out for ~900 px (e-mail/PDF width): scale the preview down like a page thumbnail
  // instead of clipping wide tables. "Open" shows it full size.
  function fit() {
    var stage = $('pv-stage'), frame = $('pv-frame');
    if (!stage || stage.hidden) { return; }
    var w = stage.clientWidth, s = Math.min(1, w / 900), h = Math.max(560, window.innerHeight - 190);
    stage.style.height = h + 'px';
    frame.style.width = (w / s) + 'px';
    frame.style.height = (h / s) + 'px';
    frame.style.transform = s < 1 ? 'scale(' + s + ')' : '';
  }
  window.addEventListener('resize', fit);
  fit();
  var current = list.querySelector('.run-item.selected');
  if (current) { current.scrollIntoView({ block: 'nearest' }); }
})();
