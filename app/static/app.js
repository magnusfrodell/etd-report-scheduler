/* ETD Report Scheduler - behaviour shared by every page. No inline scripts: see the CSP in app/web/security.py. */
(function () {
  // <form data-confirm="..."> asks before submitting. The text comes from an escaped attribute and is
  // passed to confirm() as a string, so names in it can never become code.
  document.addEventListener('submit', function (e) {
    var message = e.target.getAttribute && e.target.getAttribute('data-confirm');
    if (message && !window.confirm(message)) { e.preventDefault(); }
  }, true);
  // <select data-autosubmit> submits its form when the value changes.
  document.addEventListener('change', function (e) {
    var el = e.target;
    if (el.hasAttribute && el.hasAttribute('data-autosubmit') && el.form) { el.form.submit(); }
  });
})();
