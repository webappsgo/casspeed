/* casspeed — Admin panel JS */

(function () {
  'use strict';

  document.addEventListener('DOMContentLoaded', function () {
    initNavToggle();
    initThemeToggle();
  });

  /* ── Mobile sidebar toggle ──────────────────────────────────────── */
  function initNavToggle() {
    var toggle  = document.getElementById('navToggle');
    var nav     = document.getElementById('adminNav');
    var overlay = document.getElementById('navOverlay');
    if (!toggle || !nav || !overlay) { return; }

    function open() {
      nav.classList.add('is-open');
      overlay.classList.add('is-visible');
      overlay.setAttribute('aria-hidden', 'false');
      toggle.setAttribute('aria-expanded', 'true');
      toggle.setAttribute('aria-label', 'Close navigation');
      /* Move focus into nav */
      var first = nav.querySelector('a, button');
      if (first) { first.focus(); }
    }

    function close() {
      nav.classList.remove('is-open');
      overlay.classList.remove('is-visible');
      overlay.setAttribute('aria-hidden', 'true');
      toggle.setAttribute('aria-expanded', 'false');
      toggle.setAttribute('aria-label', 'Open navigation');
      toggle.focus();
    }

    toggle.addEventListener('click', function () {
      nav.classList.contains('is-open') ? close() : open();
    });

    overlay.addEventListener('click', close);

    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && nav.classList.contains('is-open')) {
        close();
      }
    });
  }

  /* ── Theme toggle (syncs button aria-pressed state) ─────────────── */
  function initThemeToggle() {
    var btns = document.querySelectorAll('[data-theme-btn]');
    var current = (window.__csTheme && window.__csTheme.get()) || 'auto';

    for (var i = 0; i < btns.length; i++) {
      var btn = btns[i];
      var pref = btn.dataset.themeBtn;
      btn.setAttribute('aria-pressed', pref === current ? 'true' : 'false');
      btn.addEventListener('click', (function (p) {
        return function () {
          window.__csTheme && window.__csTheme.set(p);
        };
      }(pref)));
    }
  }

}());
