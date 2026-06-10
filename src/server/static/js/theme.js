/* casspeed — Theme toggle (dark / light / auto) */
/* Runs immediately from <head> to prevent flash of wrong theme */

(function () {
  'use strict';

  var STORAGE_KEY = 'casspeed-theme';
  var VALID = ['dark', 'light', 'auto'];

  function applyTheme(pref) {
    var html = document.documentElement;
    if (pref === 'dark') {
      html.setAttribute('data-theme', 'dark');
    } else if (pref === 'light') {
      html.setAttribute('data-theme', 'light');
    } else {
      /* auto — remove explicit attribute; CSS media queries handle it */
      html.removeAttribute('data-theme');
    }
  }

  function getStored() {
    try {
      var v = localStorage.getItem(STORAGE_KEY);
      return VALID.indexOf(v) !== -1 ? v : 'auto';
    } catch (_) {
      return 'auto';
    }
  }

  function setStored(pref) {
    try {
      localStorage.setItem(STORAGE_KEY, pref);
    } catch (_) {}
  }

  /* Apply immediately to prevent FOUC */
  applyTheme(getStored());

  /* Export to window so app.js can call without re-reading storage */
  window.__csTheme = {
    get: getStored,
    set: function (pref) {
      if (VALID.indexOf(pref) === -1) { return; }
      setStored(pref);
      applyTheme(pref);
      /* Sync toggle buttons if they exist */
      var btns = document.querySelectorAll('[data-theme-btn]');
      for (var i = 0; i < btns.length; i++) {
        btns[i].setAttribute('aria-pressed', btns[i].dataset.themeBtn === pref ? 'true' : 'false');
      }
    }
  };
}());
