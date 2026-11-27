/* Optional clipboard enhancement; copy values remain selectable without JavaScript. */
(function () {
  'use strict';
  document.addEventListener('click', function (event) {
    var button = event.target.closest('[data-copy]');
    if (!button) return;
    var value = document.getElementById(button.dataset.copy);
    if (!value) return;
    var text = value.textContent || '';
    var feedback = button.parentElement.querySelector('[aria-live="polite"]');
    var finish = function (success) {
      if (feedback) feedback.textContent = success ? button.dataset.copySuccess : button.dataset.copyFailure;
    };
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(function () { finish(true); }, function () { finish(false); });
      return;
    }
    var range = document.createRange();
    range.selectNodeContents(value);
    var selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
    var copied = document.execCommand('copy');
    selection.removeAllRanges();
    finish(copied);
  });
}());
