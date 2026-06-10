/* casspeed — Speed test UI */
/* Progressive enhancement: page works without this file (form POST fallback) */

(function () {
  'use strict';

  /* ── Constants ──────────────────────────────────────────────────── */
  var WS_URL = (location.protocol === 'https:' ? 'wss://' : 'ws://') +
               location.host + '/api/v1/speed-tests/ws';

  /* Gauge arc length for a 180-degree semicircle at r=100 */
  /* Arc path used: from 180deg to 0deg on a 240x140 viewport */
  var GAUGE_ARC_LENGTH = 220;

  /* Max scale for gauge needle — anything above this shows as full */
  var GAUGE_MAX_MBPS = 1000;

  /* ── DOM references (set once on DOMContentLoaded) ─────────────── */
  var startBtn, testAgainBtn;
  var progressSection, progressFill, progressPct, progressStage;
  var phaseSteps;
  var statusMsg;
  var resultsSection, shareSection;
  var dlValue, ulValue, pingValue, jitterValue, lossValue;
  var liveNumber, liveUnit, liveStage;
  var gaugeArc, gaugeValue, gaugeUnit, gaugeLabel;
  var shareInput, shareCopyBtn;
  var noJsFallback;

  /* ── State ──────────────────────────────────────────────────────── */
  var ws = null;
  var isRunning = false;
  /* Last known speed per stage, so we can display final even if WS has no result payload */
  var stageResults = { ping: 0, download: 0, upload: 0, jitter: 0, packetLoss: 0 };

  /* ── Init ───────────────────────────────────────────────────────── */
  document.addEventListener('DOMContentLoaded', function () {
    cacheElements();
    bindEvents();
    setupThemeToggle();

    /* Hide no-JS fallback now that JS is running */
    if (noJsFallback) {
      noJsFallback.style.display = 'none';
    }
  });

  function cacheElements() {
    startBtn        = document.getElementById('startBtn');
    testAgainBtn    = document.getElementById('testAgainBtn');
    progressSection = document.getElementById('progressSection');
    progressFill    = document.getElementById('progressFill');
    progressPct     = document.getElementById('progressPct');
    progressStage   = document.getElementById('progressStage');
    phaseSteps      = document.querySelectorAll('[data-phase]');
    statusMsg       = document.getElementById('statusMsg');
    resultsSection  = document.getElementById('resultsSection');
    shareSection    = document.getElementById('shareSection');
    dlValue         = document.getElementById('dlValue');
    ulValue         = document.getElementById('ulValue');
    pingValue       = document.getElementById('pingValue');
    jitterValue     = document.getElementById('jitterValue');
    lossValue       = document.getElementById('lossValue');
    liveNumber      = document.getElementById('liveNumber');
    liveUnit        = document.getElementById('liveUnit');
    liveStage       = document.getElementById('liveStage');
    gaugeArc        = document.getElementById('gaugeArc');
    gaugeValue      = document.getElementById('gaugeValue');
    gaugeUnit       = document.getElementById('gaugeUnitText');
    gaugeLabel      = document.getElementById('gaugeLabelText');
    shareInput      = document.getElementById('shareInput');
    shareCopyBtn    = document.getElementById('shareCopyBtn');
    noJsFallback    = document.getElementById('noJsFallback');
  }

  function bindEvents() {
    if (startBtn) {
      startBtn.addEventListener('click', startTest);
    }
    if (testAgainBtn) {
      testAgainBtn.addEventListener('click', resetUI);
    }
    if (shareCopyBtn) {
      shareCopyBtn.addEventListener('click', copyShareLink);
    }
  }

  /* ── Theme toggle ───────────────────────────────────────────────── */
  function setupThemeToggle() {
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

    /* React to OS preference changes when in auto mode */
    if (window.matchMedia) {
      window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function () {
        var stored = window.__csTheme && window.__csTheme.get();
        if (stored === 'auto' || !stored) {
          /* CSS media queries already handle this; re-apply to sync state */
          window.__csTheme && window.__csTheme.set('auto');
        }
      });
    }
  }

  /* ── Speed test ─────────────────────────────────────────────────── */
  function startTest() {
    if (isRunning) { return; }
    isRunning = true;

    stageResults = { ping: 0, download: 0, upload: 0, jitter: 0, packetLoss: 0 };

    /* UI: show progress, hide results */
    if (startBtn) {
      startBtn.classList.remove('start-btn--idle');
      startBtn.classList.add('start-btn--running');
      startBtn.disabled = true;
      startBtn.textContent = 'Testing…';
    }
    if (progressSection) {
      progressSection.classList.add('is-visible');
    }
    if (resultsSection) {
      resultsSection.classList.remove('is-visible');
    }
    if (shareSection) {
      shareSection.classList.remove('is-visible');
    }

    setStatus('Connecting to server…');
    setPhase(null);
    updateProgress(0, 'Connecting');

    try {
      ws = new WebSocket(WS_URL);
    } catch (err) {
      onError('Could not open WebSocket connection.');
      return;
    }

    ws.addEventListener('open', function () {
      setStatus('Measuring ping…');
    });

    ws.addEventListener('message', function (evt) {
      var data;
      try {
        data = JSON.parse(evt.data);
      } catch (_) {
        return;
      }
      handleMessage(data);
    });

    ws.addEventListener('error', function () {
      onError('Connection lost. Please try again.');
    });

    ws.addEventListener('close', function () {
      if (isRunning) {
        /* Closed before "complete" message — treat as error */
        onError('Connection closed unexpectedly. Please try again.');
      }
    });
  }

  function handleMessage(data) {
    var stage    = data.stage || '';
    var progress = typeof data.progress === 'number' ? data.progress : 0;
    var speed    = typeof data.speed === 'number' ? data.speed : 0;
    var message  = data.message || '';

    if (stage === 'complete') {
      onComplete(data);
      return;
    }

    /* Track per-stage peak speeds */
    if (stage === 'ping' && speed > 0) {
      stageResults.ping = speed;
    }
    if (stage === 'download' && speed > 0) {
      stageResults.download = speed;
    }
    if (stage === 'upload' && speed > 0) {
      stageResults.upload = speed;
    }

    setPhase(stage);

    var stagePct = 0;
    if (stage === 'ping') {
      stagePct = progress * 0.15;
    } else if (stage === 'download') {
      stagePct = 0.15 + progress * 0.45;
    } else if (stage === 'upload') {
      stagePct = 0.60 + progress * 0.40;
    }

    updateProgress(stagePct, stageLabel(stage));
    setStatus(message || stageLabel(stage) + '…');

    /* Live speed readout */
    if (stage === 'ping') {
      setLiveSpeed(speed, 'ms', 'Ping');
      updateGauge(Math.min(speed / 200, 1), speed, 'ms', 'Ping');
    } else {
      setLiveSpeed(speed, 'Mbps', stageLabel(stage));
      updateGauge(Math.min(speed / GAUGE_MAX_MBPS, 1), speed, 'Mbps', stageLabel(stage));
    }
  }

  function onComplete(data) {
    isRunning = false;
    if (ws) { ws.close(); ws = null; }

    /* Use WS payload values if server sends them; otherwise use tracked values */
    var dl   = typeof data.download_mbps === 'number' ? data.download_mbps : stageResults.download;
    var ul   = typeof data.upload_mbps   === 'number' ? data.upload_mbps   : stageResults.upload;
    var ping = typeof data.ping_ms       === 'number' ? data.ping_ms       : stageResults.ping;
    var jit  = typeof data.jitter_ms     === 'number' ? data.jitter_ms     : (stageResults.jitter || 0);
    var loss = typeof data.packet_loss   === 'number' ? data.packet_loss   : (stageResults.packetLoss || 0);
    var shareCode = data.share_code || '';

    updateProgress(1, 'Complete');
    setPhaseAllDone();
    setStatus('Test complete');

    /* Populate result cards */
    setText(dlValue,     fmt(dl, 2));
    setText(ulValue,     fmt(ul, 2));
    setText(pingValue,   fmt(ping, 1));
    setText(jitterValue, fmt(jit, 1));
    setText(lossValue,   fmt(loss, 1) + '%');

    /* Show results */
    if (resultsSection) {
      resultsSection.classList.add('is-visible');
    }

    /* Share link */
    if (shareCode && shareSection && shareInput) {
      var shareUrl = location.protocol + '//' + location.host + '/share/' + shareCode;
      shareInput.value = shareUrl;
      shareSection.classList.add('is-visible');
    }

    /* Reset button */
    if (startBtn) {
      startBtn.classList.remove('start-btn--running');
      startBtn.style.display = 'none';
    }
    if (testAgainBtn) {
      testAgainBtn.style.display = '';
    }

    /* Final gauge showing download speed */
    updateGauge(Math.min(dl / GAUGE_MAX_MBPS, 1), dl, 'Mbps', 'Download');
    setLiveSpeed(dl, 'Mbps', 'Download');
  }

  function onError(msg) {
    isRunning = false;
    if (ws) { try { ws.close(); } catch (_) {} ws = null; }

    setStatus(msg);
    if (statusMsg) {
      statusMsg.classList.add('is-error');
    }

    if (startBtn) {
      startBtn.classList.remove('start-btn--running');
      startBtn.classList.add('start-btn--idle');
      startBtn.disabled = false;
      startBtn.textContent = 'START';
    }
    if (progressSection) {
      progressSection.classList.remove('is-visible');
    }

    showToast(msg, 'error');
  }

  function resetUI() {
    stageResults = { ping: 0, download: 0, upload: 0, jitter: 0, packetLoss: 0 };

    if (resultsSection)  { resultsSection.classList.remove('is-visible'); }
    if (shareSection)    { shareSection.classList.remove('is-visible'); }
    if (progressSection) { progressSection.classList.remove('is-visible'); }

    if (startBtn) {
      startBtn.style.display = '';
      startBtn.classList.add('start-btn--idle');
      startBtn.classList.remove('start-btn--running');
      startBtn.disabled = false;
      startBtn.textContent = 'START';
    }
    if (testAgainBtn) {
      testAgainBtn.style.display = 'none';
    }

    setStatus('');
    updateProgress(0, '');
    setPhase(null);
    setLiveSpeed(0, 'Mbps', '');
    updateGauge(0, 0, 'Mbps', 'Speed');
  }

  /* ── UI helpers ─────────────────────────────────────────────────── */

  function stageLabel(stage) {
    var labels = { ping: 'Ping', download: 'Download', upload: 'Upload' };
    return labels[stage] || stage;
  }

  function updateProgress(fraction, label) {
    var pct = Math.round(Math.min(Math.max(fraction, 0), 1) * 100);
    if (progressFill)  { progressFill.style.width = pct + '%'; }
    if (progressPct)   { progressPct.textContent = pct + '%'; }
    if (progressStage && label) { progressStage.textContent = label; }
  }

  function setPhase(active) {
    if (!phaseSteps) { return; }
    var phases = ['ping', 'download', 'upload'];
    var activeIdx = phases.indexOf(active);

    phaseSteps.forEach(function (el) {
      var phase = el.dataset.phase;
      var idx   = phases.indexOf(phase);
      el.classList.remove('is-active', 'is-done');
      if (phase === active) {
        el.classList.add('is-active');
      } else if (activeIdx >= 0 && idx < activeIdx) {
        el.classList.add('is-done');
      }
    });
  }

  function setPhaseAllDone() {
    if (!phaseSteps) { return; }
    phaseSteps.forEach(function (el) {
      el.classList.remove('is-active');
      el.classList.add('is-done');
    });
  }

  function setStatus(msg) {
    if (!statusMsg) { return; }
    statusMsg.textContent = msg;
    if (!msg) { statusMsg.classList.remove('is-error'); }
  }

  function setLiveSpeed(speed, unit, stage) {
    if (liveNumber) { liveNumber.textContent = speed > 0 ? fmt(speed, speed < 10 ? 1 : 0) : '--'; }
    if (liveUnit)   { liveUnit.textContent = unit; }
    if (liveStage)  { liveStage.textContent = stage; }
  }

  function updateGauge(fraction, speed, unit, label) {
    if (!gaugeArc) { return; }
    var offset = GAUGE_ARC_LENGTH * (1 - Math.min(Math.max(fraction, 0), 1));
    gaugeArc.style.strokeDashoffset = offset;
    if (gaugeValue) { gaugeValue.textContent = speed > 0 ? fmt(speed, speed < 10 ? 1 : 0) : '--'; }
    if (gaugeUnit)  { gaugeUnit.textContent = unit; }
    if (gaugeLabel) { gaugeLabel.textContent = label; }
  }

  function setText(el, text) {
    if (el) { el.textContent = text; }
  }

  function fmt(n, decimals) {
    if (typeof n !== 'number' || isNaN(n)) { return '--'; }
    return n.toFixed(decimals);
  }

  /* ── Copy share link ─────────────────────────────────────────────── */
  function copyShareLink() {
    if (!shareInput || !shareCopyBtn) { return; }
    var url = shareInput.value;
    if (!url) { return; }

    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(url).then(function () {
        showCopied();
      }).catch(function () {
        fallbackCopy(url);
      });
    } else {
      fallbackCopy(url);
    }
  }

  function fallbackCopy(text) {
    shareInput.select();
    try {
      document.execCommand('copy');
      showCopied();
    } catch (_) {
      showToast('Could not copy to clipboard — select the URL manually.', 'info');
    }
  }

  function showCopied() {
    if (!shareCopyBtn) { return; }
    var orig = shareCopyBtn.textContent;
    shareCopyBtn.textContent = 'Copied!';
    shareCopyBtn.classList.add('is-copied');
    showToast('Share link copied to clipboard.', 'success');
    setTimeout(function () {
      shareCopyBtn.textContent = orig;
      shareCopyBtn.classList.remove('is-copied');
    }, 2000);
  }

  /* ── Toast ───────────────────────────────────────────────────────── */
  function showToast(msg, type) {
    var container = document.getElementById('toastContainer');
    if (!container) { return; }

    var toast = document.createElement('div');
    toast.className = 'toast toast--' + (type || 'info');
    toast.setAttribute('role', 'status');
    toast.setAttribute('aria-live', 'polite');
    toast.textContent = msg;

    container.appendChild(toast);

    var duration = type === 'error' ? 6000 : 3000;
    setTimeout(function () {
      toast.classList.add('is-leaving');
      setTimeout(function () {
        if (toast.parentNode) { toast.parentNode.removeChild(toast); }
      }, 220);
    }, duration);
  }

}());
