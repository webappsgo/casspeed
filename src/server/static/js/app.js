/* casspeed — Speed test UI */
/* Progressive enhancement: page works without this file (form POST fallback) */

(function () {
  'use strict';

  /* ── Constants ──────────────────────────────────────────────────── */
  /* Gauge arc length for a 180-degree semicircle at r=100 */
  /* Arc path used: from 180deg to 0deg on a 240x140 viewport */
  var GAUGE_ARC_LENGTH = 220;

  /* Max scale for gauge needle — anything above this shows as full */
  var GAUGE_MAX_MBPS = 1000;

  var translations = {};
  var translationNode = document.getElementById('home-translations');
  if (translationNode) {
    try {
      translations = JSON.parse(translationNode.textContent || '{}');
    } catch (_) {
      translations = {};
    }
  }
  var apiBase = document.body.dataset.apiBase || '/api/v1';
  var basePath = document.body.dataset.basePath || '';

  function t(key, values) {
    var value = translations;
    key.split('.').forEach(function (part) { value = value && value[part]; });
    value = typeof value === 'string' ? value : key;
    Object.keys(values || {}).forEach(function (name) {
      value = value.replace('{' + name + '}', values[name]);
    });
    return value;
  }

  function pagePath(path) {
    if (!path || path.indexOf('//') === 0 || /^[a-z][a-z0-9+.-]*:/i.test(path)) { return path; }
    if (basePath && (path === basePath || path.indexOf(basePath + '/') === 0)) { return path; }
    return path.charAt(0) === '/' ? basePath + path : basePath + '/' + path;
  }

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
  var shareCreateBtn, resultID, testSettings;
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
    shareCreateBtn  = document.getElementById('shareCreateBtn');
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
    if (shareCreateBtn) {
      shareCreateBtn.addEventListener('click', createShareLink);
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
      startBtn.textContent = t('testing');
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

    setStatus(t('connecting_server'));
    setPhase(null);
    updateProgress(0, t('connecting'));

    fetch(apiBase + '/speed-tests', { method: 'POST', credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
      .then(function (response) {
        return response.json().then(function (body) {
          if (!response.ok || !body.ok || !body.data || !body.data.test_id) {
            throw new Error(t('could_not_start'));
          }
          resultID = body.data.test_id;
          testSettings = body.data;
          openProgressSocket(resultID, testSettings);
        });
      })
      .catch(function () { onError(t('could_not_start_retry')); });
  }

  function openProgressSocket(testID, settings) {
    var wsURL = (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host +
      apiBase + '/speed-tests/' + encodeURIComponent(testID) + '/status';
    try {
      ws = new WebSocket(wsURL);
    } catch (_) {
      onError(t('websocket_failed'));
      return;
    }

    ws.addEventListener('open', function () {
      runBrowserTest(testID, settings);
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
      onError(t('connection_lost'));
    });

    ws.addEventListener('close', function () {
      if (isRunning) {
        /* Closed before "complete" message — treat as error */
        onError(t('connection_closed'));
      }
    });
  }

  async function runBrowserTest(testID, settings) {
    try {
      setPhase('ping');
      setStatus(t('measuring_latency'));
      var pingSamples = [];
      var failedPings = 0;
      for (var i = 0; i < 10; i++) {
        var pingStart = performance.now();
        try {
          var pingResponse = await fetch(apiBase + '/server/healthz?probe=' + i + '-' + Date.now(), {
            cache: 'no-store',
            credentials: 'same-origin',
            headers: { 'Accept': 'application/json', 'Cache-Control': 'no-cache' }
          });
          await pingResponse.arrayBuffer();
          if (!pingResponse.ok) { throw new Error(t('latency_request_failed')); }
          pingSamples.push(performance.now() - pingStart);
        } catch (_) {
          failedPings++;
        }
        handleMessage({ stage: 'ping', progress: (i + 1) / 10, speed: average(pingSamples) });
      }
      if (pingSamples.length === 0) { throw new Error(t('could_not_measure_latency')); }
      var ping = average(pingSamples);
      var jitter = deviation(pingSamples, ping);
      var packetLoss = failedPings * 10;

      var duration = Number(settings.duration_seconds) || 10;
      var threads = Math.max(1, Math.min(Number(settings.threads) || 4, 16));
      var chunkSize = Math.max(65536, Math.min(Number(settings.chunk_size) || 1048576, 16777216));
      var download = await measureTransfer(testID, 'download', duration, threads, chunkSize);
      var upload = await measureTransfer(testID, 'upload', duration, threads, chunkSize);
      if (!ws || ws.readyState !== WebSocket.OPEN) { throw new Error(t('connection_lost')); }
      ws.send(JSON.stringify({
        type: 'result',
        download_mbps: download,
        upload_mbps: upload,
        ping_ms: ping,
        jitter_ms: jitter,
        packet_loss: packetLoss
      }));
    } catch (error) {
      onError(error.message || t('test_failed'));
    }
  }

  async function measureTransfer(testID, stage, durationSeconds, threads, chunkSize) {
    setPhase(stage);
    setStatus(t('measuring_stage_speed', { stage: stageLabel(stage) }));
    var started = performance.now();
    var deadline = started + durationSeconds * 1000;
    var bytesTransferred = 0;
    var requestID = 0;
    var payload = null;
    if (stage === 'upload') {
      var randomChunk = new Uint8Array(65536);
      if (window.crypto && window.crypto.getRandomValues) {
        window.crypto.getRandomValues(randomChunk);
      } else {
        throw new Error(t('secure_test_data'));
      }
      var parts = [];
      for (var part = 0; part < Math.ceil(chunkSize / randomChunk.byteLength); part++) { parts.push(randomChunk); }
      payload = new Blob(parts, { type: 'application/octet-stream' });
    }
    var timer = window.setInterval(function () {
      var elapsed = Math.max((performance.now() - started) / 1000, 0.001);
      var speed = bytesTransferred * 8 / elapsed / 1000000;
      var progress = Math.min((performance.now() - started) / (durationSeconds * 1000), 1);
      handleMessage({ stage: stage, progress: progress, speed: speed });
    }, 200);
    async function worker() {
      while (performance.now() < deadline && isRunning && ws && ws.readyState === WebSocket.OPEN) {
        var url = apiBase + '/speed-tests/' + encodeURIComponent(testID);
        var options = { method: 'GET', cache: 'no-store', credentials: 'same-origin', headers: { 'Cache-Control': 'no-cache' } };
        if (stage === 'download') {
          url += '/download?bytes=' + chunkSize + '&request=' + (requestID++);
        } else {
          url += '/uploads';
          options.method = 'POST';
          options.body = payload;
          options.headers['Content-Type'] = 'application/octet-stream';
        }
        try {
          var response = await fetch(url, options);
          if (!response.ok) { throw new Error(t('stage_transfer_failed', { stage: stageLabel(stage) })); }
          if (stage === 'download') {
            var downloaded = await response.arrayBuffer();
            bytesTransferred += downloaded.byteLength;
          } else {
            var accepted = await response.json();
            if (!accepted.ok || !accepted.data) { throw new Error(t('upload_transfer_failed')); }
            bytesTransferred += accepted.data.bytes;
          }
        } catch (_) {
          throw new Error(t('stage_transfer_failed', { stage: stageLabel(stage) }));
        }
      }
    }
    try {
      var workers = [];
      for (var index = 0; index < threads; index++) { workers.push(worker()); }
      await Promise.all(workers);
    } finally {
      window.clearInterval(timer);
    }
    var elapsedSeconds = Math.max((performance.now() - started) / 1000, 0.001);
    return bytesTransferred * 8 / elapsedSeconds / 1000000;
  }

  function average(values) {
    if (!values.length) { return 0; }
    return values.reduce(function (sum, value) { return sum + value; }, 0) / values.length;
  }

  function deviation(values, mean) {
    if (values.length < 2) { return 0; }
    var variance = values.reduce(function (sum, value) {
      return sum + Math.pow(value - mean, 2);
    }, 0) / values.length;
    return Math.sqrt(variance);
  }

  function handleMessage(data) {
    var stage    = data.stage || '';
    var progress = typeof data.progress === 'number' ? data.progress : 0;
    var speed    = typeof data.speed === 'number' ? data.speed : 0;

    if (stage === 'error') {
      onError(data.message || t('test_failed'));
      return;
    }

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
    setStatus(stage === 'ping' ? t('measuring_latency') : t('measuring_stage_speed', { stage: stageLabel(stage) }));

    /* Live speed readout */
    if (stage === 'ping') {
      setLiveSpeed(speed, 'ms', t('ping'));
      updateGauge(Math.min(speed / 200, 1), speed, 'ms', t('ping'));
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
    resultID = data.test_id || '';

    updateProgress(1, t('complete'));
    setPhaseAllDone();
    setStatus(t('test_complete'));

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
    if (shareSection) {
      shareSection.classList.add('is-visible');
    }
    if (shareCode && shareInput) {
      shareInput.value = location.protocol + '//' + location.host + pagePath('/shares/' + shareCode);
      if (shareCreateBtn) { shareCreateBtn.hidden = true; }
      if (shareCopyBtn) { shareCopyBtn.hidden = false; }
    }

    /* Reset button */
    if (startBtn) {
      startBtn.classList.remove('start-btn--running');
      startBtn.hidden = true;
    }
    if (testAgainBtn) {
      testAgainBtn.hidden = false;
    }

    /* Final gauge showing download speed */
    updateGauge(Math.min(dl / GAUGE_MAX_MBPS, 1), dl, 'Mbps', t('download'));
    setLiveSpeed(dl, 'Mbps', t('download'));
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
      startBtn.textContent = t('start');
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
    if (shareInput)      { shareInput.value = ''; }
    if (shareCreateBtn)  { shareCreateBtn.hidden = false; shareCreateBtn.disabled = false; }
    if (shareCopyBtn)    { shareCopyBtn.hidden = true; }
    resultID = '';

    if (startBtn) {
      startBtn.hidden = false;
      startBtn.classList.add('start-btn--idle');
      startBtn.classList.remove('start-btn--running');
      startBtn.disabled = false;
      startBtn.textContent = t('start');
    }
    if (testAgainBtn) {
      testAgainBtn.hidden = true;
    }

    setStatus('');
    updateProgress(0, '');
    setPhase(null);
    setLiveSpeed(0, 'Mbps', '');
    updateGauge(0, 0, 'Mbps', t('speed'));
  }

  /* ── UI helpers ─────────────────────────────────────────────────── */

  function stageLabel(stage) {
    var labels = { ping: t('ping'), download: t('download'), upload: t('upload') };
    return labels[stage] || t('speed');
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

  function createShareLink() {
    if (!resultID || !shareCreateBtn) { return; }
    shareCreateBtn.disabled = true;
    fetch(apiBase + '/speed-tests/' + encodeURIComponent(resultID) + '/shares', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Accept': 'application/json' }
    }).then(function (response) {
      return response.json().then(function (body) {
        if (!response.ok || !body.ok || !body.data || !body.data.url) {
          throw new Error(t('unable_to_create_share'));
        }
        shareInput.value = location.protocol + '//' + location.host + pagePath(body.data.url);
        shareCreateBtn.hidden = true;
        shareCopyBtn.hidden = false;
      });
    }).catch(function () {
      setStatus(t('unable_to_create_share'));
      shareCreateBtn.disabled = false;
    });
  }

  function fallbackCopy(text) {
    shareInput.select();
    try {
      document.execCommand('copy');
      showCopied();
    } catch (_) {
      showToast(t('copy_manually'), 'info');
    }
  }

  function showCopied() {
    if (!shareCopyBtn) { return; }
    var orig = shareCopyBtn.textContent;
    shareCopyBtn.textContent = t('copied');
    shareCopyBtn.classList.add('is-copied');
    showToast(t('share_copied'), 'success');
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
