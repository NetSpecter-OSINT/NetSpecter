// main.js - NetSpecter entry point
// NOTE: type="module" scripts are already deferred - no DOMContentLoaded needed

import { state, resetCounters }  from './state.js';
import { startClock, initTabs, initThemeSwitcher,
         setScanState, setTarget, setLastScan,
         resolveExtIP, initNavPickers, initModeToggle }           from './ui.js';
import { clearOutput, typeEffect,
         showProgress, hideProgress,
         line, sep, esc }         from './output.js';
import { exportTXT, copyOutput,
         initKeyboardShortcuts }  from './export.js';

import { runDNS }         from './modules/dns.js';
import { runWhois }       from './modules/whois.js';
import { runGeo }         from './modules/geo.js';
import { runSSL }         from './modules/ssl.js';
import { runSubdomains }  from './modules/subdomains.js';
import { runHeaders }     from './modules/headers.js';
import { runEmail }       from './modules/email.js';
import { runPorts }       from './modules/ports.js';
import { runFingerprint } from './modules/techscan.js';
import { runThreat }      from './modules/threat.js';
import { runFull }        from './modules/full.js';

const MODULES = {
  dns:         runDNS,
  whois:       runWhois,
  geo:         runGeo,
  ssl:         runSSL,
  subdomains:  runSubdomains,
  headers:     runHeaders,
  email:       runEmail,
  ports:       runPorts,
  fingerprint: runFingerprint,
  threat:      runThreat,
  full:        runFull,
};

const isLight = () => document.documentElement.getAttribute('data-mode') === 'light';

function parseTarget() {
  return document.getElementById('target-input').value
    .trim().toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '');
}

function isValidTarget(s) {
  const isDomain = /^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z]{2,})+$/.test(s);
  const isIP     = /^(\d{1,3}\.){3}\d{1,3}$/.test(s);
  return isDomain || isIP;
}

async function runScan() {
  if (state.scanning) return;

  const target = parseTarget();
  if (!target) {
    line('<span class="c-error">ERROR: No target specified.</span>');
    return;
  }
  if (!isValidTarget(target)) {
    line('<span class="c-error">ERROR: "' + esc(target) + '" is not a valid domain or IP address.</span>');
    return;
  }

  state.scanning = true;
  const scanBtn  = document.getElementById('scan-btn');

  scanBtn.textContent      = isLight() ? 'SCANNING...' : '[ SCANNING ]';
  scanBtn.dataset.scanning = 'true';
  scanBtn.style.opacity    = '0.6';

  clearOutput();
  resetCounters();
  setTarget(target);
  setLastScan();
  setScanState('SCANNING', 'c-warn blink');

  if (state.currentTab === 'full') showProgress('INITIALISING...', 0);

  await typeEffect(
    'INITIATING ' + state.currentTab.toUpperCase() + ' :: TARGET = ' + target.toUpperCase(),
    'c-bright'
  );
  sep();

  try {
    const fn = MODULES[state.currentTab];
    if (fn) await fn(target);
    setScanState('COMPLETE', 'c-success');
  } catch (e) {
    line('<span class="c-error">FATAL: ' + esc(e.message) + '</span>');
    setScanState('ERROR', 'c-error');
  }

  if (state.currentTab !== 'full') hideProgress();

  line(
    '<span class="c-dim">// Completed at ' + new Date().toTimeString().slice(0, 8) +
    ' | Queries: ' + state.queryCount + ' | Hits: ' + state.hitCount + '</span>'
  );

  state.scanning           = false;
  delete scanBtn.dataset.scanning;
  scanBtn.textContent      = isLight() ? 'SCAN' : '[ SCAN ]';
  scanBtn.style.opacity    = '1';
}

function handleClear() {
  if (state.scanning) return;
  clearOutput();
  hideProgress();
  setScanState('IDLE', '');
  resetCounters();
  line('<span class="c-dim">// Output cleared. Ready for next target.</span>');
}

// ---- Bootstrap ----
startClock();
initThemeSwitcher();
initNavPickers();
initModeToggle();
initTabs();

document.getElementById('scan-btn').addEventListener('click', runScan);
document.getElementById('clear-btn').addEventListener('click', handleClear);
document.getElementById('export-btn').addEventListener('click', exportTXT);
document.getElementById('copy-btn').addEventListener('click', copyOutput);

document.getElementById('target-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') runScan();
});

initKeyboardShortcuts(runScan, handleClear);

resolveExtIP();