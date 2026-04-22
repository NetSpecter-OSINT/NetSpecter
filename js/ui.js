// ui.js - clock, tabs, theme switcher, status bar updates

import { state } from './state.js';

const MODULE_LABELS = {
  dns:        'DNS_ENUMERATION',
  whois:      'WHOIS_LOOKUP',
  geo:        'GEO_IP_LOCATION',
  ssl:        'SSL_CERT_ANALYSIS',
  subdomains: 'SUBDOMAIN_DISCOVERY',
  headers:    'HTTP_HEADERS_ANALYSIS',
  email:      'EMAIL_SECURITY_AUDIT',
  threat:     'THREAT_INTELLIGENCE',
  full:       'FULL_RECON_SWEEP',
};

// ---- Clock ----
function updateClock() {
  const el = document.getElementById('clock');
  if (el) el.textContent = new Date().toTimeString().slice(0, 8);
}

export function startClock() {
  updateClock();
  setInterval(updateClock, 1000);
}

// ---- Tabs ----
export function initTabs(onSwitch) {
  document.querySelectorAll('.tab').forEach(btn => {
    btn.addEventListener('click', () => {
      if (state.scanning) return;
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      btn.classList.add('active');
      state.currentTab = btn.dataset.tab;
      const label = MODULE_LABELS[state.currentTab] || state.currentTab.toUpperCase();
      document.getElementById('active-module').textContent = label;
      if (onSwitch) onSwitch(state.currentTab);
    });
  });
}

// ---- Scan status ----
export function setScanState(text, cls = '') {
  const el = document.getElementById('scan-state');
  if (!el) return;
  el.textContent  = text;
  el.className    = cls;
}

export function setTarget(target) {
  state.currentTarget = target;
  const el = document.getElementById('current-target');
  if (el) el.textContent = target ? target.toUpperCase() : 'NULL';
}

export function setLastScan() {
  const el = document.getElementById('last-scan');
  if (el) el.textContent = new Date().toTimeString().slice(0, 8);
}

// ---- Theme switcher ----
export function initThemeSwitcher() {
  const saved = localStorage.getItem('recon-theme');
  if (saved) applyTheme(saved);

  document.querySelectorAll('.swatch').forEach(btn => {
    btn.addEventListener('click', () => {
      applyTheme(btn.dataset.theme);
      localStorage.setItem('recon-theme', btn.dataset.theme);
    });
  });
}

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  document.querySelectorAll('.swatch').forEach(s => {
    s.classList.toggle('active', s.dataset.theme === theme);
  });
}

// ---- Resolve external IP on load ----
export async function resolveExtIP() {
  try {
    const res  = await fetch('https://ipapi.co/json/');
    const data = await res.json();
    const el   = document.getElementById('ext-ip');
    if (el && data.ip) {
      el.textContent = `${data.ip} (${data.country_code || '?'})`;
    }
  } catch {
    const el = document.getElementById('ext-ip');
    if (el) el.textContent = 'N/A';
  }
}
