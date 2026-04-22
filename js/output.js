// output.js - helpers for writing to the output panel

const panel = () => document.getElementById('output');

export function clearOutput() {
  panel().innerHTML = '';
}

export function line(html, extraClass = '') {
  const el = document.createElement('span');
  el.className = 'out-line' + (extraClass ? ' ' + extraClass : '');
  el.innerHTML = html;
  panel().appendChild(el);
  panel().scrollTop = panel().scrollHeight;
  return el;
}

export function sep() {
  const el = document.createElement('span');
  el.className = 'out-sep';
  panel().appendChild(el);
}

export function header(text) {
  const el = document.createElement('span');
  el.className = 'out-header';
  el.textContent = '>> ' + text;
  panel().appendChild(el);
}

export function kv(key, val, valClass = '') {
  const el = document.createElement('span');
  el.className = 'out-line out-kv';
  el.innerHTML =
    `<span class="out-key">${esc(key)}</span>` +
    `<span class="out-val ${valClass}">${val}</span>`;
  panel().appendChild(el);
  panel().scrollTop = panel().scrollHeight;
}

export function spacer() {
  line('');
}

export function typeEffect(text, extraClass = '') {
  return new Promise(resolve => {
    const el = line('', 'typing ' + extraClass);
    let i = 0;
    const iv = setInterval(() => {
      el.textContent = text.slice(0, i++);
      panel().scrollTop = panel().scrollHeight;
      if (i > text.length) {
        clearInterval(iv);
        el.classList.remove('typing');
        resolve();
      }
    }, 16);
  });
}

// ---- Progress bar ----

export function showProgress(label = 'SCANNING...', pct = 0) {
  const wrap = document.getElementById('progress-wrap');
  const bar  = document.getElementById('progress-bar');
  const lbl  = document.getElementById('progress-label');
  const pctEl= document.getElementById('progress-pct');
  wrap.hidden = false;
  lbl.textContent  = label;
  bar.style.width  = pct + '%';
  pctEl.textContent = pct + '%';
}

export function setProgress(pct, label) {
  const bar   = document.getElementById('progress-bar');
  const lbl   = document.getElementById('progress-label');
  const pctEl = document.getElementById('progress-pct');
  if (bar)   bar.style.width    = Math.min(pct, 100) + '%';
  if (pctEl) pctEl.textContent  = Math.min(pct, 100) + '%';
  if (label && lbl) lbl.textContent = label;
}

export function hideProgress() {
  document.getElementById('progress-wrap').hidden = true;
  setProgress(0);
}

// ---- Utility ----

export function esc(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

export function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}
