// export.js - output export and keyboard shortcut handling

import { state } from './state.js';

// ---- Export output as .txt ----
export function exportTXT() {
  const el    = document.getElementById('output');
  if (!el) return;

  const timestamp = new Date().toISOString().slice(0, 19).replace('T', '_').replace(/:/g, '-');
  const target    = state.currentTarget || 'unknown';
  const filename  = `recon_${target}_${timestamp}.txt`;

  // Gather text, stripping HTML
  const lines = [...el.querySelectorAll('.out-line, .out-header, .out-kv, .out-sep')];
  const text  = lines.map(l => {
    if (l.classList.contains('out-sep')) return '-'.repeat(72);
    return l.innerText || l.textContent;
  }).join('\n');

  const header =
    `NetSpecter v2.1 - Export\n` +
    `Target  : ${target.toUpperCase()}\n` +
    `Module  : ${document.getElementById('active-module')?.textContent || ''}\n` +
    `Date    : ${new Date().toUTCString()}\n` +
    `Queries : ${state.queryCount}\n` +
    `Hits    : ${state.hitCount}\n` +
    '='.repeat(72) + '\n\n';

  const blob = new Blob([header + text], { type: 'text/plain' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);

  flashExportBtn('SAVED');
}

// ---- Copy output to clipboard ----
export async function copyOutput() {
  const el = document.getElementById('output');
  if (!el) return;

  try {
    await navigator.clipboard.writeText(el.innerText || el.textContent);
    flashExportBtn('COPIED');
  } catch {
    // fallback
    const ta = document.createElement('textarea');
    ta.value = el.innerText;
    ta.style.position = 'fixed';
    ta.style.opacity  = '0';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    flashExportBtn('COPIED');
  }
}

function flashExportBtn(msg) {
  const btn = document.getElementById('export-btn');
  if (!btn) return;
  const orig = btn.textContent;
  btn.textContent = msg;
  setTimeout(() => { btn.textContent = orig; }, 1500);
}

// ---- Keyboard shortcuts ----
export function initKeyboardShortcuts(runScan, clearOutput) {
  const tabs = ['dns','whois','geo','ssl','subdomains','headers','email','threat','full','ports','fingerprint'];

  document.addEventListener('keydown', e => {
    // Ignore when typing in input
    if (document.activeElement === document.getElementById('target-input')) return;
    if (state.scanning) return;

    switch (e.key) {
      case 'Enter':
        document.getElementById('target-input').focus();
        break;
      case 'Escape':
        clearOutput();
        break;
      case 'e': case 'E':
        exportTXT();
        break;
      case 'c': case 'C':
        copyOutput();
        break;
      case '?':
        toggleShortcutsPanel();
        break;
      default:
        // Number keys 1-9 switch tabs
        if (e.key >= '1' && e.key <= '9') {
          const idx = parseInt(e.key) - 1;
          const tabBtns = document.querySelectorAll('.tab');
          if (tabBtns[idx]) tabBtns[idx].click();
        }
    }
  });
}

// ---- Keyboard shortcuts overlay ----
function toggleShortcutsPanel() {
  let panel = document.getElementById('shortcuts-panel');
  if (panel) { panel.remove(); return; }

  panel = document.createElement('div');
  panel.id = 'shortcuts-panel';
  panel.innerHTML = `
    <div class="sc-title">KEYBOARD SHORTCUTS <span class="sc-close" id="sc-close">[X]</span></div>
    <div class="sc-grid">
      <span class="sc-key">ENTER</span><span class="sc-val">Focus input</span>
      <span class="sc-key">ESC</span><span class="sc-val">Clear output</span>
      <span class="sc-key">E</span><span class="sc-val">Export TXT</span>
      <span class="sc-key">C</span><span class="sc-val">Copy output</span>
      <span class="sc-key">?</span><span class="sc-val">Toggle shortcuts</span>
      <span class="sc-key">1-9</span><span class="sc-val">Switch tab</span>
    </div>
  `;
  document.body.appendChild(panel);
  document.getElementById('sc-close').addEventListener('click', () => panel.remove());
}
