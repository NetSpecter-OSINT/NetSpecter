// modules/headers.js
import { header, sep, kv, line, esc } from '../output.js';
import { bumpHit, bumpQuery } from '../state.js';

const SEC_HEADERS = [
  'strict-transport-security',
  'content-security-policy',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
  'x-xss-protection',
  'cross-origin-opener-policy',
  'cross-origin-resource-policy',
];

export async function runHeaders(target) {
  header('HTTP HEADERS ANALYSIS :: ' + target.toUpperCase());
  sep();
  line('<span class="c-dim">Fetching response headers via NetSpecter worker...</span>');

  try {
    bumpQuery();
    const proxyUrl = `https://netspecter-headers.shohen612.workers.dev/?target=${encodeURIComponent(target)}`;
    const res = await fetch(proxyUrl);
    const text = await res.text();
    let headers;
    try {
        headers = JSON.parse(text);
    } catch {
        throw new Error(`Proxy returned invalid JSON: ${text.slice(0, 120)}`);
    }
    if (headers.error) {
        throw new Error(headers.error);
    }
    // convert to the same flat string format the rest of the function expects
    const raw = Object.entries(headers)
        .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : v}`)
        .join('\n');

    if (raw.includes('error') || raw.includes('API count')) {
      line('<span class="c-warn">API rate limit. Direct alternatives:</span>');
      line(`  <a href="https://securityheaders.com/?q=${esc(target)}" target="_blank" rel="noopener" style="color:inherit">https://securityheaders.com/?q=${esc(target)}</a>`);
      return;
    }

    const foundSec = new Set();

    raw.split('\n').forEach(l => {
      if (!l.trim()) return;
      const idx = l.indexOf(':');
      if (idx > 0) {
        const k     = l.slice(0, idx).trim();
        const v     = l.slice(idx + 1).trim();
        const isSec = SEC_HEADERS.includes(k.toLowerCase());
        kv('  ' + k.padEnd(36), esc(v), isSec ? 'c-good' : '');
        if (isSec) foundSec.add(k.toLowerCase());
        bumpHit();
      } else if (l.trim()) {
        line(`<span class="c-hi">  ${esc(l)}</span>`);
      }
    });

    sep();
    header('SECURITY HEADER AUDIT');
    SEC_HEADERS.forEach(h => {
      const present = foundSec.has(h);
      kv('  ' + h.padEnd(40), present ? 'PRESENT' : 'MISSING', present ? 'c-good' : 'c-bad');
    });

    const score = Math.round((foundSec.size / SEC_HEADERS.length) * 100);
    sep();
    kv('  Security Header Score', `${foundSec.size}/${SEC_HEADERS.length} (${score}%)`,
      score >= 70 ? 'c-good' : score >= 40 ? 'c-warn' : 'c-bad');

  } catch (e) {
    line(`<span class="c-error">Headers fetch failed: ${esc(e.message)}</span>`);
  }

  sep();
}
