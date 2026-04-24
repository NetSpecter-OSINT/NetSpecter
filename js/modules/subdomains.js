// modules/subdomains.js
import { bumpQuery }  from '../state.js';
import { header, sep, kv, line, esc } from '../output.js';
import { bumpHit }    from '../state.js';

export async function runSubdomains(target) {
  header('SUBDOMAIN DISCOVERY :: ' + target.toUpperCase());
  sep();

  const found = new Set();

  // ---- Source 1: crt.sh ----
  line('<span class="c-dim">Source [1/2]: Certificate Transparency (crt.sh)...</span>');
  try {
    bumpQuery();
    const controller = new AbortController();
    const timeout    = setTimeout(() => controller.abort(), 8000);
    const res  = await fetch(
      `https://crt.sh/?q=%25.${encodeURIComponent(target)}&output=json`,
      { signal: controller.signal }
    );
    clearTimeout(timeout);

    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const certs = await res.json();

    if (Array.isArray(certs)) {
      certs.forEach(c => {
        (c.name_value || '').split('\n').forEach(n => {
          n = n.trim().toLowerCase().replace(/^\*\./, '');
          if (n.endsWith('.' + target) || n === target) found.add(n);
        });
        if (c.common_name) {
          const cn = c.common_name.toLowerCase().replace(/^\*\./, '');
          if (cn.endsWith('.' + target) || cn === target) found.add(cn);
        }
      });
    }
    line(`<span class="c-dim">crt.sh returned ${found.size} entries.</span>`);
  } catch (e) {
    line(`<span class="c-warn">crt.sh failed (${esc(e.message)}) - trying fallback...</span>`);
  }

  // ---- Source 2: Certspotter (no key, CORS-friendly) ----
  line('<span class="c-dim">Source [2/2]: Certspotter (certspotter.com)...</span>');
  try {
    bumpQuery();
    const controller = new AbortController();
    const timeout    = setTimeout(() => controller.abort(), 8000);
    const res = await fetch(
      `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(target)}&include_subdomains=true&expand=dns_names`,
      { signal: controller.signal }
    );
    clearTimeout(timeout);

    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const issuances = await res.json();

    if (Array.isArray(issuances)) {
      issuances.forEach(cert => {
        (cert.dns_names || []).forEach(n => {
          n = n.toLowerCase().replace(/^\*\./, '');
          if (n.endsWith('.' + target) || n === target) found.add(n);
        });
      });
    }
    line(`<span class="c-dim">Certspotter complete. Combined total: ${found.size} unique.</span>`);
  } catch (e) {
    line(`<span class="c-warn">Certspotter failed: ${esc(e.message)}</span>`);
  }

  sep();

  if (found.size === 0) {
    line('<span class="c-warn">No subdomains found. This may mean:</span>');
    line('<span class="c-dim">  - Domain has no CT log entries (new or private)</span>');
    line('<span class="c-dim">  - Both sources rate-limited (try again in a few minutes)</span>');
  } else {
    kv('  Total subdomains found', String(found.size), 'c-hi');
    sep();
    [...found].sort().forEach((sub, i) => {
      line(
        `<span class="c-dim">  [${String(i + 1).padStart(3, '0')}]</span> ` +
        `<span class="out-val">${esc(sub)}</span>`
      );
      bumpHit();
    });
  }

  sep();
}