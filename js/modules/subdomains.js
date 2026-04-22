// modules/subdomains.js
import { crtShLookup, hackerTargetQuery } from '../api.js';
import { header, sep, kv, line, esc } from '../output.js';
import { bumpHit } from '../state.js';

export async function runSubdomains(target) {
  header('SUBDOMAIN DISCOVERY :: ' + target.toUpperCase());
  sep();

  const found = new Set();

  line('<span class="c-dim">Source [1/2]: Certificate Transparency Logs (crt.sh)...</span>');
  try {
    const certs = await crtShLookup(target);
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
    line(`<span class="c-dim">CT logs yielded ${found.size} unique entries.</span>`);
  } catch {
    line('<span class="c-warn">CT log query failed.</span>');
  }

  line('<span class="c-dim">Source [2/2]: HackerTarget hostsearch...</span>');
  try {
    const raw = await hackerTargetQuery('hostsearch', target);
    if (!raw.includes('error')) {
      raw.split('\n').forEach(l => {
        const parts = l.split(',');
        if (parts[0] && parts[0].includes('.')) {
          found.add(parts[0].trim().toLowerCase());
        }
      });
    }
  } catch { /* silently ignore */ }

  sep();

  if (found.size === 0) {
    line('<span class="c-warn">No subdomains discovered from available passive sources.</span>');
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
