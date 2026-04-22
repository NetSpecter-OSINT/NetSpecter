// modules/whois.js
import { hackerTargetQuery } from '../api.js';
import { header, sep, kv, line, esc } from '../output.js';
import { bumpHit } from '../state.js';

export async function runWhois(target) {
  header('WHOIS LOOKUP :: ' + target.toUpperCase());
  sep();
  line('<span class="c-dim">Routing query via HackerTarget WHOIS proxy...</span>');

  try {
    const raw = await hackerTargetQuery('whois', target);

    if (raw.includes('error') || raw.includes('API count')) {
      line('<span class="c-warn">API rate limit reached. Try again in a few minutes.</span>');
      line(`<span class="c-dim">Alternative: </span><a href="https://who.is/whois/${esc(target)}" target="_blank" rel="noopener" style="color:inherit">https://who.is/whois/${esc(target)}</a>`);
    } else {
      raw.split('\n').forEach(l => {
        l = l.trim();
        if (!l || l.startsWith('%') || l.startsWith('#')) return;
        const idx = l.indexOf(':');
        if (idx > 0) {
          const k = l.slice(0, idx).trim();
          const v = l.slice(idx + 1).trim();
          if (v) { kv('  ' + k.padEnd(26), esc(v)); bumpHit(); }
        } else {
          line(`<span class="c-dim">  ${esc(l)}</span>`);
        }
      });
    }
  } catch (e) {
    line(`<span class="c-error">WHOIS query failed: ${esc(e.message)}</span>`);
  }

  sep();
}
