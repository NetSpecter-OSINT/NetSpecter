// modules/subdomains.js
import { bumpQuery } from '../state.js';
import { header, sep, kv, line, esc } from '../output.js';
import { bumpHit }   from '../state.js';

export async function runSubdomains(target) {
  header('SUBDOMAIN DISCOVERY :: ' + target.toUpperCase());
  sep();

  const found = new Set();

  // ---- Source 1: Certspotter CT logs ----
  line('<span class="c-dim">Source [1/2]: Certspotter CT logs...</span>');
  try {
    bumpQuery();
    const controller = new AbortController();
    const timeout    = setTimeout(() => controller.abort(), 10000);
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
    line(`<span class="c-dim">Certspotter returned ${found.size} entries.</span>`);
  } catch (e) {
    line(`<span class="c-warn">Certspotter failed: ${esc(e.message)}</span>`);
  }

  // ---- Source 2: Google DNS TXT enumeration ----
  // Probes common subdomain prefixes via DNS to supplement CT log data
  line('<span class="c-dim">Source [2/2]: Common subdomain DNS probe...</span>');
  const COMMON = [
    'www', 'mail', 'email', 'smtp', 'pop', 'imap', 'ftp', 'sftp',
    'api', 'dev', 'staging', 'test', 'beta', 'app', 'portal', 'admin',
    'dashboard', 'blog', 'shop', 'store', 'cdn', 'media', 'static',
    'assets', 'img', 'images', 'vpn', 'remote', 'mx', 'ns1', 'ns2',
    'cpanel', 'whm', 'webmail', 'autodiscover', 'autoconfig',
  ];

  let dnsHits = 0;
  await Promise.allSettled(
    COMMON.map(async prefix => {
      try {
        const sub = `${prefix}.${target}`;
        const res = await fetch(
          `https://dns.google/resolve?name=${encodeURIComponent(sub)}&type=A`
        );
        const data = await res.json();
        if (data.Answer && data.Answer.length > 0) {
          if (!found.has(sub)) {
            found.add(sub);
            dnsHits++;
          }
        }
      } catch { /* silently skip */ }
    })
  );

  line(`<span class="c-dim">DNS probe found ${dnsHits} additional subdomains.</span>`);

  sep();

  if (found.size === 0) {
    line('<span class="c-warn">No subdomains found. This may mean:</span>');
    line('<span class="c-dim">  - Domain has no CT log entries (new or private)</span>');
    line('<span class="c-dim">  - Both sources returned no results</span>');
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