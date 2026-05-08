// modules/subdomains.js
import { bumpQuery, bumpHit } from '../state.js';
import { header, sep, kv, line, esc } from '../output.js';

const TIMEOUT_MS  = 12000;
const WORKER_URL  = 'https://netspecter-headers.shohen612.workers.dev';
const PROBE_CHUNK = 50;

function timedFetch(url, ms = TIMEOUT_MS) {
  const c = new AbortController();
  const t = setTimeout(() => c.abort(), ms);
  return fetch(url, { signal: c.signal }).finally(() => clearTimeout(t));
}

export async function runSubdomains(target) {
  header('SUBDOMAIN DISCOVERY :: ' + target.toUpperCase());
  sep();

  // Map<subdomain, Set<sourceTag>> for deduplication + attribution
  const found = new Map();

  const add = (raw, source) => {
    const sub = raw.toLowerCase().replace(/^\*\./, '').trim();
    if (!sub || !(sub.endsWith('.' + target) || sub === target)) return;
    if (!found.has(sub)) found.set(sub, new Set());
    found.get(sub).add(source);
  };

  line('<span class="c-dim">Querying 2 passive sources in parallel...</span>');
  sep();

  await Promise.allSettled([

    // ---- Source 1: Certspotter ----
    (async () => {
      line('<span class="c-dim">  [1/2] Certspotter CT logs...</span>');
      try {
        bumpQuery();
        const res = await timedFetch(
          `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(target)}&include_subdomains=true&expand=dns_names`
        );
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        if (Array.isArray(data)) {
          data.forEach(cert =>
            (cert.dns_names || []).forEach(n => add(n, 'CERT'))
          );
        }
        line('<span class="c-dim">  [1/2] Certspotter: done.</span>');
      } catch (e) {
        line(`<span class="c-warn">  [1/2] Certspotter failed: ${esc(e.message)}</span>`);
      }
    })(),

    // ---- Source 2: crt.sh ----
    // Generous timeout — crt.sh is the most comprehensive CT aggregator but can be slow
    (async () => {
      line('<span class="c-dim">  [2/2] crt.sh CT aggregator...</span>');
      try {
        bumpQuery();
        const res = await timedFetch(
          `https://crt.sh/?q=%25.${encodeURIComponent(target)}&output=json`,
          28000
        );
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        if (Array.isArray(data)) {
          // name_value may contain multiple names separated by newlines
          data.forEach(entry =>
            (entry.name_value || '').split('\n').forEach(n => add(n, 'CRT'))
          );
        }
        line('<span class="c-dim">  [2/2] crt.sh: done.</span>');
      } catch (e) {
        const reason = e.message.includes('aborted')
          ? 'timed out (slow response)'
          : esc(e.message);
        line(`<span class="c-warn">  [2/2] crt.sh failed: ${reason}</span>`);
      }
    })(),

  ]);

  sep();

  // ---- Render subdomain list ----
  if (found.size === 0) {
    line('<span class="c-warn">No subdomains found across all sources.</span>');
    line('<span class="c-dim">  - Domain may have no public CT log entries</span>');
    line('<span class="c-dim">  - All sources may have rate limited or timed out</span>');
    sep();
    return;
  }

  kv('  Total unique subdomains', String(found.size), 'c-hi');
  sep();

  const renderTags = sources => [
    sources.has('CERT') ? '<span class="c-dim">[CERT]</span>' : '',
    sources.has('CRT')  ? '<span class="c-dim">[CRT]</span>'  : '',
  ].filter(Boolean).join(' ');

  const sortedSubs = [...found.entries()].sort(([a], [b]) => a.localeCompare(b));

  sortedSubs.forEach(([sub, sources], i) => {
    line(
      `<span class="c-dim">  [${String(i + 1).padStart(3, '0')}]</span> ` +
      `<span class="out-val">${esc(sub)}</span> ` +
      renderTags(sources)
    );
    bumpHit();
  });

  // ---- Live status probe ----
  sep();
  line('<span class="c-dim">Probing live HTTP status via worker...</span>');
  sep();

  const subList     = sortedSubs.map(([sub]) => sub);
  const probeResults = [];

  // Chunk into batches of 50 to stay within CF free-tier subrequest limit
  for (let i = 0; i < subList.length; i += PROBE_CHUNK) {
    const chunk = subList.slice(i, i + PROBE_CHUNK);
    try {
      bumpQuery();
      const res = await fetch(WORKER_URL, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ domains: chunk }),
      });
      if (!res.ok) throw new Error(`Worker returned HTTP ${res.status}`);
      const data = await res.json();
      if (Array.isArray(data)) probeResults.push(...data);
    } catch (e) {
      line(`<span class="c-warn">  Probe batch failed: ${esc(e.message)}</span>`);
    }
  }

  if (probeResults.length === 0) {
    line('<span class="c-warn">  No probe results returned.</span>');
    sep();
    return;
  }

  probeResults.sort((a, b) => (a.domain || '').localeCompare(b.domain || ''));

  probeResults.forEach((r, i) => {
    const idx    = `<span class="c-dim">  [${String(i + 1).padStart(3, '0')}]</span>`;
    const domain = `<span class="out-val">${esc(r.domain)}</span>`;

    let statusPart;

    if (!r.status || r.error === 'unreachable') {
      statusPart = '<span class="c-dim">  --  unreachable</span>';
    } else if (r.status >= 200 && r.status < 300) {
      const proto = r.protocol ? `<span class="c-dim"> ${r.protocol.toUpperCase()}</span>` : '';
      statusPart  = `<span class="c-hi">  ${r.status}</span>${proto}`;
    } else if (r.status >= 300 && r.status < 400) {
      const dest  = r.redirect ? ` <span class="c-dim">→ ${esc(r.redirect)}</span>` : '';
      statusPart  = `<span class="c-warn">  ${r.status}</span>${dest}`;
    } else {
      const proto = r.protocol ? `<span class="c-dim"> ${r.protocol.toUpperCase()}</span>` : '';
      statusPart  = `<span class="c-warn">  ${r.status}</span>${proto}`;
    }

    line(`${idx} ${domain}${statusPart}`);
  });

  sep();
}