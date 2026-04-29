// modules/ssl.js
import { bumpQuery } from '../state.js';
import { header, sep, kv, line, spacer, esc } from '../output.js';
import { bumpHit } from '../state.js';

const WORKER_URL = 'https://netspecter-headers.shohen612.workers.dev';

export async function runSSL(target) {
  header('SSL/TLS CERTIFICATES :: ' + target.toUpperCase());
  sep();

  // ---- Source 1: Certspotter CT logs ----
  line('<span class="c-dim">Source [1/2]: Certificate Transparency (Certspotter)...</span>');
  try {
    bumpQuery();
    const controller = new AbortController();
    const timeout    = setTimeout(() => controller.abort(), 10000);
    const res = await fetch(
      `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(target)}&include_subdomains=false&expand=dns_names`,
      { signal: controller.signal }
    );
    clearTimeout(timeout);

    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const issuances = await res.json();

    if (!Array.isArray(issuances) || issuances.length === 0) {
      line('<span class="c-dim">No CT log entries found for this domain.</span>');
    } else {
      const seen   = new Set();
      const unique = issuances.filter(c => {
        if (seen.has(c.id)) return false;
        seen.add(c.id);
        return true;
      }).slice(0, 15);

      kv('  Total CT entries', String(issuances.length), 'c-hi');
      kv('  Showing',          String(unique.length));
      sep();

      unique.forEach((cert, i) => {
        const notAfter  = cert.not_after  ? cert.not_after.slice(0, 10)  : 'N/A';
        const notBefore = cert.not_before ? cert.not_before.slice(0, 10) : 'N/A';
        const expired   = cert.not_after && new Date(cert.not_after) < new Date();
        const badgeCls  = expired ? 'bad' : 'good';
        const badgeTxt  = expired ? 'EXPIRED' : 'VALID';
        const names     = (cert.dns_names || []).join(' | ');

        line(
          `<span class="c-dim">  [${String(i + 1).padStart(2, '0')}]</span> ` +
          `<span class="out-val c-hi">${esc(cert.dns_names?.[0] || 'N/A')}</span>` +
          `<span class="badge ${badgeCls}">${badgeTxt}</span>`
        );
        kv('       Revoked', cert.revoked ? 'YES' : 'NO', cert.revoked ? 'c-bad' : 'c-good');
        kv('       Valid',  `${notBefore} &rarr; ${notAfter}`,
          expired ? 'c-bad' : 'c-good');
        kv('       SANs',   esc(names.slice(0, 140)));
        spacer();
        bumpHit();
      });
    }
  } catch (e) {
    line(`<span class="c-warn">Certspotter failed: ${esc(e.message)}</span>`);
  }

  // ---- Source 2: Live TLS analysis via SSL Labs ----
  sep();
  line('<span class="c-dim">Source [2/2]: Live TLS analysis (SSL Labs)...</span>');

  const labsReportUrl =
    `https://www.ssllabs.com/ssltest/analyze.html?d=${esc(target)}&hideResults=on`;

  try {
    bumpQuery();

    // Initial kick-off through worker (handles CORS)
    const workerUrl = `${WORKER_URL}/?ssllabs=${encodeURIComponent(target)}`;
    const kickRes   = await fetch(workerUrl);
    if (!kickRes.ok) throw new Error(`SSL Labs HTTP ${kickRes.status}`);
    const data = await kickRes.json();

    // Still running or queued — send the user to SSL Labs directly
    if (data.status === 'IN_PROGRESS' || data.status === 'DNS') {
      line('<span class="c-dim">Assessment in progress. Results are available for 24 hours once complete.</span>');
      spacer();
      line(
        `<span class="c-dim">View live progress: </span>` +
        `<a href="${labsReportUrl}" target="_blank" rel="noopener" style="color:inherit">` +
        `Open SSL Labs report &rarr;</a>`
      );
      sep();
      return;
    }

    // Error
    if (data.status === 'ERROR') {
      line(`<span class="c-warn">SSL Labs error: ${esc(data.statusMessage || 'Unknown')}</span>`);
      line(
        `<span class="c-dim">Try manually: </span>` +
        `<a href="${labsReportUrl}" target="_blank" rel="noopener" style="color:inherit">SSL Labs report</a>`
      );
      sep();
      return;
    }

    // Ready
    if (data.status === 'READY' && data.endpoints) {
      sep();
      kv('  Overall Grade', data.endpoints[0]?.grade || 'N/A',
        gradeClass(data.endpoints[0]?.grade));

      data.endpoints.forEach((ep, i) => {
        sep();
        line(`<span class="c-dim">  Endpoint [${i + 1}]</span>`);
        kv('    IP',          esc(ep.ipAddress  || 'N/A'));
        kv('    Grade',       esc(ep.grade      || 'N/A'), gradeClass(ep.grade));
        kv('    Server Name', esc(ep.serverName || 'N/A'));

        const det = ep.details;
        if (det) {
          kv('    Protocols',      esc(formatProtocols(det.protocols)));
          kv('    Forward Secrecy',
            det.forwardSecrecy >= 2 ? 'SUPPORTED' : 'LIMITED',
            det.forwardSecrecy >= 2 ? 'c-good' : 'c-warn');
          kv('    HSTS',
            det.hstsPolicy?.status === 'present' ? 'PRESENT' : 'MISSING',
            det.hstsPolicy?.status === 'present' ? 'c-good' : 'c-warn');
          kv('    Heartbleed',
            det.heartbleed ? 'VULNERABLE' : 'SAFE',
            det.heartbleed ? 'c-bad'      : 'c-good');
          kv('    POODLE',
            det.poodle     ? 'VULNERABLE' : 'SAFE',
            det.poodle     ? 'c-bad'      : 'c-good');
          kv('    BEAST',
            det.vulnBeast  ? 'VULNERABLE' : 'SAFE',
            det.vulnBeast  ? 'c-bad'      : 'c-good');

          const cert = det.certChains?.[0]?.certs?.[0];
          if (cert) {
            sep();
            kv('    Subject',     esc(cert.subject     || 'N/A'));
            kv('    Issuer',      esc(cert.issuerLabel || 'N/A'));
            kv('    Expires',
              cert.notAfter
                ? new Date(cert.notAfter).toISOString().slice(0, 10)
                : 'N/A',
              cert.notAfter && new Date(cert.notAfter) < new Date()
                ? 'c-bad' : 'c-good');
            kv('    Key Strength',
              cert.keyStrength ? cert.keyStrength + ' bits' : 'N/A',
              cert.keyStrength >= 2048 ? 'c-good' : 'c-bad');
            kv('    SHA256',
              det.sha256WithRsa ? 'YES' : 'NO',
              det.sha256WithRsa ? 'c-good' : 'c-warn');
          }
        }
        spacer();
        bumpHit();
      });

      line(
        `<span class="c-dim">// Full report: </span>` +
        `<a href="${labsReportUrl}" target="_blank" rel="noopener" style="color:inherit">SSL Labs</a>`
      );
    }

  } catch (e) {
    line(`<span class="c-warn">SSL Labs failed: ${esc(e.message)}</span>`);
    line(
      `<span class="c-dim">Manual check: </span>` +
      `<a href="${labsReportUrl}" target="_blank" rel="noopener" style="color:inherit">SSL Labs report</a>`
    );
  }

  sep();
}

function gradeClass(grade) {
  if (!grade) return '';
  if (grade.startsWith('A')) return 'c-good';
  if (grade.startsWith('B')) return 'c-warn';
  return 'c-bad';
}

function formatProtocols(protocols) {
  if (!protocols || !protocols.length) return 'N/A';
  return protocols.map(p => p.name + ' ' + p.version).join(', ');
}