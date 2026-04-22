// modules/ssl.js
import { crtShLookup } from '../api.js';
import { header, sep, kv, line, spacer, esc } from '../output.js';
import { bumpHit } from '../state.js';

export async function runSSL(target) {
  header('SSL/TLS CERTIFICATES :: ' + target.toUpperCase());
  sep();
  line('<span class="c-dim">Querying certificate transparency logs via crt.sh...</span>');

  try {
    const certs = await crtShLookup(target);
    if (!Array.isArray(certs) || certs.length === 0) {
      line('<span class="c-warn">No certificates found in CT logs.</span>');
      return;
    }

    // Deduplicate by serial number
    const seen   = new Set();
    const unique = certs.filter(c => {
      if (seen.has(c.serial_number)) return false;
      seen.add(c.serial_number);
      return true;
    }).slice(0, 20);

    kv('  Total certs in CT logs', String(certs.length),  'c-hi');
    kv('  Unique shown',           String(unique.length));
    sep();

    unique.forEach((cert, i) => {
      const notAfter  = cert.not_after  ? cert.not_after.slice(0, 10)  : 'N/A';
      const notBefore = cert.not_before ? cert.not_before.slice(0, 10) : 'N/A';
      const expired   = cert.not_after && new Date(cert.not_after) < new Date();
      const badgeCls  = expired ? 'bad' : 'good';
      const badgeTxt  = expired ? 'EXPIRED' : 'VALID';
      const names     = (cert.name_value || '').replace(/\n/g, ' | ');

      line(
        `<span class="c-dim">  [${String(i + 1).padStart(2, '0')}]</span> ` +
        `<span class="out-val c-hi">${esc(cert.common_name || 'N/A')}</span>` +
        `<span class="badge ${badgeCls}">${badgeTxt}</span>`
      );
      kv('       Issuer', esc(cert.issuer_name || 'N/A'));
      kv('       Valid',  `${notBefore} &rarr; ${notAfter}`, badgeCls === 'bad' ? 'c-bad' : 'c-good');
      kv('       SANs',   esc(names.slice(0, 140)));
      spacer();
      bumpHit();
    });
  } catch (e) {
    line(`<span class="c-error">CT log query failed: ${esc(e.message)}</span>`);
  }

  sep();
}
