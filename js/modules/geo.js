// modules/geo.js
import { dnsQuery, geoLookup } from '../api.js';
import { header, sep, kv, line, esc } from '../output.js';
import { bumpHit } from '../state.js';

export async function runGeo(target) {
  header('GEO-IP LOCATION :: ' + target.toUpperCase());
  sep();

  let ip = target;
  const isIP = /^(\d{1,3}\.){3}\d{1,3}$/.test(target);

  if (!isIP) {
    line('<span class="c-dim">Resolving IP from DNS A record...</span>');
    try {
      const d = await dnsQuery(target, 'A');
      if (d.Answer && d.Answer[0]) {
        ip = d.Answer[0].data;
        kv('  Resolved IP', esc(ip), 'c-hi');
        bumpHit();
      } else {
        line('<span class="c-error">Could not resolve IP for this domain.</span>');
        return;
      }
    } catch {
      line('<span class="c-error">DNS resolution failed.</span>');
      return;
    }
  }

  line('<span class="c-dim">Querying geo-intelligence database...</span>');
  try {
    const g = await geoLookup(ip);
    if (g.error) { line(`<span class="c-error">${esc(g.reason)}</span>`); return; }

    kv('  IP Address',   esc(g.ip || ip), 'c-hi');
    kv('  City',         esc(g.city         || 'Unknown'));
    kv('  Region',       esc(g.region        || 'Unknown'));
    kv('  Country',      `${esc(g.country_name || 'Unknown')} (${esc(g.country_code || '--')})`);
    kv('  Latitude',     esc(g.latitude       || 'N/A'));
    kv('  Longitude',    esc(g.longitude      || 'N/A'));
    kv('  Timezone',     esc(g.timezone       || 'N/A'));
    kv('  UTC Offset',   esc(g.utc_offset     || 'N/A'));
    kv('  ISP / Org',    esc(g.org            || 'N/A'));
    kv('  ASN',          esc(g.asn            || 'N/A'));
    kv('  Currency',     esc(g.currency_name  || 'N/A'));
    if (g.in_eu !== undefined) {
      kv('  EU Member', g.in_eu ? 'YES' : 'NO', g.in_eu ? 'c-good' : '');
    }
    bumpHit(8);
  } catch (e) {
    line(`<span class="c-error">Geo lookup failed: ${esc(e.message)}</span>`);
  }

  sep();
}
