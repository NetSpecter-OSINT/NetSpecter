// modules/dns.js
import { dnsQuery }        from '../api.js';
import { header, sep, kv, line, sleep, esc } from '../output.js';
import { bumpHit }         from '../state.js';

const TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA'];

export async function runDNS(target) {
  header('DNS ENUMERATION :: ' + target.toUpperCase());
  sep();

  for (const type of TYPES) {
    line(`<span class="c-dim">QUERYING</span> ${type.padEnd(6)} ...`);
    try {
      const data = await dnsQuery(target, type);
      if (data.Answer && data.Answer.length > 0) {
        data.Answer.forEach(rec => {
          const ttl = `<span class="c-dim">TTL:${rec.TTL}</span>`;
          kv(`  ${type.padEnd(10)}`, `${esc(rec.data)}&nbsp;&nbsp;${ttl}`, 'c-hi');
          bumpHit();
        });
      } else {
        kv(`  ${type.padEnd(10)}`, 'NO RECORD', 'c-dim');
      }
    } catch {
      kv(`  ${type.padEnd(10)}`, 'QUERY FAILED', 'c-bad');
    }
    await sleep(100);
  }

  sep();
  line('<span class="c-dim">// DNS enumeration complete.</span>');
}
