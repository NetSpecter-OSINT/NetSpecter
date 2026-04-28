// modules/threat.js
import { dnsQuery } from '../api.js';
import { header, sep, kv, line, sleep, esc } from '../output.js';
import { bumpHit } from '../state.js';

const THREAT_LINKS = [
  ['VirusTotal',           d => `https://www.virustotal.com/gui/domain/${d}`],
  ['Shodan',               d => `https://www.shodan.io/search?query=${d}`],
  ['AbuseIPDB',            (d, ip) => `https://www.abuseipdb.com/check/${ip}`],
  ['URLScan.io',           d => `https://urlscan.io/search/#page.domain%3A${d}`],
  ['AlienVault OTX',       d => `https://otx.alienvault.com/indicator/domain/${d}`],
  ['IBM X-Force',          d => `https://exchange.xforce.ibmcloud.com/url/${d}`],
  ['Google Safe Browsing', d => `https://transparencyreport.google.com/safe-browsing/search?url=${d}`],
  ['URLHaus',              d => `https://urlhaus.abuse.ch/browse.php?search=${d}`],
];

export async function runThreat(target) {
  header('THREAT INTELLIGENCE :: ' + target.toUpperCase());
  sep();

  let ip = target;
  const isIP = /^(\d{1,3}\.){3}\d{1,3}$/.test(target);
  if (!isIP) {
    try {
      const d = await dnsQuery(target, 'A');
      if (d.Answer && d.Answer[0]) ip = d.Answer[0].data;
    } catch { /* ignore */ }
  }

  kv('  Target Domain', esc(target), 'c-hi');
  kv('  Resolved IP',   esc(ip));
  sep();

  line('<span class="c-dim">External threat intelligence lookups (passive links):</span>');
  await sleep(200);

  THREAT_LINKS.forEach(([name, urlFn]) => {
    const url = urlFn(target, ip);
    const el = document.createElement('span');
    el.className = 'out-line';
    el.innerHTML =
      `<span class="c-dim">  [LINK]</span> ` +
      `<span class="out-key">${esc(name).padEnd(28)}</span>` +
      `<a href="${esc(url)}" target="_blank" rel="noopener" ` +
      `style="color:inherit;text-decoration:none;opacity:0.75;font-size:11px">${esc(url.slice(0, 72))}</a>`;
    document.getElementById('output').appendChild(el);
    bumpHit();
  });

  sep();
  line('<span class="c-dim">// Click any link to open in your browser for live threat analysis.</span>');
  sep();
}
