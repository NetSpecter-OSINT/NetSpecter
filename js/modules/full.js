// modules/full.js - orchestrates all modules in sequence
import { runDNS }         from './dns.js';
import { runWhois }       from './whois.js';
import { runGeo }         from './geo.js';
import { runSSL }         from './ssl.js';
import { runSubdomains }  from './subdomains.js';
import { runHeaders }     from './headers.js';
import { runEmail }       from './email.js';
import { runPorts }       from './ports.js';
import { runFingerprint } from './techscan.js';
import { runThreat }      from './threat.js';
import { line, sep, showProgress, setProgress, sleep } from '../output.js';

const STEPS = [
  { label: 'DNS_ENUMERATION',       fn: runDNS,         pct: 10 },
  { label: 'WHOIS_LOOKUP',          fn: runWhois,       pct: 20 },
  { label: 'GEO_IP_LOCATION',       fn: runGeo,         pct: 30 },
  { label: 'SSL_CERT_ANALYSIS',     fn: runSSL,         pct: 40 },
  { label: 'SUBDOMAIN_DISCOVERY',   fn: runSubdomains,  pct: 50 },
  { label: 'HTTP_HEADERS',          fn: runHeaders,     pct: 60 },
  { label: 'EMAIL_SECURITY',        fn: runEmail,       pct: 70 },
  { label: 'PORT_SCAN',             fn: runPorts,       pct: 80 },
  { label: 'TECH_FINGERPRINT',      fn: runFingerprint, pct: 91 },
  { label: 'THREAT_INTEL',          fn: runThreat,      pct: 100 },
];

export async function runFull(target) {
  showProgress('INITIALISING FULL SWEEP...', 0);

  for (const step of STEPS) {
    setProgress(step.pct - 8, 'RUNNING: ' + step.label);
    line('<span class="c-bright">// ===[ ' + step.label + ' ]===</span>');
    await step.fn(target);
    setProgress(step.pct, 'COMPLETE: ' + step.label);
    await sleep(250);
  }

  sep();
  line('<span class="c-success c-bright">// FULL RECON SWEEP COMPLETE. ALL MODULES EXECUTED.</span>');
  setProgress(100, 'SWEEP COMPLETE');
  await sleep(800);
}
