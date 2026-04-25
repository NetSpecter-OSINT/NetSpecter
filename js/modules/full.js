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
  buildRiskSummary(target);
  sep();
  line('<span class="c-success c-bright">// FULL RECON SWEEP COMPLETE. ALL MODULES EXECUTED.</span>');
  setProgress(100, 'SWEEP COMPLETE');
  await sleep(800);
}

// ============================================================
// AUTOMATED RISK SUMMARY
// ============================================================
function buildRiskSummary(target) {
  const output = document.getElementById('output');
  console.log('buildRiskSummary called for', target);
  console.log('output text sample:', (output.innerText || '').slice(0, 200));

  const sep_ = () => {
    const el = document.createElement('span');
    el.className = 'out-sep';
    output.appendChild(el);
  };

  const row = (label, value, cls, note) => {
    const el = document.createElement('span');
    el.className = 'out-line out-kv';
    el.innerHTML =
      `<span class="out-key">  ${label}</span>` +
      `<span class="out-val ${cls}" style="min-width:120px;display:inline-block">${value}</span>` +
      `<span class="c-dim">${note}</span>`;
    output.appendChild(el);
  };

  const text = output.innerText || output.textContent;
  const has  = str  => text.includes(str);
  const find = regex => { const m = text.match(regex); return m ? m[1] : null; };

  // ---- Domain age ----
  const ageDays = parseInt(find(/Domain Age\s+(\d+) days/) || '9999');
  const ageRisk = ageDays < 30  ? ['HIGH',   'c-bad',  'Registered < 30 days ago'] :
                  ageDays < 90  ? ['MEDIUM', 'c-warn', 'Registered < 90 days ago'] :
                                  ['LOW',    'c-good', 'Established domain'];

  // ---- Registrar ----
  const badRegistrar = has('Registrar associated with elevated abuse rates');
  const regRisk = badRegistrar
    ? ['MEDIUM', 'c-warn', 'Registrar has elevated abuse history']
    : ['LOW',    'c-good', 'No registrar flags'];

  // ---- Email security ----
  const noMX    = has('NONE - cannot receive email');
  const noDMARC = has('DMARC') && has('MISSING');
  const spfSoft = has('SOFTFAIL (~all)');
  const emailRisk = noMX    ? ['HIGH',   'c-bad',  'No MX - send-only or shell domain'] :
                    noDMARC ? ['MEDIUM', 'c-warn', 'DMARC missing - spoofing risk']     :
                    spfSoft ? ['LOW',    'c-warn', 'SPF softfail policy']               :
                              ['LOW',    'c-good', 'Email security configured'];

  // ---- SSL ----
  const sslGrade   = find(/Overall Grade\s+([A-F][+-]?)/);
  const hasExpired = has('EXPIRED');
  const sslRisk = hasExpired               ? ['HIGH',   'c-bad',  'Expired certificate detected']     :
                  !sslGrade                ? ['MEDIUM', 'c-warn', 'No SSL grade available']           :
                  sslGrade.startsWith('A') ? ['LOW',    'c-good', 'SSL Labs grade: ' + sslGrade]      :
                  sslGrade.startsWith('B') ? ['MEDIUM', 'c-warn', 'SSL Labs grade: ' + sslGrade]      :
                                             ['HIGH',   'c-bad',  'SSL Labs grade: ' + sslGrade];

  // ---- HTTP headers ----
  const headerScore = find(/Security Header Score\s+(\d+)\/9/);
  const hScore = parseInt(headerScore || '0');
  const headerRisk = hScore >= 6 ? ['LOW',    'c-good', hScore + '/9 security headers present']     :
                     hScore >= 3 ? ['MEDIUM', 'c-warn', hScore + '/9 security headers present']     :
                                   ['HIGH',   'c-bad',  hScore + '/9 - poorly configured'];

  // ---- CVEs ----
  const hasCVEs = has('CVEs detected') && !has('None detected in Shodan');
  const cveRisk = hasCVEs
    ? ['HIGH', 'c-bad',  'Known CVEs on host IP']
    : ['LOW',  'c-good', 'No CVEs in Shodan database'];

  // ---- Cloudflare proxy ----
  const cfProxy = has('YES - IP behind CF proxy') || has('Cloudflare (Proxy / WAF)');
  const cfRisk  = cfProxy
    ? ['INFO', 'c-dim', 'Origin server hidden behind Cloudflare']
    : ['INFO', 'c-dim', 'No Cloudflare proxy detected'];

  // ---- Shell/placeholder domain ----
  const shellDomain = has('Response body only') && has('bytes');
  const plainText   = has('returned text/plain not text/html');

  // ---- Overall score ----
  const risks  = [ageRisk, emailRisk, sslRisk, headerRisk, cveRisk, regRisk];
  const highs  = risks.filter(r => r[0] === 'HIGH').length;
  const meds   = risks.filter(r => r[0] === 'MEDIUM').length;
  const overall = highs >= 2 ? ['HIGH RISK',     'c-bad',  highs + ' high-risk indicators detected']          :
                  highs >= 1 ? ['ELEVATED RISK',  'c-warn', highs + ' high + ' + meds + ' medium indicators'] :
                  meds  >= 2 ? ['MODERATE RISK',  'c-warn', meds  + ' medium-risk indicators']                :
                               ['LOW RISK',        'c-good', 'No significant risk indicators'];

  // ---- Render ----
  const hdr = document.createElement('span');
  hdr.className = 'out-header';
  hdr.textContent = '>> AUTOMATED RISK SUMMARY :: ' + target.toUpperCase();
  output.appendChild(hdr);
  sep_();

  row('OVERALL ASSESSMENT', overall[0], overall[1] + ' c-bright', overall[2]);
  sep_();
  row('Domain Age',     ageRisk[0],    ageRisk[1],    ageRisk[2]);
  row('Registrar',      regRisk[0],    regRisk[1],    regRisk[2]);
  row('Email Security', emailRisk[0],  emailRisk[1],  emailRisk[2]);
  row('SSL / TLS',      sslRisk[0],    sslRisk[1],    sslRisk[2]);
  row('HTTP Headers',   headerRisk[0], headerRisk[1], headerRisk[2]);
  row('Known CVEs',     cveRisk[0],    cveRisk[1],    cveRisk[2]);
  row('CDN / Proxy',    cfRisk[0],     cfRisk[1],     cfRisk[2]);

  if (shellDomain || plainText) {
    sep_();
    const warn = document.createElement('span');
    warn.className = 'out-line c-bad';
    warn.textContent = '  ⚠ ANOMALY: Shell or placeholder domain detected - minimal content served.';
    output.appendChild(warn);
  }

  sep_();

  const note = document.createElement('span');
  note.className = 'out-line c-dim';
  note.textContent = '// Risk summary is probabilistic. Verify manually before drawing conclusions.';
  output.appendChild(note);
}