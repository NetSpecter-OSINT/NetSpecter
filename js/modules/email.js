// modules/email.js
import { dnsQuery } from '../api.js';
import { header, sep, kv, line, sleep, esc } from '../output.js';
import { bumpHit } from '../state.js';

const DKIM_SELECTORS = [
  // Google Workspace
  'google', 'google2', 'googledomains',
  // Microsoft 365 / Exchange Online
  'selector1', 'selector2',
  // Mailchimp / Mandrill
  'k1', 'k2', 'k3', 'mandrill',
  // SendGrid
  's1', 's2', 'smtpapi', 'em', 'sg',
  // Amazon SES
  'amazonses',
  // Mailgun
  'mailo', 'pic', 'mta', 'mx',
  // Proofpoint
  'proofpoint', 'pp1', 'pp2',
  // Mimecast
  'mc1', 'mc2',
  // HubSpot
  'hubspot1', 'hubspot2', 'hs1', 'hs2',
  // Postmark
  'pm',
  // Zendesk
  'zendesk1', 'zendesk2',
  // Salesforce
  'sfdc', 'sf1',
  // Zoho
  'zoho', 'zmail',
  // Fastmail
  'fm1', 'fm2', 'fm3',
  // ProtonMail
  'protonmail',
  // Generic / fallback
  'default', 'mail', 'email', 'dkim', 'dkim1', 'dkim2', 'key1', 'key2', 'smtp',
];

export async function runEmail(target) {
  header('EMAIL SECURITY AUDIT :: ' + target.toUpperCase());
  sep();

  // SPF
  line('<span class="c-dim">Checking SPF record...</span>');
  try {
    const spf = await dnsQuery(target, 'TXT');
    let spfRec = null;
    if (spf.Answer) {
      spf.Answer.forEach(r => { if (r.data.includes('v=spf1')) spfRec = r.data; });
    }
    if (spfRec) {
      kv('  SPF', 'PRESENT', 'c-good');
      kv('  SPF Record', esc(spfRec.replace(/"/g, '')));
      const hard = spfRec.includes('-all');
      const soft = spfRec.includes('~all');
      kv('  SPF Policy',
        hard ? 'HARDFAIL (-all)' : soft ? 'SOFTFAIL (~all)' : 'NEUTRAL (+all)',
        hard ? 'c-good' : soft ? 'c-warn' : 'c-bad'
      );
      bumpHit(2);
    } else {
      kv('  SPF', 'MISSING - spoofing risk', 'c-bad');
    }
  } catch { kv('  SPF', 'Query failed', 'c-warn'); }

  sep();

  // DKIM
  line('<span class="c-dim">Probing common DKIM selectors...</span>');
  let dkimFound = 0;
  for (const sel of DKIM_SELECTORS) {
    try {
      const d = await dnsQuery(`${sel}._domainkey.${target}`, 'TXT');
      if (d.Answer && d.Answer.length > 0) {
        kv(`  DKIM [${sel}]`, 'PRESENT', 'c-good');
        dkimFound++;
        bumpHit();
      }
    } catch { /* not found */ }
    await sleep(50);
  }
  if (dkimFound === 0) {
    kv('  DKIM', 'No common selectors found (manual check advised)', 'c-warn');
  } else {
    kv('  DKIM Selectors Found', String(dkimFound), 'c-good');
  }

  sep();

  // DMARC
  line('<span class="c-dim">Checking DMARC record...</span>');
  try {
    const dm = await dnsQuery(`_dmarc.${target}`, 'TXT');
    if (dm.Answer && dm.Answer.length > 0) {
      const rec = dm.Answer[0].data;
      kv('  DMARC', 'PRESENT', 'c-good');
      kv('  DMARC Record', esc(rec.replace(/"/g, '')));
      const policy = rec.match(/p=([^;]+)/);
      if (policy) {
        const p   = policy[1].toLowerCase();
        const cls = p === 'reject' ? 'c-good' : p === 'quarantine' ? 'c-warn' : 'c-bad';
        kv('  DMARC Policy', p.toUpperCase(), cls);
      }
      const rua = rec.match(/rua=([^;]+)/);
      if (rua) kv('  Aggregate Reports', esc(rua[1]));
      bumpHit(2);
    } else {
      kv('  DMARC', 'MISSING', 'c-bad');
    }
  } catch { kv('  DMARC', 'Query failed', 'c-warn'); }

  sep();

  // MX
  line('<span class="c-dim">Checking MX records...</span>');
  try {
    const mx = await dnsQuery(target, 'MX');
    if (mx.Answer && mx.Answer.length > 0) {
      kv('  MX Records', String(mx.Answer.length) + ' found', 'c-good');
      mx.Answer.forEach(r => {
        const parts = String(r.data).split(' ');
        kv('    Priority ' + (parts[0] || '?').padEnd(6), esc(parts[1] || r.data));
      });
      bumpHit(mx.Answer.length);
    } else {
      kv('  MX Records', 'NONE - cannot receive email', 'c-warn');
    }
  } catch { kv('  MX', 'Query failed', 'c-warn'); }

  sep();
}