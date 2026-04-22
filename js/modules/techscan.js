// modules/fingerprint.js
// DNS-based technology fingerprinting - no page requests needed.
// Infers email provider, DNS host, CDN, cloud services, and SaaS tools
// purely from A, CNAME, NS, MX, and TXT records.

import { dnsQuery } from '../api.js';
import { header, sep, kv, line, spacer, esc, sleep } from '../output.js';
import { bumpHit } from '../state.js';

// ---- DNS provider detection from NS records ----
const NS_PROVIDERS = [
  [/cloudflare\.com/i,      'Cloudflare DNS'],
  [/awsdns/i,               'AWS Route 53'],
  [/azure-dns\.com/i,       'Azure DNS'],
  [/googledomains\.com/i,   'Google Domains DNS'],
  [/dns\.google/i,          'Google Cloud DNS'],
  [/hetzner\.com/i,         'Hetzner DNS'],
  [/digitalocean\.com/i,    'DigitalOcean DNS'],
  [/namecheap\.com/i,       'Namecheap DNS'],
  [/godaddy\.com/i,         'GoDaddy DNS'],
  [/registrar-servers\.com/i,'Namecheap (Registrar)'],
  [/ovh\.net/i,             'OVH DNS'],
  [/dnsimple\.com/i,        'DNSimple'],
  [/nsone\.net/i,           'NS1'],
  [/dyn\.com/i,             'Oracle Dyn'],
  [/ultradns\.net/i,        'UltraDNS'],
];

// ---- CDN / hosting detection from CNAME or A ----
const CNAME_CDN = [
  [/cloudfront\.net/i,            'AWS CloudFront CDN'],
  [/fastly\.net/i,                'Fastly CDN'],
  [/akamai/i,                     'Akamai CDN'],
  [/azureedge\.net/i,             'Azure CDN'],
  [/azurewebsites\.net/i,         'Azure App Service'],
  [/windows\.net/i,               'Azure Storage'],
  [/cloudflare\.com/i,            'Cloudflare (CNAME)'],
  [/amazonaws\.com/i,             'AWS (S3/EC2/ELB)'],
  [/elb\.amazonaws\.com/i,        'AWS Elastic Load Balancer'],
  [/s3\.amazonaws\.com/i,         'AWS S3'],
  [/netlify\.app/i,               'Netlify'],
  [/vercel\.app/i,                'Vercel'],
  [/github\.io/i,                 'GitHub Pages'],
  [/pantheon\.io/i,               'Pantheon'],
  [/wpengine\.com/i,              'WP Engine'],
  [/shopify\.com/i,               'Shopify'],
  [/squarespace\.com/i,           'Squarespace'],
  [/wixdns\.net/i,                'Wix'],
  [/heroku\.com/i,                'Heroku'],
  [/render\.com/i,                'Render'],
  [/fly\.dev/i,                   'Fly.io'],
  [/googlehosted\.com/i,          'Google Hosted'],
  [/ghs\.google\.com/i,           'Google Sites'],
  [/zendesk\.com/i,               'Zendesk'],
  [/intercom\.io/i,               'Intercom'],
  [/hubspot\.net/i,               'HubSpot'],
];

// ---- Email provider detection from MX records ----
const MX_PROVIDERS = [
  [/google\.com|gmail\.com|googlemail/i,        'Google Workspace'],
  [/outlook\.com|hotmail\.com|protection\.outlook\.com|mail\.protection\.outlook/i, 'Microsoft 365'],
  [/protonmail\.ch|proton\.me/i,                'Proton Mail'],
  [/mailgun\.org/i,                             'Mailgun'],
  [/sendgrid\.net/i,                            'SendGrid (Twilio)'],
  [/amazonses\.com/i,                           'Amazon SES'],
  [/mimecast\.com/i,                            'Mimecast'],
  [/pphosted\.com/i,                            'Proofpoint'],
  [/barracudanetworks\.com/i,                   'Barracuda'],
  [/zoho\.com/i,                                'Zoho Mail'],
  [/fastmail\.com/i,                            'Fastmail'],
  [/mailchimp\.com/i,                           'Mailchimp Transactional'],
  [/messagelabs\.com/i,                         'Symantec MessageLabs'],
];

// ---- SaaS / service detection from TXT records ----
const TXT_SERVICES = [
  [/google-site-verification/i,         'Google Search Console'],
  [/v=ms|MS=/i,                         'Microsoft 365 / Entra ID'],
  [/docusign=/i,                        'DocuSign'],
  [/atlassian-domain-verification/i,    'Atlassian (Jira/Confluence)'],
  [/facebook-domain-verification/i,     'Meta / Facebook'],
  [/apple-domain-verification/i,        'Apple'],
  [/stripe-verification/i,              'Stripe'],
  [/zoom-/i,                            'Zoom'],
  [/hubspot-/i,                         'HubSpot'],
  [/salesforce-/i,                      'Salesforce'],
  [/_amazonses/i,                       'Amazon SES (TXT)'],
  [/klaviyo/i,                          'Klaviyo'],
  [/intercom/i,                         'Intercom'],
  [/shopify/i,                          'Shopify'],
  [/ahrefs/i,                           'Ahrefs'],
  [/semrush/i,                          'SEMrush'],
  [/braintree/i,                        'Braintree / PayPal'],
  [/sendgrid/i,                         'SendGrid'],
  [/twilio/i,                           'Twilio'],
  [/pardot/i,                           'Salesforce Pardot'],
  [/adobe-idp/i,                        'Adobe Experience Cloud'],
  [/zendesk/i,                          'Zendesk'],
  [/miro-verification/i,               'Miro'],
  [/have-i-been-pwned/i,                'HIBP Domain Check'],
];

// ---- Cloudflare IP ranges (first octet/range combos) ----
// Simplified subset for client-side detection
const CF_PREFIXES = [
  '104.16.', '104.17.', '104.18.', '104.19.',
  '104.20.', '104.21.', '172.64.', '172.65.',
  '172.66.', '172.67.', '172.68.', '172.69.',
  '162.158.', '198.41.', '190.93.',
];

function isCloudflareIP(ip) {
  return CF_PREFIXES.some(p => ip.startsWith(p));
}

export async function runFingerprint(target) {
  header('TECHNOLOGY FINGERPRINT :: ' + target.toUpperCase());
  sep();
  line('<span class="c-dim">Inferring stack from DNS records only - no direct site requests.</span>');
  sep();

  const findings = {
    dns:    null,
    cdn:    [],
    email:  null,
    saas:   [],
    cf:     false,
  };

  // ---- NS records -> DNS provider ----
  line('<span class="c-dim">Probing NS records for DNS provider...</span>');
  try {
    const ns = await dnsQuery(target, 'NS');
    if (ns.Answer && ns.Answer.length > 0) {
      const nsValues = ns.Answer.map(r => r.data.toLowerCase());
      kv('  NS Records', String(ns.Answer.length) + ' nameservers found');
      nsValues.forEach(n => kv('    NS', esc(n)));

      for (const [pattern, name] of NS_PROVIDERS) {
        if (nsValues.some(n => pattern.test(n))) {
          findings.dns = name;
          break;
        }
      }
      kv('  DNS Provider', findings.dns || 'Unknown / Self-hosted',
        findings.dns ? 'c-hi' : 'c-dim');
      bumpHit();
    }
  } catch { kv('  NS', 'Query failed', 'c-warn'); }

  await sleep(150);
  sep();

  // ---- A record -> IP + Cloudflare check ----
  line('<span class="c-dim">Probing A record for hosting/CDN signals...</span>');
  try {
    const a = await dnsQuery(target, 'A');
    if (a.Answer && a.Answer.length > 0) {
      const ips = a.Answer.map(r => r.data);
      ips.forEach(ip => {
        kv('  A Record', esc(ip), 'c-hi');
        if (isCloudflareIP(ip)) {
          findings.cf = true;
          findings.cdn.push('Cloudflare (Proxy / WAF)');
        }
      });
      bumpHit();
    }
  } catch { kv('  A Record', 'Query failed', 'c-warn'); }

  await sleep(150);

  // ---- CNAME records -> CDN / platform ----
  try {
    const cname = await dnsQuery(target, 'CNAME');
    if (cname.Answer && cname.Answer.length > 0) {
      const cnameValues = cname.Answer.map(r => r.data.toLowerCase());
      cnameValues.forEach(c => kv('  CNAME', esc(c)));
      for (const [pattern, name] of CNAME_CDN) {
        if (cnameValues.some(c => pattern.test(c))) {
          if (!findings.cdn.includes(name)) findings.cdn.push(name);
        }
      }
      bumpHit();
    }
  } catch { /* silently skip */ }

  // www subdomain CNAME check
  try {
    const wwwCname = await dnsQuery('www.' + target, 'CNAME');
    if (wwwCname.Answer && wwwCname.Answer.length > 0) {
      const vals = wwwCname.Answer.map(r => r.data.toLowerCase());
      vals.forEach(c => kv('  www CNAME', esc(c)));
      for (const [pattern, name] of CNAME_CDN) {
        if (vals.some(c => pattern.test(c))) {
          if (!findings.cdn.includes(name)) findings.cdn.push(name);
        }
      }
      bumpHit();
    }
  } catch { /* silently skip */ }

  if (findings.cdn.length > 0) {
    sep();
    header('CDN / HOSTING STACK');
    findings.cdn.forEach(c => {
      kv('  Detected', c, 'c-good');
      bumpHit();
    });
  } else {
    kv('  CDN / Hosting', 'Not detected via passive DNS', 'c-dim');
  }

  await sleep(150);
  sep();

  // ---- MX records -> email provider ----
  line('<span class="c-dim">Probing MX for email provider...</span>');
  try {
    const mx = await dnsQuery(target, 'MX');
    if (mx.Answer && mx.Answer.length > 0) {
      const mxValues = mx.Answer.map(r => r.data.toLowerCase());
      for (const [pattern, name] of MX_PROVIDERS) {
        if (mxValues.some(m => pattern.test(m))) {
          findings.email = name;
          break;
        }
      }
      kv('  Email Provider', findings.email || 'Self-hosted / Unknown',
        findings.email ? 'c-hi' : 'c-dim');
      if (!findings.email) {
        mxValues.forEach(m => kv('    MX', esc(m)));
      }
      bumpHit();
    } else {
      kv('  Email Provider', 'No MX records (no email)', 'c-warn');
    }
  } catch { kv('  Email Provider', 'Query failed', 'c-warn'); }

  await sleep(150);
  sep();

  // ---- TXT records -> SaaS services ----
  line('<span class="c-dim">Mining TXT records for SaaS service tokens...</span>');
  try {
    const txt = await dnsQuery(target, 'TXT');
    if (txt.Answer && txt.Answer.length > 0) {
      const txtValues = txt.Answer.map(r => r.data.toLowerCase());
      const detected = [];

      for (const [pattern, name] of TXT_SERVICES) {
        if (txtValues.some(t => pattern.test(t))) {
          detected.push(name);
          bumpHit();
        }
      }

      if (detected.length > 0) {
        header('SAAS / TOOL FOOTPRINT');
        detected.forEach(s => kv('  Detected', s, 'c-good'));
        findings.saas = detected;
      } else {
        kv('  SaaS Services', 'No recognisable tokens in TXT records', 'c-dim');
      }
    }
  } catch { kv('  TXT Scan', 'Query failed', 'c-warn'); }

  await sleep(100);
  sep();

  // ---- Summary ----
  header('FINGERPRINT SUMMARY');
  kv('  DNS Host',     findings.dns || 'Unknown',        findings.dns ? 'c-hi' : 'c-dim');
  kv('  CDN / WAF',    findings.cdn.length > 0 ? findings.cdn.join(', ') : 'None detected',
    findings.cdn.length > 0 ? 'c-good' : 'c-dim');
  kv('  Email Stack',  findings.email || 'Unknown',       findings.email ? 'c-hi' : 'c-dim');
  kv('  SaaS Count',   String(findings.saas.length) + ' service(s) identified',
    findings.saas.length > 0 ? 'c-hi' : 'c-dim');
  kv('  Cloudflare',   findings.cf ? 'YES - IP behind CF proxy' : 'No CF proxy detected',
    findings.cf ? 'c-warn' : 'c-dim');
  sep();
}
