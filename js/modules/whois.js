// modules/whois.js - rewritten using RDAP (modern WHOIS replacement)
import { bumpQuery }  from '../state.js';
import { header, sep, kv, line, esc, sleep } from '../output.js';
import { bumpHit }    from '../state.js';

// RDAP bootstrap - maps TLDs to their authoritative RDAP server
// Falls back to rdap.org universal gateway if not listed
const RDAP_SERVERS = {
  com:  'https://rdap.verisign.com/com/v1',
  net:  'https://rdap.verisign.com/net/v1',
  org:  'https://rdap.publicinterestregistry.org/rdap',
  io:   'https://rdap.nic.io',
  co:   'https://rdap.nic.co',
  uk:   'https://rdap.nominet.uk/uk',
  de:   'https://rdap.denic.de',
  fr:   'https://rdap.nic.fr',
  nl:   'https://rdap.sidn.nl/rdap',
  eu:   'https://rdap.eu',
  app:  'https://rdap.nic.google',
  dev:  'https://rdap.nic.google',
  page: 'https://rdap.nic.google',
};

function getRdapUrl(domain) {
  const tld = domain.split('.').pop().toLowerCase();
  const base = RDAP_SERVERS[tld] || 'https://rdap.org';
  return `${base}/domain/${encodeURIComponent(domain.toUpperCase())}`;
}

function fmt(val) {
  if (!val) return 'N/A';
  // Strip T and Z from ISO dates for readability
  return String(val).replace('T', ' ').replace('Z', ' UTC');
}

export async function runWhois(target) {
  header('WHOIS / RDAP LOOKUP :: ' + target.toUpperCase());
  sep();
  line('<span class="c-dim">Querying RDAP (Registration Data Access Protocol)...</span>');

  // Skip WHOIS for plain IPs - use ARIN RDAP instead
  const isIP = /^(\d{1,3}\.){3}\d{1,3}$/.test(target);
  const url  = isIP
    ? `https://rdap.arin.net/registry/ip/${target}`
    : getRdapUrl(target);

  bumpQuery();
  try {
    const res  = await fetch(url);
    if (!res.ok) throw new Error(`RDAP returned HTTP ${res.status}`);
    const d    = await res.json();

    if (isIP) {
      // IP RDAP response
      kv('  IP Network',   esc(d.name         || 'N/A'), 'c-hi');
      kv('  Handle',       esc(d.handle        || 'N/A'));
      kv('  Start IP',     esc(d.startAddress  || 'N/A'));
      kv('  End IP',       esc(d.endAddress    || 'N/A'));
      kv('  CIDR',         esc((d.cidr0s?.[0]?.v4prefix) || 'N/A'));
      kv('  Type',         esc(d.type          || 'N/A'));
      kv('  Country',      esc(d.country       || 'N/A'));
      // Organisation
      const org = d.entities?.find(e => e.roles?.includes('registrant'));
      if (org) {
        kv('  Organisation', esc(org.vcardArray?.[1]?.find(v => v[0] === 'fn')?.[3] || 'N/A'));
      }
      bumpHit(5);
    } else {
      // Domain RDAP response
      kv('  Domain',         esc(d.ldhName              || target.toUpperCase()), 'c-hi');
      kv('  Status',         esc((d.status || []).join(', ') || 'N/A'));

      // Dates
      const events = d.events || [];
      const created   = events.find(e => e.eventAction === 'registration');
      if (created?.eventDate) {
        const days = Math.floor(
          (new Date() - new Date(created.eventDate)) / (1000 * 60 * 60 * 24));
        const ageClass = days < 30 ? 'c-bad' : days < 90 ? 'c-warn' : 'c-good';
        const ageLabel = days < 30 ? 'VERY NEW - HIGH RISK' : days < 90 ? 'RECENT' : 'ESTABLISHED';
        kv('  Domain Age', `${days} days (${ageLabel})`, ageClass);
      }
      const updated   = events.find(e => e.eventAction === 'last changed');
      const expiry    = events.find(e => e.eventAction === 'expiration');
      kv('  Created',      esc(fmt(created?.eventDate)));
      kv('  Updated',      esc(fmt(updated?.eventDate)));
      kv('  Expires',      esc(fmt(expiry?.eventDate)),
        expiry && new Date(expiry.eventDate) < new Date() ? 'c-bad' : 'c-good');

      // Nameservers
      sep();
      const ns = d.nameservers || [];
      kv('  Nameservers',  String(ns.length) + ' found');
      ns.forEach(n => kv('    NS', esc(n.ldhName || 'N/A')));

      // Registrar
      sep();
      const registrar = d.entities?.find(e => e.roles?.includes('registrar'));
      if (registrar) {
        const vcard = registrar.vcardArray?.[1] || [];
        const name  = vcard.find(v => v[0] === 'fn')?.[3];
        const url_  = vcard.find(v => v[0] === 'url')?.[3];
        const email = vcard.find(v => v[0] === 'email')?.[3];
        kv('  Registrar',    esc(name  || 'N/A'));
        if (url_)   kv('  Registrar URL',   esc(url_));
        if (email)  kv('  Abuse Contact',   esc(email));
      }

      // Registrant
      const registrant = d.entities?.find(e => e.roles?.includes('registrant'));
      if (registrant) {
        sep();
        const vcard = registrant.vcardArray?.[1] || [];
        const name  = vcard.find(v => v[0] === 'fn')?.[3];
        const org   = vcard.find(v => v[0] === 'org')?.[3];
        const addr  = vcard.find(v => v[0] === 'adr')?.[3];
        if (name) kv('  Registrant',      esc(name));
        if (org)  kv('  Organisation',    esc(org));
        if (addr) kv('  Address',         esc(Array.isArray(addr) ? addr.filter(Boolean).join(', ') : addr));
      }

      // DNSSEC
      sep();
      kv('  DNSSEC', esc(d.secureDNS?.delegationSigned ? 'SIGNED' : 'UNSIGNED'),
        d.secureDNS?.delegationSigned ? 'c-good' : 'c-warn');

      bumpHit(8);
    }
  } catch (e) {
    line(`<span class="c-error">RDAP query failed: ${esc(e.message)}</span>`);
    line(`<span class="c-dim">Try manually: </span><a href="https://www.rdap.net/domain/${esc(target)}" target="_blank" rel="noopener" style="color:inherit">rdap.net/domain/${esc(target)}</a>`);
  }

  sep();
}