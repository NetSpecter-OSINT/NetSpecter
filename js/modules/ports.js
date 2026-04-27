// modules/ports.js - passive service data via Shodan InternetDB + DNS inference
import { dnsQuery, crtShLookup } from '../api.js';
import { bumpQuery }  from '../state.js';
import { header, sep, kv, line, spacer, esc, sleep } from '../output.js';
import { bumpHit }    from '../state.js';

const PORT_META = {
  21:    { service: 'FTP',           risk: 'HIGH', note: 'File transfer - often misconfigured' },
  22:    { service: 'SSH',           risk: 'MED',  note: 'Remote access' },
  23:    { service: 'Telnet',        risk: 'HIGH', note: 'Unencrypted remote access' },
  25:    { service: 'SMTP',          risk: 'MED',  note: 'Mail transfer' },
  53:    { service: 'DNS',           risk: 'LOW',  note: 'Name resolution' },
  80:    { service: 'HTTP',          risk: 'LOW',  note: 'Unencrypted web' },
  110:   { service: 'POP3',          risk: 'MED',  note: 'Mail retrieval' },
  143:   { service: 'IMAP',          risk: 'MED',  note: 'Mail access' },
  443:   { service: 'HTTPS',         risk: 'LOW',  note: 'Encrypted web' },
  445:   { service: 'SMB',           risk: 'HIGH', note: 'Windows file sharing' },
  465:   { service: 'SMTPS',         risk: 'LOW',  note: 'Encrypted mail' },
  587:   { service: 'SMTP/TLS',      risk: 'LOW',  note: 'Mail submission' },
  993:   { service: 'IMAPS',         risk: 'LOW',  note: 'Encrypted IMAP' },
  995:   { service: 'POP3S',         risk: 'LOW',  note: 'Encrypted POP3' },
  1433:  { service: 'MSSQL',         risk: 'HIGH', note: 'Exposed database' },
  1521:  { service: 'Oracle DB',     risk: 'HIGH', note: 'Exposed database' },
  2052:  { service: 'Cloudflare HTTP',  risk: 'LOW', note: 'CF alternative HTTP port' },
  2053:  { service: 'Cloudflare HTTPS', risk: 'LOW', note: 'CF alternative HTTPS port' },
  2082:  { service: 'cPanel HTTP',      risk: 'MED', note: 'Hosting panel unencrypted' },
  2083:  { service: 'cPanel SSL',    risk: 'MED',  note: 'Hosting control panel' },
  2086:  { service: 'WHM HTTP',         risk: 'MED', note: 'Server panel unencrypted' },
  2087:  { service: 'WHM SSL',       risk: 'MED',  note: 'Server management panel' },
  2095:  { service: 'cPanel Webmail',   risk: 'MED', note: 'Webmail unencrypted' },
  2096:  { service: 'cPanel Webmail SSL', risk: 'LOW', note: 'Webmail encrypted' },
  2375:  { service: 'Docker',        risk: 'HIGH', note: 'Unprotected Docker socket' },
  3306:  { service: 'MySQL',         risk: 'HIGH', note: 'Exposed database' },
  3389:  { service: 'RDP',           risk: 'HIGH', note: 'Remote desktop' },
  5432:  { service: 'PostgreSQL',    risk: 'HIGH', note: 'Exposed database' },
  5900:  { service: 'VNC',           risk: 'HIGH', note: 'Remote desktop' },
  6379:  { service: 'Redis',         risk: 'HIGH', note: 'Often auth-free' },
  8080:  { service: 'HTTP-alt',      risk: 'MED',  note: 'Dev/proxy endpoint' },
  8443:  { service: 'HTTPS-alt',     risk: 'MED',  note: 'Alt TLS endpoint' },
  8880:  { service: 'Cloudflare HTTP',  risk: 'LOW', note: 'CF alternative HTTP port' },
  8888:  { service: 'HTTP-alt',      risk: 'MED',  note: 'Jupyter/dev server' },
  9200:  { service: 'Elasticsearch', risk: 'HIGH', note: 'Often auth-free' },
  27017: { service: 'MongoDB',       risk: 'HIGH', note: 'Often auth-free' },
};

function riskClass(risk) {
  return risk === 'LOW' ? 'c-good' : risk === 'MED' ? 'c-warn' : 'c-bad';
}

function portInfo(port) {
  return PORT_META[port] || { service: 'Unknown', risk: 'MED', note: '' };
}

export async function runPorts(target) {
  header('SERVICES & PORTS :: ' + target.toUpperCase());
  sep();

  // ---- Resolve IP first ----
  let ip = target;
  const isIP = /^(\d{1,3}\.){3}\d{1,3}$/.test(target);

  if (!isIP) {
    line('<span class="c-dim">Resolving IP from A record...</span>');
    try {
      const a = await dnsQuery(target, 'A');
      if (a.Answer && a.Answer[0]) {
        ip = a.Answer[0].data;
        kv('  Resolved IP', esc(ip), 'c-hi');
        bumpHit();
      } else {
        line('<span class="c-warn">No A record found - skipping Shodan lookup.</span>');
        ip = null;
      }
    } catch {
      line('<span class="c-warn">DNS resolution failed.</span>');
      ip = null;
    }
    await sleep(100);
  }

  // ---- Source 1: Shodan InternetDB (real port data, no key needed) ----
  let shodanPorts = [];
  let shodanVulns = [];
  let shodanCPEs  = [];
  let shodanTags  = [];

  if (ip) {
    sep();
    line('<span class="c-dim">Querying Shodan InternetDB (passive scan data)...</span>');
    try {
      bumpQuery();
      const controller = new AbortController();
      const timeout    = setTimeout(() => controller.abort(), 8000);
      const res  = await fetch(`https://internetdb.shodan.io/${ip}`, {
        signal: controller.signal
      });
      clearTimeout(timeout);

      if (res.status === 404) {
        line('<span class="c-dim">No Shodan data for this IP (not yet scanned or private range).</span>');
      } else if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      } else {
        const data   = await res.json();
        shodanPorts  = data.ports   || [];
        shodanVulns  = data.vulns   || [];
        shodanCPEs   = data.cpes    || [];
        shodanTags   = data.tags    || [];

        // Hostnames
        if (data.hostnames && data.hostnames.length > 0) {
          kv('  Hostnames', esc(data.hostnames.slice(0, 4).join(', ')));
        }

        // Tags
        if (shodanTags.length > 0) {
          kv('  Tags', esc(shodanTags.join(', ')));
        }

        sep();

        if (shodanPorts.length > 0) {
          kv('  Open ports (Shodan)', String(shodanPorts.length), 'c-hi');
          sep();

          line(
            '<span class="c-dim">' +
            '  PORT'.padEnd(10) +
            'SERVICE'.padEnd(20) +
            'RISK'.padEnd(8) +
            'NOTES' +
            '</span>'
          );
          sep();

          shodanPorts.sort((a, b) => a - b).forEach(port => {
            const info = portInfo(port);
            line(
              `  <span class="c-hi">${String(port).padEnd(10)}</span>` +
              `<span class="out-val">${esc(info.service).padEnd(20)}</span>` +
              `<span class="${riskClass(info.risk)}">${info.risk.padEnd(8)}</span>` +
              `<span class="c-dim">${esc(info.note)}</span>`
            );
            bumpHit();
          });
        } else {
          line('<span class="c-dim">Shodan shows no open ports for this IP.</span>');
        }

        // CPEs / software fingerprints
        if (shodanCPEs.length > 0) {
          sep();
          kv('  Software (CPE)', String(shodanCPEs.length) + ' detected', 'c-hi');
          shodanCPEs.slice(0, 8).forEach(cpe => {
            // Clean up CPE string for readability
            const readable = cpe
              .replace('cpe:/a:', '')
              .replace('cpe:/o:', '')
              .replace('cpe:2.3:a:', '')
              .replace(/:/g, ' ')
              .trim();
            line(`  <span class="c-dim">  [CPE]</span> <span class="out-val">${esc(readable)}</span>`);
          });
        }

        // CVEs - this is the really valuable bit
        if (shodanVulns.length > 0) {
          sep();
          kv('  CVEs detected', String(shodanVulns.length), 'c-bad');
          line('<span class="c-warn">  WARNING: Known vulnerabilities found on this host.</span>');
          shodanVulns.slice(0, 10).forEach(cve => {
            const url = `https://nvd.nist.gov/vuln/detail/${cve}`;
            line(
              `  <span class="c-bad">  [CVE]</span> ` +
              `<a href="${esc(url)}" target="_blank" rel="noopener" ` +
              `style="color:inherit">${esc(cve)}</a>`
            );
          });
          if (shodanVulns.length > 10) {
            line(`  <span class="c-dim">  ... and ${shodanVulns.length - 10} more.</span>`);
          }
        } else if (shodanPorts.length > 0) {
          sep();
          kv('  CVEs', 'None detected in Shodan database', 'c-good');
        }
      }
    } catch (e) {
      line(`<span class="c-warn">Shodan InternetDB failed: ${esc(e.message)}</span>`);
    }
  }

  // ---- Source 2: DNS inference (always runs as supplement) ----
  await sleep(100);
  sep();
  line('<span class="c-dim">DNS signal inference (supplementary)...</span>');

  const inferred = [];

  try {
    const mx = await dnsQuery(target, 'MX');
    if (mx.Answer && mx.Answer.length > 0) {
      if (!shodanPorts.includes(25))  inferred.push({ port: 25,  basis: 'MX record' });
      if (!shodanPorts.includes(587)) inferred.push({ port: 587, basis: 'MX record' });
      if (!shodanPorts.includes(993)) inferred.push({ port: 993, basis: 'MX record' });
    }
  } catch { /* skip */ }

  await sleep(60);

  try {
    const ns = await dnsQuery(target, 'NS');
    if (ns.Answer && ns.Answer.length > 0) {
      if (!shodanPorts.includes(53)) inferred.push({ port: 53, basis: 'NS record' });
    }
  } catch { /* skip */ }

  await sleep(60);

  try {
    const certs = await crtShLookup(target);
    if (Array.isArray(certs)) {
      const names = certs.flatMap(c => (c.name_value || '').split('\n').map(n => n.toLowerCase()));
      if (names.some(n => n.startsWith('api.'))) {
        if (!shodanPorts.includes(8443)) inferred.push({ port: 8443, basis: 'api. subdomain in CT logs' });
      }
      if (names.some(n => n.startsWith('dev.') || n.startsWith('staging.'))) {
        if (!shodanPorts.includes(8080)) inferred.push({ port: 8080, basis: 'dev./staging. in CT logs' });
      }
    }
  } catch { /* skip */ }

  if (inferred.length > 0) {
    spacer();
    kv('  DNS-inferred services', String(inferred.length));
    inferred.forEach(({ port, basis }) => {
      const info = portInfo(port);
      line(
        `  <span class="c-dim">${String(port).padEnd(10)}</span>` +
        `<span class="out-val">${esc(info.service).padEnd(20)}</span>` +
        `<span class="${riskClass(info.risk)}">${info.risk.padEnd(8)}</span>` +
        `<span class="c-dim">${esc(basis)}</span>`
      );
    });
  } else {
    line('<span class="c-dim">No additional services inferred from DNS.</span>');
  }

  sep();
  const shodanUrl = ip
    ? `https://www.shodan.io/host/${ip}`
    : `https://www.shodan.io/search?query=${target}`;

  line(
    '<span class="c-dim">// Full details: </span>' +
    `<a href="${esc(shodanUrl)}" target="_blank" rel="noopener" style="color:inherit">Shodan</a>`
  );
  
  sep();
}