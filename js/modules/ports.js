// modules/ports.js
import { hackerTargetQuery } from '../api.js';
import { header, sep, kv, line, esc } from '../output.js';
import { bumpHit } from '../state.js';

const PORT_LABELS = {
  21:   'FTP',
  22:   'SSH',
  23:   'Telnet',
  25:   'SMTP',
  53:   'DNS',
  80:   'HTTP',
  110:  'POP3',
  111:  'RPC',
  135:  'MSRPC',
  139:  'NetBIOS',
  143:  'IMAP',
  443:  'HTTPS',
  445:  'SMB',
  993:  'IMAPS',
  995:  'POP3S',
  1433: 'MSSQL',
  1521: 'Oracle',
  2375: 'Docker',
  3306: 'MySQL',
  3389: 'RDP',
  4443: 'HTTPS-alt',
  5432: 'PostgreSQL',
  5900: 'VNC',
  6379: 'Redis',
  8080: 'HTTP-alt',
  8443: 'HTTPS-alt',
  8888: 'HTTP-alt',
  9200: 'Elasticsearch',
  27017:'MongoDB',
};

// Ports considered high-risk if open
const RISKY = new Set([23, 135, 139, 445, 1433, 1521, 2375, 3389, 5900, 6379, 9200, 27017]);

export async function runPorts(target) {
  header('PORT SCAN :: ' + target.toUpperCase());
  sep();
  line('<span class="c-dim">Running passive nmap via HackerTarget (common ports only)...</span>');
  line('<span class="c-dim">This may take 15-30 seconds.</span>');

  try {
    const raw = await hackerTargetQuery('nmap', target);

    if (raw.includes('error') || raw.includes('API count') || raw.includes('invalid')) {
      line('<span class="c-warn">HackerTarget rate limit or invalid target.</span>');
      line(`<span class="c-dim">Alternative: </span><a href="https://www.shodan.io/search?query=${esc(target)}" target="_blank" rel="noopener" style="color:inherit">Shodan search</a>`);
      return;
    }

    const lines   = raw.split('\n');
    let   host    = '';
    let   openCount  = 0;
    let   closedCount = 0;
    const openPorts  = [];

    lines.forEach(l => {
      l = l.trim();
      if (!l) return;

      // Host line
      if (l.startsWith('Host:') || l.startsWith('Nmap scan report for')) {
        const match = l.match(/[\d.]+/);
        if (match) { host = match[0]; kv('  Host', esc(host), 'c-hi'); }
        return;
      }

      // Port line e.g. "80/tcp   open  http"
      const portMatch = l.match(/^(\d+)\/(tcp|udp)\s+(open|closed|filtered)\s*(.*)?/i);
      if (portMatch) {
        const port    = parseInt(portMatch[1]);
        const proto   = portMatch[2].toUpperCase();
        const state_  = portMatch[3].toLowerCase();
        const service = portMatch[4]?.trim() || PORT_LABELS[port] || '?';
        const isRisky = RISKY.has(port);

        if (state_ === 'open') {
          openPorts.push({ port, proto, service, risky: isRisky });
          openCount++;
          bumpHit();
        } else {
          closedCount++;
        }
      }
    });

    if (openPorts.length === 0) {
      line('<span class="c-dim">No open ports detected in common range.</span>');
    } else {
      sep();
      kv('  Open ports',   String(openCount),   'c-hi');
      kv('  Closed/filtered', String(closedCount));
      sep();

      // Header row
      line(
        '<span class="c-dim">  PORT'.padEnd(14) +
        'PROTO'.padEnd(8) +
        'SERVICE'.padEnd(22) +
        'RISK</span>'
      );
      sep();

      openPorts.forEach(({ port, proto, service, risky }) => {
        const riskLabel = risky
          ? '<span class="c-bad">HIGH</span>'
          : '<span class="c-good">LOW</span>';
        line(
          `  <span class="out-val c-hi">${String(port).padEnd(10)}</span>` +
          `<span class="c-dim">${proto.padEnd(8)}</span>` +
          `<span class="out-val">${esc(service).padEnd(22)}</span>` +
          riskLabel
        );
      });

      if (openPorts.some(p => p.risky)) {
        sep();
        line('<span class="c-warn">WARNING: High-risk services detected. Review access controls.</span>');
      }
    }
  } catch (e) {
    line(`<span class="c-error">Port scan failed: ${esc(e.message)}</span>`);
  }

  sep();
}
