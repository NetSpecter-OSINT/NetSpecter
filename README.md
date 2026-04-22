# NetSpecter v2.1

A passive OSINT and recon tool built as a static site for GitHub Pages.
No backend, no API keys, no installs. Everything runs in the browser.

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/wabbuwabbu)

## Modules

| Module | Description | API Used |
|---|---|---|
| DNS | Full record enumeration (A, AAAA, MX, NS, TXT, CNAME, SOA) | Google DNS-over-HTTPS |
| WHOIS | Domain registration data | HackerTarget |
| GEO-IP | IP geolocation, ASN, ISP, currency, UTC offset | ipapi.co |
| SSL/CERT | Certificate transparency log analysis, expiry, SANs | crt.sh |
| SUBDOMAINS | Passive subdomain discovery from CT logs and hostsearch | crt.sh + HackerTarget |
| HTTP HEADERS | Response header audit, security header scoring | HackerTarget |
| EMAIL SEC | SPF, DKIM (10 selectors), DMARC policy grading, MX audit | Google DoH |
| PORTS | Common port scan with risk flagging | HackerTarget (nmap) |
| FINGERPRINT | DNS-based tech stack inference - CDN, email provider, SaaS tools, hosting | Google DoH |
| THREAT | Pre-built deep links to VirusTotal, Shodan, AbuseIPDB, URLScan, GreyNoise etc. | (links only) |
| FULL SCAN | All 10 modules in sequence with progress bar | All of the above |

## Keyboard Shortcuts

| Key | Action |
|---|---|
| `Enter` | Focus input |
| `Esc` | Clear output |
| `E` | Export output as .txt |
| `C` | Copy output to clipboard |
| `1-9` (0) | Switch tab by number |
| `?` | Toggle this shortcuts panel |

## API Rate Limits

HackerTarget free tier allows ~100 queries per day per IP.
The DNS (Google DoH), GEO-IP (ipapi.co), and crt.sh modules are not subject to this limit.
If you hit the HackerTarget limit, WHOIS, HTTP Headers, Subdomains (partial), and Port Scan will return a warning with fallback links.

## Colour Themes

Click any of the 6 coloured dots in the top-right to switch theme.
Choice is saved to `localStorage` and persists across sessions.

Available: **Green** (default) | **Blue** | **Purple** | **Pink** | **White** | **Gray**

## Legal

This tool performs passive reconnaissance only.
All queries use public APIs and DNS lookups.
No active exploitation, injection, or unauthorised access is performed.
Only scan domains and IPs you own or have explicit written permission to test.
