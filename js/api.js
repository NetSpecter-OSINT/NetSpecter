// api.js - all external fetch calls, each one bumps the query counter

import { bumpQuery } from './state.js';

async function get(url) {
  bumpQuery();
  const res = await fetch(url);
  return res;
}

// DNS over HTTPS via Google
export async function dnsQuery(name, type) {
  const res = await get(
    `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`
  );
  return res.json();
}

// ipapi.co geolocation
export async function geoLookup(ip) {
  const res = await get(`https://ipapi.co/${encodeURIComponent(ip)}/json/`);
  return res.json();
}

// crt.sh certificate transparency
export async function crtShLookup(domain) {
  const res = await get(
    `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`
  );
  return res.json();
}

// HackerTarget proxy endpoints
export async function hackerTargetQuery(endpoint, target) {
  const res = await get(
    `https://api.hackertarget.com/${endpoint}/?q=${encodeURIComponent(target)}`
  );
  return res.text();
}
