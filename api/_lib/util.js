'use strict';
// أدوات مشتركة بين api/trap.js و api/template.js
// المجلد ده بيبدأ بـ _ فمش بيتحول لـ endpoint عام.

const clean = (s, max = 200) =>
  String(s ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, max);

const esc = s => clean(s, 400).replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));

function getIp(req) {
  const h = req.headers || {};
  const raw = h['x-vercel-forwarded-for'] || h['x-forwarded-for'] || h['x-real-ip'] || (req.socket && req.socket.remoteAddress) || '';
  return clean(String(raw).split(',')[0].trim(), 64) || 'unknown';
}

function getGeo(req) {
  const h = req.headers || {};
  let city = h['x-vercel-ip-city'] || '';
  try { city = decodeURIComponent(city); } catch (_) {}
  return {
    country: clean(h['x-vercel-ip-country'], 8),
    region: clean(h['x-vercel-ip-country-region'], 16),
    city: clean(city, 60),
    lat: clean(h['x-vercel-ip-latitude'], 16),
    lon: clean(h['x-vercel-ip-longitude'], 16),
    tz: clean(h['x-vercel-ip-timezone'], 40)
  };
}

const TOOLS = [
  [/sqlmap/i, 'sqlmap'], [/nikto/i, 'nikto'], [/nmap/i, 'nmap'], [/masscan/i, 'masscan'],
  [/nuclei/i, 'nuclei'], [/wpscan/i, 'wpscan'], [/acunetix/i, 'acunetix'], [/dirbuster|gobuster|feroxbuster/i, 'dir-bruteforce'],
  [/ffuf|wfuzz/i, 'fuzzer'], [/burp/i, 'burp'], [/zgrab|censys|shodan|masscan/i, 'internet-scanner'],
  [/python-requests|python-urllib|aiohttp|httpx/i, 'python script'], [/curl\//i, 'curl'], [/wget/i, 'wget'],
  [/go-http-client/i, 'go script'], [/axios|node-fetch|undici/i, 'node script'], [/java\//i, 'java client']
];
const detectTool = ua => { for (const [re, n] of TOOLS) if (re.test(ua || '')) return n; return ''; };

function classify(path) {
  const p = String(path || '').toLowerCase();
  if (/\.env/.test(p)) return 'ENV-FILE';
  if (/\.git|\.svn|\.ds_store/.test(p)) return 'SOURCE-LEAK';
  if (/vaelmore_mini|\.zip|\.sql|\.bak|\.old|\.tar|\.gz|\.rar|\.7z|backup|dump/.test(p)) return 'BACKUP-SCRAPE';
  if (/serviceaccount|adminsdk|firebase|firestore\.rules|vercel\.json|config/.test(p)) return 'CONFIG-SCRAPE';
  if (/wp-|xmlrpc|\.php|phpmyadmin|pma/.test(p)) return 'CMS-SCAN';
  if (/admin|dashboard|login|panel|console|manager/.test(p)) return 'ADMIN-PROBE';
  if (/api\//.test(p)) return 'API-PROBE';
  return 'PROBE';
}

// ---- dedupe بسيط (على مستوى instance واحد، best-effort) ----
const recent = new Map();
function seen(key, ttlMs) {
  const now = Date.now();
  for (const [k, t] of recent) if (now - t > ttlMs) recent.delete(k);
  if (recent.has(key)) return true;
  recent.set(key, now);
  if (recent.size > 1000) recent.delete(recent.keys().next().value);
  return false;
}
let burst = [];
function floodLimited(max = 40, windowMs = 10 * 60 * 1000) {
  const now = Date.now();
  burst = burst.filter(t => now - t < windowMs);
  if (burst.length >= max) return true;
  burst.push(now);
  return false;
}

function snapshot(req, extra = {}) {
  const h = req.headers || {};
  const url = clean(req.url, 300);
  return {
    time: new Date().toISOString(),
    ip: getIp(req),
    geo: getGeo(req),
    method: clean(req.method, 10),
    url,
    ua: clean(h['user-agent'], 220),
    lang: clean(h['accept-language'], 60),
    referer: clean(h['referer'], 200),
    host: clean(h['host'], 100),
    ja4: clean(h['x-vercel-ja4-digest'] || h['x-vercel-ja3-digest'], 80),
    ...extra
  };
}

async function sendTelegram(lines) {
  const token = process.env.TELEGRAM_BOT_TOKEN, chat = process.env.TELEGRAM_CHAT_ID;
  if (!token || !chat) { console.warn('[honeypot] TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID مش متضبطين — التنبيه في اللوج بس'); return false; }
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 2500);
  try {
    const r = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, signal: ctrl.signal,
      body: JSON.stringify({ chat_id: chat, text: lines.join('\n').slice(0, 3900), parse_mode: 'HTML', disable_web_page_preview: true })
    });
    return r.ok;
  } catch (_) { return false; } finally { clearTimeout(timer); }
}

function formatAlert(title, d) {
  const g = d.geo || {};
  const where = [g.country, g.region, g.city].filter(Boolean).join(' / ') || '—';
  const L = [
    `🚨 <b>${esc(title)}</b>`,
    `🎯 النوع: <b>${esc(d.kind)}</b>${d.tool ? ' — 🛠 ' + esc(d.tool) : ''}`,
    `📍 الطلب: <code>${esc(d.method)} ${esc(d.path || d.url)}</code>`,
    `🌐 IP: <code>${esc(d.ip)}</code>`,
    `🗺 الموقع (تقريبي): ${esc(where)}${g.lat ? ` (${esc(g.lat)}, ${esc(g.lon)})` : ''}`,
    g.tz ? `🕒 التوقيت: ${esc(g.tz)}` : '',
    `🖥 UA: <code>${esc(d.ua || '—')}</code>`,
    d.lang ? `🗣 اللغة: ${esc(d.lang)}` : '',
    d.referer ? `↩️ Referer: ${esc(d.referer)}` : '',
    d.ja4 ? `🔑 TLS: <code>${esc(d.ja4)}</code>` : '',
    d.extra ? `📝 ${esc(d.extra)}` : '',
    `⏱ ${esc(d.time)}`,
    `🔎 https://ipinfo.io/${encodeURIComponent(d.ip)}`,
    `🛡 https://www.abuseipdb.com/check/${encodeURIComponent(d.ip)}`
  ];
  return L.filter(Boolean);
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

module.exports = { clean, esc, getIp, getGeo, detectTool, classify, seen, floodLimited, snapshot, sendTelegram, formatAlert, sleep };
