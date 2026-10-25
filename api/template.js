'use strict';
// القالب (VAELMORE_MINI.zip) مبقاش ملف عام — بيتسلّم بس لمستخدم مسجّل دخول (Firebase ID token).
// القالب نفسه موجود في api/_private/ ومش بيتقدّم كملف static.

const fs = require('fs');
const path = require('path');
const U = require('./_lib/util');

// مفتاح الـ Web API بتاع Firebase مش سر (بيظهر في الموقع)، فبنستخدمه للتحقق من التوكن.
const API_KEY = process.env.FIREBASE_API_KEY || 'AIzaSyCd2lQ6rQFPJRRGReq9pFu0IqqTClNEu3k';
const REQUIRE_VERIFIED = process.env.REQUIRE_VERIFIED === '1';   // 1 = لازم الإيميل يكون متفعّل
const PER_USER_PER_HOUR = Number(process.env.TEMPLATE_USER_LIMIT || 30);
const PER_IP_PER_HOUR = Number(process.env.TEMPLATE_IP_LIMIT || 60);

let cached;
const loadTemplate = () => cached || (cached = fs.readFileSync(path.join(__dirname, '_private', 'VAELMORE_MINI.zip')));

const hits = new Map();
function limited(key, max) {
  const now = Date.now(), arr = (hits.get(key) || []).filter(t => now - t < 3600e3);
  if (arr.length >= max) { hits.set(key, arr); return true; }
  arr.push(now); hits.set(key, arr);
  if (hits.size > 2000) hits.delete(hits.keys().next().value);
  return false;
}

async function verifyToken(idToken) {
  const ctrl = new AbortController(); const t = setTimeout(() => ctrl.abort(), 5000);
  try {
    const r = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${encodeURIComponent(API_KEY)}`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ idToken }), signal: ctrl.signal
    });
    if (!r.ok) return null;
    const j = await r.json();
    const u = j && j.users && j.users[0];
    return u && !u.disabled ? { uid: u.localId, email: u.email || '', verified: !!u.emailVerified } : null;
  } catch (_) { return null; } finally { clearTimeout(t); }
}

async function suspicious(req, why) {
  const ip = U.getIp(req);
  console.warn('[TEMPLATE-DENIED]', why, ip);
  if (U.seen(`tpl:${ip}:${why}`, 10 * 60 * 1000) || U.floodLimited()) return;
  await U.sendTelegram(U.formatAlert('ERROR 404 — محاولة سحب القالب', { ...U.snapshot(req), kind: 'TEMPLATE-' + why, tool: U.detectTool(req.headers['user-agent']) }));
}

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  const deny = (code, msg) => { res.statusCode = code; res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify({ error: msg })); };

  if (req.method !== 'GET') return deny(405, 'method not allowed');

  const ip = U.getIp(req);
  if (limited('ip:' + ip, PER_IP_PER_HOUR)) return deny(429, 'too many requests');

  const m = /^Bearer\s+([A-Za-z0-9._-]{100,4000})$/.exec(req.headers.authorization || '');
  if (!m) { await suspicious(req, 'NO-TOKEN'); return deny(401, 'login required'); }

  const user = await verifyToken(m[1]);
  if (!user) { await suspicious(req, 'BAD-TOKEN'); return deny(401, 'invalid session'); }
  if (REQUIRE_VERIFIED && !user.verified) return deny(403, 'email not verified');
  if (limited('uid:' + user.uid, PER_USER_PER_HOUR)) return deny(429, 'too many requests');

  let buf;
  try { buf = loadTemplate(); } catch (e) { console.error('template missing', e.message); return deny(500, 'template unavailable'); }
  res.statusCode = 200;
  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Length', buf.length);
  res.setHeader('Content-Disposition', 'attachment; filename="template.zip"');
  res.end(buf);
};
