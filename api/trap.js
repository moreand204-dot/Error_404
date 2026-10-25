'use strict';
// ====== الهاني بوت (Honeypot) ======
// vercel.json بيحوّل المسارات الوهمية (/admin و /.env و /.git/config و /wp-login.php ...) لهنا.
// المسارات دي مش موجودة فعلًا في الموقع، فأي حد بيطلبها بيبقى بيمسح/بيحاول يخترق.
// الدالة بتسجل بياناته وتبعتلك تنبيه على تليجرام، وبتديله بيانات مزيفة وبتبطّأ الرد (tarpit).

const crypto = require('crypto');
const U = require('./_lib/util');

const rnd = (n, enc = 'hex') => crypto.randomBytes(n).toString(enc);

const decoys = {
  env: () => [
    'NODE_ENV=production',
    'PORT=3000',
    'FIREBASE_PROJECT_ID=error404-internal',
    `FIREBASE_ADMIN_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\\n${rnd(96, 'base64')}\\n-----END PRIVATE KEY-----\\n"`,
    'FIREBASE_ADMIN_EMAIL=firebase-adminsdk@error404-internal.iam.gserviceaccount.com',
    `ADMIN_PASSWORD=${rnd(9, 'base64url')}`,
    `JWT_SECRET=${rnd(24)}`,
    `DB_URL=mongodb://admin:${rnd(8)}@10.0.0.12:27017/error404`,
    ''
  ].join('\n'),
  gitConfig: () => '[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n[remote "origin"]\n\turl = https://github.com/example-org/error404-private.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n[branch "main"]\n\tremote = origin\n\tmerge = refs/heads/main\n',
  gitHead: () => 'ref: refs/heads/main\n',
  adminSdk: () => JSON.stringify({
    type: 'service_account', project_id: 'error404-internal', private_key_id: rnd(20),
    private_key: `-----BEGIN PRIVATE KEY-----\n${rnd(120, 'base64')}\n-----END PRIVATE KEY-----\n`,
    client_email: 'firebase-adminsdk@error404-internal.iam.gserviceaccount.com', client_id: String(Math.floor(Math.random() * 1e20))
  }, null, 2),
  users: () => JSON.stringify({
    users: Array.from({ length: 5 }, (_, i) => ({ id: rnd(6), email: `user${i + 1}@example.com`, role: i === 0 ? 'admin' : 'user', passwordHash: '$2b$10$' + rnd(26, 'base64url') }))
  }, null, 2),
  login: (note = '') => `<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>Admin Login</title>
<style>body{margin:0;background:#0b0d12;color:#eee;font-family:system-ui,Tahoma;display:grid;place-items:center;min-height:100vh}form{background:#12151c;border:1px solid #2a2f39;border-radius:14px;padding:26px;width:min(340px,90vw)}input,button{width:100%;box-sizing:border-box;padding:12px;margin:6px 0;border-radius:9px;border:1px solid #333a47;background:#0b0d12;color:#fff;font:inherit}button{background:#e9ebee;color:#000;font-weight:700;cursor:pointer}p{color:#e6a9ad;font-size:13px;margin:4px 0}</style></head>
<body><form method="POST" action="/api/trap?act=login"><h3 style="margin-top:0">لوحة التحكم</h3>${note ? `<p>${note}</p>` : ''}<input name="username" placeholder="Username" autocomplete="off"><input name="password" type="password" placeholder="Password" autocomplete="off"><button>دخول</button></form>
<script>try{fetch('/api/trap?act=beacon',{method:'POST',headers:{'content-type':'application/json'},keepalive:true,body:JSON.stringify({tz:Intl.DateTimeFormat().resolvedOptions().timeZone,lang:navigator.languages&&navigator.languages.join(','),scr:screen.width+'x'+screen.height,plat:navigator.platform,cores:navigator.hardwareConcurrency,touch:navigator.maxTouchPoints,webdriver:navigator.webdriver===true})})}catch(e){}</script></body></html>`
};

function pick(path) {
  const p = path.toLowerCase();
  if (/\.env/.test(p)) return { type: 'text/plain', body: decoys.env() };
  if (/\.git\/config/.test(p)) return { type: 'text/plain', body: decoys.gitConfig() };
  if (/\.git\/head/.test(p)) return { type: 'text/plain', body: decoys.gitHead() };
  if (/serviceaccount|adminsdk|firebase-admin/.test(p)) return { type: 'application/json', body: decoys.adminSdk() };
  if (/api\/(users|bots|admin|internal|debug)|users\.json|config\.json/.test(p)) return { type: 'application/json', body: decoys.users() };
  if (/admin|login|dashboard|panel|phpmyadmin|pma|wp-|console|manager/.test(p)) return { type: 'text/html; charset=utf-8', body: decoys.login() };
  return null;
}

module.exports = async (req, res) => {
  const q = req.query || {};
  const act = String(q.act || '');
  // المسار الأصلي: بييجي من vercel.json في ?p= ، وبنسجل كمان req.url كله
  const path = U.clean(q.p || String(req.url || '').split('?')[0] || '/', 200);
  const ip = U.getIp(req);
  const base = U.snapshot(req, { path });
  const tool = U.detectTool(base.ua);

  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Robots-Tag', 'noindex, nofollow');
  res.setHeader('Server', 'nginx');

  let alertData = null;
  let response;

  if (act === 'beacon') {
    // بصمة بسيطة من المتصفح اللي فتح صفحة الأدمن الوهمية
    const b = (req.body && typeof req.body === 'object') ? req.body : {};
    const fp = ['tz', 'lang', 'scr', 'plat', 'cores', 'touch', 'webdriver'].map(k => `${k}=${U.clean(b[k], 80)}`).join(' | ');
    if (!U.seen(`beacon:${ip}`, 10 * 60 * 1000)) alertData = { ...base, kind: 'FINGERPRINT (فتح صفحة الأدمن الوهمية)', tool, extra: fp };
    response = { status: 204, type: 'text/plain', body: '' };
  } else if (act === 'login' && req.method === 'POST') {
    // محاولة دخول على اللوحة الوهمية — بنسجل اسم المستخدم وطول الباسورد بس (من غير حفظ الباسورد نفسه)
    const b = (req.body && typeof req.body === 'object') ? req.body : {};
    alertData = { ...base, kind: 'LOGIN-ATTEMPT (لوحة وهمية)', tool, extra: `user="${U.clean(b.username, 60)}" passLen=${String(b.password || '').length}` };
    response = { status: 200, type: 'text/html; charset=utf-8', body: decoys.login('بيانات الدخول غير صحيحة') };
  } else {
    const kind = U.classify(path);
    const d = pick(path);
    if (!U.seen(`${ip}:${kind}`, 5 * 60 * 1000)) alertData = { ...base, kind, tool };
    response = d ? { status: 200, type: d.type, body: d.body }
                 : { status: 404, type: 'text/html; charset=utf-8', body: '<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n' };
  }

  // دايمًا في اللوج (Vercel → Logs) حتى لو تليجرام مش متضبط
  console.log('[HONEYPOT]', JSON.stringify(alertData || { ...base, kind: 'repeat', tool }));

  const jobs = [U.sleep(act === 'beacon' ? 0 : 1200)]; // tarpit بسيط يبطّأ السكانرز
  if (alertData && !U.floodLimited()) jobs.push(U.sendTelegram(U.formatAlert('ERROR 404 HONEYPOT', alertData)));
  await Promise.all(jobs);

  res.statusCode = response.status;
  res.setHeader('Content-Type', response.type);
  res.end(response.body);
};
