import {initializeApp} from "https://www.gstatic.com/firebasejs/10.14.1/firebase-app.js";
import {getAuth,onAuthStateChanged,signInWithPopup,signInWithRedirect,getRedirectResult,GoogleAuthProvider,signInWithEmailAndPassword,createUserWithEmailAndPassword,updateProfile,sendEmailVerification,sendPasswordResetEmail,signOut} from "https://www.gstatic.com/firebasejs/10.14.1/firebase-auth.js";
import {getFirestore,doc,getDoc,setDoc,updateDoc,addDoc,deleteDoc,collection,query,where,getDocs,serverTimestamp,increment} from "https://www.gstatic.com/firebasejs/10.14.1/firebase-firestore.js";

/* ============ ✏️ الإعدادات — غيّر دول بس ============ */
const FIREBASE_CONFIG = {           // من Firebase Console ← Project settings ← Your apps ← Web app
  apiKey: "AIzaSyCd2lQ6rQFPJRRGReq9pFu0IqqTClNEu3k",
  authDomain: /^(localhost|127\.)/.test(location.hostname) ? "love-ece13.firebaseapp.com" : location.host,   // الدخول بيتم على دومين موقعك نفسه (مش firebaseapp.com) — بيتعمله بروكسي في vercel.json
  projectId: "love-ece13",
  storageBucket: "love-ece13.firebasestorage.app",
  messagingSenderId: "629134080131",
  appId: "1:629134080131:web:ed7984536666d36e0ac3b6"
};
const ADMIN_EMAILS = ["moreand458@gmail.com"];   // إيميلك (نفس اللي في firestore.rules)
const TEMPLATE_API = "/api/template";                   // القالب بيتحمّل من السيرفر بعد التحقق من تسجيل الدخول (مش ملف عام)
const HOSTING_URL = "https://www.hidencloud.com/";      // زر ادخل الاستضافة
/* ==================================================== */

const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[m]));
const ico = n => `<svg class="i"><use href="#i-${n}"/></svg>`;
const USER_SVG = '<svg class="i"><use href="#i-user"/></svg>';
const configured = !FIREBASE_CONFIG.apiKey.startsWith("PASTE");
let auth, db, me = null, profile = null, myBots = [], isAdmin = false, step = 1, editingId = null, authMode = 'login', pendingName = '', busy = false;

function toast(t){ $('toast').textContent = t; $('toast').classList.add('show'); clearTimeout(toast.t); toast.t = setTimeout(() => $('toast').classList.remove('show'), 2600); }
const safeImg = u => (typeof u === 'string' && u.length < 70000 && /^(data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+\/=]+|https:\/\/[^\s'"()\\]+)$/.test(u)) ? u : '';
const cssUrl = u => String(u).replace(/[\s'"()\\]/g, c => '%' + c.charCodeAt(0).toString(16).padStart(2, '0'));
const hostBtn = cls => `<a class="${cls}" href="${HOSTING_URL}" target="_blank" rel="noopener noreferrer">${ico('server')}ادخل الاستضافة</a>`;
function setAvatar(el, url){ url = safeImg(url); el.style.backgroundImage = url ? `url("${cssUrl(url)}")` : ''; el.innerHTML = url ? '' : USER_SVG; }
const fmtDate = t => { const d = t?.toDate ? t.toDate() : null; return d ? d.toLocaleDateString('ar-EG', {day:'numeric', month:'short', year:'numeric'}) : '—'; };
const fmtTime = t => { const d = t?.toDate ? t.toDate() : null; return d ? d.toLocaleString('ar-EG', {day:'numeric', month:'short', hour:'2-digit', minute:'2-digit'}) : '—'; };
const authErr = e => ({
  'auth/invalid-credential':'البريد أو كلمة المرور غلط', 'auth/wrong-password':'كلمة المرور غلط', 'auth/user-not-found':'مفيش حساب بالبريد ده',
  'auth/email-already-in-use':'البريد ده مسجل قبل كده', 'auth/weak-password':'كلمة المرور ضعيفة (6 حروف على الأقل)', 'auth/invalid-email':'البريد غير صحيح',
  'auth/popup-closed-by-user':'اتقفل نافذة جوجل', 'auth/too-many-requests':'محاولات كتير، جرب بعد شوية', 'auth/network-request-failed':'مشكلة في الإنترنت',
  'auth/unauthorized-domain':'الدومين ده مش مضاف في Firebase ← Authentication ← Settings ← Authorized domains',
  'auth/operation-not-allowed':'طريقة الدخول دي مش مفعّلة في Firebase ← Authentication ← Sign-in method'
}[e?.code] || (e?.message || 'حصلت مشكلة'));

/* ---------- واجهة ---------- */
function show(view){ $('authView').classList.toggle('hide', view !== 'auth'); $('appView').classList.toggle('hide', view !== 'app'); }
function closeMenu(){ $('drawer').classList.remove('open'); $('overlay').classList.remove('open'); $('drawer').setAttribute('aria-hidden','true'); }
function openMenu(){ $('drawer').classList.add('open'); $('overlay').classList.add('open'); $('drawer').setAttribute('aria-hidden','false'); }
function go(id){
  if (id === 'admin' && !isAdmin) return;
  document.querySelectorAll('.page').forEach(p => p.classList.toggle('active', p.id === id));
  document.querySelectorAll('[data-nav]').forEach(b => b.classList.toggle('on', b.dataset.nav === id));
  closeMenu(); window.scrollTo(0,0);
  if (id === 'admin') loadAdmin();
  if (id === 'profile' || id === 'home') renderBots();
}
function renderMe(){
  const name = profile?.name || me.displayName || me.email.split('@')[0];
  setAvatar($('topAvatar'), profile?.photo); setAvatar($('dAvatar'), profile?.photo); setAvatar($('profAvatar'), profile?.photo);
  $('dName').textContent = name; $('dEmail').textContent = me.email; $('profEmail').textContent = me.email;
  if (document.activeElement !== $('profName')) $('profName').value = name;
  $('navAdmin').classList.toggle('hide', !isAdmin);
  $('sSince').textContent = fmtDate(profile?.createdAt);
}

/* ---------- تسجيل الدخول ---------- */
async function ensureUserDoc(u){
  const ref = doc(db, 'users', u.uid), snap = await getDoc(ref);
  const provider = u.providerData[0]?.providerId === 'google.com' ? 'google' : 'email';
  if (!snap.exists()){
    const data = { name: pendingName || u.displayName || u.email.split('@')[0], email: u.email, photo: safeImg(u.photoURL), provider, createdAt: serverTimestamp(), lastLogin: serverTimestamp(), loginCount: 1 };
    await setDoc(ref, data); profile = { ...data, createdAt: { toDate: () => new Date() } };
  } else {
    await updateDoc(ref, { lastLogin: serverTimestamp(), loginCount: increment(1) });
    profile = snap.data();
  }
}
async function loadMine(){
  const s = await getDocs(query(collection(db, 'bots'), where('uid', '==', me.uid)));
  myBots = s.docs.map(d => ({ id: d.id, ...d.data() })).sort((a,b) => (b.createdAt?.seconds||0) - (a.createdAt?.seconds||0));
}
async function emailAuth(){
  if (busy) return; const email = $('aEmail').value.trim(), pass = $('aPass').value;
  if (!email || !pass) return toast('اكتب البريد وكلمة المرور');
  busy = true; $('authSubmit').disabled = true;
  try {
    if (authMode === 'signup'){
      const name = $('aName').value.trim(); if (!name){ toast('اكتب اسمك'); return; }
      pendingName = name;
      const c = await createUserWithEmailAndPassword(auth, email, pass);
      await updateProfile(c.user, { displayName: name });
      sendEmailVerification(c.user).catch(() => {});
      toast('تم إنشاء الحساب — وصلك إيميل تفعيل');
    } else await signInWithEmailAndPassword(auth, email, pass);
  } catch (e) { toast(authErr(e)); }
  finally { busy = false; $('authSubmit').disabled = false; }
}
async function google(){
  const p = new GoogleAuthProvider(); p.setCustomParameters({ prompt: 'select_account' });
  try { await signInWithPopup(auth, p); }
  catch (e) {
    if (e.code === 'auth/popup-blocked' || e.code === 'auth/operation-not-supported-in-this-environment'){ try { await signInWithRedirect(auth, p); } catch (x) { toast(authErr(x)); } }
    else if (e.code !== 'auth/cancelled-popup-request') toast(authErr(e));
  }
}
async function reset(){
  const email = $('aEmail').value.trim(); if (!email) return toast('اكتب بريدك الأول');
  try { await sendPasswordResetEmail(auth, email); toast('بعتنالك رابط تغيير كلمة المرور'); } catch (e) { toast(authErr(e)); }
}
function authTab(t){
  authMode = t; $('tabLogin').classList.toggle('on', t === 'login'); $('tabSignup').classList.toggle('on', t === 'signup');
  $('nameField').classList.toggle('hide', t !== 'signup'); $('authSubmit').textContent = t === 'signup' ? 'إنشاء حساب' : 'دخول';
  $('aPass').autocomplete = t === 'signup' ? 'new-password' : 'current-password';
}

/* ---------- البروفايل ---------- */
async function saveProfile(){
  const name = $('profName').value.trim(); if (!name) return toast('اكتب اسمك');
  try { await updateDoc(doc(db, 'users', me.uid), { name }); profile.name = name; renderMe(); toast('تم حفظ البروفايل'); } catch (e) { toast('مقدرتش أحفظ: ' + e.message); }
}
function resizePhoto(file){
  return new Promise((res, rej) => {
    const img = new Image(), url = URL.createObjectURL(file);
    img.onload = () => {
      const S = 192, c = document.createElement('canvas'); c.width = c.height = S;
      const m = Math.min(img.width, img.height), sx = (img.width - m) / 2, sy = (img.height - m) / 2;
      c.getContext('2d').drawImage(img, sx, sy, m, m, 0, 0, S, S); URL.revokeObjectURL(url); res(c.toDataURL('image/jpeg', .82));
    };
    img.onerror = () => rej(new Error('الصورة مش مقروءة')); img.src = url;
  });
}
async function setPhoto(photo){
  try { await updateDoc(doc(db, 'users', me.uid), { photo }); profile.photo = photo; renderMe(); toast(photo ? 'تم تغيير الصورة' : 'تم حذف الصورة'); } catch (e) { toast('مقدرتش أحفظ الصورة: ' + e.message); }
}

/* ---------- صنع البوت ---------- */
const F = ['botName','botNumber','devAr','devEn','devNumbers','channelName','channelId','channelLink','stickerPack','stickerAuthor'];
const digits = s => String(s || '').replace(/\D/g, '');
const splitNames = s => String(s || '').split(/[•,،|\n]+/).map(x => x.trim()).filter(Boolean);
function normChannel(s){ s = String(s || '').trim(); if (/^\d{10,}$/.test(s)) return s + '@newsletter'; return /^\d+@newsletter$/.test(s) ? s : ''; }
function startCreate(){ F.forEach(x => $(x).value = ''); step = 1; updateStep(); $('downloadArea').innerHTML = ''; $('buildBar').style.width = '0'; $('buildStatus').textContent = 'اضغط إنشاء وتحميل للبدء'; go('create'); }
function updateStep(){
  document.querySelectorAll('.step').forEach(s => s.classList.toggle('active', +s.dataset.step === step));
  $('stepLabel').textContent = step + ' / 5'; $('progressText').textContent = (step*20) + '%'; $('progressBar').style.width = (step*20) + '%';
  $('backBtn').style.visibility = step === 1 ? 'hidden' : 'visible';
  $('nextBtn').innerHTML = step === 5 ? ico('download') + 'إنشاء وتحميل' : 'التالي' + ico('next');
  if (step === 4) renderReview();
}
function valid(){
  if (step === 1){
    if (!$('botName').value.trim()) { toast('اكتب اسم البوت'); return false; }
    const n = digits($('botNumber').value); if (n.length < 8 || n.length > 15) { toast('رقم البوت غير صحيح'); return false; }
  }
  if (step === 2){
    const nums = $('devNumbers').value.split(/[,،\s]+/).filter(Boolean).map(digits);
    if (!nums.length || nums.some(n => n.length < 8 || n.length > 15)) { toast('اكتب رقم مطور واحد على الأقل بشكل صحيح'); return false; }
  }
  if (step === 3){
    const cl = $('channelLink').value.trim();
    if (cl && !normChannelLink(cl)) { toast('رابط القناة غير صحيح'); return false; }
  }
  return true;
}
function renderReview(){
  const ch = $('channelId').value.trim(), okCh = normChannel(ch);
  const d = { 'اسم البوت': $('botName').value, 'رقم البوت': digits($('botNumber').value), 'المطورون': $('devAr').value || $('devEn').value, 'أرقام المطورين': $('devNumbers').value, 'القناة': $('channelName').value, 'ID القناة': ch ? (okCh || 'غير صالح — هيتجاهل') : 'الافتراضي' };
  Object.assign(d, { 'رابط القناة': $('channelLink').value.trim() ? (normChannelLink($('channelLink').value) || 'غير صالح — هيتجاهل') : 'هيبقى واتساب المطور', 'حزمة الاستيكر': $('stickerPack').value || $('botName').value, 'مؤلف الاستيكر': $('stickerAuthor').value || '—' });
  $('review').innerHTML = Object.entries(d).map(([k,v]) => `<div><span>${esc(k)}</span><b>${esc(v || '—')}</b></div>`).join('');
}
function readForm(){ return { name: $('botName').value.trim(), number: digits($('botNumber').value), devAr: $('devAr').value.trim(), devEn: $('devEn').value.trim(), devNumbers: $('devNumbers').value.trim(), channelName: $('channelName').value.trim(), channelId: normChannel($('channelId').value), channelLink: normChannelLink($('channelLink').value), stickerPack: $('stickerPack').value.trim(), stickerAuthor: $('stickerAuthor').value.trim() }; }
function botConfig(b){
  const ar = splitNames(b.devAr), en = splitNames(b.devEn);
  const owners = String(b.devNumbers || '').split(/[,،\s]+/).filter(Boolean).map(digits).filter(n => n.length >= 8).map((n, i) => ({ name: ar[i] || en[i] || 'Owner', jid: n + '@s.whatsapp.net' }));
  return { botName: b.name, botNumber: b.number, owners, channelName: b.channelName || '', channelId: b.channelId || '', channelLink: b.channelLink || '', stickerPack: b.stickerPack || '', stickerAuthor: b.stickerAuthor || '' };
}

/* ---------- تبديل حقوق البوت جوه ملفات القالب ----------
   القيم الأصلية (ORIG) هي اللي مكتوبة ثابت في القالب، والموقع بيبدّلها بقيم صاحب النسخة.
   أسطر الكومنتات (هيدر المطورين الأصليين للبلجنز) مش بتتلمس. */
const ORIG = {
  "chId": "120363422581600030@newsletter",
  "chUrl": "https://whatsapp.com/channel/0029VbBbvWcJ3jv1T55BmR0f",
  "chName": "\u269c\ufe0f \ud835\udc15\ud835\udc00\ud835\udc04\ud835\udc0b\ud835\udc0c\ud835\udc0e\ud835\udc11\ud835\udc04 | \ud835\udc0e\ud835\udc1f\ud835\udc1f\ud835\udc22\ud835\udc1c\ud835\udc22\ud835\udc1a\ud835\udc25 \ud835\udc12\ud835\udc32\ud835\udc2c\ud835\udc2d\ud835\udc1e\ud835\udc26",
  "botName": "\u2661 \ud835\udc7d\ud835\udc68\ud835\udc6c\ud835\udc73\ud835\udc74\ud835\udc76\ud835\udc79\ud835\udc6c \ud835\udc69\ud835\udc76\ud835\udc7b\ud83d\udc68\ud83c\udffb\u200d\ud83d\udcbb \u3008",
  "venom": "\u25e5\u25e3 \ud835\udc15\ud835\udc6c\ud835\udc75\ud835\udd46\ud835\udc40 \u25e2\u25e4",
  "escanor": "\ud835\udc0b\ud835\udc28\ud835\udc2b\ud835\udc1d \ud835\udc04\ud835\udc12\ud835\udc02\ud835\udc00\ud835\udc0d\ud835\udee9\ud835\udc11",
  "drakon": "\ud835\udc0b\ud835\udc28\ud835\udc2b\ud835\udc1d \ud835\udc03\ud835\udc11\ud835\udc00\ud835\udc0a\ud835\udc0e\ud835\udc0d",
  "sayko": "\ud835\udc46\ud835\udc34\ud835\udc4c\ud835\udc3e\ud835\udc42 ~ \ud835\udc46\ud835\udc3e",
  "repo": "https://github.com/moreand458-eng/Oracle-bot",
  "group": "https://chat.whatsapp.com/BR3vHZUaLjy1qwhS3ttQpJ?s=cl&p=a&ilr=1"
};
const EMPTY_DB = { groups: {}, users: {}, extraOwners: [] };
const EMPTY_SETTINGS = { __replies: {}, __reminders: [], __castle: {}, __clash: {}, __system: { disabledCommands: [], disabledCategories: [] }, __reactionSubs: {} };
const DUMMY_CH = '120363000000000000@newsletter';
const jsSafe = s => String(s).replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/"/g, '\\"').replace(/`/g, '\\`').replace(/\$\{/g, '\\${').replace(/[\r\n]+/g, ' ');
const jsonSafe = s => JSON.stringify(String(s)).slice(1, -1);
const isCommentLine = l => /^\s*(\/\/|\/\*|\*(\s|\/|$))/.test(l);
function normChannelLink(s){
  s = String(s || '').trim(); const m = s.match(/whatsapp\.com\/channel\/([A-Za-z0-9]+)/);
  if (m) return 'https://whatsapp.com/channel/' + m[1];
  return /^[A-Za-z0-9]{20,}$/.test(s) ? 'https://whatsapp.com/channel/' + s : '';
}
function brandInfo(b){
  const nums = String(b.devNumbers || '').split(/[,\u060c\s]+/).filter(Boolean).map(digits).filter(n => n.length >= 8);
  const ar = splitNames(b.devAr), en = splitNames(b.devEn);
  const devs = nums.map((n, i) => ({ num: n, ar: ar[i] || en[i] || 'Owner', en: en[i] || ar[i] || 'Owner' }));
  if (!devs.length) devs.push({ num: digits(b.number), ar: 'Owner', en: 'Owner' });
  const d = i => devs[i] || devs[0];
  const code8 = ((String(b.name).normalize('NFKC').replace(/[^A-Za-z0-9]/g, '').toUpperCase()) + digits(b.number)).slice(0, 8);
  return {
    name: b.name, number: digits(b.number), devs, d, code8,
    chName: b.channelName || b.name, chId: b.channelId || DUMMY_CH,
    chUrl: normChannelLink(b.channelLink) || ('https://wa.me/' + devs[0].num),
    pack: b.stickerPack || b.name, author: b.stickerAuthor || devs[0].en
  };
}
function rebrandJs(path, text, I){
  const S = jsSafe, d = I.d, base = path.split('/').pop();
  const OWN = `const OWNERS_DATA = [\n${I.devs.map(v => `    { name: '${S(v.ar)}', jid: '${v.num}@s.whatsapp.net', lid: '', displayName: '${S(v.en)}' },`).join('\n')}\n];`;
  const SUP_URL = `const SUPPORT_TEAM = [\n${I.devs.slice(0, 2).map(v => `    { name: '${S(v.ar)}', url: 'https://wa.me/${v.num}' }`).join(',\n')}\n];`;
  const SUP_JID = `const SUPPORT_TEAM = [\n${I.devs.slice(0, 2).map(v => `    { name: '${S(v.ar)}', jid: '${v.num}@s.whatsapp.net' }`).join(',\n')}\n];`;
  const keys = [...new Set(I.devs.flatMap(v => [v.ar.toLowerCase(), v.en.toLowerCase()]))];
  const DEVS = `const DEVS = {\n${I.devs.flatMap(v => [v.ar.toLowerCase(), v.en.toLowerCase()].filter((k, i, a) => a.indexOf(k) === i).map(k => `    '${S(k)}': { name: '${S(v.ar)}', jid: '${v.num}' },`)).join('\n')}\n};`;
  // 1) بلوكات كاملة
  if (base === 'control.js'){ text = text.replace(/const OWNERS_DATA = \[[\s\S]*?\n\];/, () => OWN).replace(/const SUPPORT_TEAM = \[[\s\S]*?\n\];/, () => SUP_URL); }
  if (base === 'support.js') text = text.replace(/const SUPPORT_TEAM = \[[\s\S]*?\n\];/, () => SUP_JID);
  if (base === 'owner.js') text = text.replace(/const DEVS = \{[\s\S]*?\n\};/, () => DEVS);
  if (base === 'auto-join-channel.js') text = text.replace(/const defaultLinks = \[[\s\S]*?\n\];/, () => `const defaultLinks = [${I.chUrl.includes('/channel/') ? `\n    { url: '${I.chUrl}', type: 'channel' }\n` : ''}];`);
  if (base === 'script.js') text = text.replace(/GitHub: _\*[^\n]*\*_\s*\n\s*\nVideo: _\*[^\n]*\*_/, () => `Channel: _*${I.chUrl}*_`);
  if (base === 'sub.js') text = text.replace(/SubBots\.pariCode\("VAELMORE"\)/, () => `SubBots.pariCode("${I.code8}")`);
  if (base === 'index.js') text = text.replace(/copyright:\s*\{[^}]*\}/, () => `copyright: { pack: '${S(I.pack)}', author: '${S(I.author)}' }`);
  if (base === 'utils.js') text = text.replace(/options\.pack \|\| '[^']*'/, () => `options.pack || '${S(I.pack)}'`).replace(/options\.author \|\| '[^']*'/, () => `options.author || '${S(I.author)}'`);
  if (base === 'gifsticker.js' || base === 'qc.js') text = text.replace(/pack:\s*'[^'\n]*'/, () => `pack: '${S(I.pack)}'`).replace(/author:\s*'VAELMORE'/, () => `author: '${S(I.author)}'`);
  if (base === 'wm.js') text = text.replace(/\|\| 'VAELMORE'/, () => `|| '${S(I.author)}'`).replace(/\[pack = '[^'\n]*'/, () => `[pack = '${S(I.pack)}'`);
  // 2) استبدال سطر بسطر (من غير الكومنتات)
  const O = ORIG, rules = [
    [O.botName, I.name], [O.chName, I.chName], [O.chId, I.chId], [O.chUrl, I.chUrl], [O.repo, I.chUrl], [O.group, I.chUrl],
    [O.venom, I.d(0).ar], [O.drakon, I.d(1).ar], [O.escanor, I.d(1).ar], [O.sayko, I.d(1).ar], ['\u0627\u0644\u0634\u064a\u0637\u0627\u0646\u0647', I.d(2).ar],
    ['\u0625\u0633\u0643\u0627\u0646\u0648\u0631', I.d(1).ar], ['\u0641\u064a\u0646\u0648\u0645', I.d(0).ar],
    ['201065948582', I.d(0).num], ['79312265574', I.d(1).num], ['201092178171', I.d(1).num], ['201273317758', I.d(2).num], ['201090406441', I.d(1).num],
    ['9647882892089', I.number], ['110462431670456@lid', ''], ['275561477836913@lid', ''], ['184726359014827@lid', '']
  ];
  return text.split('\n').map(l => {
    if (isCommentLine(l)) return l;
    for (const [from, to] of rules) if (from && l.includes(from)) l = l.split(from).join(S(to));
    l = l.replace(/displayName:\s*'(Venom|Lord Drakon)'/g, (m, k) => `displayName: '${S(k === 'Venom' ? I.d(0).en : I.d(1).en)}'`);
    return brandWords(l, I.name, S);
  }).join('\n');
}
function brandWords(l, name, S){
  l = l.replace(/[\u{1D400}-\u{1D7FF}]{8}(?![\u{1D400}-\u{1D7FF}])(?:\s+[\u{1D400}-\u{1D7FF}]{3}(?![\u{1D400}-\u{1D7FF}]))?/gu, m => { const n = m.normalize('NFKC').toUpperCase(); return (n === 'VAELMORE' || n === 'VAELMORE BOT') ? S(name) : m; });
  return l.replace(/(?<![A-Za-z0-9_\-\/.])VAELMORE(?: BOT)?(?![A-Za-z0-9_\-])/g, () => S(name));
}
function rebrandText(path, text, b){
  if (/(^|\/)(node_modules|sessions?|auth_info)\//.test(path)) return text;
  const I = brandInfo(b), base = path.split('/').pop();
  if (/\.js$/.test(path)) return rebrandJs(path, text, I);
  if (base === 'database.json') return JSON.stringify(EMPTY_DB, null, 2);
  if (base === 'settings.json' && /system\//.test(path)) return JSON.stringify(EMPTY_SETTINGS, null, 2);
  if (base === 'group_schedule.json') return '{}';
  if (base === 'links.json') return JSON.stringify({ channel: { label: 'WhatsApp Channel', url: I.chUrl, type: 'whatsapp' } }, null, 2);
  if (base === 'package.json') return text.replace(/"description":\s*"[^"]*"/, () => `"description": "${jsonSafe(I.name)}"`);
  if (/README\.md$/.test(path)) return brandWords(text.replace(/\n/g, '\n'), I.name, s => s);
  return text;
}
async function brandZip(zip, b){
  const names = Object.keys(zip.files).filter(n => !zip.files[n].dir && /\.(js|json|md)$/.test(n));
  for (const n of names){
    const t = await zip.file(n).async('string'), r = rebrandText(n, t, b);
    if (r !== t) zip.file(n, r);
  }
}

async function makeZip(b){
  if (typeof JSZip === 'undefined') throw new Error('مكتبة الـ ZIP مش اتحملت — اتأكد من الإنترنت');
  let buf;
  try {
    const token = await me.getIdToken();
    const r = await fetch(TEMPLATE_API, { headers: { Authorization: 'Bearer ' + token }, cache: 'no-store' });
    if (r.status === 429) throw new Error('طلبات كتير، استنى شوية وجرّب تاني');
    if (r.status === 401 || r.status === 403) throw new Error('لازم تسجّل دخول (وتفعّل بريدك لو الموقع طالب كده) عشان تحمّل');
    if (!r.ok) throw new Error('مقدرتش أجيب القالب من السيرفر');
    buf = await r.arrayBuffer();
  } catch (e) { throw e instanceof Error && e.message !== 'Failed to fetch' ? e : new Error('مشكلة في الاتصال بالسيرفر'); }
  const zip = await JSZip.loadAsync(buf), old = Object.keys(zip.files).find(n => n.endsWith('bot.config.json'));
  await brandZip(zip, b);   // يبدّل كل الحقوق الثابتة جوه ملفات القالب
  zip.file(old || 'vaelmore-bot/bot.config.json', JSON.stringify(botConfig(b), null, 2));
  const blob = await zip.generateAsync({ type: 'blob', compression: 'DEFLATE' });
  const a = document.createElement('a'), u = URL.createObjectURL(blob);
  a.href = u; a.download = (b.name.replace(/[^a-z0-9_-]+/gi, '_') || 'bot') + '.zip'; document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(u), 4000);
}
async function buildBot(){
  if (busy) return; busy = true; $('nextBtn').disabled = $('backBtn').disabled = true;
  const data = readForm();
  try {
    $('buildStatus').textContent = 'جاري حفظ النسخة...'; $('buildBar').style.width = '30%';
    const ref = await addDoc(collection(db, 'bots'), { ...data, uid: me.uid, ownerEmail: me.email, ownerName: profile?.name || '', downloads: 1, createdAt: serverTimestamp() });
    $('buildStatus').textContent = 'جاري تجهيز الملف...'; $('buildBar').style.width = '65%';
    await makeZip(data);
    $('buildBar').style.width = '100%'; $('buildStatus').textContent = 'تم! النسخة نزلت على جهازك';
    $('downloadArea').innerHTML = `<div class="actions" style="justify-content:center;margin-top:0"><button class="ghost" data-act="dl" data-id="${esc(ref.id)}">${ico('download')}تحميل تاني</button>${hostBtn('primary')}</div>`;
    await loadMine(); renderBots(); toast('تم إنشاء النسخة');
  } catch (e) { $('buildStatus').textContent = 'حصلت مشكلة'; toast(e.message); }
  finally { busy = false; $('nextBtn').disabled = $('backBtn').disabled = false; }
}
async function download(id){
  const b = myBots.find(x => x.id === id); if (!b) return;
  try { await makeZip(b); updateDoc(doc(db, 'bots', id), { downloads: increment(1) }).then(loadMine).then(renderBots).catch(() => {}); toast('تم التحميل'); } catch (e) { toast(e.message); }
}

/* ---------- نسخي ---------- */
function botCard(b){
  return `<div class="card bot-card"><h4>${esc(b.name)}</h4><p>رقم: <span dir="ltr">${esc(b.number)}</span></p><p>المطورون: ${esc(b.devAr || b.devEn || '—')}</p><p>القناة: ${esc(b.channelName || '—')}</p><p>${esc(fmtDate(b.createdAt))}</p>
  <div class="actions"><button class="primary sm" data-act="dl" data-id="${esc(b.id)}">${ico('download')}تحميل</button>${hostBtn('ghost sm')}<button class="ghost sm" data-act="edit" data-id="${esc(b.id)}">${ico('edit')}تعديل</button><button class="danger sm" data-act="del" data-id="${esc(b.id)}">${ico('trash')}حذف</button></div></div>`;
}
function renderBots(){
  const empty = '<div class="empty">لا توجد نسخ حتى الآن.</div>';
  $('homeCount').textContent = myBots.length + ' نسخة';
  $('homeBots').innerHTML = myBots.length ? myBots.slice(0, 4).map(botCard).join('') : empty;
  $('profileBots').innerHTML = myBots.length ? myBots.map(botCard).join('') : empty;
  $('sBots').textContent = myBots.length; $('sDl').textContent = myBots.reduce((s, b) => s + (b.downloads || 0), 0);
}
function editBot(id){
  const b = myBots.find(x => x.id === id); if (!b) return; editingId = id;
  $('editName').value = b.name; $('editNumber').value = b.number; $('editDevAr').value = b.devAr || ''; $('editDevEn').value = b.devEn || '';
  $('editDevNumbers').value = b.devNumbers || ''; $('editChannel').value = b.channelName || ''; $('editChannelId').value = b.channelId || ''; $('editChannelLink').value = b.channelLink || ''; $('editStickerPack').value = b.stickerPack || ''; $('editStickerAuthor').value = b.stickerAuthor || '';
  $('editModal').classList.add('open');
}
async function saveEdit(){
  const b = myBots.find(x => x.id === editingId); if (!b) return;
  const n = { name: $('editName').value.trim(), number: digits($('editNumber').value), devAr: $('editDevAr').value.trim(), devEn: $('editDevEn').value.trim(), devNumbers: $('editDevNumbers').value.trim(), channelName: $('editChannel').value.trim(), channelId: normChannel($('editChannelId').value), channelLink: normChannelLink($('editChannelLink').value), stickerPack: $('editStickerPack').value.trim(), stickerAuthor: $('editStickerAuthor').value.trim() };
  if (!n.name || n.number.length < 8) return toast('اسم ورقم البوت مطلوبين');
  try { await updateDoc(doc(db, 'bots', editingId), n); Object.assign(b, n); $('editModal').classList.remove('open'); renderBots(); toast('تم حفظ التعديل — حمّل النسخة تاني عشان تتطبق'); } catch (e) { toast(e.message); }
}
async function delBot(id){
  if (!confirm('حذف هذه النسخة؟')) return;
  try { await deleteDoc(doc(db, 'bots', id)); myBots = myBots.filter(x => x.id !== id); renderBots(); toast('تم الحذف'); if (isAdmin && $('admin').classList.contains('active')) loadAdmin(); } catch (e) { toast(e.message); }
}

/* ---------- لوحة الأدمن ---------- */
async function loadAdmin(){
  if (!isAdmin) return;
  try {
    const [us, bs] = await Promise.all([getDocs(collection(db, 'users')), getDocs(collection(db, 'bots'))]);
    const users = us.docs.map(d => ({ id: d.id, ...d.data() })), bots = bs.docs.map(d => ({ id: d.id, ...d.data() }));
    const now = Date.now(), DAY = 864e5, ms = t => t?.toDate ? t.toDate().getTime() : 0, startToday = new Date().setHours(0,0,0,0);
    const perUser = {}; bots.forEach(b => perUser[b.uid] = (perUser[b.uid] || 0) + 1);
    const S = [
      [users.length, 'إجمالي المستخدمين'], [bots.length, 'إجمالي النسخ'],
      [users.filter(u => ms(u.lastLogin) >= startToday).length, 'دخلوا النهارده'], [users.filter(u => now - ms(u.createdAt) < 7*DAY).length, 'مستخدمين جدد (7 أيام)'],
      [bots.filter(b => now - ms(b.createdAt) < 7*DAY).length, 'نسخ جديدة (7 أيام)'], [bots.reduce((s, b) => s + (b.downloads || 0), 0), 'إجمالي التحميلات'],
      [users.reduce((s, u) => s + (u.loginCount || 0), 0), 'إجمالي مرات الدخول'], [users.filter(u => u.provider === 'google').length + ' / ' + users.filter(u => u.provider !== 'google').length, 'جوجل / بريد']
    ];
    $('adminStats').innerHTML = S.map(([v, l]) => `<div class="stat"><b>${esc(v)}</b><span>${esc(l)}</span></div>`).join('');
    const days = [...Array(7)].map((_, i) => { const d = new Date(); d.setHours(0,0,0,0); d.setDate(d.getDate() - (6 - i)); return d; });
    const counts = days.map(d => bots.filter(b => { const t = ms(b.createdAt); return t >= d.getTime() && t < d.getTime() + DAY; }).length), mx = Math.max(1, ...counts);
    $('adminChart').innerHTML = days.map((d, i) => `<div><span>${counts[i]}</span><i style="height:${Math.round(counts[i] / mx * 80)}%"></i><span>${d.toLocaleDateString('ar-EG', {weekday:'short'})}</span></div>`).join('');
    users.sort((a, b) => ms(b.lastLogin) - ms(a.lastLogin)); $('uCount').textContent = users.length + ' مستخدم';
    $('adminUsers').innerHTML = users.map(u => `<tr><td><div class="who"><div class="avatar s" style="width:32px;height:32px;${safeImg(u.photo) ? `background-image:url('${esc(cssUrl(safeImg(u.photo)))}')` : ''}">${safeImg(u.photo) ? '' : USER_SVG}</div><div><b>${esc(u.name)}</b><div class="muted" dir="ltr" style="text-align:right;font-size:11px">${esc(u.email)}</div></div></div></td><td>${u.provider === 'google' ? 'جوجل' : 'بريد'}</td><td>${perUser[u.id] || 0}</td><td>${u.loginCount || 0}</td><td>${esc(fmtTime(u.lastLogin))}</td><td>${esc(fmtDate(u.createdAt))}</td></tr>`).join('') || '<tr><td colspan="6" class="muted">لا يوجد</td></tr>';
    bots.sort((a, b) => ms(b.createdAt) - ms(a.createdAt)); $('bCount').textContent = bots.length + ' نسخة';
    $('adminBots').innerHTML = bots.map(b => `<tr><td><b>${esc(b.name)}</b></td><td dir="ltr">${esc(b.number)}</td><td>${esc(b.ownerName || '')} <span class="muted" dir="ltr">${esc(b.ownerEmail || '')}</span></td><td>${esc(fmtTime(b.createdAt))}</td><td><button class="danger sm" data-act="del" data-id="${esc(b.id)}" aria-label="حذف">${ico('trash')}</button></td></tr>`).join('') || '<tr><td colspan="5" class="muted">لا يوجد</td></tr>';
  } catch (e) { toast('مقدرتش أجيب البيانات — تأكد من قواعد Firestore: ' + e.message); }
}

/* ---------- ربط الأحداث ---------- */
const ACT = {
  openMenu, closeMenu, go: t => go(t.dataset.page), authTab: t => authTab(t.dataset.tab), google, emailAuth, reset,
  startCreate, nextStep: () => { if (step < 5){ if (!valid()) return; step++; updateStep(); } else buildBot(); },
  prevStep: () => { if (step > 1){ step--; updateStep(); } },
  logout: async () => { closeMenu(); await signOut(auth); }, pickPhoto: () => $('photoInput').click(), saveProfile, removePhoto: () => setPhoto(''),
  dl: t => download(t.dataset.id), edit: t => editBot(t.dataset.id), del: t => delBot(t.dataset.id), saveEdit, closeEdit: () => $('editModal').classList.remove('open'), loadAdmin
};
document.addEventListener('click', e => { const t = e.target.closest('[data-act]'); if (t && ACT[t.dataset.act]) ACT[t.dataset.act](t); });
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeMenu(); if (e.key === 'Enter' && !$('authView').classList.contains('hide') && e.target.tagName === 'INPUT') emailAuth(); });
$('photoInput').addEventListener('change', async e => { const f = e.target.files[0]; e.target.value = ''; if (!f) return; try { await setPhoto(await resizePhoto(f)); } catch (x) { toast(x.message); } });

/* ---------- تشغيل ---------- */
if (!configured){
  show('auth'); $('setupNote').classList.remove('hide');
  $('setupNote').innerHTML = 'لازم تحط بيانات Firebase بتاعتك في أول سكربت <b>index.html</b> (FIREBASE_CONFIG) وإيميل الأدمن في ADMIN_EMAILS. بعدها الدخول هيشتغل.';
} else {
  const app = initializeApp(FIREBASE_CONFIG); auth = getAuth(app); db = getFirestore(app); auth.languageCode = 'ar'; getRedirectResult(auth).catch(e => toast(authErr(e)));
  onAuthStateChanged(auth, async u => {
    if (!u){ me = profile = null; myBots = []; isAdmin = false; closeMenu(); show('auth'); return; }
    me = u;
    try { await ensureUserDoc(u); await loadMine(); }
    catch (e) { toast('مشكلة في قاعدة البيانات — اتأكد من قواعد Firestore: ' + e.message); profile = profile || { name: u.displayName || u.email.split('@')[0] }; }
    isAdmin = u.emailVerified && ADMIN_EMAILS.map(x => x.toLowerCase()).includes((u.email || '').toLowerCase());
    renderMe(); renderBots(); show('app'); go('home');
    if (!u.emailVerified && u.providerData[0]?.providerId === 'password') toast('فعّل بريدك من الإيميل اللي وصلك');
  });
}
