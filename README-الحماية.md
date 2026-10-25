# ERROR 404 — نسخة محمية

## إيه اللي اتغيّر
- **زر "ادخل الاستضافة"** جنب زر التحميل (في كارت كل نسخة وبعد الإنشاء مباشرة) → https://www.hidencloud.com/
- **السبب الحقيقي للسحب:** كل الملفات كانت في الروت فكانت كلها متاحة للتحميل (`VAELMORE_MINI.zip` و `firestore.rules` و `firebase.json`...). دلوقتي الموقع بيتقدّم من مجلد `public/` بس، والباقي برّه.
- **القالب مبقاش ملف عام:** بيتحمّل من `/api/template` وبيتحقق من توكن Firebase + حد أقصى للتحميل (30/ساعة للمستخدم، 60/ساعة للـ IP).
- **هاني بوت (الفخ):** مسارات وهمية (`/admin` `/.env` `/.git/config` `/wp-login.php` `/phpmyadmin` `/VAELMORE_MINI.zip` القديم `/firebase-adminsdk.json` ... + أي `.php/.sql/.bak/.zip`) بتديله بيانات مزيفة وبتبطّأ الرد، وبتبعتلك على تليجرام: **IP، البلد/المدينة (تقريبي)، الـ User-Agent، الأداة (sqlmap/curl/...)، اللغة، المسار، بصمة المتصفح، واسم المستخدم لو جرّب يدخل** + لينكات فحص الـ IP.
- **Firestore rules:** كل حقل متحقق منه (الطول والنوع)، المستخدم ميقدرش يغيّر `uid/email/createdAt/provider`، ومينفعش يكتب حاجة برّه الحقول المسموحة.
- **Headers:** CSP صارم + HSTS + منع الـ iframe + nosniff. وبقت الصور بتتفلتر (`safeImg`/`cssUrl`) ضد حقن CSS في لوحة الأدمن.

## خطوات التفعيل (بالترتيب)
1. ارفع المحتوى كله على GitHub/Vercel بدل القديم (المجلد ده هو الروت، **مفيش** إعداد Framework — `vercel.json` ظابطه).
2. في Vercel → Settings → Environment Variables ضيف:
   `TELEGRAM_BOT_TOKEN` و `TELEGRAM_CHAT_ID` (شوف `.env.example`) ثم Redeploy.
3. انشر القواعد: `firebase deploy --only firestore:rules --project love-ece13`
4. **Google Cloud Console → APIs & Services → Credentials → Browser key:** قيّد المفتاح بـ HTTP referrers:
   `https://error404-xi-three.vercel.app/*` و `https://love-ece13.firebaseapp.com/*` (ومحدّد الـ APIs: Identity Toolkit, Token Service, Firestore).
5. **Firebase → App Check:** فعّل reCAPTCHA v3 وبعدين Enforce على Firestore (بيوقف السكريبتات اللي بتكلم الداتابيز من برّه الموقع).
6. **Vercel → Firewall:** فعّل Bot Protection + Rate Limit rule على `/api/*` (مثلًا 20 طلب/دقيقة). ولو جالك IP في تنبيه، ضيفه في Custom Rule → Deny.
7. اختياري: `REQUIRE_VERIFIED=1` عشان محدش يحمّل القالب إلا بإيميل متفعّل.

## ملاحظات صريحة
- الـ IP بيدّي مكان **تقريبي** بس، ولو الشخص على VPN/Proxy مش هيبان مكانه الحقيقي. الفخ للكشف والتنبيه والحظر مش أكتر.
- أي حد معاه حساب شغّال هيقدر يحمّل القالب (ده المنتج نفسه). اللي اتمنع هو التحميل من غير حساب والسحب بالسكريبتات.
- لوحة الأدمن مفيش لها رابط على السيرفر؛ هي جزء من الصفحة وبتتحمي بقواعد Firestore (إيميلك المتفعّل بس). كود الواجهة نفسه ظاهر لأي حد وده طبيعي في أي موقع.
- الـ CSP لو منع حاجة جديدة ضفتها (مكتبة/CDN)، ضيف الدومين في `script-src`/`connect-src` جوه `vercel.json`.
- القالب فيه مفتاحين عامين لخدمات خارجية (tenor و termai في `utils.js` و `emojimix.js`) — مش أسرارك، بس لو حابب غيّرهم بمفاتيحك.
