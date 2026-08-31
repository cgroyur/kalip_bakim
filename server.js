"use strict";
const express     = require("express");
const bcrypt      = require("bcryptjs");

// ── TEK OTURUM YÖNETİMİ ──
const ACTIVE_SESSIONS = {};
function newSid() { return Date.now().toString(36) + Math.random().toString(36).slice(2, 10); }

// Türkiye saati (UTC+3) — client nowStr() ile TUTARLI olması için
function nowStrTR() {
  var d = new Date(Date.now() + 3 * 3600 * 1000); // UTC+3
  return d.toISOString().replace("T", " ").slice(0, 19);
}

const SEED_USERS = () => [
  { id:"U001", name:"Admin Yönetici", role:"admin", username:"admin", password_hash: bcrypt.hashSync("Admin2026!",10), active:true, must_change_password:true },
  { id:"U002", name:"Uğur Bükücü", role:"admin", username:"ugur.bukucu", password_hash: bcrypt.hashSync("IlkGiris2026!",10), active:true, must_change_password:true },
  { id:"U003", name:"Ersin Donat", role:"leader", username:"ersin.donat", password_hash: bcrypt.hashSync("IlkGiris2026!",10), active:true, must_change_password:true },
  { id:"U004", name:"İbrahim Kaya", role:"tech", username:"ibrahim.kaya", password_hash: bcrypt.hashSync("IlkGiris2026!",10), active:true, must_change_password:true },
  { id:"U005", name:"Bilal Aslan", role:"tech", username:"bilal.aslan", password_hash: bcrypt.hashSync("IlkGiris2026!",10), active:true, must_change_password:true },
  { id:"U006", name:"Doğan Tor", role:"tech", username:"dogan.tor", password_hash: bcrypt.hashSync("IlkGiris2026!",10), active:true, must_change_password:true },
  { id:"U007", name:"Yusuf Şen", role:"tech", username:"yusuf.sen", password_hash: bcrypt.hashSync("IlkGiris2026!",10), active:true, must_change_password:true },
  { id:"U008", name:"Hamdi Çakır", role:"tech", username:"hamdi.cakir", password_hash: bcrypt.hashSync("IlkGiris2026!",10), active:true, must_change_password:true },
  { id:"U009", name:"Ferhat Koçuk", role:"op", username:"ferhat.kocuk", password_hash: bcrypt.hashSync("IlkGiris2026!",10), active:true, must_change_password:true },
  { id:"U010", name:"Mehmet Kahraman", role:"op", username:"mehmet.kahraman", password_hash: bcrypt.hashSync("IlkGiris2026!",10), active:true, must_change_password:true },
  { id:"U011", name:"Mehmet Yılmaz", role:"op", username:"mehmet.yilmaz", password_hash: bcrypt.hashSync("IlkGiris2026!",10), active:true, must_change_password:true },
  { id:"U012", name:"İsmail Açıkgöz", role:"op", username:"ismail.acikgoz", password_hash: bcrypt.hashSync("IlkGiris2026!",10), active:true, must_change_password:true },
  { id:"U013", name:"Murat Akgün", role:"op", username:"murat.akgun", password_hash: bcrypt.hashSync("IlkGiris2026!",10), active:true, must_change_password:true },
  { id:"U014", name:"Gökhan Koçak", role:"op", username:"gokhan.kocak", password_hash: bcrypt.hashSync("IlkGiris2026!",10), active:true, must_change_password:true },
  { id:"U015", name:"Cüneyt Dincel", role:"op", username:"cuneyt.dincel", password_hash: bcrypt.hashSync("IlkGiris2026!",10), active:true, must_change_password:true },
  { id:"U016", name:"Gökhan Karadeniz", role:"op", username:"gokhan.karadeniz", password_hash: bcrypt.hashSync("IlkGiris2026!",10), active:true, must_change_password:true },
  { id:"U017", name:"Muhammed Akyol", role:"op", username:"muhammed.akyol", password_hash: bcrypt.hashSync("IlkGiris2026!",10), active:true, must_change_password:true }
];

const jwt         = require("jsonwebtoken");
const path        = require("path");
const fs          = require("fs");
const compression = require("compression");
const rateLimit    = require("express-rate-limit");
const { WebSocketServer } = require("ws");
const {
  validate, loginSchema, changePasswordSchema, createUserSchema, updateUserSchema,
  workOrderSchema, tvClaimSchema, auditSchema, systemResetSchema, resetSeedSchema, stateSchema,
  attachmentSchema, qualitySettingsSchema, supplierPmCreateSchema, supplierPmCompleteSchema,
  supplierArizCreateSchema, supplierSampleSentSchema, supplierArizCompleteSchema, teklifRejectSchema,
} = require("./validation");

const app  = express();
// Render (ve genel olarak çoğu PaaS) tek bir reverse proxy hop'u arkasında çalışır.
// Bu ayar olmadan express-rate-limit gerçek istemci IP'sini değil proxy IP'sini görür
// ve tüm kullanıcılar aynı rate-limit kovasını paylaşır (login limiter etkisiz kalır).
app.set("trust proxy", 1);

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "cmms-v15-change-me-in-production";
if (process.env.NODE_ENV === "production" && !process.env.JWT_SECRET) {
  console.error("❌ KRİTİK: NODE_ENV=production ancak JWT_SECRET ortam değişkeni tanımlı değil. " +
    "Kod içindeki bilinen varsayılan değer kullanılacaktı — bu, token sahteciliğine (forged admin JWT) izin verir. " +
    "Sunucu güvenlik nedeniyle başlatılmıyor. JWT_SECRET tanımlayıp yeniden başlatın.");
  process.exit(1);
}
const MIN_PASSWORD_LEN = 6;

// ── LOGIN RATE LIMIT ── 5 deneme / 15 dakika (IP başına)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Çok fazla başarısız giriş denemesi. 15 dakika sonra tekrar deneyin." },
  skipSuccessfulRequests: true, // başarılı girişler sayaca dahil değil
});

// ── ŞİFRE DEĞİŞTİRME RATE LIMIT ── çalınmış/geçerli bir token ile currentPassword
// kaba kuvvet denemesini engeller (login limiter bu endpoint'i kapsamıyordu)
const changePasswordLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Çok fazla şifre değiştirme denemesi. 15 dakika sonra tekrar deneyin." },
  skipSuccessfulRequests: true,
});

const DATA_DIR  = process.env.DB_DIR || path.join(__dirname, "data");
const PG_URL    = process.env.DATABASE_URL || null;

if (!fs.existsSync(DATA_DIR)) { try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch(e) {} }

// ── Veri katmanı ──
// Kalıcılık: DATABASE_URL varsa PostgreSQL (Neon — ücretsiz, kalıcı, ilişkisel
// tablolar), yoksa JSON koleksiyon dosyaları (lokal geliştirme). İkisi de aynı
// store arayüzünü uygular (db/pgStore.js, db/fileStore.js) — route'lar hangisinin
// aktif olduğunu bilmez. Eski tek-JSONB-blob formatından otomatik göç edilir.
const { createPgStore } = require("./db/pgStore");
const { createFileStore } = require("./db/fileStore");

let pgPool = null;
let store = null;

if (PG_URL) {
  const { Pool } = require("pg");
  pgPool = new Pool({
    connectionString: PG_URL,
    ssl: { rejectUnauthorized: true },
    max: 3
  });
  console.log("🐘 PostgreSQL modu aktif (kalıcı depolama)");
}

function addAudit(userId, userName, role, action, entityType, entityId, detail) {
  return store.appendAudit({
    ts: new Date().toISOString().replace("T"," ").slice(0,19),
    user_id: userId, user_name: userName, role,
    action, entity_type: entityType, entity_id: entityId, detail
  });
}

// ── KALIP DURUMU OTOMATİK EŞLEME (Depoda ⇄ Bakımda) ──
// Bir kalıba ait bir iş emri AKTİF hale geldiğinde (DEVAM_EDİYOR — arıza veya
// modifikasyon fark etmez), kalıp "Depoda" durumundaysa otomatik "Bakımda"ya
// alınır. İş kapandığında, o kalıba ait başka aktif iş kalmadıysa VE durum bu
// mekanizma tarafından otomatik değiştirilmişse "Depoda"ya geri döner.
// Sadece "Depoda" durumundaki kalıplar için çalışır — kullanıcının elle
// "Transfer"/"Hurda" gibi bilinçli olarak verdiği bir durumun üzerine yazmaz
// ("tereddütlü/süreci başlamamış" kalıplar için, bkz. kullanıcı talebi).
async function syncMoldStatusForWO(wo, prevStatus, actor) {
  if (!wo.mold_id) return;
  const molds = await store.getMolds();
  const mold = molds.find(m => m.id === wo.mold_id);
  if (!mold) return;

  const startedNow = wo.status === "DEVAM_EDİYOR" && prevStatus !== "DEVAM_EDİYOR";
  const closedNow = wo.status === "KAPATILDI" && prevStatus !== "KAPATILDI";

  if (startedNow && mold.status === "Depoda") {
    mold.status = "Bakımda";
    mold._auto_bakimda = true;
    await store.upsertMold(mold);
    broadcast({ type: "molds_replaced", molds });
    if (actor) {
      await addAudit(actor.id, actor.name, actor.role, "Kalıp Durumu Otomatik Değişti", "mold", mold.id,
        `${wo.id} iş emri başladığı için Depoda → Bakımda (otomatik)`);
    }
  } else if (closedNow && mold._auto_bakimda) {
    const allWos = await store.getWorkOrders();
    const stillWorking = allWos.some(w => w.mold_id === wo.mold_id && w.id !== wo.id && w.status === "DEVAM_EDİYOR");
    if (!stillWorking) {
      mold.status = "Depoda";
      delete mold._auto_bakimda;
      await store.upsertMold(mold);
      broadcast({ type: "molds_replaced", molds });
      if (actor) {
        await addAudit(actor.id, actor.name, actor.role, "Kalıp Durumu Otomatik Değişti", "mold", mold.id,
          `${wo.id} iş emri kapandığı için Bakımda → Depoda (otomatik)`);
      }
    }
  }
}

// Bir kalıp+arıza tipi kombinasyonu, kapatılan bu iş emri dahil son 30 günde
// 3. kez tekrarlıyorsa ve bu iş emrinde RCA (kök neden) girilmemişse "kronik,
// RCA'sız" kabul edilir — frontend'deki detectRecurringFailures() ile aynı
// 30 günlük pencere mantığı, kapanış anında sunucu tarafında da uygulanır.
function isChronicWithoutRCA(cw, allWos) {
  if (!cw.mold_id || !cw.fail_code || cw.rca_cause) return false;
  const refTime = new Date(String(cw.created_at || "").replace(" ", "T")).getTime();
  if (isNaN(refTime)) return false;
  const cutoff = refTime - 30 * 86400000;
  const sameGroup = allWos.filter(w =>
    w.mold_id === cw.mold_id && w.fail_code === cw.fail_code && w.type === "ARIZ" && w.id !== cw.id);
  const withinWindow = sameGroup.filter(w => {
    const t = new Date(String(w.created_at || "").replace(" ", "T")).getTime();
    return !isNaN(t) && t >= cutoff && t <= refTime;
  });
  return withinWindow.length + 1 >= 3; // +1: kapanan iş emrinin kendisi
}

// Kalite onayı gerekiyor mu? Ayar kapalıysa hiçbir zaman gerekmez (varsayılan
// davranış korunur). Açıksa üç bağımsız tetikleyiciden biri yeterli:
// modifikasyon işleri her zaman, operatörün "Kalite Sorunu" işaretlediği
// arızalar her zaman, ve admin'in ayrıca seçtiği arıza tipleri.
function isQualityApprovalRequired(cw, qualitySettings) {
  if (!qualitySettings || !qualitySettings.enabled) return false;
  if (cw.type === "MODİF") return true;
  if (cw.impact === "Kalite Sorunu") return true;
  const triggerCodes = qualitySettings.trigger_fail_codes || [];
  if (cw.fail_code && triggerCodes.includes(cw.fail_code)) return true;
  return false;
}

// ── GERÇEK ZAMANLI SENKRONİZASYON (WebSocket) ──
// REST uçları (GET/POST /api/state) ilk yükleme ve yedek yol olarak AYNEN kalıyor —
// WS sadece üzerine ek: bir mutasyon başarılı olduğunda bağlı istemcilere anlık olay
// yayınlanır. wss, gerçek bir HTTP sunucusu dinlemeye başlamadan (testlerde olduğu
// gibi) null kalır — broadcast() bu durumda sessizce no-op'tur.
let wss = null;
const wsClients = new Set();
function broadcast(msg) {
  if (!wss) return;
  const json = JSON.stringify(msg);
  for (const client of wsClients) {
    if (client.readyState === client.OPEN) {
      try { client.send(json); } catch(e) { /* bağlantı kopmuş olabilir, güvenle yok say */ }
    }
  }
}
function setupWebSocket(httpServer) {
  wss = new WebSocketServer({
    server: httpServer,
    path: "/ws",
    // Geçersiz/eksik token'ı HTTP upgrade aşamasında reddeder — istemci tarafında
    // 'open' hiç tetiklenmez (bağlan-sonra-kapat yerine bağlanma isteği baştan reddedilir).
    verifyClient: (info, callback) => {
      try {
        const url = new URL(info.req.url, "http://localhost");
        const token = url.searchParams.get("token");
        if (!token) return callback(false, 401, "Token gerekli");
        const payload = jwt.verify(token, JWT_SECRET);
        // Tedarikçi rolü tüm sisteme yayın yapan bu genel WS kanalına asla
        // bağlanamaz — portal kendi verisini yalnızca REST ile çeker.
        if (payload.role === "tedarikci") return callback(false, 403, "Bu rol için erişilemez");
        callback(true);
      } catch(e) {
        callback(false, 401, "Geçersiz token");
      }
    },
  });
  wss.on("connection", (ws) => {
    wsClients.add(ws);
    ws.on("close", () => wsClients.delete(ws));
    ws.on("error", () => wsClients.delete(ws));
  });
}

// İlk yükleme — async başlangıç
// initData(): veri katmanını hazırlar ama dinlemeye başlamaz (testler bunu kullanır).
// initServer(): initData() + gerçek HTTP dinleme (normal çalışma zamanı burayı kullanır).
async function initData() {
  if (pgPool) {
    try {
      store = createPgStore(pgPool);
      await store.init();
    } catch(e) {
      console.error("❌ PostgreSQL hatası:", e.message, "— dosya moduna düşülüyor");
      pgPool = null;
      store = null;
    }
  }
  if (!store) {
    store = createFileStore(DATA_DIR);
    await store.init();
  }
  await ensureDemoUsers();
  await migrateExistingUsersPasswordFlag();
  await migrateDefaultMoldStatus();
}
async function initServer() {
  await initData();
  startListen();
}

async function ensureDemoUsers() {
  // Demo kullanıcılar yoksa oluştur
  const users = await store.getUsers();
  if (!users || users.length === 0) {
    await store.saveUsers(SEED_USERS());
    console.log("✅ Demo kullanıcılar oluşturuldu  →  admin / Admin2026! (ilk girişte şifre değişimi zorunlu)");
  }
}

// ── GÖÇ: v15.6 öncesi oluşturulan kullanıcılarda must_change_password alanı yok ──
// Bu alan hiç tanımlı değilse (eski kayıt), güvenlik gereği ZORUNLU işaretlenir.
// Kullanıcı bir kez şifresini değiştirdiğinde alan false olur ve bir daha tetiklenmez —
// bu fonksiyon sadece alanı hiç GÖRMEMİŞ kayıtlara dokunur, idempotent'tir.
async function migrateExistingUsersPasswordFlag() {
  const users = await store.getUsers();
  if (!users || users.length === 0) return;
  var migrated = 0;
  users.forEach(function(u) {
    if (!("must_change_password" in u)) {
      u.must_change_password = true;
      migrated++;
    }
  });
  if (migrated > 0) {
    await store.saveUsers(users);
    console.log(`🔒 Güvenlik göçü: ${migrated} mevcut kullanıcı ilk girişte şifre değiştirmeye zorlanacak`);
  }
}


// ── GÖÇ: Varsayılan kalıp durumunu "Kullanılabilir"dan "Depoda"ya çevir ──
// Geçmişte neredeyse tüm kalıplar "Kullanılabilir" (=üretimde) olarak işaretlenmişti;
// bu, "883 kalıbın 882'si üretimde" gibi gerçekçi olmayan bir görünüme yol açıyordu.
// Gerçekte kalıpların büyük çoğunluğu depoda bekler — sadece üzerinde aktif iş olan
// kalıplar "Bakımda" olur (bkz. syncMoldStatusForWO). Elle "Transfer"/"Hurda" olarak
// işaretlenmiş kalıplara dokunulmaz. TEK SEFERLİK ve idempotent'tir (state_extra'daki
// bayrakla işaretlenir). Henüz hiç veri kaydedilmemiş taze kurulumlarda ÇALIŞMAZ —
// aksi halde hasState() erken tetiklenir ve ilk-kurulum akışı bozulur.
async function migrateDefaultMoldStatus() {
  if (!(await store.hasState())) return;
  const extra = await store.getStateExtra();
  if (extra && extra._mold_status_migrated_v1) return;
  const molds = await store.getMolds();
  let migrated = 0;
  for (const m of molds) {
    if (!m.status || m.status === "Kullanılabilir") {
      m.status = "Depoda";
      await store.upsertMold(m);
      migrated++;
    }
  }
  await store.saveStateExtra({ ...(extra || {}), _mold_status_migrated_v1: true });
  if (migrated > 0) {
    console.log(`📦 Varsayılan kalıp durumu göçü: ${migrated} kalıp "Depoda" olarak işaretlendi`);
  }
}

// ── MIDDLEWARE ──
// app.use(compression()); // Büyük HTML ile sorun yaratabiliyor
app.use(express.json({ limit: "25mb" }));
app.use(express.urlencoded({ extended: false }));
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("Referrer-Policy", "same-origin");
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  next();
});

// Tedarikçi rolü portal-dışı hiçbir API'ye erişemez — tek tek route'ları
// işaretlemek yerine burada TEK bir yerden, kaçırma riski olmadan uygulanır.
// İzin verilen: kendi /api/supplier/* uçları + oturum/şifre kendi kendine
// hizmet uçları (login zaten auth'suz, logout/change-password kendi hesabı içindir).
const SUPPLIER_ALLOWED_PREFIXES = ["/api/supplier/", "/api/logout", "/api/change-password"];
function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h?.startsWith("Bearer ")) return res.status(401).json({ error: "Token gerekli" });
  try {
    const payload = jwt.verify(h.slice(7), JWT_SECRET);
    const cur = ACTIVE_SESSIONS[payload.id];
    if (payload.sid && cur && cur.sid !== payload.sid) {
      return res.status(401).json({ error: "Bu hesap başka bir cihazdan açıldı. Oturumunuz sonlandırıldı.", session_takeover: true });
    }
    if (payload.role === "tedarikci" && !SUPPLIER_ALLOWED_PREFIXES.some(p => req.path.startsWith(p))) {
      return res.status(403).json({ error: "Bu rol için erişilemez" });
    }
    req.user = payload; next();
  }
  catch { res.status(401).json({ error: "Geçersiz veya süresi dolmuş token" }); }
}
function adminOnly(req, res, next) {
  if (req.user?.role !== "admin") return res.status(403).json({ error: "Sadece admin" });
  next();
}
function supplierOnly(req, res, next) {
  if (req.user?.role !== "tedarikci") return res.status(403).json({ error: "Sadece tedarikçi" });
  next();
}
async function getSupplierName(userId) {
  const users = await store.getUsers();
  const u = users.find(x => x.id === userId);
  return (u && u.supplier_name) || null;
}

// ── AUTH ──
app.post("/api/login", loginLimiter, validate(loginSchema), async (req, res) => {
  const { username, password } = req.body;
  const uname = String(username).trim();
  const users = await store.getUsers();
  const u = users.find(x => x.username === uname && x.active);
  if (!u || !bcrypt.compareSync(password, u.password_hash))
    return res.status(401).json({ error: "Kullanıcı adı veya şifre hatalı" });
  const prev = ACTIVE_SESSIONS[u.id];
  const sid = newSid();
  ACTIVE_SESSIONS[u.id] = { sid, at: nowStrTR(), ua: String(req.headers["user-agent"] || "").slice(0, 80) };
  const token = jwt.sign({ id:u.id, username:u.username, role:u.role, name:u.name, sid }, JWT_SECRET, { expiresIn:"30m" });
  if (prev) await addAudit(u.id, u.name, u.role, "Oturum Devralındı", "auth", null, `${u.name} yeni cihazdan giriş yaptı — önceki oturum sonlandırıldı`);
  else await addAudit(u.id, u.name, u.role, "Giriş", "auth", null, `${u.name} sisteme giriş yaptı`);
  res.json({
    token,
    user: { id:u.id, name:u.name, role:u.role, username:u.username, supplier_name: u.supplier_name || null, custom_pages: u.custom_pages || null },
    takeover: !!prev,
    must_change_password: !!u.must_change_password
  });
});

// ── ŞİFRE DEĞİŞTİRME (kendi hesabı) ──
app.post("/api/change-password", changePasswordLimiter, auth, validate(changePasswordSchema), async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (String(newPassword).length < MIN_PASSWORD_LEN)
    return res.status(400).json({ error: `Yeni şifre en az ${MIN_PASSWORD_LEN} karakter olmalı` });
  const users = await store.getUsers();
  const u = users.find(x => x.id === req.user.id && x.active);
  if (!u) return res.status(404).json({ error: "Kullanıcı bulunamadı" });
  if (!bcrypt.compareSync(currentPassword, u.password_hash))
    return res.status(401).json({ error: "Mevcut şifre hatalı" });
  u.password_hash = bcrypt.hashSync(newPassword, 10);
  u.must_change_password = false;
  await store.saveUsers(users);
  await addAudit(u.id, u.name, u.role, "Şifre Değiştirildi", "user", u.id, `${u.name} kendi şifresini değiştirdi`);
  res.json({ ok: true });
});

app.post("/api/logout", auth, async (req, res) => {
  await addAudit(req.user.id, req.user.name, req.user.role, "Çıkış", "auth", null, `${req.user.name} çıkış yaptı`);
  res.json({ ok: true });
});

// ── STATE ──
app.get("/api/state", auth, async (req, res) => {
  // Tedarikçi rolü tüm sistemi gören bu genel uca hiçbir zaman erişemez —
  // frontend zaten bu isteği hiç göndermez, burası ikinci savunma katmanı.
  if (req.user.role === "tedarikci") return res.status(403).json({ error: "Bu rol için erişilemez" });
  if (!(await store.hasState())) return res.json(null);
  const [molds, wos, extra, users, auditRecent] = await Promise.all([
    store.getMolds(), store.getWorkOrders(), store.getStateExtra(), store.getUsers(), store.getAuditLogRecent(2000),
  ]);
  const state = { ...extra, molds, wos };
  state.users = users.filter(u=>u.active)
    .map(u => ({ id:u.id, name:u.name, role:u.role, username:u.username, user:u.username, pass:"",
      supplier_name: u.supplier_name || null, custom_pages: u.custom_pages || null }));
  state.auditLog = auditRecent;
  res.json(state);
});

// ── ROL BAZLI YAZMA KORUMASI ──
// admin/leader: tam yetki (kalıp/maliyet/yedek parça dahil).
// tech/op: kalıp ana verisini (parça adı, göz sayısı, PM aralığı, konum vb.) DEĞİŞTİREMEZ,
// sadece kendi iş akışının doğal sonucu olan PM sayaç alanlarını güncelleyebilir.
// Yedek parça kataloğu (stok/fiyat) tech/op için tamamen salt-okunurdur.
// Not: iş emirleri (wos) bu fonksiyonun kapsamı dışında — satır bazlı upsert +
// updated_at karşılaştırması (db/shared.js) çakışmayı doğal olarak çözer.
const MOLD_FIELDS_TECH_CAN_EDIT = new Set(["pm_counter", "total_shots", "last_pm_date", "is_regular", "regular_days", "regular_updated"]);
function sanitizeMoldsForRole(role, serverMolds, incomingMolds) {
  if (role === "admin" || role === "leader") return incomingMolds || [];
  if (!Array.isArray(incomingMolds)) return serverMolds;
  const clientMap = new Map(incomingMolds.map(m => [m.id, m]));
  return serverMolds.map(sm => {
    const cm = clientMap.get(sm.id);
    if (!cm) return sm; // istemci bu kalıbı göndermemiş — sunucu korur (silme/kayıp engellenir)
    const merged = { ...sm };
    for (const f of MOLD_FIELDS_TECH_CAN_EDIT) {
      if (cm[f] !== undefined) merged[f] = cm[f];
    }
    return merged; // diğer tüm alanlar (parça adı, göz, PM aralığı, konum...) sunucu değerinde kalır
    // İstemcinin yeni kalıp eklemeye çalışması (sunucuda olmayan id) sessizce yok sayılır.
  });
}
function sanitizeExtraForRole(role, extra) {
  if (role === "admin" || role === "leader") return extra;
  if ("spareparts" in extra) {
    const { spareparts, ...rest } = extra;
    return rest;
  }
  return extra;
}

app.post("/api/state", (req, res, next) => {
  // sendBeacon token'ı query param olarak gönderir
  if (req.query.token && !req.headers.authorization) {
    req.headers.authorization = "Bearer " + req.query.token;
  }
  auth(req, res, next);
}, validate(stateSchema), async (req, res) => {
  if (req.user.role === "tedarikci") return res.status(403).json({ error: "Bu rol için erişilemez" });
  const { users, auditLog, deleted_wo_ids, molds: incomingMolds, wos: incomingWos, ...extra } = req.body;

  const serverMolds = await store.getMolds();
  const sanitizedMolds = sanitizeMoldsForRole(req.user.role, serverMolds, incomingMolds);
  await store.replaceMolds(sanitizedMolds);
  broadcast({ type: "molds_replaced", molds: sanitizedMolds });

  // ── WO yazma: satır bazlı upsert, updated_at çakışması db/shared.js'te çözülür ──
  const deletedIds = new Set(deleted_wo_ids || []);
  const wosSnapshotForChronicCheck = await store.getWorkOrders();
  const qualitySettingsSnapshot = await store.getQualitySettings();
  for (const cw of (incomingWos || [])) {
    if (deletedIds.has(cw.id)) continue; // istemci bilinçli silmiş, aşağıda silinecek
    const prevWo = await store.getWorkOrderById(cw.id);
    const closingNow = cw.status === "KAPATILDI" && (!prevWo || prevWo.status !== "KAPATILDI");
    // quality_approved yalnızca kalite/admin rolünden gelen isteklerde geçerli
    // sayılır — başka bir rol bu alanı gövdeye eklese bile sunucu, mevcut
    // sunucu-taraflı değeri korur (kapanış kapısını atlatmayı engeller).
    if (cw.quality_approved !== undefined && !["kalite", "admin"].includes(req.user.role)) {
      cw.quality_approved = prevWo ? !!prevWo.quality_approved : false;
    }
    // ── Bağımsız doğrulama kuralı: KRİTİK öncelikli bir işi, işi yapan teknisyen
    // tek başına KAPATILDI'ya çekemez — sunucu bu tek alanı sessizce "TAMAMLANDI"ya
    // düşürür (leader/admin'in "Doğrulama Bekleyen İşler" ekranından onaylaması
    // gerekir). admin/leader için ya da kritik olmayan işlerde davranış değişmez.
    if (closingNow && cw.priority === "KRİTİK" && req.user.role === "tech") {
      cw.status = "TAMAMLANDI";
      cw.closed_at = null;
    }
    // ── Kronik arıza kuralı: aynı kalıp+arıza tipi son 30 günde 3. kez
    // kapatılıyorsa ve RCA girilmemişse, kim kapatırsa kapatsın "TAMAMLANDI"
    // durumuna düşürülür — RCA eklenip yeniden kapatılana kadar kronik döngü
    // sessizce kapanamaz.
    else if (closingNow && isChronicWithoutRCA(cw, wosSnapshotForChronicCheck)) {
      cw.status = "TAMAMLANDI";
      cw.closed_at = null;
      await addAudit(req.user.id, req.user.name, req.user.role, "Kronik Arıza — RCA Gerekli", "wo", cw.id,
        `${cw.mold_id} / ${cw.fail_code}: son 30 günde 3. tekrar, RCA eksik olduğu için kapatma engellendi`);
    }
    // ── Kalite onayı kapısı: yukarıdaki kapılardan sonra hâlâ KAPATILDI'ya
    // geçmeye çalışıyorsa (yani KRİTİK/kronik kapıları tetiklenmediyse) ve bu
    // iş kalite onayı gerektiriyorsa (modifikasyon, "Kalite Sorunu" etkisi
    // veya admin'in seçtiği arıza tipleri), kalite onayı verilmiş olmadıkça
    // "KALITE_BEKLIYOR" durumuna düşürülür. Ayar kapalıyken hiçbir etkisi yok.
    if (cw.status === "KAPATILDI" && !cw.quality_approved &&
        isQualityApprovalRequired(cw, qualitySettingsSnapshot)) {
      cw.status = "KALITE_BEKLIYOR";
      cw.closed_at = null;
      if (closingNow) {
        await addAudit(req.user.id, req.user.name, req.user.role, "Kalite Onayı Bekliyor", "wo", cw.id,
          `${cw.mold_id}: kalite onayı gerekiyor (tip=${cw.type}, etki=${cw.impact || "—"}, arıza=${cw.fail_code || "—"})`);
      }
    }
    const applied = await store.upsertWorkOrder(cw);
    if (applied) {
      broadcast({ type: "wo_updated", wo: cw });
      await syncMoldStatusForWO(cw, prevWo ? prevWo.status : null, req.user);
    }
  }
  for (const id of deletedIds) {
    await store.deleteWorkOrder(id);
    broadcast({ type: "wo_deleted", id });
  }

  // _mold_status_migrated_v1 sunucunun kendi göç bayrağıdır — istemcinin tam-obje
  // üzerine yazma davranışıyla (extra) her kaydda silinmemesi için burada korunur.
  const mergedExtra = sanitizeExtraForRole(req.user.role, extra);
  const existingExtra = await store.getStateExtra();
  if (existingExtra && existingExtra._mold_status_migrated_v1) mergedExtra._mold_status_migrated_v1 = true;
  await store.saveStateExtra(mergedExtra);

  const allWos = await store.getWorkOrders();
  res.json({ ok: true, woCount: allWos.length });
});

// ── KULLANICILAR ──
app.get("/api/users", auth, adminOnly, async (req, res) => {
  const users = await store.getUsers();
  res.json(users.map(u => ({ id:u.id, name:u.name, role:u.role, username:u.username, active:u.active, supplier_name:u.supplier_name || null, custom_pages:u.custom_pages || null })));
});

app.post("/api/users", auth, adminOnly, validate(createUserSchema), async (req, res) => {
  let { id, name, role, username, password, supplier_name } = req.body;
  if (String(password).length < MIN_PASSWORD_LEN)
    return res.status(400).json({ error:`Şifre en az ${MIN_PASSWORD_LEN} karakter olmalı` });
  username = String(username).trim();
  name = String(name).trim();
  if (!username) return res.status(400).json({ error:"Kullanıcı adı boş olamaz" });

  let users = await store.getUsers();
  const existing = users.find(u => u.username.toLowerCase() === username.toLowerCase());
  if (existing && existing.active && existing.id !== id) {
    return res.status(400).json({ error:"Bu kullanıcı adı zaten kullanılıyor" });
  }
  // Pasif (silinmiş) veya aynı id'li kayıt varsa üzerine yaz — username yeniden kullanılabilir
  users = users.filter(u => u.id !== id && u.username.toLowerCase() !== username.toLowerCase());
  // Admin başkası için şifre belirlediğinde ilk girişte değiştirme zorunluluğu
  users.push({ id, name, role, username, password_hash: bcrypt.hashSync(password,10), active:true, must_change_password:true, supplier_name: supplier_name || null });
  await store.saveUsers(users);
  await addAudit(req.user.id, req.user.name, req.user.role, "Kullanıcı Eklendi", "user", id, `${name} (${role}) eklendi`);
  res.json({ ok: true });
});

app.put("/api/users/:id", auth, adminOnly, validate(updateUserSchema), async (req, res) => {
  let { name, role, username, password, supplier_name, custom_pages } = req.body;
  if (password && String(password).length < MIN_PASSWORD_LEN)
    return res.status(400).json({ error:`Şifre en az ${MIN_PASSWORD_LEN} karakter olmalı` });
  username = username ? String(username).trim() : username;
  name = name ? String(name).trim() : name;
  let users = await store.getUsers();
  const u = users.find(x=>x.id===req.params.id);
  if (!u) {
    // Kullanıcı sunucuda yok (eski sürümden kalan yerel kayıt) — şifre verildiyse oluştur
    if (!password) return res.status(404).json({ error:"Kullanıcı sunucuda yok. Şifre girerek kaydedin, yeniden oluşturulsun." });
    const clash = users.find(x => x.username.toLowerCase() === username.toLowerCase() && x.active);
    if (clash) return res.status(400).json({ error:"Bu kullanıcı adı zaten kullanılıyor" });
    users = users.filter(x => x.username.toLowerCase() !== username.toLowerCase());
    users.push({ id: req.params.id, name, role, username, password_hash: bcrypt.hashSync(password,10), active:true, must_change_password:true, supplier_name: supplier_name || null });
    await store.saveUsers(users);
    await addAudit(req.user.id, req.user.name, req.user.role, "Kullanıcı Oluşturuldu (kurtarma)", "user", req.params.id, `${name} sunucuya kaydedildi`);
    return res.json({ ok: true, created: true });
  }
  if (name) u.name=name;
  if (role) u.role=role;
  if (username) u.username=username;
  if (supplier_name !== undefined) u.supplier_name = supplier_name || null;
  if (custom_pages !== undefined) u.custom_pages = custom_pages;
  u.active = true;
  // Admin başkasının şifresini sıfırladığında ilk girişte değiştirme zorunluluğu
  if (password) { u.password_hash = bcrypt.hashSync(password,10); u.must_change_password = true; }
  await store.saveUsers(users);
  await addAudit(req.user.id, req.user.name, req.user.role, "Kullanıcı Düzenlendi", "user", req.params.id, `${u.name} güncellendi`);
  res.json({ ok: true });
});

app.delete("/api/users/:id", auth, adminOnly, async (req, res) => {
  if (req.params.id===req.user.id) return res.status(400).json({ error:"Kendinizi silemezsiniz" });
  const users = await store.getUsers();
  const u = users.find(x=>x.id===req.params.id);
  if (u) { u.active=false; await store.saveUsers(users); }
  await addAudit(req.user.id, req.user.name, req.user.role, "Kullanıcı Silindi", "user", req.params.id, "Pasif yapıldı");
  res.json({ ok: true });
});

// ── AUDİT ──
app.post("/api/audit", auth, validate(auditSchema), async (req, res) => {
  const { action, entity_type, entity_id, detail } = req.body;
  await addAudit(req.user.id, req.user.name, req.user.role, action, entity_type||null, entity_id||null, detail||null);
  res.json({ ok: true });
});

app.get("/api/audit", auth, adminOnly, async (req, res) => {
  const { rows, total } = await store.getAuditLogPage(500);
  res.json({ rows, total });
});

// ── SİSTEM ──
app.get("/api/health", (req, res) => res.json({ status:"ok", version:"15.0.0" }));

// GET /api/tv — Giriş gerektirmeyen TV modu verisi
app.get("/api/tv", async (req, res) => {
  const [molds, wos, users] = await Promise.all([store.getMolds(), store.getWorkOrders(), store.getUsers()]);
  const openWos = wos.filter(w => w.status !== "KAPATILDI");
  const critWos = openWos.filter(w => w.priority === "KRİTİK");
  const now = new Date().toISOString().slice(0,10);
  const todayWos = wos.filter(w => w.created_at && w.created_at.slice(0,10) === now);
  const closedToday = todayWos.filter(w => w.status === "KAPATILDI");
  const transferMolds = molds.filter(m => m.status === "Transfer");
  const closedAriz = wos.filter(w => w.status==="KAPATILDI" && w.started_at && w.closed_at);
  const avgMin = closedAriz.length > 0 ? Math.round(closedAriz.reduce((s,w) => s + (new Date(w.closed_at)-new Date(w.started_at))/60000, 0) / closedAriz.length) : 0;
  const activeMolds = molds.filter(m => m.status === "Kullanılabilir" || m.status === "Bakımda");
  // Havuzdaki işler (atanmamış veya beklemede)
  const poolWos = openWos.filter(w => !w.assigned || w.status === "BEKLEMEDE");
  res.json({
    open: openWos.length,
    critical: critWos.length,
    mttr: avgMin,
    activeMolds: activeMolds.length,
    transfer: transferMolds.length,
    closedToday: closedToday.length,
    totalMolds: molds.length,
    totalWos: wos.length,
    openWos: openWos.slice(0, 30).map(w => ({
      id: w.id, mold_id: w.mold_id, type: w.type, priority: w.priority,
      status: w.status, description: (w.description||"").slice(0,60),
      assigned: w.assigned||null, created_at: w.created_at, cavity_no: w.cavity_no
    })),
    poolWos: poolWos.slice(0, 20).map(w => ({
      id: w.id, mold_id: w.mold_id, type: w.type, priority: w.priority,
      description: (w.description||"").slice(0,60), created_at: w.created_at
    })),
    transferMolds: transferMolds.map(m => ({
      id: m.id, transfer_to: m.transfer_to, transfer_date: m.transfer_date,
      transfer_return_date: m.transfer_return_date
    })),
    // Devam eden işler — kim hangi işte çalışıyor
    inProgressWos: wos.filter(w => w.status === "DEVAM_EDİYOR" || w.status === "DEVAM_EDIYOR").slice(0, 20).map(w => {
      const u = w.assigned ? users.find(x=>x.id===w.assigned) : null;
      return {
        id: w.id, mold_id: w.mold_id, type: w.type, priority: w.priority,
        description: (w.description||"").slice(0,60), assigned: u ? u.name : (w.assigned||""),
        started_at: w.started_at, cavity_no: w.cavity_no
      };
    }),
    ts: new Date().toISOString()
  });
});

// POST /api/users/reset-seed — Sabit kullanıcı listesini yeniden yükle (admin)
// POST /api/users/force-password-reset — Tüm aktif kullanıcılara ilk girişte şifre değiştirme zorunluluğu (admin)
app.post("/api/users/force-password-reset", auth, adminOnly, async (req, res) => {
  const users = await store.getUsers();
  var count = 0;
  users.forEach(function(u) {
    if (u.active && u.id !== req.user.id) { // kendi hesabını zorunlu kılmaz — o zaten değiştirebilir
      u.must_change_password = true;
      count++;
    }
  });
  await store.saveUsers(users);
  await addAudit(req.user.id, req.user.name, req.user.role, "Toplu Şifre Sıfırlama Zorunluluğu", "user", "all",
    `${count} kullanıcı bir sonraki girişte şifre değiştirmeye zorlandı`);
  res.json({ ok: true, count: count });
});

app.post("/api/users/reset-seed", auth, validate(resetSeedSchema), async (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Yetkisiz" });
  const mode = req.body.mode || "merge"; // "merge" = eksikleri ekle, "replace" = tümünü değiştir
  const seed = SEED_USERS();
  let users = await store.getUsers();

  if (mode === "replace") {
    // Tüm kullanıcıları sabit listeyle değiştir
    users = seed;
    await store.saveUsers(users);
    await addAudit(req.user.id, req.user.name, req.user.role, "Kullanıcılar Sıfırlandı", "user", "seed",
      `Tüm kullanıcılar sabit listeyle değiştirildi (${seed.length} kişi)`);
    return res.json({ ok: true, mode: "replace", total: users.length });
  }

  // MERGE: mevcut olmayan kullanıcıları ekle (username bazlı)
  const existingUsernames = new Set(users.map(u => u.username));
  const existingIds = new Set(users.map(u => u.id));
  let added = 0;
  for (const su of seed) {
    if (!existingUsernames.has(su.username)) {
      // ID çakışması varsa yeni ID ver
      let newUser = { ...su };
      if (existingIds.has(newUser.id)) {
        let n = 100;
        while (existingIds.has("U" + n)) n++;
        newUser.id = "U" + n;
      }
      users.push(newUser);
      existingIds.add(newUser.id);
      existingUsernames.add(newUser.username);
      added++;
    }
  }
  await store.saveUsers(users);
  await addAudit(req.user.id, req.user.name, req.user.role, "Kullanıcılar Yüklendi", "user", "seed",
    `${added} yeni kullanıcı eklendi (merge)`);
  res.json({ ok: true, mode: "merge", added: added, total: users.length });
});

// POST /api/workorders — Doğrudan iş emri oluştur (arıza bildirimi)
app.post("/api/workorders", auth, validate(workOrderSchema), async (req, res) => {
  const wo = req.body;

  // ID ata
  if (!wo.id) {
    const existing = await store.getWorkOrders();
    const maxNum = existing.reduce((max, w) => {
      const m = (w.id||"").match(/LG-(\d+)/);
      return m ? Math.max(max, parseInt(m[1])) : max;
    }, 0);
    wo.id = "LG-" + String(maxNum + 1).padStart(3, "0");
  }

  // Varsayılan alanlar
  wo.status = wo.status || "BEKLEMEDE";
  wo.assigned = wo.assigned || null;
  wo.created_at = wo.created_at || nowStrTR();
  wo.reported_by = wo.reported_by || req.user.id;

  await store.upsertWorkOrder(wo);
  broadcast({ type: "wo_updated", wo });
  await syncMoldStatusForWO(wo, null, req.user);

  // Audit log
  await addAudit(req.user.id, req.user.name, req.user.role, "Arıza Bildirimi", "wo", wo.id,
    `${wo.mold_id} — ${wo.type}: ${(wo.description||"").slice(0,60)}`);

  console.log(`📋 Yeni WO: ${wo.id} (${wo.mold_id}) by ${req.user.name}`);
  res.json({ ok: true, wo: wo });
});

// POST /api/tv/claim — İş emri üstlenme (login gerekli)
app.post("/api/tv/claim", auth, validate(tvClaimSchema), async (req, res) => {
  const { wo_id } = req.body;
  const wo = await store.getWorkOrderById(wo_id);
  if (!wo) return res.status(404).json({ error: "İş emri bulunamadı" });
  if (!["leader","tech"].includes(req.user.role)) return res.status(403).json({ error: "Sadece lider ve teknisyenler iş üstlenebilir" });
  if (wo.assigned && wo.status !== "BEKLEMEDE") return res.status(400).json({ error: "Bu iş zaten atanmış" });
  const prevStatus = wo.status;
  wo.assigned = req.user.id;
  wo.status = "DEVAM_EDİYOR";
  wo.assigned_at = wo.assigned_at || nowStrTR();
  wo.started_at = nowStrTR();
  wo.updated_at = new Date().toISOString();
  await store.upsertWorkOrder(wo);
  broadcast({ type: "wo_updated", wo });
  await syncMoldStatusForWO(wo, prevStatus, req.user);
  await addAudit(req.user.id, req.user.name, req.user.role, "İş Üstlenildi (TV)", "wo", wo_id,
    req.user.name + " " + wo_id + " iş emrini TV modundan üstlendi");
  res.json({ ok: true, wo_id, assigned: req.user.name });
});

// ── DOKÜMAN EKLERİ ── (teknik çizim, üretici manueli, onarım fotoğrafı vb.)
// Kalıp/iş emri kayıtlarından ayrı tutulur, GET /api/state'e dahil edilmez —
// sadece ilgili kayıt açıldığında ayrıca (isteğe bağlı) çekilir.
app.get("/api/attachments", auth, async (req, res) => {
  const { entity_type, entity_id } = req.query;
  if (!entity_type || !entity_id) return res.status(400).json({ error: "entity_type ve entity_id gerekli" });
  const rows = await store.getAttachmentsMeta(String(entity_type), String(entity_id));
  res.json(rows);
});

app.post("/api/attachments", auth, validate(attachmentSchema), async (req, res) => {
  const { entity_type, entity_id, filename, mime_type, data_base64 } = req.body;
  const sizeBytes = Math.round(data_base64.length * 3 / 4);
  const att = {
    id: "ATT-" + Date.now().toString(36).toUpperCase() + Math.random().toString(36).slice(2, 6).toUpperCase(),
    entity_type, entity_id, filename, mime_type: mime_type || "application/octet-stream",
    size_bytes: sizeBytes, data_base64,
    uploaded_by: req.user.id, uploaded_by_name: req.user.name, uploaded_at: nowStrTR(),
  };
  await store.saveAttachment(att);
  await addAudit(req.user.id, req.user.name, req.user.role, "Dosya Eklendi", entity_type, entity_id,
    `${filename} (${Math.round(sizeBytes/1024)} KB) eklendi`);
  const { data_base64: _drop, ...meta } = att;
  res.json({ ok: true, attachment: meta });
});

app.get("/api/attachments/:id/content", auth, async (req, res) => {
  const att = await store.getAttachmentById(req.params.id);
  if (!att) return res.status(404).json({ error: "Dosya bulunamadı" });
  res.json({ filename: att.filename, mime_type: att.mime_type, data_base64: att.data_base64 });
});

app.delete("/api/attachments/:id", auth, async (req, res) => {
  if (!["admin", "leader"].includes(req.user.role)) return res.status(403).json({ error: "Yetkisiz" });
  const att = await store.getAttachmentById(req.params.id);
  if (!att) return res.status(404).json({ error: "Dosya bulunamadı" });
  await store.deleteAttachment(req.params.id);
  await addAudit(req.user.id, req.user.name, req.user.role, "Dosya Silindi", att.entity_type, att.entity_id, att.filename);
  res.json({ ok: true });
});

// Kalite onayı ayarları — varsayılan kapalı (enabled:false). Devreye alınana
// kadar iş emri kapanış akışında hiçbir değişiklik olmaz. GET herkese açık
// (frontend'in gate durumunu bilmesi gerekir), PUT sadece admin.
app.get("/api/system/quality-settings", auth, async (req, res) => {
  const s = await store.getQualitySettings();
  res.json({ enabled: !!s.enabled, trigger_fail_codes: s.trigger_fail_codes || [] });
});

app.put("/api/system/quality-settings", auth, adminOnly, validate(qualitySettingsSchema), async (req, res) => {
  const current = await store.getQualitySettings();
  const next = {
    enabled: req.body.enabled !== undefined ? req.body.enabled : !!current.enabled,
    trigger_fail_codes: req.body.trigger_fail_codes !== undefined ? req.body.trigger_fail_codes : (current.trigger_fail_codes || []),
  };
  await store.saveQualitySettings(next);
  await addAudit(req.user.id, req.user.name, req.user.role, "Kalite Onayı Ayarları Değiştirildi", "system", null,
    `enabled=${next.enabled}, tetikleyici arıza tipleri: ${next.trigger_fail_codes.join(", ") || "yok"}`);
  res.json({ ok: true, ...next });
});

// ── TEDARİKÇİ PORTALI ──
// Dar kapsamlı, izole uç noktalar — tedarikci rolü GENEL /api/state'e hiç
// erişemez (server.js'in başka hiçbir yerinde bu role izin verilmez). Bu
// route'lar sadece kullanıcının kendi supplier_name'iyle eşleşen, o an
// "Transfer" durumundaki kalıpları ve bu portaldan açtığı iş emirlerini
// döndürür/değiştirir.
app.get("/api/supplier/molds", auth, supplierOnly, async (req, res) => {
  const supplierName = await getSupplierName(req.user.id);
  if (!supplierName) return res.json([]);
  const molds = await store.getMolds();
  const mine = molds.filter(m => m.status === "Transfer" && m.transfer_to === supplierName);
  res.json(mine.map(m => ({
    id: m.id, part_name: m.part_name, transfer_date: m.transfer_date,
    pm_counter: m.pm_counter || 0, pm_interval: m.pm_interval || 50000, last_pm_date: m.last_pm_date || null,
  })));
});

app.get("/api/supplier/wos", auth, supplierOnly, async (req, res) => {
  const supplierName = await getSupplierName(req.user.id);
  if (!supplierName) return res.json([]);
  const wos = await store.getWorkOrders();
  const mine = wos.filter(w => w.source === "tedarikci_portali" && w.supplier_name === supplierName);
  res.json(mine.map(w => ({
    id: w.id, mold_id: w.mold_id, type: w.type, status: w.status,
    created_at: w.created_at, started_at: w.started_at, closed_at: w.closed_at, description: w.description,
    cavity_no: w.cavity_no, teklif_items: w.teklif_items, teklif_total: w.teklif_total, sample_sent: !!w.sample_sent,
    checklist_done: w.checklist_done || [], quality_approved: !!w.quality_approved,
  })));
});

app.post("/api/supplier/pm", auth, supplierOnly, validate(supplierPmCreateSchema), async (req, res) => {
  const supplierName = await getSupplierName(req.user.id);
  if (!supplierName) return res.status(403).json({ error: "Tedarikçi kimliği tanımlı değil — admin ile iletişime geçin" });
  const molds = await store.getMolds();
  const mold = molds.find(m => m.id === req.body.mold_id);
  if (!mold || mold.status !== "Transfer" || mold.transfer_to !== supplierName)
    return res.status(403).json({ error: "Bu kalıp şu an sizde görünmüyor" });
  const wos = await store.getWorkOrders();
  const maxNum = wos.reduce((max, w) => {
    const m = (w.id || "").match(/LG-(\d+)/);
    return m ? Math.max(max, parseInt(m[1])) : max;
  }, 0);
  const id = "LG-" + String(maxNum + 1).padStart(3, "0");
  const ts = nowStrTR();
  const wo = {
    id, mold_id: mold.id, type: "PM", status: "DEVAM_EDİYOR", priority: "NORMAL",
    description: `${supplierName} tarafından tedarikçi portalından başlatılan planlı bakım`,
    assigned: null, reported_by: req.user.id, created_at: ts, started_at: ts, closed_at: null,
    source: "tedarikci_portali", supplier_name: supplierName,
  };
  await store.upsertWorkOrder(wo);
  broadcast({ type: "wo_updated", wo });
  await addAudit(req.user.id, supplierName, "tedarikci", "Tedarikçi Planlı Bakım Başlattı", "wo", id,
    `${mold.id} için ${supplierName} planlı bakım başlattı`);
  res.json({ ok: true, wo });
});

app.post("/api/supplier/pm/:id/complete", auth, supplierOnly, validate(supplierPmCompleteSchema), async (req, res) => {
  const supplierName = await getSupplierName(req.user.id);
  if (!supplierName) return res.status(403).json({ error: "Tedarikçi kimliği tanımlı değil — admin ile iletişime geçin" });
  const wo = await store.getWorkOrderById(req.params.id);
  if (!wo || wo.type !== "PM" || wo.source !== "tedarikci_portali" || wo.supplier_name !== supplierName)
    return res.status(404).json({ error: "İş emri bulunamadı" });
  if (wo.status === "KAPATILDI" || wo.status === "TAMAMLANDI")
    return res.status(400).json({ error: "Bu iş zaten tamamlanmış" });
  const ts = nowStrTR();
  // Planlı bakım — arızi onarımın aksine — ayrıca bir doğrulama gerektirmez:
  // doğrudan KAPATILDI'ya geçer. İç PM checklist'iyle aynı madde seti burada
  // da kullanılır (checklist_done), tedarikçinin gördüğü sorunlar not olarak
  // eklenebilir.
  wo.status = "KAPATILDI";
  wo.closed_at = ts;
  wo.checklist_done = Array.isArray(req.body.checklist_done) ? req.body.checklist_done : [];
  wo.description = (wo.description || "") + (req.body.note ? ` | Tedarikçi notu: ${req.body.note}` : "");
  await store.upsertWorkOrder(wo);
  broadcast({ type: "wo_updated", wo });
  // Şot sayacı tamamlanma anında sıfırlanır.
  const molds = await store.getMolds();
  const mold = molds.find(m => m.id === wo.mold_id);
  if (mold) {
    mold.pm_counter = 0;
    mold.last_pm_date = ts.split(" ")[0];
    await store.upsertMold(mold);
    broadcast({ type: "molds_replaced", molds });
  }
  await addAudit(req.user.id, supplierName, "tedarikci", "Tedarikçi Planlı Bakımı Tamamladı", "wo", wo.id,
    `${wo.mold_id} için planlı bakım tamamlandı ve kapatıldı`);
  res.json({ ok: true, wo });
});

// ── Tedarikçi arıza bildirimi + (opsiyonel) teklif ──
// Akış: tedarikçi arızayı bildirir; kırılımlı fiyat teklifi eklemesi
// ZORUNLU DEĞİL — sadece bilgilendirmek isterse teklif_items boş geçilir.
//   • teklif_items doluysa → TEKLIF_BEKLIYOR (fiyatlı, onay gerekiyor)
//   • teklif_items boşsa  → BILDIRIM_BEKLIYOR (fiyatsız, sadece bilgi notu)
// Her iki durumda da fabrika tarafı aynı onay ekranından karar verir: kabul
// ederse (DEVAM_EDİYOR, tedarikçi çalışır) veya reddederse (kalıp "Bakımda"ya
// alınır, iş iç arıza havuzuna düşer). Onaylanan işte tedarikçi numune
// gönderdiğini işaretlemeden tamamlayamaz → tamamlanınca genel kalite onayı
// ayarından BAĞIMSIZ olarak her zaman KALITE_BEKLIYOR'a düşer (tedarikçi
// kendi yaptığı iş için ayrıca bir güven kontrolü).
app.post("/api/supplier/ariz", auth, supplierOnly, validate(supplierArizCreateSchema), async (req, res) => {
  const supplierName = await getSupplierName(req.user.id);
  if (!supplierName) return res.status(403).json({ error: "Tedarikçi kimliği tanımlı değil — admin ile iletişime geçin" });
  const molds = await store.getMolds();
  const mold = molds.find(m => m.id === req.body.mold_id);
  if (!mold || mold.status !== "Transfer" || mold.transfer_to !== supplierName)
    return res.status(403).json({ error: "Bu kalıp şu an sizde görünmüyor" });
  const wos = await store.getWorkOrders();
  const maxNum = wos.reduce((max, w) => {
    const m = (w.id || "").match(/LG-(\d+)/);
    return m ? Math.max(max, parseInt(m[1])) : max;
  }, 0);
  const id = "LG-" + String(maxNum + 1).padStart(3, "0");
  const ts = nowStrTR();
  const items = req.body.teklif_items || [];
  const hasTeklif = items.length > 0;
  const teklifTotal = items.reduce((s, it) => s + it.price, 0);
  const wo = {
    id, mold_id: mold.id, type: "DIŞ_ARIZ", status: hasTeklif ? "TEKLIF_BEKLIYOR" : "BILDIRIM_BEKLIYOR", priority: "NORMAL",
    cavity_no: req.body.cavity_no || null,
    description: req.body.description,
    teklif_items: items, teklif_total: teklifTotal,
    sample_sent: false,
    assigned: null, reported_by: req.user.id, created_at: ts, started_at: null, closed_at: null,
    source: "tedarikci_portali", supplier_name: supplierName,
  };
  await store.upsertWorkOrder(wo);
  broadcast({ type: "wo_updated", wo });
  await addAudit(req.user.id, supplierName, "tedarikci", hasTeklif ? "Tedarikçi Teklifi Gönderildi" : "Tedarikçi Bildirimi Gönderildi", "wo", id,
    hasTeklif
      ? `${mold.id} için arıza bildirdi, teklif tutarı ₺${teklifTotal.toLocaleString("tr-TR")}, onay bekliyor`
      : `${mold.id} için teklifsiz arıza bildirimi yapıldı, onay bekliyor`);
  res.json({ ok: true, wo });
});

app.post("/api/supplier/ariz/:id/sample-sent", auth, supplierOnly, validate(supplierSampleSentSchema), async (req, res) => {
  const supplierName = await getSupplierName(req.user.id);
  if (!supplierName) return res.status(403).json({ error: "Tedarikçi kimliği tanımlı değil — admin ile iletişime geçin" });
  const wo = await store.getWorkOrderById(req.params.id);
  if (!wo || wo.source !== "tedarikci_portali" || wo.supplier_name !== supplierName)
    return res.status(404).json({ error: "İş emri bulunamadı" });
  if (wo.status !== "DEVAM_EDİYOR")
    return res.status(400).json({ error: "Numune, ancak teklif onaylandıktan sonra gönderilebilir" });
  wo.sample_sent = true;
  wo.sample_sent_at = nowStrTR();
  await store.upsertWorkOrder(wo);
  broadcast({ type: "wo_updated", wo });
  await addAudit(req.user.id, supplierName, "tedarikci", "Tedarikçi Numune Gönderdi", "wo", wo.id,
    `${wo.mold_id} için numune gönderildi`);
  res.json({ ok: true, wo });
});

app.post("/api/supplier/ariz/:id/complete", auth, supplierOnly, validate(supplierArizCompleteSchema), async (req, res) => {
  const supplierName = await getSupplierName(req.user.id);
  if (!supplierName) return res.status(403).json({ error: "Tedarikçi kimliği tanımlı değil — admin ile iletişime geçin" });
  const wo = await store.getWorkOrderById(req.params.id);
  if (!wo || wo.source !== "tedarikci_portali" || wo.supplier_name !== supplierName)
    return res.status(404).json({ error: "İş emri bulunamadı" });
  if (wo.status !== "DEVAM_EDİYOR")
    return res.status(400).json({ error: "Bu iş tamamlanabilir durumda değil" });
  if (!wo.sample_sent)
    return res.status(400).json({ error: "Tamamlamadan önce numune gönderdiğinizi işaretlemelisiniz" });
  const ts = nowStrTR();
  // Genel kalite onayı ayarı kapalı olsa bile, tedarikçinin kendi yaptığı
  // tadilat/onarım HER ZAMAN kalite onayına gider — bu, ayrı ve koşulsuz
  // bir güven kontrolüdür (bkz. kullanıcı talebi).
  wo.status = "KALITE_BEKLIYOR";
  wo.closed_at = null;
  wo.description = (wo.description || "") + (req.body.note ? ` | Tedarikçi notu: ${req.body.note}` : "");
  await store.upsertWorkOrder(wo);
  broadcast({ type: "wo_updated", wo });
  await addAudit(req.user.id, supplierName, "tedarikci", "Tedarikçi Onarımı Tamamladı", "wo", wo.id,
    `${wo.mold_id} için onarım tamamlandı, kalite onayı bekliyor`);
  res.json({ ok: true, wo });
});

// ── Admin (varsayılan) / yetkili lider: tedarikçi teklif+bildirimlerini onayla/reddet ──
// Bu iki route, hem fiyat teklifi (TEKLIF_BEKLIYOR) hem de fiyatsız bildirim
// (BILDIRIM_BEKLIYOR) durumundaki işleri aynı şekilde işler — onay her iki
// durumda da tedarikçiyi çalışmaya başlatır, red her iki durumda da kalıbı
// fiziksel olarak geri getirir.
const TEKLIF_PENDING_STATUSES = ["TEKLIF_BEKLIYOR", "BILDIRIM_BEKLIYOR"];
app.post("/api/workorders/:id/teklif-approve", auth, async (req, res) => {
  if (!["admin", "leader"].includes(req.user.role)) return res.status(403).json({ error: "Yetkisiz" });
  const wo = await store.getWorkOrderById(req.params.id);
  if (!wo || !TEKLIF_PENDING_STATUSES.includes(wo.status)) return res.status(404).json({ error: "Onay bekleyen kayıt bulunamadı" });
  wo.status = "DEVAM_EDİYOR";
  wo.started_at = nowStrTR();
  wo.teklif_decision = "approved";
  wo.teklif_decided_by = req.user.id;
  wo.teklif_decided_by_name = req.user.name;
  wo.teklif_decided_at = nowStrTR();
  await store.upsertWorkOrder(wo);
  broadcast({ type: "wo_updated", wo });
  await addAudit(req.user.id, req.user.name, req.user.role, "Tedarikçi Bildirimi Onaylandı", "wo", wo.id,
    `${wo.mold_id} için ${wo.supplier_name} bildirimi onaylandı` + (wo.teklif_total ? ` (₺${wo.teklif_total.toLocaleString("tr-TR")})` : " (teklifsiz)"));
  res.json({ ok: true, wo });
});

app.post("/api/workorders/:id/teklif-reject", auth, validate(teklifRejectSchema), async (req, res) => {
  if (!["admin", "leader"].includes(req.user.role)) return res.status(403).json({ error: "Yetkisiz" });
  const wo = await store.getWorkOrderById(req.params.id);
  if (!wo || !TEKLIF_PENDING_STATUSES.includes(wo.status)) return res.status(404).json({ error: "Onay bekleyen kayıt bulunamadı" });
  // Kalıp fiziksel olarak geri döndüğü kabul edilir — durum "Bakımda"ya alınır
  // (Transfer'de kalmaz) ve iş, iç arıza havuzuna atanmamış olarak düşer.
  wo.status = "BEKLEMEDE";
  wo.assigned = null;
  wo.description = (wo.description || "") + (req.body.reason ? ` | Reddedildi: ${req.body.reason}` : " | Reddedildi, kalıp iç bünyede onarılacak");
  wo.teklif_decision = "rejected";
  wo.teklif_decided_by = req.user.id;
  wo.teklif_decided_by_name = req.user.name;
  wo.teklif_decided_at = nowStrTR();
  wo.teklif_reject_reason = req.body.reason || null;
  await store.upsertWorkOrder(wo);
  broadcast({ type: "wo_updated", wo });
  const molds = await store.getMolds();
  const mold = molds.find(m => m.id === wo.mold_id);
  if (mold) {
    mold.status = "Bakımda";
    await store.upsertMold(mold);
    broadcast({ type: "molds_replaced", molds });
  }
  await addAudit(req.user.id, req.user.name, req.user.role, "Tedarikçi Bildirimi Reddedildi", "wo", wo.id,
    `${wo.mold_id} için ${wo.supplier_name} bildirimi reddedildi, kalıp Bakımda'ya alındı, iç arıza havuzuna düştü`);
  res.json({ ok: true, wo });
});

app.get("/api/system/info", auth, adminOnly, async (req, res) => {
  const [molds, wos, auditPage, users, storageInfo] = await Promise.all([
    store.getMolds(), store.getWorkOrders(), store.getAuditLogPage(1), store.getUsers(), store.getStorageInfo(),
  ]);
  res.json({
    db_size_kb:    storageInfo.sizeKb || 0,
    db_path:       storageInfo.kind === "postgres" ? "postgresql" : storageInfo.path,
    wos:           wos.length,
    molds:         molds.length,
    audit_entries: auditPage.total,
    active_users:  users.filter(u=>u.active).length,
    node_version:  process.version,
    uptime_sec:    Math.round(process.uptime()),
    memory_mb:     Math.round(process.memoryUsage().heapUsed/1024/1024),
    storage:       storageInfo.kind === "postgres" ? "postgresql" : "disk",
  });
});

app.post("/api/system/reset", auth, adminOnly, validate(systemResetSchema), async (req, res) => {
  const { type } = req.body;
  if (type === "auditlog") { await store.clearAuditLog(); }
  await addAudit(req.user.id, req.user.name, req.user.role, "Sistem Sıfırlama", "system", type, `${type} sıfırlandı`);
  res.json({ ok: true });
});

// /tv — Doğrudan TV Modu (login gerektirmez)
app.get("/tv", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "tv.html"));
});

// ── STATİK + SPA ──
app.use(express.static(path.join(__dirname,"public"), {
  index: "index.html",
  maxAge:"1d",
  setHeaders(res,fp) { if(fp.endsWith(".html")) res.setHeader("Cache-Control","no-cache"); }
}));
app.get("*", (req,res) => res.sendFile(path.join(__dirname,"public","index.html")));

function startListen() {
  const httpServer = app.listen(PORT, "0.0.0.0", () => {
    console.log(`CMMS v15 → http://0.0.0.0:${PORT}`);
    console.log(`Depolama → ${pgPool ? "PostgreSQL (kalıcı)" : DATA_DIR}`);
  });
  setupWebSocket(httpServer);
}

module.exports = { app, initServer, initData };

if (require.main === module) {
  initServer();
}
