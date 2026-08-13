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
        jwt.verify(token, JWT_SECRET);
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

function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h?.startsWith("Bearer ")) return res.status(401).json({ error: "Token gerekli" });
  try {
    const payload = jwt.verify(h.slice(7), JWT_SECRET);
    const cur = ACTIVE_SESSIONS[payload.id];
    if (payload.sid && cur && cur.sid !== payload.sid) {
      return res.status(401).json({ error: "Bu hesap başka bir cihazdan açıldı. Oturumunuz sonlandırıldı.", session_takeover: true });
    }
    req.user = payload; next();
  }
  catch { res.status(401).json({ error: "Geçersiz veya süresi dolmuş token" }); }
}
function adminOnly(req, res, next) {
  if (req.user?.role !== "admin") return res.status(403).json({ error: "Sadece admin" });
  next();
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
    user: { id:u.id, name:u.name, role:u.role, username:u.username },
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
  if (!(await store.hasState())) return res.json(null);
  const [molds, wos, extra, users, auditRecent] = await Promise.all([
    store.getMolds(), store.getWorkOrders(), store.getStateExtra(), store.getUsers(), store.getAuditLogRecent(2000),
  ]);
  const state = { ...extra, molds, wos };
  state.users = users.filter(u=>u.active)
    .map(u => ({ id:u.id, name:u.name, role:u.role, username:u.username, user:u.username, pass:"" }));
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
  const { users, auditLog, deleted_wo_ids, molds: incomingMolds, wos: incomingWos, ...extra } = req.body;

  const serverMolds = await store.getMolds();
  const sanitizedMolds = sanitizeMoldsForRole(req.user.role, serverMolds, incomingMolds);
  await store.replaceMolds(sanitizedMolds);
  broadcast({ type: "molds_replaced", molds: sanitizedMolds });

  // ── WO yazma: satır bazlı upsert, updated_at çakışması db/shared.js'te çözülür ──
  const deletedIds = new Set(deleted_wo_ids || []);
  for (const cw of (incomingWos || [])) {
    if (deletedIds.has(cw.id)) continue; // istemci bilinçli silmiş, aşağıda silinecek
    const applied = await store.upsertWorkOrder(cw);
    if (applied) broadcast({ type: "wo_updated", wo: cw });
  }
  for (const id of deletedIds) {
    await store.deleteWorkOrder(id);
    broadcast({ type: "wo_deleted", id });
  }

  await store.saveStateExtra(sanitizeExtraForRole(req.user.role, extra));

  const allWos = await store.getWorkOrders();
  res.json({ ok: true, woCount: allWos.length });
});

// ── KULLANICILAR ──
app.get("/api/users", auth, adminOnly, async (req, res) => {
  const users = await store.getUsers();
  res.json(users.map(u => ({ id:u.id, name:u.name, role:u.role, username:u.username, active:u.active })));
});

app.post("/api/users", auth, adminOnly, validate(createUserSchema), async (req, res) => {
  let { id, name, role, username, password } = req.body;
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
  users.push({ id, name, role, username, password_hash: bcrypt.hashSync(password,10), active:true, must_change_password:true });
  await store.saveUsers(users);
  await addAudit(req.user.id, req.user.name, req.user.role, "Kullanıcı Eklendi", "user", id, `${name} (${role}) eklendi`);
  res.json({ ok: true });
});

app.put("/api/users/:id", auth, adminOnly, validate(updateUserSchema), async (req, res) => {
  let { name, role, username, password } = req.body;
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
    users.push({ id: req.params.id, name, role, username, password_hash: bcrypt.hashSync(password,10), active:true, must_change_password:true });
    await store.saveUsers(users);
    await addAudit(req.user.id, req.user.name, req.user.role, "Kullanıcı Oluşturuldu (kurtarma)", "user", req.params.id, `${name} sunucuya kaydedildi`);
    return res.json({ ok: true, created: true });
  }
  if (name) u.name=name;
  if (role) u.role=role;
  if (username) u.username=username;
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
  wo.assigned = req.user.id;
  wo.status = "DEVAM_EDİYOR";
  wo.assigned_at = wo.assigned_at || nowStrTR();
  wo.started_at = nowStrTR();
  wo.updated_at = new Date().toISOString();
  await store.upsertWorkOrder(wo);
  broadcast({ type: "wo_updated", wo });
  await addAudit(req.user.id, req.user.name, req.user.role, "İş Üstlenildi (TV)", "wo", wo_id,
    req.user.name + " " + wo_id + " iş emrini TV modundan üstlendi");
  res.json({ ok: true, wo_id, assigned: req.user.name });
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
