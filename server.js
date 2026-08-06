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
  { id:"U001", name:"Admin Yönetici", role:"admin", username:"admin", password_hash: bcrypt.hashSync("admin123",10), active:true, must_change_password:true },
  { id:"U002", name:"Uğur Bükücü", role:"admin", username:"ugur.bukucu", password_hash: bcrypt.hashSync("1234",10), active:true, must_change_password:true },
  { id:"U003", name:"Ersin Donat", role:"leader", username:"ersin.donat", password_hash: bcrypt.hashSync("1234",10), active:true, must_change_password:true },
  { id:"U004", name:"İbrahim Kaya", role:"tech", username:"ibrahim.kaya", password_hash: bcrypt.hashSync("1234",10), active:true, must_change_password:true },
  { id:"U005", name:"Bilal Aslan", role:"tech", username:"bilal.aslan", password_hash: bcrypt.hashSync("1234",10), active:true, must_change_password:true },
  { id:"U006", name:"Doğan Tor", role:"tech", username:"dogan.tor", password_hash: bcrypt.hashSync("1234",10), active:true, must_change_password:true },
  { id:"U007", name:"Yusuf Şen", role:"tech", username:"yusuf.sen", password_hash: bcrypt.hashSync("1234",10), active:true, must_change_password:true },
  { id:"U008", name:"Hamdi Çakır", role:"tech", username:"hamdi.cakir", password_hash: bcrypt.hashSync("1234",10), active:true, must_change_password:true },
  { id:"U009", name:"Ferhat Koçuk", role:"op", username:"ferhat.kocuk", password_hash: bcrypt.hashSync("1234",10), active:true, must_change_password:true },
  { id:"U010", name:"Mehmet Kahraman", role:"op", username:"mehmet.kahraman", password_hash: bcrypt.hashSync("1234",10), active:true, must_change_password:true },
  { id:"U011", name:"Mehmet Yılmaz", role:"op", username:"mehmet.yilmaz", password_hash: bcrypt.hashSync("1234",10), active:true, must_change_password:true },
  { id:"U012", name:"İsmail Açıkgöz", role:"op", username:"ismail.acikgoz", password_hash: bcrypt.hashSync("1234",10), active:true, must_change_password:true },
  { id:"U013", name:"Murat Akgün", role:"op", username:"murat.akgun", password_hash: bcrypt.hashSync("1234",10), active:true, must_change_password:true },
  { id:"U014", name:"Gökhan Koçak", role:"op", username:"gokhan.kocak", password_hash: bcrypt.hashSync("1234",10), active:true, must_change_password:true },
  { id:"U015", name:"Cüneyt Dincel", role:"op", username:"cuneyt.dincel", password_hash: bcrypt.hashSync("1234",10), active:true, must_change_password:true },
  { id:"U016", name:"Gökhan Karadeniz", role:"op", username:"gokhan.karadeniz", password_hash: bcrypt.hashSync("1234",10), active:true, must_change_password:true },
  { id:"U017", name:"Muhammed Akyol", role:"op", username:"muhammed.akyol", password_hash: bcrypt.hashSync("1234",10), active:true, must_change_password:true }
];

const jwt         = require("jsonwebtoken");
const path        = require("path");
const fs          = require("fs");
const compression = require("compression");
const rateLimit    = require("express-rate-limit");

const app  = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "cmms-v15-change-me-in-production";
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

const DATA_DIR  = process.env.DB_DIR || path.join(__dirname, "data");
const DATA_FILE = path.join(DATA_DIR, "cmms_data.json");
const PG_URL    = process.env.DATABASE_URL || null;

if (!fs.existsSync(DATA_DIR)) { try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch(e) {} }

// ── Bellek içi DB ──
// Kalıcılık: DATABASE_URL varsa PostgreSQL (Neon — ücretsiz, kalıcı),
//            yoksa JSON dosyası (lokal geliştirme)
let DB = { users: [], state: null, auditLog: [] };
let pgPool = null;

if (PG_URL) {
  const { Pool } = require("pg");
  pgPool = new Pool({
    connectionString: PG_URL,
    ssl: { rejectUnauthorized: false },
    max: 3
  });
  console.log("🐘 PostgreSQL modu aktif (kalıcı depolama)");
}

async function loadDB() {
  if (pgPool) {
    try {
      await pgPool.query(
        "CREATE TABLE IF NOT EXISTS cmms_store (id INT PRIMARY KEY DEFAULT 1, data JSONB NOT NULL, updated_at TIMESTAMPTZ DEFAULT now())"
      );
      const r = await pgPool.query("SELECT data FROM cmms_store WHERE id = 1");
      if (r.rows.length > 0 && r.rows[0].data) {
        DB = r.rows[0].data;
        const woCount = (DB.state && DB.state.wos) ? DB.state.wos.length : 0;
        console.log(`✅ Veri PostgreSQL'den yüklendi (${woCount} iş emri)`);
        return;
      }
      console.log("ℹ PostgreSQL boş — ilk kurulum");
      return;
    } catch(e) {
      console.error("❌ PostgreSQL hatası:", e.message, "— dosya moduna düşülüyor");
      pgPool = null;
    }
  }
  try {
    if (fs.existsSync(DATA_FILE)) {
      DB = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
      console.log(`✅ Veri dosyadan yüklendi (${Math.round(fs.statSync(DATA_FILE).size/1024)} KB)`);
    }
  } catch(e) { console.warn("Veri yüklenemedi:", e.message); }
}

let _saveTimer = null;
let _saving = false;
function saveDB() {
  clearTimeout(_saveTimer);
  _saveTimer = setTimeout(async () => {
    if (pgPool) {
      if (_saving) { saveDB(); return; }
      _saving = true;
      try {
        await pgPool.query(
          "INSERT INTO cmms_store (id, data, updated_at) VALUES (1, $1, now()) ON CONFLICT (id) DO UPDATE SET data = $1, updated_at = now()",
          [JSON.stringify(DB)]
        );
      } catch(e) { console.warn("PG kaydetme hatası:", e.message); }
      _saving = false;
    } else {
      try { fs.writeFileSync(DATA_FILE, JSON.stringify(DB), "utf8"); }
      catch(e) { console.warn("Kaydetme hatası:", e.message); }
    }
  }, 800);
}

function addAudit(userId, userName, role, action, entityType, entityId, detail) {
  if (!DB.auditLog) DB.auditLog = [];
  DB.auditLog.push({
    ts: new Date().toISOString().replace("T"," ").slice(0,19),
    user_id: userId, user_name: userName, role,
    action, entity_type: entityType, entity_id: entityId, detail
  });
  if (DB.auditLog.length > 2000) DB.auditLog = DB.auditLog.slice(-2000);
  saveDB();
}

// İlk yükleme — async başlangıç
async function initServer() {
  await loadDB();
  ensureDemoUsers();
  migrateExistingUsersPasswordFlag();
  startListen();
}

function ensureDemoUsers() {
// Demo kullanıcılar yoksa oluştur
if (!DB.users || DB.users.length === 0) {
  DB.users = SEED_USERS();
  DB.auditLog = [];
  saveDB();
  console.log("✅ Demo kullanıcılar oluşturuldu  →  admin / admin123");
}
}

// ── GÖÇ: v15.6 öncesi oluşturulan kullanıcılarda must_change_password alanı yok ──
// Bu alan hiç tanımlı değilse (eski kayıt), güvenlik gereği ZORUNLU işaretlenir.
// Kullanıcı bir kez şifresini değiştirdiğinde alan false olur ve bir daha tetiklenmez —
// bu fonksiyon sadece alanı hiç GÖRMEMİŞ kayıtlara dokunur, idempotent'tir.
function migrateExistingUsersPasswordFlag() {
  if (!DB.users || DB.users.length === 0) return;
  var migrated = 0;
  DB.users.forEach(function(u) {
    if (!("must_change_password" in u)) {
      u.must_change_password = true;
      migrated++;
    }
  });
  if (migrated > 0) {
    saveDB();
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
app.post("/api/login", loginLimiter, (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Eksik bilgi" });
  const uname = String(username).trim();
  const u = (DB.users||[]).find(x => x.username === uname && x.active);
  if (!u || !bcrypt.compareSync(password, u.password_hash))
    return res.status(401).json({ error: "Kullanıcı adı veya şifre hatalı" });
  const prev = ACTIVE_SESSIONS[u.id];
  const sid = newSid();
  ACTIVE_SESSIONS[u.id] = { sid, at: nowStrTR(), ua: String(req.headers["user-agent"] || "").slice(0, 80) };
  const token = jwt.sign({ id:u.id, username:u.username, role:u.role, name:u.name, sid }, JWT_SECRET, { expiresIn:"30m" });
  if (prev) addAudit(u.id, u.name, u.role, "Oturum Devralındı", "auth", null, `${u.name} yeni cihazdan giriş yaptı — önceki oturum sonlandırıldı`);
  else addAudit(u.id, u.name, u.role, "Giriş", "auth", null, `${u.name} sisteme giriş yaptı`);
  res.json({
    token,
    user: { id:u.id, name:u.name, role:u.role, username:u.username },
    takeover: !!prev,
    must_change_password: !!u.must_change_password
  });
});

// ── ŞİFRE DEĞİŞTİRME (kendi hesabı) ──
app.post("/api/change-password", auth, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) return res.status(400).json({ error: "Eksik bilgi" });
  if (String(newPassword).length < MIN_PASSWORD_LEN)
    return res.status(400).json({ error: `Yeni şifre en az ${MIN_PASSWORD_LEN} karakter olmalı` });
  const u = (DB.users||[]).find(x => x.id === req.user.id && x.active);
  if (!u) return res.status(404).json({ error: "Kullanıcı bulunamadı" });
  if (!bcrypt.compareSync(currentPassword, u.password_hash))
    return res.status(401).json({ error: "Mevcut şifre hatalı" });
  u.password_hash = bcrypt.hashSync(newPassword, 10);
  u.must_change_password = false;
  addAudit(u.id, u.name, u.role, "Şifre Değiştirildi", "user", u.id, `${u.name} kendi şifresini değiştirdi`);
  saveDB();
  res.json({ ok: true });
});

app.post("/api/logout", auth, (req, res) => {
  addAudit(req.user.id, req.user.name, req.user.role, "Çıkış", "auth", null, `${req.user.name} çıkış yaptı`);
  res.json({ ok: true });
});

// ── STATE ──
app.get("/api/state", auth, (req, res) => {
  if (!DB.state) return res.json(null);
  const state = { ...DB.state };
  state.users = (DB.users||[]).filter(u=>u.active)
    .map(u => ({ id:u.id, name:u.name, role:u.role, username:u.username, user:u.username, pass:"" }));
  state.auditLog = DB.auditLog || [];
  res.json(state);
});

// ── ROL BAZLI YAZMA KORUMASI ──
// admin/leader: tam yetki (kalıp/maliyet/yedek parça dahil).
// tech/op: kalıp ana verisini (parça adı, göz sayısı, PM aralığı, konum vb.) DEĞİŞTİREMEZ,
// sadece kendi iş akışının doğal sonucu olan PM sayaç alanlarını güncelleyebilir.
// Yedek parça kataloğu (stok/fiyat) tech/op için tamamen salt-okunurdur.
// Not: iş emirleri (wos) bu fonksiyonun kapsamı dışında — mevcut merge mantığıyla yönetilir,
// çünkü havuzdan iş üstlenme/devretme gibi meşru çok kullanıcılı akışlar zaten var.
const MOLD_FIELDS_TECH_CAN_EDIT = new Set(["pm_counter", "total_shots", "last_pm_date", "is_regular", "regular_days", "regular_updated"]);
function sanitizeStateForRole(role, serverState, incoming) {
  if (role === "admin" || role === "leader") return incoming;
  const sanitized = { ...incoming };
  const serverMolds = (serverState && serverState.molds) || [];
  const clientMolds = incoming.molds;
  if (Array.isArray(clientMolds)) {
    const clientMap = new Map(clientMolds.map(m => [m.id, m]));
    sanitized.molds = serverMolds.map(sm => {
      const cm = clientMap.get(sm.id);
      if (!cm) return sm; // istemci bu kalıbı göndermemiş — sunucu korur (silme/kayıp engellenir)
      const merged = { ...sm };
      for (const f of MOLD_FIELDS_TECH_CAN_EDIT) {
        if (cm[f] !== undefined) merged[f] = cm[f];
      }
      return merged; // diğer tüm alanlar (parça adı, göz, PM aralığı, konum...) sunucu değerinde kalır
    });
    // İstemcinin yeni kalıp eklemeye çalışması (sunucuda olmayan id) sessizce yok sayılır.
  }
  if ("spareparts" in sanitized) sanitized.spareparts = (serverState && serverState.spareparts) || [];
  return sanitized;
}

app.post("/api/state", (req, res, next) => {
  // sendBeacon token'ı query param olarak gönderir
  if (req.query.token && !req.headers.authorization) {
    req.headers.authorization = "Bearer " + req.query.token;
  }
  auth(req, res, next);
}, (req, res) => {
  const { users, auditLog, deleted_wo_ids, ...rawRest } = req.body;
  const rest = sanitizeStateForRole(req.user.role, DB.state, rawRest);

  // ── WO MERGE: başkalarının eklediği/değiştirdiği işleri koru ──
  const serverWos = (DB.state && DB.state.wos) ? DB.state.wos : [];
  const clientWos = rest.wos || [];
  const deletedIds = new Set(deleted_wo_ids || []);
  
  const clientMap = new Map(clientWos.map(w => [w.id, w]));
  const merged = [];
  const seen = new Set();
  
  // 1. Sunucudaki her WO: istemcide varsa istemci versiyonu (daha güncel olabilir),
  //    istemcide yoksa ve silinmemişse KORU (başkası eklemiş olabilir)
  for (const sw of serverWos) {
    if (deletedIds.has(sw.id)) continue; // istemci bilinçli silmiş
    if (clientMap.has(sw.id)) {
      // Çakışma çözümü: SADECE updated_at karşılaştırılır (created_at'e düşme!)
      // created_at yerel saat, updated_at UTC — karıştırılamaz.
      const cw = clientMap.get(sw.id);
      const sHas = !!sw.updated_at;
      const cHas = !!cw.updated_at;
      if (sHas && cHas) {
        // İkisinde de damga var — yeni olan kazanır
        const sTime = new Date(sw.updated_at).getTime();
        const cTime = new Date(cw.updated_at).getTime();
        merged.push(cTime >= sTime ? cw : sw);
      } else if (cHas && !sHas) {
        merged.push(cw); // sadece client değişmiş — client kazanır
      } else if (sHas && !cHas) {
        merged.push(sw); // sadece sunucu değişmiş — sunucu kazanır
      } else {
        merged.push(cw); // ikisinde de yok — client kazanır (son gönderen)
      }
    } else {
      merged.push(sw); // istemci görmemiş — koru!
    }
    seen.add(sw.id);
  }
  // 2. İstemcide olup sunucuda olmayan yeni WO'lar
  for (const cw of clientWos) {
    if (!seen.has(cw.id) && !deletedIds.has(cw.id)) merged.push(cw);
  }
  
  rest.wos = merged;
  DB.state = rest;
  saveDB();
  res.json({ ok: true, woCount: merged.length });
});

// ── KULLANICILAR ──
app.get("/api/users", auth, adminOnly, (req, res) => {
  res.json((DB.users||[]).map(u => ({ id:u.id, name:u.name, role:u.role, username:u.username, active:u.active })));
});

app.post("/api/users", auth, adminOnly, (req, res) => {
  let { id, name, role, username, password } = req.body;
  if (!id||!name||!role||!username||!password) return res.status(400).json({ error:"Tüm alanlar zorunlu" });
  if (String(password).length < MIN_PASSWORD_LEN)
    return res.status(400).json({ error:`Şifre en az ${MIN_PASSWORD_LEN} karakter olmalı` });
  username = String(username).trim();
  name = String(name).trim();
  if (!username) return res.status(400).json({ error:"Kullanıcı adı boş olamaz" });

  const existing = (DB.users||[]).find(u => u.username.toLowerCase() === username.toLowerCase());
  if (existing && existing.active && existing.id !== id) {
    return res.status(400).json({ error:"Bu kullanıcı adı zaten kullanılıyor" });
  }
  // Pasif (silinmiş) veya aynı id'li kayıt varsa üzerine yaz — username yeniden kullanılabilir
  DB.users = (DB.users||[]).filter(u =>
    u.id !== id && u.username.toLowerCase() !== username.toLowerCase()
  );
  // Admin başkası için şifre belirlediğinde ilk girişte değiştirme zorunluluğu
  DB.users.push({ id, name, role, username, password_hash: bcrypt.hashSync(password,10), active:true, must_change_password:true });
  addAudit(req.user.id, req.user.name, req.user.role, "Kullanıcı Eklendi", "user", id, `${name} (${role}) eklendi`);
  saveDB();
  res.json({ ok: true });
});

app.put("/api/users/:id", auth, adminOnly, (req, res) => {
  let { name, role, username, password } = req.body;
  if (password && String(password).length < MIN_PASSWORD_LEN)
    return res.status(400).json({ error:`Şifre en az ${MIN_PASSWORD_LEN} karakter olmalı` });
  username = username ? String(username).trim() : username;
  name = name ? String(name).trim() : name;
  const u = (DB.users||[]).find(x=>x.id===req.params.id);
  if (!u) {
    // Kullanıcı sunucuda yok (eski sürümden kalan yerel kayıt) — şifre verildiyse oluştur
    if (!password) return res.status(404).json({ error:"Kullanıcı sunucuda yok. Şifre girerek kaydedin, yeniden oluşturulsun." });
    const clash = (DB.users||[]).find(x => x.username.toLowerCase() === username.toLowerCase() && x.active);
    if (clash) return res.status(400).json({ error:"Bu kullanıcı adı zaten kullanılıyor" });
    DB.users = (DB.users||[]).filter(x => x.username.toLowerCase() !== username.toLowerCase());
    DB.users.push({ id: req.params.id, name, role, username, password_hash: bcrypt.hashSync(password,10), active:true, must_change_password:true });
    addAudit(req.user.id, req.user.name, req.user.role, "Kullanıcı Oluşturuldu (kurtarma)", "user", req.params.id, `${name} sunucuya kaydedildi`);
    saveDB();
    return res.json({ ok: true, created: true });
  }
  if (name) u.name=name;
  if (role) u.role=role;
  if (username) u.username=username;
  u.active = true;
  // Admin başkasının şifresini sıfırladığında ilk girişte değiştirme zorunluluğu
  if (password) { u.password_hash = bcrypt.hashSync(password,10); u.must_change_password = true; }
  addAudit(req.user.id, req.user.name, req.user.role, "Kullanıcı Düzenlendi", "user", req.params.id, `${u.name} güncellendi`);
  saveDB();
  res.json({ ok: true });
});

app.delete("/api/users/:id", auth, adminOnly, (req, res) => {
  if (req.params.id===req.user.id) return res.status(400).json({ error:"Kendinizi silemezsiniz" });
  const u = (DB.users||[]).find(x=>x.id===req.params.id);
  if (u) { u.active=false; saveDB(); }
  addAudit(req.user.id, req.user.name, req.user.role, "Kullanıcı Silindi", "user", req.params.id, "Pasif yapıldı");
  res.json({ ok: true });
});

// ── AUDİT ──
app.post("/api/audit", auth, (req, res) => {
  const { action, entity_type, entity_id, detail } = req.body;
  if (!action) return res.status(400).json({ error:"action zorunlu" });
  addAudit(req.user.id, req.user.name, req.user.role, action, entity_type||null, entity_id||null, detail||null);
  res.json({ ok: true });
});

app.get("/api/audit", auth, adminOnly, (req, res) => {
  const logs = [...(DB.auditLog||[])].reverse().slice(0,500);
  res.json({ rows: logs, total: (DB.auditLog||[]).length });
});

// ── SİSTEM ──
app.get("/api/health", (req, res) => res.json({ status:"ok", version:"15.0.0" }));

// GET /api/tv — Giriş gerektirmeyen TV modu verisi
app.get("/api/tv", (req, res) => {
  const state = DB.state || {};
  const molds = state.molds || [];
  const wos = state.wos || [];
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
      const u = w.assigned ? (DB.users||[]).find(x=>x.id===w.assigned) : null;
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
app.post("/api/users/force-password-reset", auth, adminOnly, (req, res) => {
  var count = 0;
  (DB.users || []).forEach(function(u) {
    if (u.active && u.id !== req.user.id) { // kendi hesabını zorunlu kılmaz — o zaten değiştirebilir
      u.must_change_password = true;
      count++;
    }
  });
  addAudit(req.user.id, req.user.name, req.user.role, "Toplu Şifre Sıfırlama Zorunluluğu", "user", "all",
    `${count} kullanıcı bir sonraki girişte şifre değiştirmeye zorlandı`);
  saveDB();
  res.json({ ok: true, count: count });
});

app.post("/api/users/reset-seed", auth, (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Yetkisiz" });
  const mode = req.body.mode || "merge"; // "merge" = eksikleri ekle, "replace" = tümünü değiştir
  const seed = SEED_USERS();
  
  if (mode === "replace") {
    // Tüm kullanıcıları sabit listeyle değiştir
    DB.users = seed;
  } else {
    // MERGE: mevcut olmayan kullanıcıları ekle (username bazlı)
    const existingUsernames = new Set(DB.users.map(u => u.username));
    const existingIds = new Set(DB.users.map(u => u.id));
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
        DB.users.push(newUser);
        existingIds.add(newUser.id);
        existingUsernames.add(newUser.username);
        added++;
      }
    }
    addAudit(req.user.id, req.user.name, req.user.role, "Kullanıcılar Yüklendi", "user", "seed",
      `${added} yeni kullanıcı eklendi (merge)`);
    saveDB();
    return res.json({ ok: true, mode: "merge", added: added, total: DB.users.length });
  }
  
  addAudit(req.user.id, req.user.name, req.user.role, "Kullanıcılar Sıfırlandı", "user", "seed",
    `Tüm kullanıcılar sabit listeyle değiştirildi (${seed.length} kişi)`);
  saveDB();
  res.json({ ok: true, mode: "replace", total: DB.users.length });
});

// POST /api/workorders — Doğrudan iş emri oluştur (arıza bildirimi)
app.post("/api/workorders", auth, (req, res) => {
  const wo = req.body;
  if (!wo || !wo.mold_id || !wo.type) return res.status(400).json({ error: "Kalıp ve tip zorunlu" });
  
  // ID ata
  if (!wo.id) {
    const existing = (DB.state && DB.state.wos) ? DB.state.wos : [];
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
  
  // State'e ekle
  if (!DB.state) DB.state = { molds: [], wos: [] };
  if (!DB.state.wos) DB.state.wos = [];
  DB.state.wos.push(wo);
  
  // Audit log
  addAudit(req.user.id, req.user.name, req.user.role, "Arıza Bildirimi", "wo", wo.id,
    `${wo.mold_id} — ${wo.type}: ${(wo.description||"").slice(0,60)}`);
  
  saveDB();
  console.log(`📋 Yeni WO: ${wo.id} (${wo.mold_id}) by ${req.user.name}`);
  res.json({ ok: true, wo: wo });
});

// POST /api/tv/claim — İş emri üstlenme (login gerekli)
app.post("/api/tv/claim", auth, (req, res) => {
  const { wo_id } = req.body;
  if (!wo_id) return res.status(400).json({ error: "wo_id gerekli" });
  if (!DB.state || !DB.state.wos) return res.status(404).json({ error: "İş emri bulunamadı" });
  const wo = DB.state.wos.find(w => w.id === wo_id);
  if (!wo) return res.status(404).json({ error: "İş emri bulunamadı" });
  if (!["leader","tech"].includes(req.user.role)) return res.status(403).json({ error: "Sadece lider ve teknisyenler iş üstlenebilir" });
  if (wo.assigned && wo.status !== "BEKLEMEDE") return res.status(400).json({ error: "Bu iş zaten atanmış" });
  wo.assigned = req.user.id;
  wo.status = "DEVAM_EDİYOR";
  wo.assigned_at = wo.assigned_at || nowStrTR();
  wo.started_at = nowStrTR();
  wo.updated_at = new Date().toISOString();
  addAudit(req.user.id, req.user.name, req.user.role, "İş Üstlenildi (TV)", "wo", wo_id,
    req.user.name + " " + wo_id + " iş emrini TV modundan üstlendi");
  saveDB();
  res.json({ ok: true, wo_id, assigned: req.user.name });
});

app.get("/api/system/info", auth, adminOnly, (req, res) => {
  let dbSizeKb = 0;
  try { dbSizeKb = Math.round(fs.statSync(DATA_FILE).size/1024); } catch {}
  res.json({
    db_size_kb:    dbSizeKb,
    db_path:       DATA_FILE,
    wos:           (DB.state?.wos||[]).length,
    molds:         (DB.state?.molds||[]).length,
    audit_entries: (DB.auditLog||[]).length,
    active_users:  (DB.users||[]).filter(u=>u.active).length,
    node_version:  process.version,
    uptime_sec:    Math.round(process.uptime()),
    memory_mb:     Math.round(process.memoryUsage().heapUsed/1024/1024),
    storage:       fs.existsSync(DATA_FILE) ? "disk" : "memory",
  });
});

app.post("/api/system/reset", auth, adminOnly, (req, res) => {
  const { type } = req.body;
  if (type === "auditlog") { DB.auditLog = []; saveDB(); }
  addAudit(req.user.id, req.user.name, req.user.role, "Sistem Sıfırlama", "system", type, `${type} sıfırlandı`);
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
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`CMMS v15 → http://0.0.0.0:${PORT}`);
    console.log(`Depolama → ${pgPool ? "PostgreSQL (kalıcı)" : DATA_FILE}`);
  });
}

initServer();
