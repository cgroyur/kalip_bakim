"use strict";
const express     = require("express");
const bcrypt      = require("bcryptjs");
const jwt         = require("jsonwebtoken");
const path        = require("path");
const fs          = require("fs");
const compression = require("compression");

const app  = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "cmms-v15-change-me-in-production";

const DATA_DIR  = process.env.DB_DIR || path.join(__dirname, "data");
const DATA_FILE = path.join(DATA_DIR, "cmms_data.json");

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// ── Bellek içi DB (JSON dosyasına persist edilir) ──
let DB = { users: [], state: null, auditLog: [] };

function loadDB() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      DB = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
      console.log(`✅ Veri yüklendi (${Math.round(fs.statSync(DATA_FILE).size/1024)} KB)`);
    }
  } catch(e) { console.warn("Veri yüklenemedi:", e.message); }
}

let _saveTimer = null;
function saveDB() {
  clearTimeout(_saveTimer);
  _saveTimer = setTimeout(() => {
    try { fs.writeFileSync(DATA_FILE, JSON.stringify(DB), "utf8"); }
    catch(e) { console.warn("Kaydetme hatası:", e.message); }
  }, 1000);
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

// İlk yükleme
loadDB();

// Demo kullanıcılar yoksa oluştur
if (!DB.users || DB.users.length === 0) {
  DB.users = [
    { id:"U001", name:"Admin Yönetici", role:"admin",   username:"admin",   password_hash: bcrypt.hashSync("admin123",10), active:true },
    { id:"U002", name:"Mehmet Lider",   role:"leader",  username:"leader1", password_hash: bcrypt.hashSync("1234",10),     active:true },
    { id:"U003", name:"Ali Teknisyen",  role:"tech",    username:"tech1",   password_hash: bcrypt.hashSync("1234",10),     active:true },
    { id:"U004", name:"Veli Teknisyen", role:"tech",    username:"tech2",   password_hash: bcrypt.hashSync("1234",10),     active:true },
    { id:"U005", name:"Kemal Teknisyen",role:"tech",    username:"tech3",   password_hash: bcrypt.hashSync("1234",10),     active:true },
    { id:"U006", name:"Hasan Operatör", role:"op",      username:"op1",     password_hash: bcrypt.hashSync("1234",10),     active:true },
    { id:"U007", name:"İbrahim Oper.",  role:"op",      username:"op2",     password_hash: bcrypt.hashSync("1234",10),     active:true },
  ];
  DB.auditLog = [];
  saveDB();
  console.log("✅ Demo kullanıcılar oluşturuldu  →  admin / admin123");
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
  try { req.user = jwt.verify(h.slice(7), JWT_SECRET); next(); }
  catch { res.status(401).json({ error: "Geçersiz veya süresi dolmuş token" }); }
}
function adminOnly(req, res, next) {
  if (req.user?.role !== "admin") return res.status(403).json({ error: "Sadece admin" });
  next();
}

// ── AUTH ──
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Eksik bilgi" });
  const uname = String(username).trim();
  const u = (DB.users||[]).find(x => x.username === uname && x.active);
  if (!u || !bcrypt.compareSync(password, u.password_hash))
    return res.status(401).json({ error: "Kullanıcı adı veya şifre hatalı" });
  const token = jwt.sign({ id:u.id, username:u.username, role:u.role, name:u.name }, JWT_SECRET, { expiresIn:"30m" });
  addAudit(u.id, u.name, u.role, "Giriş", "auth", null, `${u.name} sisteme giriş yaptı`);
  res.json({ token, user: { id:u.id, name:u.name, role:u.role, username:u.username } });
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

app.post("/api/state", (req, res, next) => {
  // sendBeacon token'ı query param olarak gönderir
  if (req.query.token && !req.headers.authorization) {
    req.headers.authorization = "Bearer " + req.query.token;
  }
  auth(req, res, next);
}, (req, res) => {
  const { users, auditLog, ...rest } = req.body;
  DB.state = rest;
  saveDB();
  res.json({ ok: true });
});

// ── KULLANICILAR ──
app.get("/api/users", auth, adminOnly, (req, res) => {
  res.json((DB.users||[]).map(u => ({ id:u.id, name:u.name, role:u.role, username:u.username, active:u.active })));
});

app.post("/api/users", auth, adminOnly, (req, res) => {
  let { id, name, role, username, password } = req.body;
  if (!id||!name||!role||!username||!password) return res.status(400).json({ error:"Tüm alanlar zorunlu" });
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
  DB.users.push({ id, name, role, username, password_hash: bcrypt.hashSync(password,10), active:true });
  addAudit(req.user.id, req.user.name, req.user.role, "Kullanıcı Eklendi", "user", id, `${name} (${role}) eklendi`);
  saveDB();
  res.json({ ok: true });
});

app.put("/api/users/:id", auth, adminOnly, (req, res) => {
  let { name, role, username, password } = req.body;
  username = username ? String(username).trim() : username;
  name = name ? String(name).trim() : name;
  const u = (DB.users||[]).find(x=>x.id===req.params.id);
  if (!u) {
    // Kullanıcı sunucuda yok (eski sürümden kalan yerel kayıt) — şifre verildiyse oluştur
    if (!password) return res.status(404).json({ error:"Kullanıcı sunucuda yok. Şifre girerek kaydedin, yeniden oluşturulsun." });
    const clash = (DB.users||[]).find(x => x.username.toLowerCase() === username.toLowerCase() && x.active);
    if (clash) return res.status(400).json({ error:"Bu kullanıcı adı zaten kullanılıyor" });
    DB.users = (DB.users||[]).filter(x => x.username.toLowerCase() !== username.toLowerCase());
    DB.users.push({ id: req.params.id, name, role, username, password_hash: bcrypt.hashSync(password,10), active:true });
    addAudit(req.user.id, req.user.name, req.user.role, "Kullanıcı Oluşturuldu (kurtarma)", "user", req.params.id, `${name} sunucuya kaydedildi`);
    saveDB();
    return res.json({ ok: true, created: true });
  }
  if (name) u.name=name;
  if (role) u.role=role;
  if (username) u.username=username;
  u.active = true;
  if (password) u.password_hash = bcrypt.hashSync(password,10);
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
  wo.created_at = wo.created_at || new Date().toISOString().replace("T"," ").slice(0,19);
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
  wo.started_at = new Date().toISOString().replace("T"," ").slice(0,19);
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

app.listen(PORT, "0.0.0.0", () => {
  console.log(`CMMS v15 → http://0.0.0.0:${PORT}`);
  console.log(`Veri     → ${DATA_FILE}`);
});
