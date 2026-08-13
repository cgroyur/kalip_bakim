"use strict";
const fs = require("fs");
const path = require("path");
const { shouldOverwriteWo } = require("./shared");

// Yerel geliştirme için dosya tabanlı store — tek bir dev blob dosyası yerine
// koleksiyon başına bir JSON dosyası (users.json, molds.json, work_orders.json,
// audit_log.json, state_extra.json). Eski tek-blob formatından (cmms_data.json)
// otomatik ve idempotent göç yapar.
function createFileStore(dataDir) {
  const usersFile = path.join(dataDir, "users.json");
  const auditFile = path.join(dataDir, "audit_log.json");
  const moldsFile = path.join(dataDir, "molds.json");
  const wosFile = path.join(dataDir, "work_orders.json");
  const extraFile = path.join(dataDir, "state_extra.json");
  const legacyFile = path.join(dataDir, "cmms_data.json");

  function readJson(file, fallback) {
    try {
      if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, "utf8"));
    } catch (e) { console.warn("Okuma hatası:", file, e.message); }
    return fallback;
  }
  function writeJson(file, data) {
    try { fs.writeFileSync(file, JSON.stringify(data), "utf8"); }
    catch (e) { console.warn("Kaydetme hatası:", file, e.message); }
  }

  let users = [];
  let auditLog = [];
  let molds = [];
  let wos = [];
  let stateExtra = {};

  function migrateLegacyBlobIfNeeded() {
    const alreadyMigrated = fs.existsSync(usersFile) || fs.existsSync(moldsFile) || fs.existsSync(wosFile);
    if (alreadyMigrated) return;
    const legacy = readJson(legacyFile, null);
    if (!legacy) return;
    users = legacy.users || [];
    auditLog = legacy.auditLog || [];
    const legacyState = legacy.state || {};
    molds = legacyState.molds || [];
    wos = legacyState.wos || [];
    const { molds: _m, wos: _w, ...rest } = legacyState;
    stateExtra = rest;
    writeJson(usersFile, users);
    writeJson(auditFile, auditLog);
    writeJson(moldsFile, molds);
    writeJson(wosFile, wos);
    writeJson(extraFile, stateExtra);
    console.log(`🔁 Eski blob formatından yeni koleksiyon dosyalarına göç edildi (${users.length} kullanıcı, ${molds.length} kalıp, ${wos.length} iş emri)`);
  }

  return {
    async init() {
      users = readJson(usersFile, []);
      auditLog = readJson(auditFile, []);
      molds = readJson(moldsFile, []);
      wos = readJson(wosFile, []);
      stateExtra = readJson(extraFile, {});
      migrateLegacyBlobIfNeeded();
    },

    async hasState() { return fs.existsSync(extraFile); },

    // Users
    async getUsers() { return users; },
    async saveUsers(next) { users = next; writeJson(usersFile, users); },

    // Molds
    async getMolds() { return molds; },
    async getMoldIds() { return molds.map((m) => m.id); },
    async upsertMold(mold) {
      const idx = molds.findIndex((m) => m.id === mold.id);
      if (idx >= 0) molds[idx] = mold; else molds.push(mold);
      writeJson(moldsFile, molds);
    },
    async deleteMold(id) { molds = molds.filter((m) => m.id !== id); writeJson(moldsFile, molds); },
    async replaceMolds(nextMolds) {
      const incomingIds = new Set(nextMolds.map((m) => m.id));
      const byId = new Map(molds.map((m) => [m.id, m]));
      for (const m of nextMolds) byId.set(m.id, m);
      for (const id of Array.from(byId.keys())) {
        if (!incomingIds.has(id)) byId.delete(id);
      }
      molds = Array.from(byId.values());
      writeJson(moldsFile, molds);
    },

    // Work orders
    async getWorkOrders() { return wos; },
    async getWorkOrderById(id) { return wos.find((w) => w.id === id) || null; },
    async upsertWorkOrder(wo) {
      const idx = wos.findIndex((w) => w.id === wo.id);
      const existing = idx >= 0 ? wos[idx] : null;
      if (!shouldOverwriteWo(existing, wo)) return false;
      if (idx >= 0) wos[idx] = wo; else wos.push(wo);
      writeJson(wosFile, wos);
      return true;
    },
    async deleteWorkOrder(id) { wos = wos.filter((w) => w.id !== id); writeJson(wosFile, wos); },

    // Audit log
    async appendAudit(entry) {
      auditLog.push(entry);
      if (auditLog.length > 2000) auditLog = auditLog.slice(-2000);
      writeJson(auditFile, auditLog);
    },
    async getAuditLogRecent(limit) { return auditLog.slice(-limit); },
    async getAuditLogPage(limit) {
      const rows = [...auditLog].reverse().slice(0, limit);
      return { rows, total: auditLog.length };
    },
    async clearAuditLog() { auditLog = []; writeJson(auditFile, auditLog); },

    // Molds/wos dışındaki üst seviye state alanları (bilinmeyen/gelecekteki alanlar için)
    async getStateExtra() { return stateExtra; },
    async saveStateExtra(next) { stateExtra = next; writeJson(extraFile, stateExtra); },

    async getStorageInfo() {
      let sizeKb = 0;
      try {
        const files = [usersFile, auditFile, moldsFile, wosFile, extraFile];
        sizeKb = Math.round(files.reduce((s, f) => s + (fs.existsSync(f) ? fs.statSync(f).size : 0), 0) / 1024);
      } catch (e) { /* boyut bilgisi kritik değil */ }
      return { kind: "disk", sizeKb, path: dataDir };
    },
  };
}

module.exports = { createFileStore };
