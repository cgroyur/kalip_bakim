"use strict";
const { shouldOverwriteWo } = require("./shared");

const MOLD_CORE_FIELDS = [
  "id", "part_name", "status", "location", "pm_counter", "pm_interval",
  "last_pm_date", "is_regular", "regular_days", "regular_updated", "total_shots",
];
const WO_CORE_FIELDS = [
  "id", "mold_id", "type", "status", "assigned", "priority", "description",
  "cavity_no", "created_at", "started_at", "closed_at", "updated_at", "reported_by",
];

function omit(obj, keys) {
  const out = {};
  for (const k of Object.keys(obj || {})) if (!keys.includes(k)) out[k] = obj[k];
  return out;
}

// node-pg, taşma/hassasiyet kaybını önlemek için NUMERIC kolonlarını varsayılan
// olarak STRING döndürür (ör. pm_counter: "0"). Orijinal JSON-blob depolamada bu
// alanlar hep gerçek JS number'dı ve frontend üzerlerinde doğrudan aritmetik
// yapıyor (pm_counter+1 vb.) — string kalırsa "0"+1 = "01" gibi sessiz bir
// bozulmaya yol açar. Bu yüzden okurken açıkça Number'a çeviriyoruz.
function toNum(v) { return v === null || v === undefined ? null : Number(v); }

function rowToMold(row) {
  return {
    ...row.extra,
    id: row.id, part_name: row.part_name, status: row.status, location: row.location,
    pm_counter: toNum(row.pm_counter), pm_interval: toNum(row.pm_interval), last_pm_date: row.last_pm_date,
    is_regular: row.is_regular, regular_days: toNum(row.regular_days), regular_updated: row.regular_updated,
    total_shots: toNum(row.total_shots),
    parts: row.parts || [],
  };
}

function rowToWo(row) {
  return {
    ...row.extra,
    id: row.id, mold_id: row.mold_id, type: row.type, status: row.status, assigned: row.assigned,
    priority: row.priority, description: row.description, cavity_no: row.cavity_no,
    created_at: row.created_at, started_at: row.started_at, closed_at: row.closed_at,
    updated_at: row.updated_at, reported_by: row.reported_by,
  };
}

function rowToAudit(row) {
  return {
    ts: row.ts, user_id: row.user_id, user_name: row.user_name, role: row.role,
    action: row.action, entity_type: row.entity_type, entity_id: row.entity_id, detail: row.detail,
  };
}

// "Çekirdek kolonlar + JSONB taşma" hibrit şema: molds/work_orders sık sorgulanan
// alanları gerçek kolon olarak tutar (indexlenebilir, satır bazlı yazılabilir),
// geri kalan geniş/organik alan seti `extra` JSONB'de saklanır. mold_parts ayrı
// gerçek tablo çünkü GlobalSparePartsPage kalıplar arası sorgu/rapor yapıyor.
function createPgStore(pool) {
  const store = {
    async init() {
      await pool.query(`CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, role TEXT NOT NULL, username TEXT NOT NULL,
        password_hash TEXT NOT NULL, active BOOLEAN NOT NULL DEFAULT true,
        must_change_password BOOLEAN NOT NULL DEFAULT true
      )`);
      await pool.query(`CREATE TABLE IF NOT EXISTS audit_log (
        id BIGSERIAL PRIMARY KEY, ts TEXT, user_id TEXT, user_name TEXT, role TEXT,
        action TEXT, entity_type TEXT, entity_id TEXT, detail TEXT
      )`);
      await pool.query(`CREATE TABLE IF NOT EXISTS molds (
        id TEXT PRIMARY KEY, part_name TEXT, status TEXT, location TEXT,
        pm_counter NUMERIC, pm_interval NUMERIC, last_pm_date TEXT, is_regular BOOLEAN,
        regular_days NUMERIC, regular_updated TEXT, total_shots NUMERIC,
        extra JSONB NOT NULL DEFAULT '{}'::jsonb
      )`);
      await pool.query(`CREATE TABLE IF NOT EXISTS mold_parts (
        id TEXT PRIMARY KEY, mold_id TEXT NOT NULL REFERENCES molds(id) ON DELETE CASCADE,
        code TEXT, name TEXT, unit TEXT, critical BOOLEAN, stock NUMERIC, min_stock NUMERIC
      )`);
      await pool.query(`CREATE INDEX IF NOT EXISTS mold_parts_mold_id_idx ON mold_parts (mold_id)`);
      await pool.query(`CREATE TABLE IF NOT EXISTS work_orders (
        id TEXT PRIMARY KEY, mold_id TEXT, type TEXT, status TEXT, assigned TEXT,
        priority TEXT, description TEXT, cavity_no TEXT, created_at TEXT, started_at TEXT,
        closed_at TEXT, updated_at TEXT, reported_by TEXT, extra JSONB NOT NULL DEFAULT '{}'::jsonb
      )`);
      await pool.query(`CREATE INDEX IF NOT EXISTS work_orders_status_idx ON work_orders (status)`);
      await pool.query(`CREATE INDEX IF NOT EXISTS work_orders_mold_id_idx ON work_orders (mold_id)`);
      await pool.query(`CREATE TABLE IF NOT EXISTS state_extra (
        id INT PRIMARY KEY DEFAULT 1, data JSONB NOT NULL DEFAULT '{}'::jsonb
      )`);

      await require("./migrateLegacyBlob").migrateIfNeeded(pool, store);
    },

    async hasState() {
      const r = await pool.query("SELECT EXISTS(SELECT 1 FROM state_extra WHERE id = 1) AS e");
      return r.rows[0].e;
    },

    // Users — küçük tablo, tüm-diziyi-oku/tüm-diziyi-yaz deseni (basit ve düşük riskli)
    async getUsers() {
      const r = await pool.query("SELECT * FROM users");
      return r.rows.map((u) => ({ ...u, active: !!u.active, must_change_password: !!u.must_change_password }));
    },
    async saveUsers(users) {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        await client.query("DELETE FROM users");
        for (const u of users) {
          await client.query(
            `INSERT INTO users (id,name,role,username,password_hash,active,must_change_password)
             VALUES ($1,$2,$3,$4,$5,$6,$7)`,
            [u.id, u.name, u.role, u.username, u.password_hash, !!u.active, !!u.must_change_password]
          );
        }
        await client.query("COMMIT");
      } catch (e) {
        await client.query("ROLLBACK");
        throw e;
      } finally {
        client.release();
      }
    },

    // Molds
    async getMolds() {
      const moldsR = await pool.query("SELECT * FROM molds");
      const partsR = await pool.query("SELECT * FROM mold_parts");
      const partsByMold = new Map();
      for (const p of partsR.rows) {
        if (!partsByMold.has(p.mold_id)) partsByMold.set(p.mold_id, []);
        partsByMold.get(p.mold_id).push({
          id: p.id, code: p.code, name: p.name, unit: p.unit,
          critical: p.critical, stock: toNum(p.stock), min_stock: toNum(p.min_stock),
        });
      }
      return moldsR.rows.map((row) => rowToMold({ ...row, parts: partsByMold.get(row.id) || [] }));
    },
    async getMoldIds() {
      const r = await pool.query("SELECT id FROM molds");
      return r.rows.map((x) => x.id);
    },
    async upsertMold(mold) {
      const extra = omit(mold, [...MOLD_CORE_FIELDS, "parts"]);
      await pool.query(
        `INSERT INTO molds (id,part_name,status,location,pm_counter,pm_interval,last_pm_date,is_regular,regular_days,regular_updated,total_shots,extra)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
         ON CONFLICT (id) DO UPDATE SET part_name=$2,status=$3,location=$4,pm_counter=$5,pm_interval=$6,
           last_pm_date=$7,is_regular=$8,regular_days=$9,regular_updated=$10,total_shots=$11,extra=$12`,
        [
          mold.id, mold.part_name ?? null, mold.status ?? null, mold.location ?? null,
          mold.pm_counter ?? null, mold.pm_interval ?? null, mold.last_pm_date ?? null,
          mold.is_regular ?? null, mold.regular_days ?? null, mold.regular_updated ?? null,
          mold.total_shots ?? null, JSON.stringify(extra),
        ]
      );
      await pool.query("DELETE FROM mold_parts WHERE mold_id = $1", [mold.id]);
      for (const p of mold.parts || []) {
        await pool.query(
          `INSERT INTO mold_parts (id, mold_id, code, name, unit, critical, stock, min_stock)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
          [p.id || `PT-${mold.id}-${p.code}`, mold.id, p.code ?? null, p.name ?? null, p.unit ?? null, !!p.critical, p.stock ?? null, p.min_stock ?? null]
        );
      }
    },
    async deleteMold(id) { await pool.query("DELETE FROM molds WHERE id = $1", [id]); },
    async replaceMolds(nextMolds) {
      for (const m of nextMolds) await store.upsertMold(m);
      const incomingIds = nextMolds.map((m) => m.id);
      if (incomingIds.length > 0) {
        await pool.query("DELETE FROM molds WHERE NOT (id = ANY($1::text[]))", [incomingIds]);
      } else {
        await pool.query("DELETE FROM molds");
      }
    },

    // Work orders
    async getWorkOrders() {
      const r = await pool.query("SELECT * FROM work_orders");
      return r.rows.map(rowToWo);
    },
    async getWorkOrderById(id) {
      const r = await pool.query("SELECT * FROM work_orders WHERE id = $1", [id]);
      return r.rows[0] ? rowToWo(r.rows[0]) : null;
    },
    async upsertWorkOrder(wo) {
      const existing = await store.getWorkOrderById(wo.id);
      if (!shouldOverwriteWo(existing, wo)) return false;
      const extra = omit(wo, WO_CORE_FIELDS);
      await pool.query(
        `INSERT INTO work_orders (id,mold_id,type,status,assigned,priority,description,cavity_no,created_at,started_at,closed_at,updated_at,reported_by,extra)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
         ON CONFLICT (id) DO UPDATE SET mold_id=$2,type=$3,status=$4,assigned=$5,priority=$6,description=$7,
           cavity_no=$8,created_at=$9,started_at=$10,closed_at=$11,updated_at=$12,reported_by=$13,extra=$14`,
        [
          wo.id, wo.mold_id ?? null, wo.type ?? null, wo.status ?? null, wo.assigned ?? null,
          wo.priority ?? null, wo.description ?? null, wo.cavity_no ?? null, wo.created_at ?? null,
          wo.started_at ?? null, wo.closed_at ?? null, wo.updated_at ?? null, wo.reported_by ?? null,
          JSON.stringify(extra),
        ]
      );
      return true;
    },
    async deleteWorkOrder(id) { await pool.query("DELETE FROM work_orders WHERE id = $1", [id]); },

    // Audit log
    async appendAudit(entry) {
      await pool.query(
        `INSERT INTO audit_log (ts,user_id,user_name,role,action,entity_type,entity_id,detail)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        [entry.ts, entry.user_id, entry.user_name, entry.role, entry.action, entry.entity_type, entry.entity_id, entry.detail]
      );
      await pool.query(`DELETE FROM audit_log WHERE id IN (SELECT id FROM audit_log ORDER BY id DESC OFFSET 2000)`);
    },
    async getAuditLogRecent(limit) {
      // En YENİ `limit` kaydı al, ama kronolojik (artan) sırada döndür —
      // orijinal DB.auditLog dizisiyle aynı sıralama.
      const r = await pool.query(
        "SELECT * FROM (SELECT * FROM audit_log ORDER BY id DESC LIMIT $1) sub ORDER BY id ASC",
        [limit]
      );
      return r.rows.map(rowToAudit);
    },
    async getAuditLogPage(limit) {
      const totalR = await pool.query("SELECT COUNT(*)::int AS c FROM audit_log");
      const r = await pool.query("SELECT * FROM audit_log ORDER BY id DESC LIMIT $1", [limit]);
      return { rows: r.rows.map(rowToAudit), total: totalR.rows[0].c };
    },
    async clearAuditLog() { await pool.query("DELETE FROM audit_log"); },

    // State extra
    async getStateExtra() {
      const r = await pool.query("SELECT data FROM state_extra WHERE id = 1");
      return r.rows[0] ? r.rows[0].data : {};
    },
    async saveStateExtra(data) {
      await pool.query(
        `INSERT INTO state_extra (id, data) VALUES (1, $1) ON CONFLICT (id) DO UPDATE SET data = $1`,
        [JSON.stringify(data)]
      );
    },

    async getStorageInfo() {
      const r = await pool.query(`SELECT
        (SELECT COUNT(*)::int FROM molds) AS molds,
        (SELECT COUNT(*)::int FROM work_orders) AS wos,
        (SELECT COUNT(*)::int FROM audit_log) AS audit_entries,
        (SELECT COUNT(*)::int FROM users WHERE active) AS active_users
      `);
      return { kind: "postgres", ...r.rows[0] };
    },
  };
  return store;
}

module.exports = { createPgStore };
