"use strict";

// Eski tek-JSONB-blob formatından (cmms_store tablosu, id=1) yeni ilişkisel
// tablolara bir seferlik, idempotent göç. Yeni tablolar zaten doluysa (users
// tablosunda satır varsa) hiçbir şey yapmaz — hem "zaten göç edilmiş" hem
// "taze kurulum, ensureDemoUsers() halledecek" durumlarını güvenle kapsar.
// Eski cmms_store tablosu SİLİNMEZ (rollback güvenliği için birkaç sürüm
// boyunca tutulur, sonra elle temizlenebilir).
async function migrateIfNeeded(pool, store) {
  const countR = await pool.query("SELECT COUNT(*)::int AS c FROM users");
  if (countR.rows[0].c > 0) return;

  const legacyExists = await pool.query(
    `SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'cmms_store') AS exists`
  );
  if (!legacyExists.rows[0].exists) return;

  const r = await pool.query("SELECT data FROM cmms_store WHERE id = 1");
  if (r.rows.length === 0 || !r.rows[0].data) return;

  const legacy = r.rows[0].data;
  const users = legacy.users || [];
  const auditLog = legacy.auditLog || [];
  const state = legacy.state || {};
  const molds = state.molds || [];
  const wos = state.wos || [];
  const { molds: _m, wos: _w, ...stateExtra } = state;

  if (users.length) await store.saveUsers(users);
  for (const m of molds) await store.upsertMold(m);
  for (const w of wos) await store.upsertWorkOrder(w);
  for (const a of auditLog) await store.appendAudit(a);
  // legacy.state hiç POST /api/state almamış eski kurulumlarda null'dur —
  // bu durumda saveStateExtra ÇAĞRILMAZ, hasState() orijinal "DB.state===null" ile aynı şekilde false döner.
  if (legacy.state != null) {
    await store.saveStateExtra(stateExtra);
  }

  console.log(
    `🔁 Eski JSONB blob'dan yeni ilişkisel tablolara göç edildi ` +
    `(${users.length} kullanıcı, ${molds.length} kalıp, ${wos.length} iş emri, ${auditLog.length} audit kaydı)`
  );
}

module.exports = { migrateIfNeeded };
