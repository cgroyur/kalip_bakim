"use strict";
const { z } = require("zod");

function validate(schema) {
  return (req, res, next) => {
    const result = schema.safeParse(req.body);
    if (!result.success) {
      const first = result.error.issues[0];
      const field = first && first.path.length ? first.path.join(".") : null;
      const msg = first ? first.message : "Geçersiz istek";
      return res.status(400).json({ error: field ? `${field}: ${msg}` : msg });
    }
    req.body = result.data;
    next();
  };
}

const ROLE_ENUM = z.enum(["admin", "leader", "tech", "op", "kalite", "tedarikci"]);

const loginSchema = z.object({
  username: z.string().min(1, "Kullanıcı adı gerekli"),
  password: z.string().min(1, "Şifre gerekli"),
});

const changePasswordSchema = z.object({
  currentPassword: z.string().min(1, "Mevcut şifre gerekli"),
  newPassword: z.string().min(1, "Yeni şifre gerekli"),
});

const createUserSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  role: ROLE_ENUM,
  username: z.string().min(1),
  password: z.string().min(1),
  supplier_name: z.string().max(120).optional(),
});

const updateUserSchema = z.object({
  name: z.string().min(1).optional(),
  role: ROLE_ENUM.optional(),
  username: z.string().min(1).optional(),
  password: z.string().min(1).optional(),
  supplier_name: z.string().max(120).optional(),
});

// İş emri (work order) alan seti çok geniş (RCA analizi, maliyet, tip-özel alanlar vb.)
// — burada sadece zorunlu iki alan doğrulanır, geri kalanı serbest geçer (passthrough).
const workOrderSchema = z.object({
  id: z.string().min(1).optional(),
  mold_id: z.string().min(1, "Kalıp zorunlu"),
  type: z.string().min(1, "Tip zorunlu"),
}).passthrough();

const tvClaimSchema = z.object({
  wo_id: z.string().min(1, "wo_id gerekli"),
});

const auditSchema = z.object({
  action: z.string().min(1, "action zorunlu"),
  entity_type: z.string().nullish(),
  entity_id: z.union([z.string(), z.number()]).nullish(),
  detail: z.string().nullish(),
});

const systemResetSchema = z.object({
  type: z.string().min(1),
});

const resetSeedSchema = z.object({
  mode: z.enum(["merge", "replace"]).optional(),
});

// Kalıp/iş emri gövdesinin üst seviye şekli — her alanı tek tek doğrulamak yerine
// (molds/wos alan sayısı çok geniş ve organik olarak büyüyor) sadece dizi/obje şekli
// ve her kaydın bir `id`'si olduğu doğrulanır; geri kalan alanlar serbest geçer.
const entityShape = z.object({ id: z.union([z.string(), z.number()]) }).passthrough();

const stateSchema = z.object({
  molds: z.array(entityShape).optional(),
  wos: z.array(entityShape).optional(),
  deleted_wo_ids: z.array(z.union([z.string(), z.number()])).optional(),
}).passthrough();

// Doküman ekleri (teknik çizim, üretici manueli, onarım fotoğrafı vb.). Dosya
// içeriği base64 olarak gönderilir; ~12M karakter sınırı ~9MB'lık bir dosyaya
// karşılık gelir — express.json'daki 25mb gövde limitinin altında rahat kalır.
const attachmentSchema = z.object({
  entity_type: z.enum(["mold", "wo"]),
  entity_id: z.string().min(1),
  filename: z.string().min(1).max(200),
  mime_type: z.string().max(120).optional(),
  data_base64: z.string().min(1).max(12_000_000, "Dosya çok büyük (maks. ~9MB)"),
});

// Kalite onayı sistem ayarları — hangi durumlarda bir iş emrinin kapanışının
// kalite rolü tarafından onaylanması gerektiğini belirler. Varsayılan kapalı;
// admin devreye alana kadar mevcut kapanış akışında hiçbir değişiklik olmaz.
const qualitySettingsSchema = z.object({
  enabled: z.boolean().optional(),
  trigger_fail_codes: z.array(z.string()).optional(),
});

// Tedarikçi portalı — dar kapsamlı, sadece kendi kalıpları için PM açma/kapama.
const supplierPmCreateSchema = z.object({
  mold_id: z.string().min(1, "Kalıp zorunlu"),
});
const supplierPmCompleteSchema = z.object({
  note: z.string().max(2000).optional(),
});

// Tedarikçi arıza bildirimi + teklif — kırılımlı fiyat (işlem + fiyat) satırları.
const teklifItemSchema = z.object({
  op: z.string().min(1).max(200),
  price: z.number().nonnegative(),
});
const supplierArizCreateSchema = z.object({
  mold_id: z.string().min(1, "Kalıp zorunlu"),
  cavity_no: z.string().max(50).optional(),
  description: z.string().min(1, "Açıklama zorunlu").max(4000),
  teklif_items: z.array(teklifItemSchema).min(1, "En az bir işlem/fiyat satırı gerekli"),
});
const supplierSampleSentSchema = z.object({}).passthrough();
const supplierArizCompleteSchema = z.object({
  note: z.string().max(2000).optional(),
});
const teklifRejectSchema = z.object({
  reason: z.string().max(2000).optional(),
});

module.exports = {
  validate,
  loginSchema,
  changePasswordSchema,
  createUserSchema,
  updateUserSchema,
  workOrderSchema,
  tvClaimSchema,
  auditSchema,
  systemResetSchema,
  resetSeedSchema,
  stateSchema,
  attachmentSchema,
  qualitySettingsSchema,
  supplierPmCreateSchema,
  supplierPmCompleteSchema,
  supplierArizCreateSchema,
  supplierSampleSentSchema,
  supplierArizCompleteSchema,
  teklifRejectSchema,
};
