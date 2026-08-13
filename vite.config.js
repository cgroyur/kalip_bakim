const { defineConfig } = require("vite");

// frontend/ Vite'ın kök dizini (index.html + src/app.js burada).
// public/ zaten Express'in statik servis ettiği dizin (tv.html, manifest.json,
// icon.svg, sw.js, escHtml.js) — build çıktısı da AYNI dizine yazılır ki
// Express tarafında hiçbir değişiklik gerekmesin. emptyOutDir:false ile
// build öncesi public/ temizlenmez (mevcut statik dosyalar korunur).
module.exports = defineConfig({
  root: "frontend",
  publicDir: false, // public/ zaten outDir ile aynı — Vite'ın ayrıca kopyalamasına gerek yok
  build: {
    outDir: "../public",
    emptyOutDir: false,
  },
});
