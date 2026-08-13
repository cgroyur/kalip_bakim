"use strict";
const fs = require("fs");
const os = require("os");
const path = require("path");

// Her test dosyası kendi izole DB_DIR'iyle server.js'i sıfırdan require eder —
// böylece test dosyaları arasında DB/rate-limit state sızıntısı olmaz ve
// gerçek data/ klasörü hiç kirlenmez.
function startTestServer() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cmms-test-"));
  process.env.DB_DIR = dir;
  jest.resetModules();
  const serverPath = path.resolve(__dirname, "../../server.js");
  const mod = require(serverPath);
  return { app: mod.app, initData: mod.initData, tmpDir: dir };
}

// saveDB() 800ms debounce kullanır — testler bitmeden pending yazma varsa
// açık handle uyarısı/yarış durumu olur, bu yüzden temizlemeden önce bekliyoruz.
async function stopTestServer(tmpDir) {
  await new Promise((r) => setTimeout(r, 900));
  fs.rmSync(tmpDir, { recursive: true, force: true });
}

module.exports = { startTestServer, stopTestServer };
