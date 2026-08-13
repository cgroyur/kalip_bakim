"use strict";
const request = require("supertest");
const { startTestServer, stopTestServer } = require("./helpers/testServer");
const { loginAs } = require("./helpers/auth");

describe("POST /api/state — iş emri (WO) merge mantığı", () => {
  let app, tmpDir, token;

  beforeAll(async () => {
    const s = startTestServer();
    app = s.app;
    tmpDir = s.tmpDir;
    await s.initData();
    token = await loginAs(app, "admin", "Admin2026!");

    await request(app)
      .post("/api/state")
      .set("Authorization", `Bearer ${token}`)
      .send({
        molds: [],
        wos: [
          { id: "W1", mold_id: "M1", type: "ARIZA", status: "BEKLEMEDE", updated_at: "2026-01-01T00:00:00.000Z" },
          { id: "W2", mold_id: "M1", type: "ARIZA", status: "BEKLEMEDE", updated_at: "2026-01-01T00:00:00.000Z" },
        ],
      });
  });

  afterAll(async () => {
    await stopTestServer(tmpDir);
  });

  test("istemci görmediği (göndermediği) WO'yu sunucu korur", async () => {
    // İstemci sadece W1'i biliyor, W2'yi hiç göndermiyor (deleted_wo_ids da yok).
    await request(app)
      .post("/api/state")
      .set("Authorization", `Bearer ${token}`)
      .send({
        molds: [],
        wos: [{ id: "W1", mold_id: "M1", type: "ARIZA", status: "DEVAM_EDİYOR", updated_at: "2026-01-02T00:00:00.000Z" }],
      });

    const state = await request(app).get("/api/state").set("Authorization", `Bearer ${token}`);
    const ids = state.body.wos.map((w) => w.id);
    expect(ids).toEqual(expect.arrayContaining(["W1", "W2"]));
    expect(state.body.wos.find((w) => w.id === "W1").status).toBe("DEVAM_EDİYOR");
    expect(state.body.wos.find((w) => w.id === "W2").status).toBe("BEKLEMEDE");
  });

  test("daha eski updated_at'e sahip istemci verisi, daha yeni sunucu verisini eziyor olamaz", async () => {
    // Sunucuda W1.updated_at = 2026-01-02. İstemci daha ESKİ bir damgayla (2026-01-01T12:00) gönderiyor.
    await request(app)
      .post("/api/state")
      .set("Authorization", `Bearer ${token}`)
      .send({
        molds: [],
        wos: [{ id: "W1", mold_id: "M1", type: "ARIZA", status: "KAPATILDI", updated_at: "2026-01-01T12:00:00.000Z" }],
      });

    const state = await request(app).get("/api/state").set("Authorization", `Bearer ${token}`);
    expect(state.body.wos.find((w) => w.id === "W1").status).toBe("DEVAM_EDİYOR"); // sunucu kazandı
  });

  test("deleted_wo_ids ile bilinçli silme uygulanır", async () => {
    await request(app)
      .post("/api/state")
      .set("Authorization", `Bearer ${token}`)
      .send({ molds: [], wos: [], deleted_wo_ids: ["W2"] });

    const state = await request(app).get("/api/state").set("Authorization", `Bearer ${token}`);
    const ids = state.body.wos.map((w) => w.id);
    expect(ids).not.toContain("W2");
    expect(ids).toContain("W1"); // istemci göndermedi ama silinmemiş olan hâlâ korunur
  });
});
