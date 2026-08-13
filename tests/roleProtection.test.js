"use strict";
const request = require("supertest");
const { startTestServer, stopTestServer } = require("./helpers/testServer");
const { loginAs } = require("./helpers/auth");

describe("Rol bazlı yazma koruması (sanitizeStateForRole)", () => {
  let app, tmpDir, adminToken, techToken;

  beforeAll(async () => {
    const s = startTestServer();
    app = s.app;
    tmpDir = s.tmpDir;
    await s.initData();
    adminToken = await loginAs(app, "admin", "Admin2026!");

    await request(app)
      .post("/api/state")
      .set("Authorization", `Bearer ${adminToken}`)
      .send({ molds: [{ id: "M1", part_name: "Orijinal Parça", pm_counter: 0, status: "Kullanılabilir" }], wos: [] });

    await request(app)
      .post("/api/users")
      .set("Authorization", `Bearer ${adminToken}`)
      .send({ id: "T1", name: "Test Tekniker", role: "tech", username: "test.tekniker", password: "TeknikerSifre1!" });

    techToken = await loginAs(app, "test.tekniker", "TeknikerSifre1!");
  });

  afterAll(async () => {
    await stopTestServer(tmpDir);
  });

  test("tech kullanıcı kalıp ana alanını (part_name) değiştiremez ama pm_counter'ı değiştirebilir", async () => {
    const res = await request(app)
      .post("/api/state")
      .set("Authorization", `Bearer ${techToken}`)
      .send({ molds: [{ id: "M1", part_name: "HACK", pm_counter: 5, status: "Bakımda" }], wos: [] });
    expect(res.status).toBe(200);

    const state = await request(app).get("/api/state").set("Authorization", `Bearer ${adminToken}`);
    const mold = state.body.molds.find((m) => m.id === "M1");
    expect(mold.part_name).toBe("Orijinal Parça"); // korunan alan — değişmedi
    expect(mold.status).toBe("Kullanılabilir"); // korunan alan — değişmedi
    expect(mold.pm_counter).toBe(5); // tech-editable alan — değişti
  });

  test("admin kullanıcı kalıp ana alanlarını değiştirebilir", async () => {
    const res = await request(app)
      .post("/api/state")
      .set("Authorization", `Bearer ${adminToken}`)
      .send({ molds: [{ id: "M1", part_name: "Güncellenmiş Parça", pm_counter: 5, status: "Bakımda" }], wos: [] });
    expect(res.status).toBe(200);

    const state = await request(app).get("/api/state").set("Authorization", `Bearer ${adminToken}`);
    const mold = state.body.molds.find((m) => m.id === "M1");
    expect(mold.part_name).toBe("Güncellenmiş Parça");
    expect(mold.status).toBe("Bakımda");
  });
});
