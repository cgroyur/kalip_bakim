"use strict";
const request = require("supertest");
const { startTestServer, stopTestServer } = require("./helpers/testServer");
const { loginAs } = require("./helpers/auth");

describe("POST /api/change-password", () => {
  let app, tmpDir, token;

  beforeAll(async () => {
    const s = startTestServer();
    app = s.app;
    tmpDir = s.tmpDir;
    await s.initData();
    token = await loginAs(app, "admin", "Admin2026!");
  });

  afterAll(async () => {
    await stopTestServer(tmpDir);
  });

  test("mevcut şifre yanlışsa 401 döner", async () => {
    const res = await request(app)
      .post("/api/change-password")
      .set("Authorization", `Bearer ${token}`)
      .send({ currentPassword: "yanlis", newPassword: "YeniSifre123!" });
    expect(res.status).toBe(401);
  });

  test("eksik alanlarla 400 döner", async () => {
    const res = await request(app)
      .post("/api/change-password")
      .set("Authorization", `Bearer ${token}`)
      .send({ currentPassword: "Admin2026!" });
    expect(res.status).toBe(400);
  });

  test("doğru mevcut şifre ile değişim başarılı ve must_change_password false olur", async () => {
    const res = await request(app)
      .post("/api/change-password")
      .set("Authorization", `Bearer ${token}`)
      .send({ currentPassword: "Admin2026!", newPassword: "YeniSifre123!" });
    expect(res.status).toBe(200);

    const relogin = await request(app).post("/api/login").send({ username: "admin", password: "YeniSifre123!" });
    expect(relogin.status).toBe(200);
    expect(relogin.body.must_change_password).toBe(false);
  });
});
