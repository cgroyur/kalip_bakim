"use strict";
const request = require("supertest");
const { startTestServer, stopTestServer } = require("./helpers/testServer");
const { loginAs } = require("./helpers/auth");

describe("POST /api/change-password rate limit", () => {
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

  test("5 başarısız denemeden sonra 6. deneme rate limit ile engellenir", async () => {
    for (let i = 0; i < 5; i++) {
      const res = await request(app)
        .post("/api/change-password")
        .set("Authorization", `Bearer ${token}`)
        .send({ currentPassword: "yanlis", newPassword: "YeniSifre123!" });
      expect(res.status).toBe(401);
    }
    const blocked = await request(app)
      .post("/api/change-password")
      .set("Authorization", `Bearer ${token}`)
      .send({ currentPassword: "yanlis", newPassword: "YeniSifre123!" });
    expect(blocked.status).toBe(429);
  });
});
