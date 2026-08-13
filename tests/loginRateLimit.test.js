"use strict";
const request = require("supertest");
const { startTestServer, stopTestServer } = require("./helpers/testServer");

// Ayrı dosyada — kendi izole app/rate-limit sayacına sahip, diğer login
// testlerinin başarısız deneme sayısıyla karışmasın diye.
describe("POST /api/login rate limit", () => {
  let app, tmpDir;

  beforeAll(async () => {
    const s = startTestServer();
    app = s.app;
    tmpDir = s.tmpDir;
    await s.initData();
  });

  afterAll(async () => {
    await stopTestServer(tmpDir);
  });

  test("5 başarısız denemeden sonra 6. deneme rate limit ile engellenir", async () => {
    for (let i = 0; i < 5; i++) {
      const res = await request(app).post("/api/login").send({ username: "admin", password: "yanlis" });
      expect(res.status).toBe(401);
    }
    const blocked = await request(app).post("/api/login").send({ username: "admin", password: "yanlis" });
    expect(blocked.status).toBe(429);
  });
});
