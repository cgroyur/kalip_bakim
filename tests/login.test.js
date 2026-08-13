"use strict";
const request = require("supertest");
const { startTestServer, stopTestServer } = require("./helpers/testServer");

describe("POST /api/login", () => {
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

  test("eksik alanlarla 400 döner", async () => {
    const res = await request(app).post("/api/login").send({ username: "admin" });
    expect(res.status).toBe(400);
  });

  test("yanlış şifre ile 401 döner", async () => {
    const res = await request(app).post("/api/login").send({ username: "admin", password: "yanlis" });
    expect(res.status).toBe(401);
  });

  test("doğru bilgilerle giriş başarılı, token ve must_change_password döner", async () => {
    const res = await request(app).post("/api/login").send({ username: "admin", password: "Admin2026!" });
    expect(res.status).toBe(200);
    expect(res.body.token).toBeTruthy();
    expect(res.body.user.role).toBe("admin");
    expect(res.body.must_change_password).toBe(true);
  });

  test("olmayan kullanıcı adıyla 401 döner", async () => {
    const res = await request(app).post("/api/login").send({ username: "yok.kullanici", password: "herhangi" });
    expect(res.status).toBe(401);
  });
});
