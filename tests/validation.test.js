"use strict";
const request = require("supertest");
const { startTestServer, stopTestServer } = require("./helpers/testServer");
const { loginAs } = require("./helpers/auth");

describe("Zod istek doğrulama — çeşitli endpoint'ler", () => {
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

  test("POST /api/tv/claim — wo_id eksikse 400", async () => {
    const res = await request(app).post("/api/tv/claim").set("Authorization", `Bearer ${token}`).send({});
    expect(res.status).toBe(400);
  });

  test("POST /api/system/reset — type eksikse 400", async () => {
    const res = await request(app).post("/api/system/reset").set("Authorization", `Bearer ${token}`).send({});
    expect(res.status).toBe(400);
  });

  test("POST /api/state — id'siz mold öğesi 400 döner", async () => {
    const res = await request(app)
      .post("/api/state")
      .set("Authorization", `Bearer ${token}`)
      .send({ molds: [{ part_name: "id yok" }], wos: [] });
    expect(res.status).toBe(400);
  });

  test("POST /api/users — geçersiz rol 400 döner", async () => {
    const res = await request(app)
      .post("/api/users")
      .set("Authorization", `Bearer ${token}`)
      .send({ id: "UX", name: "X", role: "superadmin", username: "x.y", password: "abcdef" });
    expect(res.status).toBe(400);
  });

  test("POST /api/workorders — bilinmeyen ekstra alanlar (RCA vb.) reddedilmez, geçer", async () => {
    const res = await request(app)
      .post("/api/workorders")
      .set("Authorization", `Bearer ${token}`)
      .send({ mold_id: "M1", type: "ARIZA", rca_cause: "test", cost_labor: 100, actions: [{ ts: "x", act: "y" }] });
    expect(res.status).toBe(200);
    expect(res.body.wo.rca_cause).toBe("test");
  });
});
