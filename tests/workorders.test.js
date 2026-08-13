"use strict";
const request = require("supertest");
const { startTestServer, stopTestServer } = require("./helpers/testServer");
const { loginAs } = require("./helpers/auth");

describe("POST /api/workorders", () => {
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

  test("kalıp/tip zorunlu — eksikse 400 döner", async () => {
    const res = await request(app)
      .post("/api/workorders")
      .set("Authorization", `Bearer ${token}`)
      .send({ mold_id: "M1" });
    expect(res.status).toBe(400);
  });

  test("ID otomatik atanır ve varsayılan alanlar doldurulur", async () => {
    const res = await request(app)
      .post("/api/workorders")
      .set("Authorization", `Bearer ${token}`)
      .send({ mold_id: "M1", type: "ARIZA", description: "test arızası" });
    expect(res.status).toBe(200);
    expect(res.body.wo.id).toBe("LG-001");
    expect(res.body.wo.status).toBe("BEKLEMEDE");
    expect(res.body.wo.assigned).toBeNull();
    expect(res.body.wo.created_at).toBeTruthy();
    expect(res.body.wo.reported_by).toBeTruthy();
  });

  test("ikinci iş emri sıradaki ID'yi alır (LG-002)", async () => {
    const res = await request(app)
      .post("/api/workorders")
      .set("Authorization", `Bearer ${token}`)
      .send({ mold_id: "M2", type: "MODİF" });
    expect(res.status).toBe(200);
    expect(res.body.wo.id).toBe("LG-002");
  });
});
