"use strict";
const request = require("supertest");

async function loginAs(app, username, password) {
  const res = await request(app).post("/api/login").send({ username, password });
  if (res.status !== 200) {
    throw new Error(`login failed for ${username}: ${res.status} ${JSON.stringify(res.body)}`);
  }
  return res.body.token;
}

module.exports = { loginAs };
