"use strict";
const escHtml = require("../public/escHtml");

describe("escHtml (frontend XSS koruması)", () => {
  test("HTML özel karakterlerini kaçırır", () => {
    expect(escHtml('<img src=x onerror=alert(1)>')).toBe(
      "&lt;img src=x onerror=alert(1)&gt;"
    );
  });

  test("tırnak ve ampersandı kaçırır", () => {
    expect(escHtml(`"quoted" & 'single'`)).toBe("&quot;quoted&quot; &amp; &#39;single&#39;");
  });

  test("normal metni değiştirmeden bırakır", () => {
    expect(escHtml("LG-001 — M-KLP-14")).toBe("LG-001 — M-KLP-14");
  });

  test("null/undefined boş string döner", () => {
    expect(escHtml(null)).toBe("");
    expect(escHtml(undefined)).toBe("");
  });
});
