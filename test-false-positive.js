// =============================================================
// VEXLIT False Positive Test Suite
// 실제 개발자 코드에서 흔히 쓰이는 애매한 패턴 모음
// 오탐지(false positive) vs 정탐지(true positive) 테스트용
// =============================================================

const express = require("express");
const crypto = require("crypto");
const { Pool } = require("pg");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const path = require("path");
const { execFile } = require("child_process");
const _ = require("lodash");

const app = express();
const pool = new Pool();

// -----------------------------------------------------------
// 1. SQL — parameterized query (안전, 오탐지여야 함)
// -----------------------------------------------------------
async function getUserById(id) {
  const result = await pool.query("SELECT * FROM users WHERE id = $1", [id]);
  return result.rows[0];
}

// 2. SQL — template literal이지만 상수만 사용 (안전, 오탐지여야 함)
async function getActiveUsers() {
  const table = "users";
  const status = "active";
  const result = await pool.query(`SELECT * FROM ${table} WHERE status = '${status}'`);
  return result.rows;
}

// 3. SQL — 사용자 입력 직접 삽입 (위험, 정탐지여야 함)
async function searchUsers(req, res) {
  const { name } = req.query;
  const result = await pool.query(`SELECT * FROM users WHERE name = '${name}'`);
  res.json(result.rows);
}

// -----------------------------------------------------------
// 4. eval — JSON.parse로 대체 가능한 패턴 (안전, 오탐지여야 함)
// -----------------------------------------------------------
function parseConfig(jsonString) {
  return JSON.parse(jsonString);
}

// 5. eval — 실제 eval 사용 (위험, 정탐지여야 함)
function evalUserExpression(expr) {
  return eval(expr);
}

// 6. Function constructor — 동적 함수 생성 (위험, 정탐지여야 함)
function createDynamicFunction(code) {
  return new Function("x", code);
}

// -----------------------------------------------------------
// 7. crypto — createHash로 SHA-256 사용 (안전, 오탐지여야 함)
// -----------------------------------------------------------
function hashPassword(password) {
  return crypto.createHash("sha256").update(password).digest("hex");
}

// 8. crypto — MD5지만 파일 체크섬 용도 (안전한 용도, 오탐지여야 함)
function fileChecksum(buffer) {
  return crypto.createHash("md5").update(buffer).digest("hex");
}

// 9. crypto — MD5로 비밀번호 해시 (위험, 정탐지여야 함)
function weakPasswordHash(password) {
  return crypto.createHash("md5").update(password).digest("hex");
}

// -----------------------------------------------------------
// 10. hardcoded secret — 테스트/예시 값 (안전, 오탐지여야 함)
// -----------------------------------------------------------
const TEST_API_KEY = "test_key_12345";
const EXAMPLE_TOKEN = "example-token-for-docs";
const PLACEHOLDER = "sk-ant-api03-xxxxxxxxxxxxxxxx";

// 11. hardcoded secret — 진짜 키처럼 보이는 값 (위험, 정탐지여야 함)
const API_KEY = "AKIAIOSFODNN7REALKEY1";
// vexlit-test: fake key for scanner testing (not a real secret)
const STRIPE_KEY = "sk_live_" + "51HG7dK2eZvKYlo2C0r8N9mB4pQ";

// -----------------------------------------------------------
// 12. JWT — 환경변수 사용 (안전, 오탐지여야 함)
// -----------------------------------------------------------
function signToken(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "1h" });
}

// 13. JWT — 하드코딩된 시크릿 (위험, 정탐지여야 함)
function signTokenInsecure(payload) {
  return jwt.sign(payload, "my-super-secret-key", { expiresIn: "1h" });
}

// 14. JWT — algorithm: "none" (위험, 정탐지여야 함)
function signTokenNone(payload) {
  return jwt.sign(payload, "", { algorithm: "none" });
}

// -----------------------------------------------------------
// 15. XSS — React에서 textContent 사용 (안전, 오탐지여야 함)
// -----------------------------------------------------------
function SafeComponent({ userInput }) {
  return `<div>${escapeHtml(userInput)}</div>`;
}

function escapeHtml(str) {
  return str.replace(/[&<>"']/g, (m) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[m])
  );
}

// 16. XSS — innerHTML에 사용자 입력 (위험, 정탐지여야 함)
app.get("/preview", (req, res) => {
  const { content } = req.query;
  res.send(`<html><body><div>${content}</div></body></html>`);
});

// -----------------------------------------------------------
// 17. Command Injection — execFile 사용 (안전, 오탐지여야 함)
// -----------------------------------------------------------
function listFiles(directory) {
  return new Promise((resolve, reject) => {
    execFile("ls", ["-la", directory], (err, stdout) => {
      if (err) reject(err);
      else resolve(stdout);
    });
  });
}

// 18. exec — 사용자 입력 포함 (위험, 정탐지여야 함)
const { exec } = require("child_process");
function runUserCommand(userInput) {
  exec(`git log --oneline ${userInput}`, (err, stdout) => {
    console.log(stdout);
  });
}

// -----------------------------------------------------------
// 19. Path Traversal — path.join + 검증 (안전, 오탐지여야 함)
// -----------------------------------------------------------
function getFileSafe(filename) {
  const baseDir = path.resolve("/app/uploads");
  const filePath = path.resolve(baseDir, filename);
  if (!filePath.startsWith(baseDir)) {
    throw new Error("Path traversal detected");
  }
  return filePath;
}

// 20. Path Traversal — 검증 없이 사용자 입력 사용 (위험, 정탐지여야 함)
app.get("/files/:name", (req, res) => {
  const filePath = path.join("/app/uploads", req.params.name);
  res.sendFile(filePath);
});

// -----------------------------------------------------------
// 21. Prototype Pollution — for..in with hasOwnProperty (안전, 오탐지여야 함)
// -----------------------------------------------------------
function safeIterate(obj) {
  const result = {};
  for (const key in obj) {
    if (Object.prototype.hasOwnProperty.call(obj, key)) {
      result[key] = obj[key];
    }
  }
  return result;
}

// 22. Prototype Pollution — for..in without guard (위험, 정탐지여야 함)
function unsafeIterate(obj, target) {
  for (const key in obj) {
    target[key] = obj[key];
  }
}

// 23. Object.assign — 빈 객체 대상 (비교적 안전, 오탐지여야 함)
function mergeDefaults(options) {
  return Object.assign({}, { timeout: 3000, retries: 3 }, options);
}

// 24. _.merge — 사용자 입력 (위험, 정탐지여야 함)
app.post("/settings", (req, res) => {
  const config = {};
  _.merge(config, req.body);
  res.json(config);
});

// -----------------------------------------------------------
// 25. SSRF — 내부 URL 하드코딩 (안전, 오탐지여야 함)
// -----------------------------------------------------------
async function healthCheck() {
  const res = await fetch("http://localhost:3000/health");
  return res.json();
}

// 26. SSRF — 사용자가 URL 지정 (위험, 정탐지여야 함)
app.get("/proxy", async (req, res) => {
  const { url } = req.query;
  const response = await fetch(url);
  const data = await response.text();
  res.send(data);
});

// -----------------------------------------------------------
// 27. Timing Attack — bcrypt.compare 사용 (안전, 오탐지여야 함)
// -----------------------------------------------------------
async function verifyPassword(input, hash) {
  return bcrypt.compare(input, hash);
}

// 28. Timing Attack — 문자열 직접 비교 (위험, 정탐지여야 함)
function verifyApiKey(input, stored) {
  return input === stored;
}

// -----------------------------------------------------------
// 29. Insecure Randomness — crypto.randomBytes (안전, 오탐지여야 함)
// -----------------------------------------------------------
function generateSecureToken() {
  return crypto.randomBytes(32).toString("hex");
}

// 30. Insecure Randomness — Math.random (위험, 정탐지여야 함)
function generateInsecureToken() {
  return Math.random().toString(36).substring(2);
}

// -----------------------------------------------------------
// 31. Open Redirect — 화이트리스트 검증 (안전, 오탐지여야 함)
// -----------------------------------------------------------
const ALLOWED_HOSTS = ["example.com", "app.example.com"];
app.get("/redirect-safe", (req, res) => {
  const { url } = req.query;
  try {
    const parsed = new URL(url);
    if (ALLOWED_HOSTS.includes(parsed.hostname)) {
      return res.redirect(url);
    }
  } catch {}
  res.redirect("/");
});

// 32. Open Redirect — 검증 없이 리다이렉트 (위험, 정탐지여야 함)
app.get("/redirect", (req, res) => {
  res.redirect(req.query.url);
});

// -----------------------------------------------------------
// 33. Cookie — secure + httpOnly (안전, 오탐지여야 함)
// -----------------------------------------------------------
app.get("/login-ok", (req, res) => {
  res.cookie("session", "abc123", {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 3600000,
  });
  res.json({ ok: true });
});

// 34. Cookie — secure 없음 (위험, 정탐지여야 함)
app.get("/login-bad", (req, res) => {
  res.cookie("session", "abc123");
  res.json({ ok: true });
});

// -----------------------------------------------------------
// 35. CORS — 특정 origin만 허용 (안전, 오탐지여야 함)
// -----------------------------------------------------------
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "https://app.example.com");
  next();
});

// 36. CORS — origin: * (위험, 정탐지여야 함)
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  next();
});

// -----------------------------------------------------------
// 37. Deserialization — JSON.parse (안전, 오탐지여야 함)
// -----------------------------------------------------------
function parseData(raw) {
  return JSON.parse(raw);
}

// 38. Deserialization — node-serialize (위험, 정탐지여야 함)
const serialize = require("node-serialize");
function unsafeDeserialize(data) {
  return serialize.unserialize(data);
}

// -----------------------------------------------------------
// 39. TLS — rejectUnauthorized: true (안전, 오탐지여야 함)
// -----------------------------------------------------------
const https = require("https");
function secureRequest() {
  return https.request({ hostname: "api.example.com", rejectUnauthorized: true });
}

// 40. TLS — rejectUnauthorized: false (위험, 정탐지여야 함)
function insecureRequest() {
  return https.request({ hostname: "api.example.com", rejectUnauthorized: false });
}

// -----------------------------------------------------------
// Summary:
// 20 safe patterns (should NOT be flagged = false positive if flagged)
// 20 dangerous patterns (SHOULD be flagged = true positive)
//
// Expected: true positives should be detected, safe patterns should not.
// Any safe pattern flagged = false positive (FP)
// Any dangerous pattern missed = false negative (FN)
// -----------------------------------------------------------

module.exports = { app };
