// 데모용 '바이브코딩 결과물' 예시(JavaScript).
// AI 에게 "로그인되는 간단한 Express API" 를 시켜 나온 듯한, 동작하지만 취약한 코드.
// 실제 키/비밀은 모두 가짜다.

const express = require("express");
const crypto = require("crypto");
const { exec } = require("child_process");
const https = require("https");
const app = express();

// (취약) 시크릿을 코드에 하드코딩
const JWT_SECRET = "supersecret_jwt_value_1234567890";

// (취약) 모든 출처 허용 CORS
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  next();
});

app.get("/user", (req, res) => {
  // (취약) 템플릿 문자열로 SQL 조립 -> SQL 인젝션
  const id = req.query.id;
  db.query(`SELECT * FROM users WHERE id = ${id}`, (e, rows) => res.json(rows));
});

app.get("/token", (req, res) => {
  // (취약) Math.random() 으로 보안 토큰 생성
  res.json({ token: Math.random().toString(36) });
});

app.get("/run", (req, res) => {
  // (취약) 사용자 입력을 셸 명령으로 실행 -> 명령어 주입
  exec(`echo ${req.query.msg}`, (e, out) => res.send(out));
});

app.get("/render", (req, res) => {
  // (취약) eval 사용
  const result = eval(req.query.expr);
  res.send(String(result));
});

// (취약) TLS 인증서 검증 비활성화
const agent = new https.Agent({ rejectUnauthorized: false });

app.listen(3000);
