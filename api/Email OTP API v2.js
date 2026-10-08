"use strict";

/**
 * Vercel Node.js function for email OTP.
 * Put this file at: api/email-otp.js
 * Install: npm install nodemailer firebase-admin
 *
 * Request body for sending a signup code:
 *   { "action": "send", "email": "name@example.com", "phone": "+923001234567" }
 * Request body for checking an account and sending a reset code:
 *   { "action": "check_and_send", "email": "name@example.com", "phone": "+923001234567" }
 * Request body for checking a code:
 *   { "action": "verify", "ticket": "...", "code": "123456" }
 */

const crypto = require("node:crypto");
const nodemailer = require("nodemailer");
const admin = require("firebase-admin");

const OTP_LIFETIME_MS = 10 * 60 * 1000;
const VERIFIED_TOKEN_LIFETIME_MS = 15 * 60 * 1000;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PAKISTAN_PHONE_RE = /^\+923\d{9}$/;

class ServerConfigurationError extends Error {}
let firebaseState;

function requiredEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing server setting: ${name}`);
  return value;
}

function getFirebase() {
  if (!firebaseState) {
    try {
      const raw = process.env.FIREBASE_SERVICE_ACCOUNT;
      if (!raw) throw new ServerConfigurationError();
      const serviceAccount = JSON.parse(raw);
      const app = admin.apps.length
        ? admin.app()
        : admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
      firebaseState = { app, auth: admin.auth(app), db: admin.firestore(app) };
    } catch (error) {
      firebaseState = {
        error:
          error instanceof ServerConfigurationError
            ? error
            : new ServerConfigurationError(),
      };
    }
  }
  if (firebaseState.error) throw firebaseState.error;
  return firebaseState;
}

function base64url(value) {
  return Buffer.from(value).toString("base64url");
}

function hmac(value) {
  return crypto
    .createHmac("sha256", requiredEnv("OTP_SECRET"))
    .update(value)
    .digest("base64url");
}

function safeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function signObject(object) {
  const payload = base64url(JSON.stringify(object));
  return `${payload}.${hmac(payload)}`;
}

function readSignedObject(token) {
  if (typeof token !== "string") throw new Error("Invalid ticket");
  const parts = token.split(".");
  if (parts.length !== 2 || !safeEqual(hmac(parts[0]), parts[1])) {
    throw new Error("Invalid ticket");
  }
  try {
    return JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
  } catch {
    throw new Error("Invalid ticket");
  }
}

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function cleanCode(value) {
  return String(value || "").replace(/\D/g, "");
}

function allowedOrigins() {
  return requiredEnv("ALLOWED_ORIGIN")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean);
}

function allowCors(req, res) {
  const origins = allowedOrigins();
  const requestOrigin = req.headers.origin;
  if (requestOrigin && origins.includes(requestOrigin)) {
    res.setHeader("Access-Control-Allow-Origin", requestOrigin);
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

function reject(res, status, message) {
  return res.status(status).json({ ok: false, message });
}

function validateIdentity(res, body) {
  const email = normalizeEmail(body.email);
  const phone = String(body.phone || "").trim();
  if (!EMAIL_RE.test(email)) {
    reject(res, 400, "Enter a valid email address.");
    return null;
  }
  if (!PAKISTAN_PHONE_RE.test(phone)) {
    reject(res, 400, "Enter a Pakistani number like +923001234567.");
    return null;
  }
  return { email, phone };
}

async function sendCode(res, body, purpose = "signup", uid) {
  const identity = validateIdentity(res, body);
  if (!identity) return;
  const { email, phone } = identity;

  const code = crypto.randomInt(0, 1_000_000).toString().padStart(6, "0");
  const expiresAt = Date.now() + OTP_LIFETIME_MS;
  const nonce = crypto.randomBytes(18).toString("base64url");
  const codeDigest = hmac(`otp|${email}|${phone}|${code}|${expiresAt}|${nonce}`);
  const ticketData = {
    type: "email-otp",
    version: 1,
    purpose,
    email,
    phone,
    expiresAt,
    nonce,
    codeDigest,
  };
  if (uid) ticketData.uid = uid;
  const ticket = signObject(ticketData);

  const gmailUser = requiredEnv("GMAIL_USER");
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: gmailUser,
      pass: requiredEnv("GMAIL_APP_PASSWORD"),
    },
  });

  await transporter.sendMail({
    from: `Verification <${gmailUser}>`,
    to: email,
    subject: "Your verification code",
    text: `Your verification code is ${code}. It will expire in 10 minutes. If you did not request it, ignore this email.`,
    html: `
      <div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;padding:28px">
        <h2 style="margin:0 0 12px">Verify your email</h2>
        <p style="color:#444">Use this 6-digit code:</p>
        <div style="font-size:34px;font-weight:700;letter-spacing:8px;margin:24px 0">${code}</div>
        <p style="color:#555">This code will expire in 10 minutes.</p>
        <p style="color:#777;font-size:13px">If you did not request this code, ignore this email.</p>
      </div>`,
  });

  return res.status(200).json({
    ok: true,
    message: "Code sent. Check your email.",
    ticket,
    expiresInSeconds: OTP_LIFETIME_MS / 1000,
  });
}

async function checkAndSend(res, body) {
  const identity = validateIdentity(res, body);
  if (!identity) return;
  const { email, phone } = identity;
  const { db } = getFirebase();
  const snapshot = await db.collection("users").where("email", "==", email).limit(1).get();
  if (snapshot.empty || snapshot.docs[0].data().phone !== phone) {
    return reject(res, 400, "This email and number do not match our records.");
  }
  return sendCode(res, { email, phone }, "forgot", snapshot.docs[0].id);
}

function verifyCode(res, body) {
  const code = cleanCode(body.code);
  if (!/^\d{6}$/.test(code)) return reject(res, 400, "Enter the 6-digit code.");

  let data;
  try {
    data = readSignedObject(body.ticket);
  } catch {
    return reject(res, 400, "This verification request is not valid. Send a new code.");
  }

  if (data.type !== "email-otp" || data.version !== 1) {
    return reject(res, 400, "This verification request is not valid. Send a new code.");
  }
  if (!Number.isFinite(data.expiresAt) || Date.now() > data.expiresAt) {
    return reject(res, 400, "This code has expired. Send a new code.");
  }

  const expected = hmac(
    `otp|${data.email}|${data.phone}|${code}|${data.expiresAt}|${data.nonce}`
  );
  if (!safeEqual(expected, data.codeDigest)) {
    return reject(res, 400, "The code is not correct.");
  }

  const now = Date.now();
  const tokenData = {
    type: "verified-email",
    version: 1,
    purpose: data.purpose,
    email: data.email,
    phone: data.phone,
    verifiedAt: now,
    expiresAt: now + VERIFIED_TOKEN_LIFETIME_MS,
    nonce: crypto.randomBytes(18).toString("base64url"),
  };
  if (data.uid) tokenData.uid = data.uid;
  const verificationToken = signObject(tokenData);

  return res.status(200).json({
    ok: true,
    verified: true,
    message: "Email verified.",
    email: data.email,
    phone: data.phone,
    verificationToken,
    tokenExpiresInSeconds: VERIFIED_TOKEN_LIFETIME_MS / 1000,
  });
}

module.exports = async function handler(req, res) {
  try {
    allowCors(req, res);

    if (req.method === "OPTIONS") return res.status(204).end();
    if (req.method !== "POST") return reject(res, 405, "Use POST.");

    const origins = allowedOrigins();
    if (req.headers.origin && !origins.includes(req.headers.origin)) {
      return reject(res, 403, "This website is not allowed.");
    }

    const body = typeof req.body === "string" ? JSON.parse(req.body) : req.body || {};
    if (body.action === "send") return await sendCode(res, body, "signup");
    if (body.action === "check_and_send") return await checkAndSend(res, body);
    if (body.action === "verify") return verifyCode(res, body);
    return reject(res, 400, "Use action: send or verify.");
  } catch (error) {
    if (error instanceof ServerConfigurationError) {
      return reject(res, 500, "Server is not configured.");
    }
    console.error("Email OTP error:", error.message);
    return reject(res, 500, "The server could not complete this request.");
  }
};
