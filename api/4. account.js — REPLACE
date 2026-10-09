"use strict";

/**
 * Vercel Node.js function for account creation and password reset.
 * Put this file at: api/account.js
 */

const crypto = require("node:crypto");
const admin = require("firebase-admin");

const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX = 30;
const rateBuckets = new Map();

class ServerConfigurationError extends Error {}
class RequestError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}
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
  if (typeof token !== "string") throw new Error("Invalid token");
  const parts = token.split(".");
  if (parts.length !== 2 || !safeEqual(hmac(parts[0]), parts[1])) {
    throw new Error("Invalid token");
  }
  try {
    return JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
  } catch {
    throw new Error("Invalid token");
  }
}

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
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
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
}

function reject(res, status, message) {
  return res.status(status).json({ ok: false, message });
}

function cleanText(value) {
  return typeof value === "string" ? value.trim() : "";
}

function clientIp(req) {
  const forwarded = cleanText(req.headers["x-forwarded-for"] || "");
  return (forwarded.split(",")[0] || req.socket?.remoteAddress || "unknown").trim();
}

function enforceRateLimit(req, uid) {
  const now = Date.now();
  const key = `${clientIp(req)}|${uid}`;
  const current = rateBuckets.get(key);
  if (!current || now >= current.resetAt) {
    rateBuckets.set(key, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
  } else {
    current.count += 1;
    if (current.count > RATE_LIMIT_MAX) throw new RequestError(429, "Too many requests. Try again shortly.");
  }
  if (rateBuckets.size > 5000) {
    for (const [bucketKey, bucket] of rateBuckets) {
      if (now >= bucket.resetAt) rateBuckets.delete(bucketKey);
    }
  }
}

async function authenticate(req, firebase) {
  const header = cleanText(req.headers.authorization || "");
  const match = header.match(/^Bearer\s+(.+)$/i);
  if (!match) throw new RequestError(401, "Sign in is required.");
  try {
    const token = await firebase.auth.verifyIdToken(match[1], true);
    if (!token.uid) throw new Error("Missing uid");
    return { uid: token.uid };
  } catch {
    throw new RequestError(401, "Your session is not valid. Sign in again.");
  }
}

function isStrongPassword(password) {
  return (
    typeof password === "string" &&
    password.length >= 8 &&
    /[A-Z]/.test(password) &&
    /[a-z]/.test(password) &&
    /\d/.test(password) &&
    /[^A-Za-z0-9]/.test(password)
  );
}

function readVerificationToken(token, purpose) {
  let data;
  try {
    data = readSignedObject(token);
  } catch {
    return null;
  }
  if (
    data.type !== "verified-email" ||
    data.version !== 1 ||
    data.purpose !== purpose ||
    !Number.isFinite(data.expiresAt) ||
    Date.now() > data.expiresAt
  ) {
    return null;
  }
  return data;
}

async function signup(res, body, firebase) {
  const email = normalizeEmail(body.email);
  const phone = String(body.phone || "").trim();
  const token = readVerificationToken(body.verificationToken, "signup");
  if (
    !token ||
    normalizeEmail(token.email) !== email ||
    String(token.phone || "").trim() !== phone
  ) {
    return reject(res, 400, "Verification has expired. Send a new code.");
  }
  if (!isStrongPassword(body.password)) {
    return reject(res, 400, "Password is not strong enough.");
  }

  const existing = await firebase.db
    .collection("users")
    .where("email", "==", email)
    .limit(1)
    .get();
  if (!existing.empty) {
    return reject(res, 400, "This email is already registered.");
  }

  let userRecord;
  try {
    userRecord = await firebase.auth.createUser({
      email,
      password: body.password,
      emailVerified: true,
    });
  } catch (error) {
    if (error && error.code === "auth/email-already-exists") {
      return reject(res, 400, "This email is already registered.");
    }
    throw error;
  }

  try {
    await firebase.db.collection("users").doc(userRecord.uid).set({
      email,
      phone,
      createdAt: new Date().toISOString(),
    });
  } catch (error) {
    try {
      await firebase.auth.deleteUser(userRecord.uid);
    } catch {
      // Best-effort rollback; keep the original Firestore error.
    }
    throw error;
  }

  return res.status(200).json({ ok: true, message: "Account created." });
}

async function resetPassword(res, body, firebase) {
  const token = readVerificationToken(body.verificationToken, "forgot");
  if (!token || typeof token.uid !== "string" || !token.uid) {
    return reject(res, 400, "Verification has expired. Send a new code.");
  }
  if (!isStrongPassword(body.newPassword)) {
    return reject(res, 400, "Password is not strong enough.");
  }

  await firebase.auth.updateUser(token.uid, { password: body.newPassword });
  return res.status(200).json({ ok: true, message: "Password updated." });
}

async function profile(res, req, firebase) {
  const user = await authenticate(req, firebase);
  enforceRateLimit(req, user.uid);
  const snapshot = await firebase.db.collection("users").doc(user.uid).get();
  if (!snapshot.exists) throw new RequestError(404, "Profile not found.");
  const data = snapshot.data();
  return res.status(200).json({
    ok: true,
    profile: {
      email: normalizeEmail(data.email),
      phone: cleanText(data.phone),
      createdAt: cleanText(data.createdAt),
    },
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
    if (body.action === "signup") {
      return await signup(res, body, getFirebase());
    }
    if (body.action === "reset_password") {
      return await resetPassword(res, body, getFirebase());
    }
    if (body.action === "profile") {
      return await profile(res, req, getFirebase());
    }
    return reject(res, 400, "Use action: signup, reset_password, or profile.");
  } catch (error) {
    if (error instanceof RequestError) return reject(res, error.status, error.message);
    if (error instanceof ServerConfigurationError) {
      return reject(res, 500, "Server is not configured.");
    }
    console.error("Account API error:", error.message);
    return reject(res, 500, "The server could not complete this request.");
  }
};
