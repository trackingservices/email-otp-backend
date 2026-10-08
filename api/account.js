"use strict";

/**
 * Vercel Node.js function for account creation and password reset.
 * Put this file at: api/account.js
 */

const crypto = require("node:crypto");
const admin = require("firebase-admin");

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
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

function reject(res, status, message) {
