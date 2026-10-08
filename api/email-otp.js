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
