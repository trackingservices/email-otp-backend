"use strict";

/**
 * Vercel Node.js function for secure TrackingsPK administration.
 * Put this file at: api/admin.js
 */

const crypto = require("node:crypto");
const admin = require("firebase-admin");
const nodemailer = require("nodemailer");

const ORDER_ID_RE = /^TPK-[A-Z0-9]{6,24}$/;
const SAFE_ID_RE = /^[A-Za-z0-9_-]{1,60}$/;
const MANUAL_TRACKING_RE = /^[A-Z0-9-]{4,40}$/;
const DATE_ONLY_RE = /^\d{4}-\d{2}-\d{2}$/;
const ALLOWED_COURIERS = new Set(["DPD", "DHL UK", "Royal Mail", "Evri"]);
const ORDER_STATUSES = new Set(["pending", "paid", "delivered", "rejected", "refunded", "cancelled"]);
const INVENTORY_STATUSES = new Set(["available", "reserved", "sold", "refunded"]);
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX = 60;
const PENDING_EXPIRY_HOURS = 24;
const rateBuckets = new Map();

const PACKAGE_SEEDS = [
  { id: "per-tracking", name: "Pay Per Tracking", type: "per_unit", pricePerUnit: 40, minQty: 1, maxQty: 4, currency: "PKR", active: true, sortOrder: 1 },
  { id: "pack-5", name: "Bulk Pack", type: "per_unit", pricePerUnit: 36, regularPricePerUnit: 40, minQty: 5, maxQty: 9, currency: "PKR", active: true, sortOrder: 2 },
  { id: "pack-10", name: "Value Pack", type: "per_unit", pricePerUnit: 35, regularPricePerUnit: 40, minQty: 10, maxQty: 100, currency: "PKR", active: true, sortOrder: 3 },
];

const PAYMENT_METHOD_SEEDS = [
  {
    id: "easypaisa",
    name: "Easypaisa",
    holderName: "Muhammad Asghar",
    accountNumber: "03246692194",
    instructions: "Kindly send the payment to the above Easypaisa account, then enter the number/account you sent the payment from. It will be verified within 1-10 minutes, usually within seconds. If admin is offline, it might take more time than usual.",
    enabled: true,
  },
  {
    id: "jazzcash",
    name: "JazzCash",
    holderName: "Muhammad Asghar",
    accountNumber: "03043302951",
    instructions: "Kindly send the payment to the above JazzCash account, then enter the number/account you sent the payment from. It will be verified within 1-10 minutes, usually within seconds. If admin is offline, it might take more time than usual.",
    enabled: true,
  },
];

class ServerConfigurationError extends Error {}
class RequestError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}
let firebaseState;
let seedPromise;
let mailTransporter;

function requiredEnv(name) {
  const value = process.env[name];
  if (!value) throw new ServerConfigurationError();
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
      firebaseState = { error: error instanceof ServerConfigurationError ? error : new ServerConfigurationError() };
    }
  }
  if (firebaseState.error) throw firebaseState.error;
  return firebaseState;
}

function getMailTransporter() {
  if (!mailTransporter) {
    mailTransporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: requiredEnv("GMAIL_USER"),
        pass: requiredEnv("GMAIL_APP_PASSWORD"),
      },
    });
  }
  return mailTransporter;
}

function allowedOrigins() {
  return requiredEnv("ALLOWED_ORIGIN")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean);
}

function adminEmails() {
  return requiredEnv("ADMIN_EMAILS")
    .split(",")
    .map((email) => email.trim().toLowerCase())
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

async function authenticateAdmin(req, firebase) {
  const header = cleanText(req.headers.authorization || "");
  const match = header.match(/^Bearer\s+(.+)$/i);
  if (!match) throw new RequestError(401, "Sign in is required.");
  let token;
  try {
    token = await firebase.auth.verifyIdToken(match[1], true);
  } catch {
    throw new RequestError(401, "Your session is not valid. Sign in again.");
  }
  const email = cleanText(token.email).toLowerCase();
  if (!token.uid || !email || !adminEmails().includes(email)) throw new RequestError(403, "Admin access is required.");
  return { uid: token.uid, email };
}

async function seedCollectionIfEmpty(db, collectionName, rows) {
  const snapshot = await db.collection(collectionName).limit(1).get();
  if (!snapshot.empty) return;
  const batch = db.batch();
  for (const row of rows) {
    const { id, ...data } = row;
    batch.set(db.collection(collectionName).doc(id), data);
  }
  await batch.commit();
}

async function ensureSeedData(db) {
  if (!seedPromise) {
    seedPromise = Promise.all([
      seedCollectionIfEmpty(db, "packages", PACKAGE_SEEDS),
      seedCollectionIfEmpty(db, "payment_methods", PAYMENT_METHOD_SEEDS),
    ]).catch((error) => {
      seedPromise = undefined;
      throw error;
    });
  }
  await seedPromise;
}

async function autoExpirePendings(db) {
  try {
    const now = new Date();
    const nowIso = now.toISOString();
    const cutoffIso = new Date(now.getTime() - PENDING_EXPIRY_HOURS * 60 * 60 * 1000).toISOString();
    const snapshot = await db.collection("orders")
      .where("status", "==", "pending")
      .where("placedAt", "<", cutoffIso)
      .limit(100)
      .get();

    for (const candidate of snapshot.docs) {
      try {
        await db.runTransaction(async (transaction) => {
          const orderDoc = await transaction.get(candidate.ref);
          if (!orderDoc.exists) return;
          const order = orderDoc.data();
          const placedAt = cleanText(order.placedAt || order.createdAt);
          if (order.status !== "pending" || !placedAt || placedAt >= cutoffIso) return;

          const orderId = cleanText(order.orderId) || candidate.id;
          const reservedSnapshot = await transaction.get(
            db.collection("tracking_numbers")
              .where("orderId", "==", orderId)
              .where("status", "==", "reserved")
              .limit(200)
          );
          for (const inventoryDoc of reservedSnapshot.docs) {
            transaction.update(inventoryDoc.ref, {
              status: "available",
              orderId: admin.firestore.FieldValue.delete(),
              reservedAt: admin.firestore.FieldValue.delete(),
            });
          }
          transaction.update(candidate.ref, {
            status: "cancelled",
            cancelledAt: nowIso,
            cancelReason: "auto_expired",
            updatedAt: nowIso,
          });
          transaction.set(db.collection("notifications").doc(), {
            uid: order.uid,
            type: "order_expired",
            orderId,
            message: `Your pending order ${orderId} was cancelled after 24 hours without payment.`,
            read: false,
            createdAt: nowIso,
          });
          transaction.set(db.collection("audit_logs").doc(), {
            type: "order_auto_expired",
            orderId,
            uid: order.uid,
            email: cleanText(order.email),
            detail: { reason: "auto_expired", releasedCount: reservedSnapshot.size },
            at: nowIso,
          });
        });
      } catch (error) {
        console.error(`Auto-expiry failed for ${candidate.id}:`, error.message);
      }
    }
  } catch (error) {
    console.error("Pending-order auto-expiry failed:", error.message);
  }
}

function parseBody(req) {
  try {
    return typeof req.body === "string" ? JSON.parse(req.body) : req.body || {};
  } catch {
    throw new RequestError(400, "Request body must be valid JSON.");
  }
}

function numberInRange(value, name, min, max, integer = true) {
  const number = Number(value);
  if (!Number.isFinite(number) || (integer && !Number.isInteger(number)) || number < min || number > max) {
    throw new RequestError(400, `${name} is not valid.`);
  }
  return number;
}

function boolValue(value, name) {
  if (typeof value !== "boolean") throw new RequestError(400, `${name} must be true or false.`);
  return value;
}

function orderIdFrom(body) {
  const orderId = cleanText(body.orderId).toUpperCase();
  if (!ORDER_ID_RE.test(orderId)) throw new RequestError(400, "Enter a valid order ID.");
  return orderId;
}

function safeId(value, name) {
  const id = cleanText(value);
  if (!SAFE_ID_RE.test(id)) throw new RequestError(400, `${name} is not valid.`);
  return id;
}

function requestedLimit(value, fallback = 100, max = 200) {
  if (value === undefined || value === null || value === "") return fallback;
  return numberInRange(value, "Limit", 1, max);
}

function auditData(type, adminUser, detail, orderId) {
  const data = { type, adminEmail: adminUser.email, detail, at: new Date().toISOString() };
  if (orderId) data.orderId = orderId;
  return data;
}

function inventoryId(number) {
  return crypto.createHash("sha256").update(number).digest("hex");
}

function suitableFromDateOnly(value) {
  if (!value) return null;
  let parsed;
  try {
    parsed = typeof value.toDate === "function" ? value.toDate() : new Date(value);
  } catch {
    return null;
  }
  if (!(parsed instanceof Date) || Number.isNaN(parsed.getTime())) return null;
  return parsed.toISOString().slice(0, 10);
}

function parseSuitableFrom(value) {
  if (value === undefined || value === null || value === "") return null;
  if (typeof value !== "string") {
    throw new RequestError(400, "Suitable from must be a valid date in YYYY-MM-DD format.");
  }
  const dateOnly = value.trim();
  if (!DATE_ONLY_RE.test(dateOnly)) {
    throw new RequestError(400, "Suitable from must be a valid date in YYYY-MM-DD format.");
  }
  const parsed = new Date(`${dateOnly}T00:00:00.000Z`);
  if (Number.isNaN(parsed.getTime()) || parsed.toISOString().slice(0, 10) !== dateOnly) {
    throw new RequestError(400, "Suitable from must be a valid date in YYYY-MM-DD format.");
  }
  return parsed.toISOString();
}

function storedSuitableFromIso(value) {
  const dateOnly = suitableFromDateOnly(value);
  return dateOnly ? `${dateOnly}T00:00:00.000Z` : null;
}

function normalizeDeliveredEntry(value) {
  if (typeof value === "string") return { number: cleanText(value).toUpperCase(), courier: null };
  if (!value || typeof value !== "object") return { number: "", courier: null };
  return { number: cleanText(value.number).toUpperCase(), courier: cleanText(value.courier) || null };
}

async function hydrateDeliveredNumbers(db, values) {
  const entries = (Array.isArray(values) ? values : []).map(normalizeDeliveredEntry).filter((row) => row.number);
  if (!entries.length) return [];
  const refs = entries.map((row) => db.collection("tracking_numbers").doc(inventoryId(row.number)));
  const snapshots = await db.getAll(...refs);
  return entries.map((row, index) => {
    const inventory = snapshots[index].exists ? snapshots[index].data() : {};
    return {
      number: row.number,
      courier: row.courier || cleanText(inventory.courier) || null,
      claimed: inventory.claimed === true,
      claimedAt: inventory.claimedAt || null,
    };
  });
}

async function adminCustomerContact(db, order) {
  const uid = cleanText(order.uid || order.userId);
  let profile = {};
  if (uid) {
    const snapshot = await db.collection("users").doc(uid).get();
    if (snapshot.exists) profile = snapshot.data() || {};
  }
  return {
    customerEmail: cleanText(profile.email) || cleanText(order.email) || null,
    customerPhone: cleanText(profile.phone) || null,
  };
}

async function adminOrderResponse(db, order) {
  const orderCreatedAt = order.orderCreatedAt || order.createdAt || null;
  const placedAt = order.placedAt || order.createdAt || null;
  const [customer, deliveredNumbers] = await Promise.all([
    adminCustomerContact(db, order),
    hydrateDeliveredNumbers(db, order.deliveredNumbers),
  ]);
  return {
    orderId: order.orderId,
    orderCreatedAt,
    placedAt,
    email: customer.customerEmail,
    customerEmail: customer.customerEmail,
    customerPhone: customer.customerPhone,
    packageName: order.packageName,
    quantity: order.quantity,
    amountPkr: Number(order.amountPkr ?? order.price ?? 0),
    price: Number(order.price ?? order.amountPkr ?? 0),
    currency: cleanText(order.currency) || "PKR",
    isGift: order.isGift === true,
    paymentMethodName: cleanText(order.paymentMethodName) || null,
    txnRef: cleanText(order.txnRef) || null,
    senderNumber: cleanText(order.senderNumber) || null,
    status: order.status,
    deliveryStatus: cleanText(order.deliveryStatus),
    expectedDeliveryDate: order.expectedDeliveryDate || null,
    deliveredNumbers,
    deliveredAt: order.deliveredAt || null,
    createdAt: orderCreatedAt,
    updatedAt: order.updatedAt,
  };
}

async function getOrderDetail(res, body, db) {
  const orderId = orderIdFrom(body);
  const snapshot = await db.collection("orders").doc(orderId).get();
  if (!snapshot.exists) throw new RequestError(404, "Order not found.");
  return res.status(200).json({ ok: true, order: await adminOrderResponse(db, snapshot.data()) });
}

async function listOrders(res, body, db) {
  await autoExpirePendings(db);
  const status = cleanText(body.status).toLowerCase();
  const search = cleanText(body.search).toLowerCase();
  const limit = requestedLimit(body.limit);
  if (status && !ORDER_STATUSES.has(status)) throw new RequestError(400, "Order status is not valid.");
  if (search.length > 100) throw new RequestError(400, "Search is too long.");

  const snapshot = await db.collection("orders").limit(500).get();
  const selected = snapshot.docs
    .map((doc) => doc.data())
    .filter((order) => !status || order.status === status)
    .filter((order) => {
      if (!search) return true;
      return cleanText(order.orderId).toLowerCase().startsWith(search) || cleanText(order.email).toLowerCase().includes(search);
    })
    .sort((a, b) => String(b.orderCreatedAt || b.createdAt).localeCompare(String(a.orderCreatedAt || a.createdAt)))
    .slice(0, limit);
  const orders = await Promise.all(selected.map((order) => adminOrderResponse(db, order)));
  return res.status(200).json({ ok: true, orders });
}

async function approvePayment(res, body, db, adminUser) {
  const orderId = orderIdFrom(body);
  const orderRef = db.collection("orders").doc(orderId);
  await db.runTransaction(async (transaction) => {
    const orderDoc = await transaction.get(orderRef);
    if (!orderDoc.exists) throw new RequestError(404, "Order not found.");
    const order = orderDoc.data();
    if (order.isGift === true) throw new RequestError(400, "gift orders skip payment verification");
    if (order.status !== "pending") throw new RequestError(409, "Only pending orders can be approved.");

    const reservedSnapshot = await transaction.get(
      db.collection("tracking_numbers").where("orderId", "==", orderId).where("status", "==", "reserved").limit(200)
    );
    const now = new Date().toISOString();
    for (const inventoryDoc of reservedSnapshot.docs) {
      transaction.update(inventoryDoc.ref, {
        status: "available",
        orderId: admin.firestore.FieldValue.delete(),
        reservedAt: admin.firestore.FieldValue.delete(),
      });
    }
    transaction.update(orderRef, {
      status: "paid",
      paidAt: now,
      verifiedBy: adminUser.email,
      updatedAt: now,
    });
    transaction.set(db.collection("audit_logs").doc(), auditData(
      "payment_approved",
      adminUser,
      { releasedCount: reservedSnapshot.size },
      orderId
    ));
  });
  return res.status(200).json({ ok: true });
}

function normalizeTrackingItems(value) {
  if (!Array.isArray(value)) throw new RequestError(400, "Tracking items are required.");
  const items = value.map((item) => ({
    number: cleanText(item && item.number).toUpperCase(),
    courier: cleanText(item && item.courier),
  }));
  if (items.some((item) => !MANUAL_TRACKING_RE.test(item.number))) {
    throw new RequestError(400, "Each tracking number must be 4-40 letters, numbers, or hyphens.");
  }
  if (items.some((item) => !ALLOWED_COURIERS.has(item.courier))) {
    throw new RequestError(400, "Choose DPD, DHL UK, Royal Mail, or Evri for each tracking number.");
  }
  if (new Set(items.map((item) => item.number)).size !== items.length) {
    throw new RequestError(400, "Tracking numbers must not be duplicated.");
  }
  return items;
}

async function sendTrackingReadyEmail(order, orderId, items) {
  const gmailUser = requiredEnv("GMAIL_USER");
  const customer = await admin.auth().getUser(order.uid);
  const customerEmail = cleanText(customer.email);
  if (!customerEmail) throw new Error("Customer email is unavailable");
  const giftText = order.isGift === true ? "gift " : "";
  const itemLines = items.map((item) => `- ${item.number} — ${item.courier}`).join("\n");
  const text = [
    "Hello,",
    "",
    `Your ${giftText}tracking numbers for order ${orderId} are ready.`,
    "",
    itemLines,
    "",
    "Open My Trackings: https://trackingspk.vercel.app",
    `Support: ${gmailUser}`,
    "",
    "TrackingsPK",
  ].join("\n");
  await getMailTransporter().sendMail({
    from: `TrackingsPK <${gmailUser}>`,
    to: customerEmail,
    subject: "Your TrackingsPK tracking numbers are ready",
    text,
  });
}

async function addTracking(res, body, db, adminUser) {
  const orderId = orderIdFrom(body);
  const items = normalizeTrackingItems(body.items);
  const orderRef = db.collection("orders").doc(orderId);
  let deliveredCount = 0;
  let deliveredOrder = null;

  await db.runTransaction(async (transaction) => {
    const orderDoc = await transaction.get(orderRef);
    if (!orderDoc.exists) throw new RequestError(404, "Order not found.");
    const order = orderDoc.data();
    if (order.status !== "paid") throw new RequestError(409, "Only paid orders awaiting tracking can receive tracking numbers.");
    if (items.length !== Number(order.quantity)) {
      throw new RequestError(400, `Enter exactly ${Number(order.quantity)} tracking number(s) for this package.`);
    }

    const refs = items.map((item) => db.collection("tracking_numbers").doc(inventoryId(item.number)));
    const snapshots = refs.length ? await transaction.getAll(...refs) : [];
    const enforceSuitableFrom = cleanText(order.deliveryStatus).toLowerCase() === "delivered";
    const orderCreatedDate = enforceSuitableFrom ? suitableFromDateOnly(order.orderCreatedAt) : null;
    if (enforceSuitableFrom && !orderCreatedDate) {
      throw new RequestError(400, "Order created time is invalid.");
    }
    const todayMinus2Date = new Date();
    todayMinus2Date.setUTCDate(todayMinus2Date.getUTCDate() - 2);
    const todayMinus2 = todayMinus2Date.toISOString().slice(0, 10);
    const suitableFromValues = [];
    for (let index = 0; index < snapshots.length; index += 1) {
      const inventory = snapshots[index].exists ? snapshots[index].data() : null;
      if (inventory && inventory.status === "sold") {
        throw new RequestError(409, `Tracking number ${items[index].number} is already sold.`);
      }
      const suitableFrom = inventory ? storedSuitableFromIso(inventory.suitableFrom) : null;
      const suitableDate = suitableFrom ? suitableFrom.slice(0, 10) : null;
      if (enforceSuitableFrom && suitableDate && (suitableDate < orderCreatedDate || suitableDate > todayMinus2)) {
        throw new RequestError(400, `Tracking number ${items[index].number} is not suitable for this order date.`);
      }
      suitableFromValues.push(suitableFrom);
    }

    const now = new Date().toISOString();
    for (let index = 0; index < refs.length; index += 1) {
      const item = items[index];
      transaction.set(refs[index], {
        number: item.number,
        packageId: cleanText(order.packageId),
        courier: item.courier,
        status: "sold",
        orderId,
        uid: order.uid,
        soldAt: now,
        deliveredAt: now,
        suitableFrom: suitableFromValues[index],
      });
    }
    transaction.update(orderRef, {
      status: "delivered",
      deliveredNumbers: items,
      deliveredAt: now,
      updatedAt: now,
    });
    transaction.set(db.collection("notifications").doc(), {
      uid: order.uid,
      type: "tracking_delivered",
      orderId,
      message: order.isGift === true
        ? `Your gift tracking numbers for order ${orderId} are ready — open My Trackings.`
        : `Your tracking numbers for order ${orderId} are ready — open My Trackings.`,
      read: false,
      createdAt: now,
    });
    transaction.set(db.collection("audit_logs").doc(), auditData(
      "tracking_delivered",
      adminUser,
      { deliveredCount: items.length, items },
      orderId
    ));
    deliveredCount = items.length;
    deliveredOrder = { uid: order.uid, isGift: order.isGift === true };
  });

  try {
    await sendTrackingReadyEmail(deliveredOrder, orderId, items);
  } catch (error) {
    console.error(`Tracking-ready email failed for ${orderId}:`, error.message);
  }
  return res.status(200).json({ ok: true, deliveredCount });
}

async function editTracking(res, body, db, adminUser) {
  const orderId = orderIdFrom(body);
  const items = normalizeTrackingItems(body.items);
  const orderRef = db.collection("orders").doc(orderId);

  await db.runTransaction(async (transaction) => {
    const orderDoc = await transaction.get(orderRef);
    if (!orderDoc.exists) throw new RequestError(404, "Order not found.");
    const order = orderDoc.data();
    if (order.status !== "delivered") {
      throw new RequestError(409, "Only delivered orders can have tracking numbers edited.");
    }
    if (items.length !== Number(order.quantity)) {
      throw new RequestError(400, `Enter exactly ${Number(order.quantity)} tracking number(s) for this package.`);
    }

    const before = (Array.isArray(order.deliveredNumbers) ? order.deliveredNumbers : [])
      .map(normalizeDeliveredEntry)
      .filter((item) => item.number);
    const beforeNumbers = new Set(before.map((item) => item.number));
    const afterNumbers = new Set(items.map((item) => item.number));
    const newRefs = items.map((item) => db.collection("tracking_numbers").doc(inventoryId(item.number)));
    const newSnapshots = newRefs.length ? await transaction.getAll(...newRefs) : [];

    for (let index = 0; index < newSnapshots.length; index += 1) {
      const snapshot = newSnapshots[index];
      if (beforeNumbers.has(items[index].number) || !snapshot.exists) continue;
      const inventory = snapshot.data();
      if (inventory.status === "sold" && cleanText(inventory.orderId) !== orderId) {
        throw new RequestError(409, `Tracking number ${items[index].number} is already sold.`);
      }
    }

    const now = new Date().toISOString();
    for (const oldItem of before) {
      if (afterNumbers.has(oldItem.number)) continue;
      const oldRef = db.collection("tracking_numbers").doc(inventoryId(oldItem.number));
      transaction.set(oldRef, {
        status: "available",
        orderId: admin.firestore.FieldValue.delete(),
        uid: admin.firestore.FieldValue.delete(),
        soldAt: admin.firestore.FieldValue.delete(),
        claimed: admin.firestore.FieldValue.delete(),
        claimedAt: admin.firestore.FieldValue.delete(),
      }, { merge: true });
    }

    for (let index = 0; index < items.length; index += 1) {
      const item = items[index];
      const inventory = {
        number: item.number,
        packageId: cleanText(order.packageId),
        courier: item.courier,
        status: "sold",
        orderId,
        uid: order.uid,
        soldAt: now,
      };
      if (beforeNumbers.has(item.number)) transaction.set(newRefs[index], inventory, { merge: true });
      else transaction.set(newRefs[index], inventory);
    }

    transaction.update(orderRef, { deliveredNumbers: items, updatedAt: now });
    transaction.set(db.collection("audit_logs").doc(), auditData(
      "tracking_edited",
      adminUser,
      { before, after: items },
      orderId
    ));
  });
  return res.status(200).json({ ok: true });
}

async function rejectOrder(res, body, db, adminUser) {
  const orderId = orderIdFrom(body);
  const reason = cleanText(body.reason);
  if (reason.length > 300) throw new RequestError(400, "Reason is too long.");
  const orderRef = db.collection("orders").doc(orderId);
  await db.runTransaction(async (transaction) => {
    const orderDoc = await transaction.get(orderRef);
    if (!orderDoc.exists) throw new RequestError(404, "Order not found.");
    if (orderDoc.data().status !== "pending") throw new RequestError(409, "Only pending orders can be rejected.");
    const inventorySnapshot = await transaction.get(
      db.collection("tracking_numbers").where("orderId", "==", orderId).where("status", "==", "reserved").limit(200)
    );
    const now = new Date().toISOString();
    for (const inventoryDoc of inventorySnapshot.docs) {
      transaction.update(inventoryDoc.ref, {
        status: "available",
        orderId: admin.firestore.FieldValue.delete(),
        reservedAt: admin.firestore.FieldValue.delete(),
      });
    }
    transaction.update(orderRef, { status: "rejected", rejectionReason: reason, updatedAt: now });
    transaction.set(db.collection("audit_logs").doc(), auditData("order_rejected", adminUser, { reason, releasedCount: inventorySnapshot.size }, orderId));
  });
  return res.status(200).json({ ok: true });
}

async function refundOrder(res, body, db, adminUser) {
  const orderId = orderIdFrom(body);
  const orderRef = db.collection("orders").doc(orderId);
  let refundedCount = 0;
  await db.runTransaction(async (transaction) => {
    const orderDoc = await transaction.get(orderRef);
    if (!orderDoc.exists) throw new RequestError(404, "Order not found.");
    if (orderDoc.data().status !== "paid") throw new RequestError(409, "Only paid orders can be refunded.");
    const inventorySnapshot = await transaction.get(
      db.collection("tracking_numbers").where("orderId", "==", orderId).where("status", "==", "sold").limit(200)
    );
    const now = new Date().toISOString();
    for (const inventoryDoc of inventorySnapshot.docs) {
      transaction.update(inventoryDoc.ref, { status: "refunded", refundedAt: now, orderId });
    }
    transaction.update(orderRef, { status: "refunded", refundedAt: now, updatedAt: now });
    transaction.set(db.collection("audit_logs").doc(), auditData("order_refunded", adminUser, { refundedCount: inventorySnapshot.size }, orderId));
    refundedCount = inventorySnapshot.size;
  });
  return res.status(200).json({ ok: true, refundedCount });
}

async function listPackages(res, db) {
  const snapshot = await db.collection("packages").get();
  const packages = snapshot.docs
    .map((doc) => ({ id: doc.id, ...doc.data() }))
    .filter((row) => cleanText(row.type).toLowerCase() === "per_unit")
    .map((row) => ({
      id: row.id,
      name: cleanText(row.name),
      type: "per_unit",
      pricePerUnit: Number(row.pricePerUnit),
      regularPricePerUnit: row.regularPricePerUnit === undefined ? null : Number(row.regularPricePerUnit),
      minQty: Number(row.minQty),
      maxQty: Number(row.maxQty),
      currency: cleanText(row.currency) || "PKR",
      active: row.active === true,
      sortOrder: Number(row.sortOrder) || 0,
    }))
    .sort((a, b) => a.sortOrder - b.sortOrder || a.minQty - b.minQty);
  return res.status(200).json({ ok: true, packages });
}

async function upsertPackage(res, body, db, adminUser) {
  const id = body.id ? safeId(body.id, "Package ID") : `pkg_${crypto.randomBytes(5).toString("hex")}`;
  const name = cleanText(body.name);
  if (name.length < 2 || name.length > 100) throw new RequestError(400, "Package name must be 2-100 characters.");
  const type = cleanText(body.type).toLowerCase();
  if (type !== "per_unit") throw new RequestError(400, "Package type must be per_unit.");
  const currency = cleanText(body.currency) || "PKR";
  if (!/^[A-Z]{3}$/.test(currency)) throw new RequestError(400, "Currency must be a 3-letter uppercase code.");
  const active = boolValue(body.active, "Active");
  const sortOrder = body.sortOrder === undefined ? 0 : numberInRange(body.sortOrder, "Sort order", 0, 10000);
  const pricePerUnit = numberInRange(body.pricePerUnit, "Price per unit", 1, 10000000);
  let regularPricePerUnit = null;
  if (body.regularPricePerUnit !== undefined && body.regularPricePerUnit !== null && body.regularPricePerUnit !== "") {
    regularPricePerUnit = numberInRange(body.regularPricePerUnit, "Regular price per unit", 1, 10000000);
  }
  const minQty = numberInRange(body.minQty, "Minimum quantity", 1, 1000);
  const maxQty = numberInRange(body.maxQty, "Maximum quantity", 1, 1000);
  if (minQty > maxQty) throw new RequestError(400, "Minimum quantity cannot be greater than maximum quantity.");

  const packageData = {
    name, type: "per_unit", pricePerUnit, minQty, maxQty, currency, active, sortOrder,
    updatedAt: new Date().toISOString(),
  };
  if (regularPricePerUnit !== null) packageData.regularPricePerUnit = regularPricePerUnit;
  const batch = db.batch();
  batch.set(db.collection("packages").doc(id), packageData, { merge: true });
  batch.set(db.collection("audit_logs").doc(), auditData("package_upserted", adminUser, { id, ...packageData }));
  await batch.commit();
  return res.status(200).json({ ok: true, id });
}

async function listPaymentMethods(res, db) {
  const snapshot = await db.collection("payment_methods").get();
  const paymentMethods = snapshot.docs.map((doc) => ({ id: doc.id, ...doc.data() })).sort((a, b) => String(a.name).localeCompare(String(b.name)));
  return res.status(200).json({ ok: true, paymentMethods });
}

async function upsertPaymentMethod(res, body, db, adminUser) {
  const id = body.id ? safeId(body.id, "Payment method ID") : `pay_${crypto.randomBytes(5).toString("hex")}`;
  const name = cleanText(body.name);
  const holderName = cleanText(body.holderName);
  const accountNumber = cleanText(body.accountNumber);
  const instructions = cleanText(body.instructions);
  if (name.length < 2 || name.length > 80) throw new RequestError(400, "Payment method name must be 2-80 characters.");
  if (holderName.length > 100 || accountNumber.length > 120 || instructions.length > 1000) throw new RequestError(400, "Payment method details are too long.");
  const enabled = boolValue(body.enabled, "Enabled");
  const now = new Date().toISOString();
  const batch = db.batch();
  batch.set(db.collection("payment_methods").doc(id), { name, holderName, accountNumber, instructions, enabled, updatedAt: now }, { merge: true });
  batch.set(db.collection("audit_logs").doc(), auditData("payment_method_upserted", adminUser, { id, name, enabled }));
  await batch.commit();
  return res.status(200).json({ ok: true, id });
}

function normalizeInventoryNumber(value) {
  const number = cleanText(value).toUpperCase();
  if (!MANUAL_TRACKING_RE.test(number)) {
    throw new RequestError(400, "Use 4-40 letters, numbers, or hyphens for each tracking number (no spaces or special characters).");
  }
  return number;
}

async function addInventory(res, body, db, adminUser) {
  if (!Array.isArray(body.numbers) || body.numbers.length < 1 || body.numbers.length > 400) {
    throw new RequestError(400, "Provide 1-400 tracking numbers.");
  }
  const packageId = cleanText(body.packageId);
  if (body.courier !== undefined && body.courier !== null && typeof body.courier !== "string") {
    throw new RequestError(400, "Courier must be a valid courier name.");
  }
  const courier = cleanText(body.courier) || null;
  const suitableFrom = parseSuitableFrom(body.suitableFrom);
  if (packageId && !SAFE_ID_RE.test(packageId)) throw new RequestError(400, "Package ID is not valid.");
  if (courier && !ALLOWED_COURIERS.has(courier)) {
    throw new RequestError(400, "Choose DPD, DHL UK, Royal Mail, or Evri for the inventory batch.");
  }
  if (packageId) {
    const packageDoc = await db.collection("packages").doc(packageId).get();
    if (!packageDoc.exists) throw new RequestError(400, "Package not found.");
  }

  const uniqueNumbers = [...new Set(body.numbers.map(normalizeInventoryNumber))];
  const duplicateInputCount = body.numbers.length - uniqueNumbers.length;
  const refs = uniqueNumbers.map((number) => db.collection("tracking_numbers").doc(inventoryId(number)));
  const now = new Date().toISOString();
  let added = 0;
  let existingCount = 0;

  await db.runTransaction(async (transaction) => {
    const snapshots = refs.length ? await transaction.getAll(...refs) : [];
    for (let index = 0; index < snapshots.length; index += 1) {
      if (snapshots[index].exists) {
        existingCount += 1;
      } else {
        transaction.create(refs[index], {
          number: uniqueNumbers[index],
          packageId: packageId || "",
          courier,
          status: "available",
          suitableFrom,
          addedAt: now,
          createdAt: now,
        });
        added += 1;
      }
    }
    transaction.set(db.collection("audit_logs").doc(), auditData("inventory_added", adminUser, { added, skipped: existingCount + duplicateInputCount, packageId: packageId || "", courier }));
  });
  return res.status(200).json({ ok: true, added, skipped: existingCount + duplicateInputCount });
}

async function listInventory(res, body, db) {
  const status = cleanText(body.status).toLowerCase();
  if (status && !INVENTORY_STATUSES.has(status)) throw new RequestError(400, "Inventory status is not valid.");
  let query = db.collection("tracking_numbers");
  if (status) query = query.where("status", "==", status);
  const snapshot = await query.limit(500).get();
  const numbers = snapshot.docs
    .map((doc) => {
      const row = doc.data();
      return { id: doc.id, ...row, suitableFrom: suitableFromDateOnly(row.suitableFrom) };
    })
    .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
  return res.status(200).json({ ok: true, numbers });
}

async function listAvailableInventory(res, db) {
  const snapshot = await db.collection("tracking_numbers")
    .where("status", "==", "available")
    .orderBy("createdAt", "desc")
    .limit(200)
    .get();
  const numbers = snapshot.docs.map((doc) => {
    const row = doc.data();
    return {
      number: cleanText(row.number).toUpperCase(),
      courier: cleanText(row.courier) || null,
      suitableFrom: suitableFromDateOnly(row.suitableFrom),
      addedAt: row.addedAt || row.createdAt || null,
    };
  });
  return res.status(200).json({ ok: true, numbers });
}

async function listAudit(res, body, db) {
  const limit = requestedLimit(body.limit, 100, 200);
  const snapshot = await db.collection("audit_logs").limit(500).get();
  const logs = snapshot.docs
    .map((doc) => ({ id: doc.id, ...doc.data() }))
    .sort((a, b) => String(b.at).localeCompare(String(a.at)))
    .slice(0, limit);
  return res.status(200).json({ ok: true, logs });
}


function csvCell(value) {
  const text = value === undefined || value === null ? "" : String(value);
  return `"${text.replace(/"/g, '""')}"`;
}

function isoValue(value) {
  if (!value) return "";
  try {
    if (typeof value.toDate === "function") return value.toDate().toISOString();
    const parsed = value instanceof Date ? value : new Date(value);
    return Number.isNaN(parsed.getTime()) ? cleanText(value) : parsed.toISOString();
  } catch {
    return cleanText(value);
  }
}

function csvDocument(headers, rows) {
  return [headers, ...rows].map((row) => row.map(csvCell).join(",")).join("\r\n");
}

function exportDateStamp() {
  return new Date().toISOString().slice(0, 10).replace(/-/g, "");
}

async function exportOrders(res, db) {
  const snapshot = await db.collection("orders").orderBy("placedAt", "desc").limit(5000).get();
  const headers = [
    "Order ID", "Type", "Date", "Placed At", "Customer UID", "Package", "Quantity",
    "Amount PKR", "Status", "Delivery Status", "Expected Date", "Sender Number", "Txn Ref",
    "Tracking Numbers", "Couriers",
  ];
  const rows = snapshot.docs.map((doc) => {
    const order = doc.data();
    const delivered = (Array.isArray(order.deliveredNumbers) ? order.deliveredNumbers : [])
      .map(normalizeDeliveredEntry)
      .filter((item) => item.number);
    return [
      cleanText(order.orderId) || doc.id,
      cleanText(order.type) || (order.isGift === true ? "gift" : "order"),
      isoValue(order.orderCreatedAt || order.createdAt),
      isoValue(order.placedAt || order.createdAt),
      cleanText(order.uid),
      cleanText(order.packageName),
      Number(order.quantity) || 0,
      Number(order.amountPkr ?? order.price ?? 0),
      cleanText(order.status),
      cleanText(order.deliveryStatus),
      cleanText(order.expectedDeliveryDate),
      cleanText(order.senderNumber),
      cleanText(order.txnRef),
      delivered.map((item) => item.number).join(";"),
      delivered.map((item) => cleanText(item.courier)).join(";"),
    ];
  });
  const filename = `trackings-orders-${exportDateStamp()}.csv`;
  return res.status(200).json({ ok: true, filename, csv: csvDocument(headers, rows) });
}

async function exportInventory(res, db) {
  const snapshot = await db.collection("tracking_numbers").limit(10000).get();
  const headers = ["Number", "Courier", "Status", "Order ID", "Added At", "Sold At"];
  const rows = snapshot.docs
    .map((doc) => doc.data())
    .sort((a, b) => String(b.addedAt || b.createdAt || "").localeCompare(String(a.addedAt || a.createdAt || "")))
    .map((item) => [
      cleanText(item.number),
      cleanText(item.courier),
      cleanText(item.status),
      cleanText(item.orderId),
      isoValue(item.addedAt || item.createdAt),
      isoValue(item.soldAt),
    ]);
  const filename = `trackings-inventory-${exportDateStamp()}.csv`;
  return res.status(200).json({ ok: true, filename, csv: csvDocument(headers, rows) });
}

async function stats(res, db) {
  const snapshot = await db.collection("orders").get();
  let pendingCount = 0;
  let paidCount = 0;
  let refundedCount = 0;
  let totalSalesPkr = 0;
  for (const doc of snapshot.docs) {
    const order = doc.data();
    if (order.status === "pending") pendingCount += 1;
    if (order.status === "paid") {
      paidCount += 1;
      totalSalesPkr += Number(order.amountPkr) || 0;
    }
    if (order.status === "refunded") refundedCount += 1;
  }
  return res.status(200).json({
    ok: true,
    stats: { totalOrders: snapshot.size, pendingCount, paidCount, totalSalesPkr, refundedCount },
  });
}

module.exports = async function handler(req, res) {
  try {
    allowCors(req, res);
    if (req.method === "OPTIONS") return res.status(204).end();
    if (req.method !== "POST") return reject(res, 405, "Use POST.");

    const origins = allowedOrigins();
    if (req.headers.origin && !origins.includes(req.headers.origin)) return reject(res, 403, "This website is not allowed.");

    const firebase = getFirebase();
    const adminUser = await authenticateAdmin(req, firebase);
    enforceRateLimit(req, adminUser.uid);
    await ensureSeedData(firebase.db);
    const body = parseBody(req);

    if (body.action === "me") return res.status(200).json({ ok: true, isAdmin: true, email: adminUser.email });
    if (body.action === "orders") return await listOrders(res, body, firebase.db);
    if (body.action === "order" || body.action === "order_detail") return await getOrderDetail(res, body, firebase.db);
    if (body.action === "approve_payment") return await approvePayment(res, body, firebase.db, adminUser);
    if (body.action === "add_tracking") return await addTracking(res, body, firebase.db, adminUser);
    if (body.action === "edit_tracking") return await editTracking(res, body, firebase.db, adminUser);
    if (body.action === "reject") return await rejectOrder(res, body, firebase.db, adminUser);
    if (body.action === "refund") return await refundOrder(res, body, firebase.db, adminUser);
    if (body.action === "packages") return await listPackages(res, firebase.db);
    if (body.action === "package_upsert") return await upsertPackage(res, body, firebase.db, adminUser);
    if (body.action === "payment_methods") return await listPaymentMethods(res, firebase.db);
    if (body.action === "payment_method_upsert") return await upsertPaymentMethod(res, body, firebase.db, adminUser);
    if (body.action === "inventory_add") return await addInventory(res, body, firebase.db, adminUser);
    if (body.action === "inventory_available") return await listAvailableInventory(res, firebase.db);
    if (body.action === "inventory_list") return await listInventory(res, body, firebase.db);
    if (body.action === "export_orders") return await exportOrders(res, firebase.db);
    if (body.action === "export_inventory") return await exportInventory(res, firebase.db);
    if (body.action === "audit") return await listAudit(res, body, firebase.db);
    if (body.action === "stats") return await stats(res, firebase.db);
    return reject(res, 400, "Unknown admin action.");
  } catch (error) {
    if (error instanceof RequestError) return reject(res, error.status, error.message);
    if (error instanceof ServerConfigurationError) return reject(res, 500, "Server is not configured.");
    console.error("Admin API error:", error.message);
    return reject(res, 500, "The server could not complete this request.");
  }
};
