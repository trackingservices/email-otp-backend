"use strict";

/**
 * Vercel Node.js function for authenticated customer orders.
 * Put this file at: api/orders.js
 */

const crypto = require("node:crypto");
const admin = require("firebase-admin");

const TXN_REF_RE = /^[A-Za-z0-9-]{4,40}$/;
const SENDER_NUMBER_RE = /^[0-9A-Za-z +\-.]{6,30}$/;
const ORDER_ID_RE = /^TPK-[A-Z0-9]{6,24}$/;
const TRACKING_NUMBER_RE = /^[A-Z0-9-]{4,40}$/;
const DELIVERY_STATUSES = new Set(["delivered", "in_transit"]);
const ORDER_TIME_FUTURE_SKEW_MS = 5 * 60 * 1000;
const ORDER_TIME_MAX_AGE_MS = 90 * 24 * 60 * 60 * 1000;
const ISO_DATETIME_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,3}))?)?(Z|[+-]\d{2}:\d{2})$/;
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX = 30;
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
  constructor(status, message, code) {
    super(message);
    this.status = status;
    this.code = code || null;
  }
}
let firebaseState;
let seedPromise;

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

function reject(res, status, message, errorCode) {
  if (errorCode) return res.status(status).json({ ok: false, error: errorCode });
  return res.status(status).json({ ok: false, message });
}

function cleanText(value) {
  return typeof value === "string" ? value.trim() : "";
}

function parseOrderCreatedAt(value) {
  const input = cleanText(value);
  const match = input.match(ISO_DATETIME_RE);
  if (!match) {
    throw new RequestError(400, "Order created time is required and must be a valid ISO 8601 datetime.");
  }
  const [, yearText, monthText, dayText, hourText, minuteText, secondText = "0"] = match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  const calendarDate = new Date(Date.UTC(year, month - 1, day));
  if (calendarDate.getUTCFullYear() !== year || calendarDate.getUTCMonth() !== month - 1 ||
      calendarDate.getUTCDate() !== day || hour > 23 || minute > 59 || second > 59) {
    throw new RequestError(400, "Order created time is not valid.");
  }
  const parsed = new Date(input);
  const milliseconds = parsed.getTime();
  if (Number.isNaN(milliseconds)) {
    throw new RequestError(400, "Order created time is not valid.");
  }
  const now = Date.now();
  if (milliseconds > now + ORDER_TIME_FUTURE_SKEW_MS) {
    throw new RequestError(400, "Order created time cannot be in the future.");
  }
  if (milliseconds < now - ORDER_TIME_MAX_AGE_MS) {
    throw new RequestError(400, "Order created time cannot be more than 90 days old.");
  }
  return parsed.toISOString();
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
    return { uid: token.uid, email: cleanText(token.email).toLowerCase() };
  } catch {
    throw new RequestError(401, "Your session is not valid. Sign in again.");
  }
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

function publicOrder(order, deliveredNumbers = []) {
  const orderCreatedAt = order.orderCreatedAt || order.createdAt || null;
  const placedAt = order.placedAt || order.createdAt || null;
  return {
    orderId: order.orderId,
    orderCreatedAt,
    placedAt,
    createdAt: orderCreatedAt,
    packageName: order.packageName,
    quantity: order.quantity,
    amountPkr: Number(order.amountPkr ?? order.price ?? 0),
    price: Number(order.price ?? order.amountPkr ?? 0),
    currency: cleanText(order.currency) || "PKR",
    isGift: order.isGift === true,
    status: order.status,
    deliveryStatus: cleanText(order.deliveryStatus),
    expectedDeliveryDate: order.expectedDeliveryDate || null,
    txnRef: cleanText(order.txnRef) || null,
    deliveredNumbers,
    deliveredAt: order.deliveredAt || null,
  };
}

function inventoryId(number) {
  return crypto.createHash("sha256").update(number).digest("hex");
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

function todayInPakistan() {
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone: "Asia/Karachi", year: "numeric", month: "2-digit", day: "2-digit",
  }).formatToParts(new Date());
  const value = Object.fromEntries(parts.map((part) => [part.type, part.value]));
  return `${value.year}-${value.month}-${value.day}`;
}


function generateOrderId() {
  const time = Date.now().toString(36).toUpperCase().slice(-6);
  const random = crypto.randomBytes(3).toString("hex").toUpperCase();
  return `TPK-${time}${random}`;
}

async function uniqueOrderId(db) {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const orderId = generateOrderId();
    const snapshot = await db.collection("orders").doc(orderId).get();
    if (!snapshot.exists) return orderId;
  }
  throw new Error("Could not generate a unique order ID");
}

function eligibleInventory(doc, packageId) {
  const data = doc.data();
  return data.status === "available" && (!cleanText(data.packageId) || data.packageId === packageId);
}

async function createOrder(res, body, firebase, user) {
  const packageId = cleanText(body.packageId);
  const paymentMethodId = cleanText(body.paymentMethodId);
  if (body.txnRef !== undefined && body.txnRef !== null && typeof body.txnRef !== "string") {
    throw new RequestError(400, "Transaction reference must be 4-40 letters, numbers, or hyphens.");
  }
  const txnRef = cleanText(body.txnRef) || null;
  const senderNumber = cleanText(body.senderNumber);
  const deliveryStatus = cleanText(body.deliveryStatus).toLowerCase();
  const orderCreatedAt = parseOrderCreatedAt(body.orderCreatedAt);
  let expectedDeliveryDate = null;

  if (!/^[A-Za-z0-9_-]{1,60}$/.test(packageId)) throw new RequestError(400, "Choose a valid package.");
  if (!/^[A-Za-z0-9_-]{1,60}$/.test(paymentMethodId)) throw new RequestError(400, "Choose a valid payment method.");
  if (txnRef !== null && !TXN_REF_RE.test(txnRef)) throw new RequestError(400, "Transaction reference must be 4-40 letters, numbers, or hyphens.");
  if (!SENDER_NUMBER_RE.test(senderNumber)) throw new RequestError(400, "Sender number or account must be 6-30 valid characters.");
  if (!DELIVERY_STATUSES.has(deliveryStatus)) throw new RequestError(400, "Choose delivered or in transit.");
  if (deliveryStatus === "in_transit") {
    expectedDeliveryDate = cleanText(body.expectedDeliveryDate);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(expectedDeliveryDate)) {
      throw new RequestError(400, "Expected delivery date must use YYYY-MM-DD.");
    }
    const parsedDate = new Date(`${expectedDeliveryDate}T00:00:00Z`);
    if (Number.isNaN(parsedDate.getTime()) || parsedDate.toISOString().slice(0, 10) !== expectedDeliveryDate) {
      throw new RequestError(400, "Expected delivery date is not valid.");
    }
    if (expectedDeliveryDate < todayInPakistan()) throw new RequestError(400, "Expected delivery date cannot be in the past.");
  }

  const [packageDoc, paymentDoc] = await Promise.all([
    firebase.db.collection("packages").doc(packageId).get(),
    firebase.db.collection("payment_methods").doc(paymentMethodId).get(),
  ]);
  if (!packageDoc.exists) throw new RequestError(400, "This package is not available.");
  const packageData = packageDoc.data();
  const packageType = cleanText(packageData.type).toLowerCase();
  if (packageData.active !== true || packageType !== "per_unit") {
    throw new RequestError(400, "This package is not available.");
  }
  if (!paymentDoc.exists || paymentDoc.data().enabled !== true) throw new RequestError(400, "This payment method is not available.");

  const paymentData = paymentDoc.data();
  const minQty = Number(packageData.minQty);
  const maxQty = Number(packageData.maxQty);
  const pricePerUnit = Number(packageData.pricePerUnit);
  const quantity = Number(body.quantity);
  if (!Number.isInteger(minQty) || !Number.isInteger(maxQty) || minQty < 1 || minQty > maxQty || maxQty > 1000 ||
      !Number.isInteger(pricePerUnit) || pricePerUnit <= 0) {
    throw new Error("Invalid per-unit package configuration");
  }
  if (!Number.isInteger(quantity) || quantity < minQty || quantity > maxQty) {
    throw new RequestError(400, `Choose a quantity from ${minQty} to ${maxQty}.`);
  }
  const amountPkr = quantity * pricePerUnit;

  const orderId = await uniqueOrderId(firebase.db);
  const orderRef = firebase.db.collection("orders").doc(orderId);
  const auditRef = firebase.db.collection("audit_logs").doc();
  const placedAt = new Date().toISOString();

  await firebase.db.runTransaction(async (transaction) => {
    const existingOrder = await transaction.get(orderRef);
    if (existingOrder.exists) throw new RequestError(409, "Order ID collision. Please try again.");

    const availableSnapshot = await transaction.get(
      firebase.db.collection("tracking_numbers").where("status", "==", "available")
    );
    const selected = availableSnapshot.docs.filter((doc) => eligibleInventory(doc, packageId)).slice(0, quantity);
    for (const inventoryDoc of selected) {
      transaction.update(inventoryDoc.ref, { status: "reserved", orderId, reservedAt: placedAt });
    }
    transaction.create(orderRef, {
      orderId,
      uid: user.uid,
      email: user.email,
      packageId,
      packageName: cleanText(packageData.name),
      packageType,
      quantity,
      amount: amountPkr,
      amountPkr,
      currency: cleanText(packageData.currency) || "PKR",
      paymentMethodId,
      paymentMethodName: cleanText(paymentData.name),
      txnRef,
      senderNumber,
      deliveryStatus,
      expectedDeliveryDate,
      reservedCount: selected.length,
      status: "pending",
      orderCreatedAt,
      placedAt,
      createdAt: orderCreatedAt,
      updatedAt: placedAt,
    });
    transaction.set(auditRef, { type: "order_created", orderId, uid: user.uid, email: user.email, orderCreatedAt, at: placedAt });
  });

  return res.status(200).json({
    ok: true,
    orderId,
    orderCreatedAt,
    placedAt,
    amountPkr,
    paymentMethod: {
      name: cleanText(paymentData.name),
      holderName: cleanText(paymentData.holderName),
      accountNumber: cleanText(paymentData.accountNumber),
      instructions: cleanText(paymentData.instructions),
    },
  });
}


function giftStateFrom(data) {
  const used = Number(data && data.usedSlots);
  const usedSlots = Number.isInteger(used) ? Math.min(1, Math.max(0, used)) : 0;
  return {
    claimed: Boolean(data && data.claimed === true),
    totalSlots: 1,
    usedSlots,
    remainingSlots: 1 - usedSlots,
  };
}

async function giftStatus(res, firebase, user) {
  const snapshot = await firebase.db.collection("gifts").doc(user.uid).get();
  return res.status(200).json(giftStateFrom(snapshot.exists ? snapshot.data() : null));
}

async function claimGift(res, firebase, user) {
  const giftRef = firebase.db.collection("gifts").doc(user.uid);
  const auditRef = firebase.db.collection("audit_logs").doc();
  const now = new Date().toISOString();
  await firebase.db.runTransaction(async (transaction) => {
    const giftDoc = await transaction.get(giftRef);
    if (giftDoc.exists && giftDoc.data().claimed === true) {
      throw new RequestError(409, "New User Gift has already been claimed.", "already_claimed");
    }
    transaction.set(giftRef, {
      uid: user.uid,
      claimed: true,
      totalSlots: 1,
      usedSlots: 0,
      claimedAt: now,
      updatedAt: now,
    });
    transaction.set(auditRef, {
      type: "gift_claimed",
      uid: user.uid,
      email: user.email,
      at: now,
    });
  });
  return res.status(200).json({ ok: true, remainingSlots: 1 });
}

function validateGiftDelivery(body) {
  const quantity = Number(body.quantity);
  const orderCreatedAt = parseOrderCreatedAt(body.orderCreatedAt);
  if (!Number.isInteger(quantity) || quantity !== 1) {
    throw new RequestError(400, "Gift quantity must be exactly 1.");
  }
  const deliveryStatus = cleanText(body.deliveryStatus).toLowerCase();
  if (!DELIVERY_STATUSES.has(deliveryStatus)) {
    throw new RequestError(400, "Choose delivered or in transit.");
  }
  let expectedDeliveryDate = null;
  if (deliveryStatus === "in_transit") {
    expectedDeliveryDate = cleanText(body.expectedDeliveryDate);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(expectedDeliveryDate)) {
      throw new RequestError(400, "Expected delivery date must use YYYY-MM-DD.");
    }
    const parsedDate = new Date(`${expectedDeliveryDate}T00:00:00Z`);
    if (Number.isNaN(parsedDate.getTime()) || parsedDate.toISOString().slice(0, 10) !== expectedDeliveryDate) {
      throw new RequestError(400, "Expected delivery date is not valid.");
    }
    if (expectedDeliveryDate < todayInPakistan()) {
      throw new RequestError(400, "Expected delivery date cannot be in the past.");
    }
  }
  return { quantity, deliveryStatus, expectedDeliveryDate, orderCreatedAt };
}

async function redeemGift(res, body, firebase, user) {
  const { quantity, deliveryStatus, expectedDeliveryDate, orderCreatedAt } = validateGiftDelivery(body);
  const orderId = await uniqueOrderId(firebase.db);
  const giftRef = firebase.db.collection("gifts").doc(user.uid);
  const orderRef = firebase.db.collection("orders").doc(orderId);
  const auditRef = firebase.db.collection("audit_logs").doc();
  const placedAt = new Date().toISOString();
  let remainingSlots = 0;

  await firebase.db.runTransaction(async (transaction) => {
    const [giftDoc, orderDoc] = await Promise.all([
      transaction.get(giftRef),
      transaction.get(orderRef),
    ]);
    if (!giftDoc.exists || giftDoc.data().claimed !== true) {
      throw new RequestError(409, "Claim the New User Gift before using it.", "gift_not_claimed");
    }
    const state = giftStateFrom(giftDoc.data());
    if (state.remainingSlots < quantity) {
      throw new RequestError(409, "Not enough gift tracking slots remain.", "insufficient_slots");
    }
    if (orderDoc.exists) throw new RequestError(409, "Order ID collision. Please try again.");
    remainingSlots = state.remainingSlots - quantity;
    transaction.create(orderRef, {
      orderId,
      uid: user.uid,
      email: user.email,
      type: "gift",
      isGift: true,
      packageId: "gift",
      packageName: "New User Gift",
      quantity,
      price: 0,
      amountPkr: 0,
      currency: "PKR",
      deliveryStatus,
      expectedDeliveryDate,
      status: "paid",
      txnRef: null,
      senderNumber: null,
      reservedCount: 0,
      orderCreatedAt,
      placedAt,
      createdAt: orderCreatedAt,
      updatedAt: placedAt,
    });
    transaction.update(giftRef, { usedSlots: state.usedSlots + quantity, updatedAt: placedAt });
    transaction.set(auditRef, {
      type: "gift_redeemed",
      orderId,
      uid: user.uid,
      email: user.email,
      detail: { quantity, remainingSlots, orderCreatedAt },
      at: placedAt,
    });
  });

  return res.status(200).json({ ok: true, orderId, orderCreatedAt, placedAt, remainingSlots });
}

async function cancelOrder(res, body, firebase, user) {
  const orderId = cleanText(body.orderId).toUpperCase();
  if (!ORDER_ID_RE.test(orderId)) throw new RequestError(400, "Enter a valid order ID.");
  const orderRef = firebase.db.collection("orders").doc(orderId);
  const auditRef = firebase.db.collection("audit_logs").doc();

  await firebase.db.runTransaction(async (transaction) => {
    const orderDoc = await transaction.get(orderRef);
    if (!orderDoc.exists || orderDoc.data().uid !== user.uid) {
      throw new RequestError(404, "Order not found.");
    }
    if (orderDoc.data().status !== "pending") {
      throw new RequestError(409, "Only pending orders can be cancelled.");
    }
    const reservedSnapshot = await transaction.get(
      firebase.db.collection("tracking_numbers")
        .where("orderId", "==", orderId)
        .where("status", "==", "reserved")
        .limit(200)
    );
    const now = new Date().toISOString();
    for (const inventoryDoc of reservedSnapshot.docs) {
      transaction.update(inventoryDoc.ref, {
        status: "available",
        orderId: admin.firestore.FieldValue.delete(),
        reservedAt: admin.firestore.FieldValue.delete(),
      });
    }
    transaction.update(orderRef, { status: "cancelled", cancelledAt: now, updatedAt: now });
    transaction.set(auditRef, {
      type: "order_cancelled",
      orderId,
      uid: user.uid,
      email: user.email,
      detail: { releasedCount: reservedSnapshot.size },
      at: now,
    });
  });
  return res.status(200).json({ ok: true });
}

async function listOrders(res, firebase, user) {
  await autoExpirePendings(firebase.db);
  const snapshot = await firebase.db.collection("orders").where("uid", "==", user.uid).limit(200).get();
  const orders = await Promise.all(snapshot.docs.map(async (doc) => {
    const order = doc.data();
    const deliveredNumbers = await hydrateDeliveredNumbers(firebase.db, order.deliveredNumbers);
    return publicOrder(order, deliveredNumbers);
  }));
  orders.sort((a, b) => String(b.orderCreatedAt).localeCompare(String(a.orderCreatedAt)));
  return res.status(200).json({ ok: true, orders });
}

async function listCustomerPackages(res, db) {
  const snapshot = await db.collection("packages").get();
  const packages = snapshot.docs
    .map((doc) => ({ id: doc.id, ...doc.data() }))
    .filter((row) => row.active === true && cleanText(row.type).toLowerCase() === "per_unit")
    .map((row) => ({
      id: row.id,
      name: cleanText(row.name),
      type: "per_unit",
      pricePerUnit: Number(row.pricePerUnit),
      regularPricePerUnit: row.regularPricePerUnit === undefined ? null : Number(row.regularPricePerUnit),
      minQty: Number(row.minQty),
      maxQty: Number(row.maxQty),
      currency: cleanText(row.currency) || "PKR",
      active: true,
      sortOrder: Number(row.sortOrder) || 0,
    }))
    .filter((row) => Number.isInteger(row.pricePerUnit) && row.pricePerUnit > 0 &&
      (row.regularPricePerUnit === null || (Number.isInteger(row.regularPricePerUnit) && row.regularPricePerUnit > 0)) &&
      Number.isInteger(row.minQty) && Number.isInteger(row.maxQty) && row.minQty >= 1 &&
      row.minQty <= row.maxQty && row.maxQty <= 1000)
    .sort((a, b) => a.sortOrder - b.sortOrder || a.minQty - b.minQty);
  return res.status(200).json({ ok: true, packages });
}

async function listCustomerPaymentMethods(res, db) {
  const snapshot = await db.collection("payment_methods").get();
  const paymentMethods = snapshot.docs
    .map((doc) => ({ id: doc.id, ...doc.data() }))
    .filter((row) => row.enabled === true)
    .map((row) => ({
      id: row.id,
      name: cleanText(row.name),
      holderName: cleanText(row.holderName),
      accountNumber: cleanText(row.accountNumber),
      instructions: cleanText(row.instructions),
    }))
    .sort((a, b) => a.name.localeCompare(b.name));
  return res.status(200).json({ ok: true, paymentMethods });
}

async function listMyNumbers(res, firebase, user) {
  const snapshot = await firebase.db.collection("orders").where("uid", "==", user.uid).limit(200).get();
  const numbers = [];
  for (const doc of snapshot.docs) {
    const order = doc.data();
    if (order.status !== "delivered" || !Array.isArray(order.deliveredNumbers)) continue;
    const deliveredAt = cleanText(order.deliveredAt) || cleanText(order.updatedAt) || cleanText(order.createdAt);
    const orderId = cleanText(order.orderId) || doc.id;
    const orderCreatedAt = order.orderCreatedAt || order.createdAt || null;
    const placedAt = order.placedAt || order.createdAt || null;
    const hydrated = await hydrateDeliveredNumbers(firebase.db, order.deliveredNumbers);
    for (const value of hydrated) numbers.push({ ...value, orderId, orderCreatedAt, placedAt, deliveredAt });
  }
  numbers.sort((a, b) => String(b.deliveredAt).localeCompare(String(a.deliveredAt)));
  return res.status(200).json({ ok: true, numbers });
}

async function getOrder(res, body, firebase, user) {
  const orderId = cleanText(body.orderId).toUpperCase();
  if (!ORDER_ID_RE.test(orderId)) throw new RequestError(400, "Enter a valid order ID.");
  const snapshot = await firebase.db.collection("orders").doc(orderId).get();
  if (!snapshot.exists || snapshot.data().uid !== user.uid) throw new RequestError(404, "Order not found.");
  const order = snapshot.data();
  const deliveredNumbers = await hydrateDeliveredNumbers(firebase.db, order.deliveredNumbers);
  const result = {
    ...publicOrder(order, deliveredNumbers),
    updatedAt: order.updatedAt,
    paymentMethodName: order.paymentMethodName,
    senderNumber: order.senderNumber,
  };
  return res.status(200).json({ ok: true, order: result });
}


async function listNotifications(res, firebase, user) {
  const snapshot = await firebase.db.collection("notifications").where("uid", "==", user.uid).get();
  const notifications = snapshot.docs
    .map((doc) => {
      const row = doc.data();
      return {
        id: doc.id,
        type: cleanText(row.type),
        orderId: cleanText(row.orderId),
        message: cleanText(row.message),
        read: row.read === true,
        createdAt: cleanText(row.createdAt),
      };
    })
    .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
  return res.status(200).json({ ok: true, notifications });
}

async function markNotificationsRead(res, body, firebase, user) {
  let ids = null;
  if (body.ids !== undefined) {
    if (!Array.isArray(body.ids) || body.ids.length > 200) throw new RequestError(400, "Notification IDs are not valid.");
    ids = [...new Set(body.ids.map(cleanText))];
    if (ids.some((id) => !/^[A-Za-z0-9_-]{1,200}$/.test(id))) throw new RequestError(400, "Notification IDs are not valid.");
  }
  const snapshot = await firebase.db.collection("notifications").where("uid", "==", user.uid).get();
  const selected = snapshot.docs.filter((doc) => ids === null || ids.includes(doc.id));
  for (let start = 0; start < selected.length; start += 450) {
    const batch = firebase.db.batch();
    for (const doc of selected.slice(start, start + 450)) batch.update(doc.ref, { read: true });
    await batch.commit();
  }
  return res.status(200).json({ ok: true });
}

async function claimTracking(res, body, firebase, user) {
  const orderId = cleanText(body.orderId).toUpperCase();
  const number = cleanText(body.number).toUpperCase();
  if (!ORDER_ID_RE.test(orderId)) throw new RequestError(400, "Enter a valid order ID.");
  if (!TRACKING_NUMBER_RE.test(number)) throw new RequestError(400, "Enter a valid tracking number.");
  const orderRef = firebase.db.collection("orders").doc(orderId);
  const inventoryRef = firebase.db.collection("tracking_numbers").doc(inventoryId(number));
  const auditRef = firebase.db.collection("audit_logs").doc();
  await firebase.db.runTransaction(async (transaction) => {
    const orderDoc = await transaction.get(orderRef);
    if (!orderDoc.exists || orderDoc.data().uid !== user.uid) throw new RequestError(404, "Order not found.");
    const order = orderDoc.data();
    if (order.status !== "delivered") throw new RequestError(409, "Tracking numbers are not ready for this order.");
    const delivered = (Array.isArray(order.deliveredNumbers) ? order.deliveredNumbers : []).map(normalizeDeliveredEntry);
    if (!delivered.some((row) => row.number === number)) throw new RequestError(404, "Tracking number not found in this order.");
    const now = new Date().toISOString();
    transaction.set(inventoryRef, { claimed: true, claimedAt: now }, { merge: true });
    transaction.set(auditRef, { type: "tracking_claimed", orderId, uid: user.uid, email: user.email, number, at: now });
  });
  return res.status(200).json({ ok: true });
}

module.exports = async function handler(req, res) {
  try {
    allowCors(req, res);
    if (req.method === "OPTIONS") return res.status(204).end();
    if (req.method !== "POST") return reject(res, 405, "Use POST.");

    const origins = allowedOrigins();
    if (req.headers.origin && !origins.includes(req.headers.origin)) return reject(res, 403, "This website is not allowed.");

    const firebase = getFirebase();
    const user = await authenticate(req, firebase);
    enforceRateLimit(req, user.uid);
    await ensureSeedData(firebase.db);
    const body = parseBody(req);

    if (body.action === "create") return await createOrder(res, body, firebase, user);
    if (body.action === "cancel_order") return await cancelOrder(res, body, firebase, user);
    if (body.action === "list") return await listOrders(res, firebase, user);
    if (body.action === "get") return await getOrder(res, body, firebase, user);
    if (body.action === "packages") return await listCustomerPackages(res, firebase.db);
    if (body.action === "payment_methods") return await listCustomerPaymentMethods(res, firebase.db);
    if (body.action === "my_numbers") return await listMyNumbers(res, firebase, user);
    if (body.action === "notifications") return await listNotifications(res, firebase, user);
    if (body.action === "notifications_read") return await markNotificationsRead(res, body, firebase, user);
    if (body.action === "track_claim") return await claimTracking(res, body, firebase, user);
    if (body.action === "gift_status") return await giftStatus(res, firebase, user);
    if (body.action === "gift_claim") return await claimGift(res, firebase, user);
    if (body.action === "gift_redeem") return await redeemGift(res, body, firebase, user);
    return reject(res, 400, "Use create, list, get, packages, payment_methods, or my_numbers; notification, tracking-claim, and gift actions are also supported.");
  } catch (error) {
    if (error instanceof RequestError) return reject(res, error.status, error.message, error.code);
    if (error instanceof ServerConfigurationError) return reject(res, 500, "Server is not configured.");
    console.error("Orders API error:", error.message);
    return reject(res, 500, "The server could not complete this request.");
  }
};
