/**
 * PizzaHub / Pizza Plaza API
 * --------------------------
 * One small Express server. Every route is grouped by who is allowed to use it.
 *
 * Authentication flow:
 *   Next.js (Better Auth) signs a JWT -> the client sends it as
 *   "Authorization: Bearer <token>" -> requireAuth() verifies the signature
 *   against Better Auth's public keys (JWKS) and loads the user from MongoDB.
 *   Roles and ownership are ALWAYS read from the database, never from the body.
 */

import express from "express";
import cors from "cors";
import { MongoClient, ObjectId } from "mongodb";
import { createRemoteJWKSet, jwtVerify } from "jose";
import Stripe from "stripe";
import "dotenv/config";

// ---------------------------------------------------------------------------
// 1. Configuration
// ---------------------------------------------------------------------------

const PORT = Number(process.env.PORT) || 5000;
const CLIENT_URL = (process.env.CLIENT_URL || process.env.BETTER_AUTH_URL || "http://localhost:3000").replace(/\/+$/, "");
const AUTH_URL = (process.env.BETTER_AUTH_URL || process.env.CLIENT_URL || "").replace(/\/+$/, "");

const CATEGORIES = [
  "Classic Pizzas",
  "Vegetarian Pizzas",
  "Meat Lovers",
  "Specialty / Gourmet Pizzas",
  "Sides & Appetizers",
  "Beverages & Desserts",
];
const ITEM_STATUSES = ["pending", "approved", "rejected", "inactive"];
const ORDER_STATUSES = ["pending", "accepted", "rejected", "cancelled"];
const FREE_ITEM_LIMIT = 3;
const PREMIUM_PRICE_CENTS = 999; // $9.99 — change here if you want a different price
const PREMIUM_CURRENCY = "usd";
const PREMIUM_DURATION_DAYS = 365;

if (!process.env.MONGO_CLIENT_URI) {
  console.error("Missing MONGO_CLIENT_URI in .env");
  process.exit(1);
}
if (!AUTH_URL) {
  console.warn("BETTER_AUTH_URL is not set — protected routes will return an error.");
}

// ---------------------------------------------------------------------------
// 2. Database
// ---------------------------------------------------------------------------

const client = new MongoClient(process.env.MONGO_CLIENT_URI);
await client.connect();
console.log("Connected to MongoDB");

const db = client.db("pizzaplaza");
// Better Auth uses these two collection names by default.
const users = db.collection("user");
const items = db.collection("items"); // "menuItems" in the requirements
const orders = db.collection("orders");
const transactions = db.collection("transactions");

// Stripe is optional locally: without keys, payment routes return a clear 503.
const stripe = process.env.STRIPE_SECRET_KEY ? new Stripe(process.env.STRIPE_SECRET_KEY) : null;

// Public keys published by the Next.js app (Better Auth JWT plugin).
const jwks = AUTH_URL
  ? createRemoteJWKSet(new URL(`${AUTH_URL}/api/auth/jwks`), { cooldownDuration: 30_000 })
  : null;

// ---------------------------------------------------------------------------
// 3. Small helpers
// ---------------------------------------------------------------------------

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

// Wrap async routes so we do not have to write try/catch in every handler.
const asyncRoute = (handler) => (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);

const isObjectId = (value) => typeof value === "string" && /^[a-f\d]{24}$/i.test(value);

const byId = (id) =>
  isObjectId(id) ? { $or: [{ _id: new ObjectId(id) }, { id }] } : { id };

const cleanText = (value, field, { max = 500, required = true } = {}) => {
  const text = typeof value === "string" ? value.trim() : "";
  if (required && !text) throw new HttpError(400, `${field} is required.`);
  if (text.length > max) throw new HttpError(400, `${field} is too long (max ${max} characters).`);
  return text;
};

const cleanPrice = (value) => {
  const price = Number(value);
  if (!Number.isFinite(price) || price <= 0) throw new HttpError(400, "Price must be a positive number.");
  return Math.round(price * 100) / 100;
};

const escapeRegex = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const toPublicItem = (doc) => ({ ...doc, _id: doc._id.toString(), id: doc._id.toString() });

const hasPremium = (user) => {
  if (user.subscriptionPlan !== "premium") return false;
  if (!user.subscriptionExpiresAt) return true;
  return new Date(user.subscriptionExpiresAt).getTime() > Date.now();
};

// ---------------------------------------------------------------------------
// 4. Authentication and role middleware
// ---------------------------------------------------------------------------

async function requireAuth(req, res, next) {
  try {
    if (!jwks) throw new HttpError(500, "The server is missing BETTER_AUTH_URL.");

    const [scheme, token] = (req.headers.authorization || "").split(" ");
    if (scheme !== "Bearer" || !token) {
      return res.status(401).json({ message: "Please sign in to continue." });
    }

    // jose checks the signature, expiry, issuer and audience for us.
    const { payload } = await jwtVerify(token, jwks, {
      issuer: AUTH_URL,
      audience: AUTH_URL,
    });
    if (!payload.sub) return res.status(401).json({ message: "Invalid session." });

    const user = await users.findOne(byId(payload.sub));
    if (!user) return res.status(401).json({ message: "Account not found." });
    if (user.isBlocked) return res.status(403).json({ message: "This account is blocked." });

    // A premium subscription can expire. Downgrade once, then treat as free.
    if (user.subscriptionPlan === "premium" && user.subscriptionExpiresAt &&
        new Date(user.subscriptionExpiresAt).getTime() <= Date.now()) {
      await users.updateOne(
        { _id: user._id },
        { $set: { subscriptionPlan: "free", subscriptionExpiresAt: null } }
      );
      user.subscriptionPlan = "free";
    }

    // Only safe values go on req.user. Roles never come from the request body.
    req.user = {
      id: user._id.toString(),
      name: user.name,
      email: user.email,
      image: user.image,
      role: user.role,
      businessName: user.businessName,
      subscriptionPlan: user.subscriptionPlan ?? "free",
      isPremium: hasPremium(user),
    };
    return next();
  } catch (error) {
    console.error("JWT verification failed:", error.message);
    return res.status(401).json({ message: "Invalid or expired session." });
  }
}

const requireRole = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) {
    return res.status(403).json({ message: "You do not have permission to do that." });
  }
  return next();
};

// ---------------------------------------------------------------------------
// 5. App + middleware (webhook must come before express.json())
// ---------------------------------------------------------------------------

const app = express();

app.use(cors({
  origin(origin, callback) {
    if (!origin || origin === CLIENT_URL) return callback(null, true);
    return callback(null, false); // browsers block the response for other origins
  },
  credentials: true,
}));

app.post("/payments/webhook", express.raw({ type: "application/json" }), asyncRoute(handleStripeWebhook));
app.use(express.json());

// ---------------------------------------------------------------------------
// 6. Public routes — anyone can read approved items
// ---------------------------------------------------------------------------

app.get("/", (req, res) => {
  res.json({ message: "Welcome to the PizzaHub API" });
});

// GET /items?q=&category=&location=&minPrice=&maxPrice=&sort=price_asc
// Used by the home page and Browse Menu. Only approved items are returned.
app.get("/items", asyncRoute(async (req, res) => {
  const query = { status: "approved" };

  const search = typeof req.query.q === "string" ? req.query.q.trim() : "";
  if (search) {
    const pattern = new RegExp(escapeRegex(search), "i");
    query.$or = [
      { itemName: pattern },
      { description: pattern },
      { category: pattern },
      { location: pattern },
    ];
  }
  if (typeof req.query.category === "string" && req.query.category) query.category = req.query.category;
  if (typeof req.query.location === "string" && req.query.location) query.location = req.query.location;

  const minPrice = Number(req.query.minPrice);
  const maxPrice = Number(req.query.maxPrice);
  if (Number.isFinite(minPrice) && req.query.minPrice !== undefined && req.query.minPrice !== "") query.price = { ...query.price, $gte: minPrice };
  if (Number.isFinite(maxPrice) && req.query.maxPrice !== undefined && req.query.maxPrice !== "") query.price = { ...query.price, $lte: maxPrice };

  let cursor = items.find(query);
  if (req.query.sort === "price_asc") cursor = cursor.sort({ price: 1 });
  else if (req.query.sort === "price_desc") cursor = cursor.sort({ price: -1 });
  else cursor = cursor.sort({ createdAt: -1 });

  res.json((await cursor.toArray()).map(toPublicItem));
}));

// GET /items/:id — the public detail page. Pending/rejected items are hidden.
app.get("/items/:id", asyncRoute(async (req, res) => {
  const item = await items.findOne({ ...byId(req.params.id), status: "approved" });
  if (!item) return res.status(404).json({ message: "Item not found." });
  return res.json(toPublicItem(item));
}));

// ---------------------------------------------------------------------------
// 7. Vendor menu management
// ---------------------------------------------------------------------------

// GET /vendor/items — the vendor sees ALL of their own items, any status.
app.get("/vendor/items", requireAuth, requireRole("vendor"), asyncRoute(async (req, res) => {
  const query = { vendorId: req.user.id };
  if (ITEM_STATUSES.includes(req.query.status)) query.status = req.query.status;
  const list = await items.find(query).sort({ createdAt: -1 }).toArray();
  res.json(list.map(toPublicItem));
}));

// POST /items — create a pending item. Identity and status come from the server.
app.post("/items", requireAuth, requireRole("vendor"), asyncRoute(async (req, res) => {
  const body = req.body ?? {};
  const category = cleanText(body.category, "Category");
  if (!CATEGORIES.includes(category)) throw new HttpError(400, "Choose a valid category.");

  if (!req.user.isPremium) {
    const activeCount = await items.countDocuments({
      vendorId: req.user.id,
      status: { $in: ["pending", "approved"] },
    });
    if (activeCount >= FREE_ITEM_LIMIT) {
      throw new HttpError(403, "The Free plan allows 3 active menu items. Upgrade to Premium to add more.");
    }
  }

  const item = {
    vendorId: req.user.id,
    itemName: cleanText(body.itemName, "Item name", { max: 120 }),
    category,
    description: cleanText(body.description, "Description", { max: 1000 }),
    price: cleanPrice(body.price),
    location: cleanText(body.location, "Location", { max: 150 }),
    images: cleanText(body.images, "Item image", { max: 1000 }),
    status: "pending", // an admin must approve it before customers can see it
    createdAt: new Date(),
  };

  const result = await items.insertOne(item);
  res.status(201).json({ message: "Item submitted for review.", item: toPublicItem({ ...item, _id: result.insertedId }) });
}));

// PATCH /items/:id — edit your own item. Status is admin-only.
app.patch("/items/:id", requireAuth, requireRole("vendor"), asyncRoute(async (req, res) => {
  const item = await items.findOne(byId(req.params.id));
  if (!item) throw new HttpError(404, "Item not found.");
  if (item.vendorId !== req.user.id) throw new HttpError(403, "This is not your item.");

  const body = req.body ?? {};
  const update = {};
  if (body.itemName !== undefined) update.itemName = cleanText(body.itemName, "Item name", { max: 120 });
  if (body.category !== undefined) {
    update.category = cleanText(body.category, "Category");
    if (!CATEGORIES.includes(update.category)) throw new HttpError(400, "Choose a valid category.");
  }
  if (body.description !== undefined) update.description = cleanText(body.description, "Description", { max: 1000 });
  if (body.price !== undefined) update.price = cleanPrice(body.price);
  if (body.location !== undefined) update.location = cleanText(body.location, "Location", { max: 150 });
  if (body.images !== undefined) update.images = cleanText(body.images, "Item image", { max: 1000 });

  const updated = await items.findOneAndUpdate(
    { _id: item._id },
    { $set: update },
    { returnDocument: "after" }
  );
  res.json({ message: "Item updated.", item: toPublicItem(updated)});
}));

// PATCH /items/:id/availability — approved <-> inactive, vendor only.
app.patch("/items/:id/availability", requireAuth, requireRole("vendor"), asyncRoute(async (req, res) => {
  const item = await items.findOne(byId(req.params.id));
  if (!item) throw new HttpError(404, "Item not found.");
  if (item.vendorId !== req.user.id) throw new HttpError(403, "This is not your item.");
  if (!["approved", "inactive"].includes(item.status)) {
    throw new HttpError(400, "Only published items can be hidden or shown.");
  }
  if (typeof req.body?.isActive !== "boolean") throw new HttpError(400, "isActive must be true or false.");

  const status = req.body.isActive ? "approved" : "inactive";
  await items.updateOne({ _id: item._id }, { $set: { status } });
  res.json({ message: `Item is now ${status}.`, status });
}));

// DELETE /items/:id — the owner or an admin can delete.
app.delete("/items/:id", requireAuth, asyncRoute(async (req, res) => {
  const item = await items.findOne(byId(req.params.id));
  if (!item) throw new HttpError(404, "Item not found.");
  if (req.user.role !== "admin" && item.vendorId !== req.user.id) {
    throw new HttpError(403, "You cannot delete this item.");
  }
  await items.deleteOne({ _id: item._id });
  res.json({ message: "Item deleted." });
}));

// ---------------------------------------------------------------------------
// 8. Admin menu + users
// ---------------------------------------------------------------------------

// GET /admin/items — every submitted item, with filters.
app.get("/admin/items", requireAuth, requireRole("admin"), asyncRoute(async (req, res) => {
  const query = {};
  if (ITEM_STATUSES.includes(req.query.status)) query.status = req.query.status;
  if (typeof req.query.category === "string" && req.query.category) query.category = req.query.category;
  const search = typeof req.query.q === "string" ? req.query.q.trim() : "";
  if (search) query.itemName = new RegExp(escapeRegex(search), "i");

  const list = await items.find(query).sort({ createdAt: -1 }).toArray();
  res.json(list.map(toPublicItem));
}));

// PATCH /items/:id/status — approve, reject or hide an item (admin only).
app.patch("/items/:id/status", requireAuth, requireRole("admin"), asyncRoute(async (req, res) => {
  const status = req.body?.status;
  if (!ITEM_STATUSES.includes(status)) throw new HttpError(400, "Choose a valid status.");

  const updated = await items.findOneAndUpdate(
    byId(req.params.id),
    { $set: { status } },
    { returnDocument: "after" }
  );
  if (!updated) throw new HttpError(404, "Item not found.");
  res.json({ message: "Item status updated.", item: toPublicItem(updated) });
}));

// GET /users?q=&role= — admin only. Never send password hashes to the client.
app.get("/users", requireAuth, requireRole("admin"), asyncRoute(async (req, res) => {
  const query = {};
  const search = typeof req.query.q === "string" ? req.query.q.trim() : "";
  if (search) {
    const pattern = new RegExp(escapeRegex(search), "i");
    query.$or = [{ name: pattern }, { email: pattern }];
  }
  if (["vendor", "customer", "admin"].includes(req.query.role)) query.role = req.query.role;

  const list = await users.find(query).sort({ createdAt: -1 }).toArray();
  res.json(list.map((user) => ({
    id: user._id.toString(),
    name: user.name,
    email: user.email,
    image: user.image,
    role: user.role,
    isBlocked: Boolean(user.isBlocked),
    businessName: user.businessName,
    subscriptionPlan: user.subscriptionPlan ?? "free",
    subscriptionExpiresAt: user.subscriptionExpiresAt,
    createdAt: user.createdAt,
  })));
}));

// PATCH /users/:id/block — optional admin feature, kept small and safe.
app.patch("/users/:id/block", requireAuth, requireRole("admin"), asyncRoute(async (req, res) => {
  if (typeof req.body?.isBlocked !== "boolean") throw new HttpError(400, "isBlocked must be true or false.");
  const target = await users.findOne(byId(req.params.id));
  if (!target) throw new HttpError(404, "User not found.");
  if (target.role === "admin") throw new HttpError(403, "Admin accounts cannot be blocked here.");

  await users.updateOne({ _id: target._id }, { $set: { isBlocked: req.body.isBlocked } });
  res.json({ message: req.body.isBlocked ? "User blocked." : "User unblocked." });
}));

// ---------------------------------------------------------------------------
// 9. Orders
// ---------------------------------------------------------------------------

// POST /orders — customers only. The server decides who the customer is and
// which vendor owns the item, so a client cannot fake either one.
app.post("/orders", requireAuth, requireRole("customer"), asyncRoute(async (req, res) => {
  const body = req.body ?? {};
  const itemId = cleanText(body.itemId, "Item");
  const deliveryDate = cleanText(body.deliveryDate, "Delivery date");
  const deliveryAddress = cleanText(body.deliveryAddress, "Delivery address", { max: 300 });
  const message = cleanText(body.message ?? "", "Message", { max: 500, required: false });

  if (Number.isNaN(Date.parse(deliveryDate))) throw new HttpError(400, "Please provide a valid delivery date.");
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  if (new Date(deliveryDate).getTime() < today.getTime()) {
    throw new HttpError(400, "Please choose today or a future delivery date.");
  }

  const item = await items.findOne({ ...byId(itemId), status: "approved" });
  if (!item) throw new HttpError(404, "This item is not available.");
  if (item.vendorId === req.user.id) throw new HttpError(403, "You cannot order your own item.");

  const duplicate = await orders.findOne({
    customerId: req.user.id,
    itemId: item._id.toString(),
    deliveryDate,
    status: { $in: ["pending", "accepted"] },
  });
  if (duplicate) throw new HttpError(409, "You already have an active order for this item on that date.");

  const order = {
    itemId: item._id.toString(),
    vendorId: item.vendorId,
    customerId: req.user.id,
    deliveryDate,
    deliveryAddress,
    message,
    status: "pending",
    createdAt: new Date(),
  };
  const result = await orders.insertOne(order);
  res.status(201).json({ message: "Order placed.", order: toPublicItem({ ...order, _id: result.insertedId }) });
}));

// GET /orders — each role sees only its own orders; admin sees all.
// Query filters customerId/vendorId from clients are intentionally ignored.
app.get("/orders", requireAuth, asyncRoute(async (req, res) => {
  const query = {};
  if (req.user.role === "customer") query.customerId = req.user.id;
  else if (req.user.role === "vendor") query.vendorId = req.user.id;
  if (ORDER_STATUSES.includes(req.query.status)) query.status = req.query.status;

  const list = await orders.find(query).sort({ createdAt: -1 }).toArray();

  // Attach a small item snapshot so the UI can show a name/image even if the
  // item was later rejected or removed. The stored order is not modified.
  const ids = list.map((order) => order.itemId).filter(isObjectId);
  const related = ids.length
    ? await items.find({ _id: { $in: ids.map((id) => new ObjectId(id)) } }).toArray()
    : [];
  const itemMap = new Map(related.map((item) => [item._id.toString(), item]));

  res.json(list.map((order) => {
    const item = itemMap.get(order.itemId);
    return {
      ...order,
      _id: order._id.toString(),
      id: order._id.toString(),
      item: item
        ? { _id: item._id.toString(), itemName: item.itemName, images: item.images, price: item.price, category: item.category, location: item.location }
        : null,
    };
  }));
}));

// PATCH /orders/:id/status — vendor accepts/rejects, customer cancels.
app.patch("/orders/:id/status", requireAuth, asyncRoute(async (req, res) => {
  const status = req.body?.status;
  const order = await orders.findOne(byId(req.params.id));
  if (!order) throw new HttpError(404, "Order not found.");
  if (order.status !== "pending") throw new HttpError(400, "Only pending orders can be changed.");

  if (req.user.role === "vendor") {
    if (order.vendorId !== req.user.id) throw new HttpError(403, "This order is not for your restaurant.");
    if (!["accepted", "rejected"].includes(status)) throw new HttpError(400, "Vendors can only accept or reject.");
  } else if (req.user.role === "customer") {
    if (order.customerId !== req.user.id) throw new HttpError(403, "This is not your order.");
    if (status !== "cancelled") throw new HttpError(400, "Customers can only cancel.");
  } else {
    throw new HttpError(403, "Admins cannot change order statuses.");
  }

  await orders.updateOne({ _id: order._id }, { $set: { status } });
  res.json({ message: `Order ${status}.`, status });
}));

// ---------------------------------------------------------------------------
// 10. Transactions + Stripe subscription payment
// ---------------------------------------------------------------------------

// GET /transactions — admin only. Records are read-only: no edit/delete route.
app.get("/transactions", requireAuth, requireRole("admin"), asyncRoute(async (req, res) => {
  const query = {};
  if (typeof req.query.vendorId === "string" && req.query.vendorId) query.vendorId = req.query.vendorId;
  const list = await transactions.find(query).sort({ createdAt: -1 }).toArray();
  res.json(list.map((row) => ({ ...row, _id: row._id.toString() })));
}));

// POST /payments/checkout — creates a Stripe Checkout session for THIS vendor.
app.post("/payments/checkout", requireAuth, requireRole("vendor"), asyncRoute(async (req, res) => {
  if (!stripe) throw new HttpError(503, "Payments are not configured on the server.");
  if (req.user.isPremium) throw new HttpError(400, "You already have an active Premium plan.");

  const session = await stripe.checkout.sessions.create({
    mode: "payment",
    payment_method_types: ["card"],
    line_items: [{
      price_data: {
        currency: PREMIUM_CURRENCY,
        product_data: { name: "PizzaHub Premium Subscription" },
        unit_amount: PREMIUM_PRICE_CENTS,
      },
      quantity: 1,
    }],
    customer_email: req.user.email,
    client_reference_id: req.user.id,
    metadata: { vendorId: req.user.id, plan: "premium" },
    success_url: `${CLIENT_URL}/payment/success?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: `${CLIENT_URL}/payment/cancel`,
  });

  await transactions.insertOne({
    vendorId: req.user.id,
    plan: "premium",
    amount: PREMIUM_PRICE_CENTS / 100,
    currency: PREMIUM_CURRENCY,
    stripeSessionId: session.id,
    stripeSubscriptionId: null,
    status: "pending",
    createdAt: new Date(),
  });

  res.json({ url: session.url, sessionId: session.id });
}));

// GET /payments/session/:sessionId — the success page can check the result.
app.get("/payments/session/:sessionId", requireAuth, requireRole("vendor"), asyncRoute(async (req, res) => {
  const row = await transactions.findOne({
    stripeSessionId: req.params.sessionId,
    vendorId: req.user.id,
  });
  if (!row) throw new HttpError(404, "Payment session not found.");
  res.json({ status: row.status, plan: row.plan, isPremium: req.user.isPremium });
}));

// POST /payments/webhook — Stripe calls this. Premium is activated HERE only,
// after Stripe's signature is verified. The success redirect is never trusted.
async function handleStripeWebhook(req, res) {
  if (!process.env.STRIPE_WEBHOOK_SECRET || !stripe) {
    return res.status(503).json({ message: "Webhook is not configured." });
  }

  let event;
  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      req.headers["stripe-signature"],
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (error) {
    console.error("Stripe signature check failed:", error.message);
    return res.status(400).json({ message: "Invalid webhook signature." });
  }

  if (event.type === "checkout.session.completed" || event.type === "checkout.session.async_payment_succeeded") {
    const session = event.data.object;
    if (session.payment_status === "paid") {
      const vendorId = session.metadata?.vendorId || session.client_reference_id;
      const vendor = vendorId ? await users.findOne(byId(vendorId)) : null;

      if (vendor) {
        const expiresAt = new Date(Date.now() + PREMIUM_DURATION_DAYS * 24 * 60 * 60 * 1000);
        await transactions.updateOne(
          { stripeSessionId: session.id },
          {
            $set: {
              status: "succeeded",
              stripeSubscriptionId: session.subscription ?? null,
            },
          }
        );
        await users.updateOne(
          { _id: vendor._id },
          { $set: { subscriptionPlan: "premium", subscriptionExpiresAt: expiresAt.toISOString() } }
        );
      }
    }
  }

  if (event.type === "checkout.session.expired" || event.type === "checkout.session.async_payment_failed") {
    await transactions.updateOne(
      { stripeSessionId: event.data.object.id },
      { $set: { status: "failed" } }
    );
  }

  return res.json({ received: true });
}

// ---------------------------------------------------------------------------
// 11. 404 + central error handler
// ---------------------------------------------------------------------------

app.use((req, res) => {
  res.status(404).json({ message: "Route not found." });
});

app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);
  console.error(error);

  if (error instanceof HttpError) {
    return res.status(error.status).json({ message: error.message });
  }
  if (error.type === "entity.parse.failed") {
    return res.status(400).json({ message: "Invalid JSON in the request body." });
  }
  if (typeof error.type === "string" && error.type.startsWith("Stripe")) {
    return res.status(502).json({ message: "The payment provider could not be reached." });
  }
  return res.status(500).json({ message: "Something went wrong on the server." });
});

app.listen(PORT, () => {
  console.log(`PizzaHub API listening on port ${PORT}`);
});
