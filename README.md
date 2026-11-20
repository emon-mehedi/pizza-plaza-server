# PizzaHub API Server

Express + MongoDB API for **PizzaHub — Pizza Ordering & Delivery Platform**. It powers the public menu, role-based dashboards, orders and the vendor Premium subscription flow. The Next.js client is in a separate repository.

## Links

- **Live site:** `[ADD AFTER DEPLOYMENT]`
- **Client repository:** https://github.com/emon-mehedi/pizza-plaza-client
- **Server repository:** https://github.com/emon-mehedi/pizza-plaza-server

> Fill in the live link and working admin credentials after deployment. Never commit `.env` files or real secrets.

## What this server does

- Serves only **approved** menu items to the public, with search, filters, sorting and featured placement.
- Verifies Better Auth JWTs with `jose` using the client's JWKS endpoint.
- Applies role checks (`admin`, `vendor`, `customer`) and ownership checks on every protected route.
- Stores menu items, orders and subscription transactions in MongoDB.
- Creates Stripe Checkout Sessions for vendors and activates Premium **only** after a verified webhook.
- Expires Premium plans lazily when the vendor is next seen.

## Technology stack

| Package | Purpose |
| --- | --- |
| `express@5.3.0` | HTTP routes and middleware |
| `mongodb@7.9.0` | Database driver |
| `dotenv@18.0.10` | Loads `.env` locally |
| `cors@2.8.6` | Allows only the configured client origin |
| `jose@6.2.18` | Verifies Better Auth JWTs against JWKS |
| `stripe@23.2.0` | Checkout Sessions and webhook signature verification |

The whole API is intentionally kept in one readable file: `index.js`.

## Local setup

You need Node.js 20+, npm, MongoDB and the Next.js client running.

```bash
git clone https://github.com/emon-mehedi/pizza-plaza-server.git
cd pizza-plaza-server
npm install
cp .env.example .env
# Fill in the values in .env
npm run dev
```

The API listens on `http://localhost:5000` by default. In the client's `.env`, set:

```bash
BASE_API_URL=http://localhost:5000
```

### Scripts

```bash
npm run dev   # restart on file changes
npm start     # normal production-style start
node --check index.js  # syntax check
```

Check the server with `GET http://localhost:5000/`. It should return:

```json
{ "message": "Welcome to the PizzaHub API" }
```

## Environment variables

Create a local `.env` from `.env.example`. Only the names are committed.

| Variable | Purpose |
| --- | --- |
| `MONGO_CLIENT_URI` | MongoDB connection string. Required; the server exits without it. |
| `PORT` | Port to listen on. Defaults to `5000`. |
| `CLIENT_URL` | Next.js origin used for CORS and Stripe success/cancel redirects. Falls back to `BETTER_AUTH_URL`. |
| `BETTER_AUTH_URL` | Next.js origin that publishes Better Auth JWTs and JWKS. Must match the client exactly. |
| `STRIPE_SECRET_KEY` | Creates Checkout Sessions. Without it, payment routes return `503`. |
| `STRIPE_WEBHOOK_SECRET` | Verifies `/payments/webhook` signatures. Required for webhook processing. |

### Stripe webhook locally

```bash
stripe listen --forward-to localhost:5000/payments/webhook
```

Copy the printed `whsec_...` value into `STRIPE_WEBHOOK_SECRET`. In production, register `https://<your-server>/payments/webhook` in the Stripe dashboard and use that endpoint's signing secret.

## Authentication

Protected routes expect:

```http
Authorization: Bearer <Better Auth JWT>
```

The client stores the JWT through the Better Auth `jwt()` plugin and sends it with `apiFetch(path, { withAuth: true })`.

Verification flow in `requireAuth()`:

1. Read the `Bearer` token. Missing tokens get `401`.
2. `jose` verifies the signature, expiry, issuer and audience using `${BETTER_AUTH_URL}/api/auth/jwks`.
3. Load the user from MongoDB using the token's `sub`.
4. Blocked users get `403`. Expired Premium plans are downgraded once.
5. Only safe DB-derived values are attached to `req.user`. Client-supplied roles or user IDs are never trusted.

`requireRole(...roles)` returns `403` when the verified role is not allowed. Successful writes that need ownership compare the resource's stored owner ID with `req.user.id`.

Errors use a consistent JSON shape: `{ "message": "..." }`.

## API reference

### Public routes

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/` | Health/welcome message. |
| `GET` | `/items` | Approved items. Query: `q`, `category`, `location`, `minPrice`, `maxPrice`, `sort=price_asc\|price_desc`, `featured=1`, `limit` (1–12). |
| `GET` | `/items/:id` | One approved item. Returns `404` for hidden or invalid IDs. |
| `POST` | `/payments/webhook` | Stripe webhook. Requires a valid `stripe-signature`; no JWT. |

`featured=1` promotes vendors with an active Premium plan first, then newest items.

### Authenticated routes — any verified role

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/orders` | Customers see their own orders, vendors their restaurant's orders, admins see all. Optional `status` filter. |
| `GET` | `/orders/:id` | Ownership checked for customers and vendors. |
| `PATCH` | `/orders/:id/status` | Vendor may accept/reject a pending order; customer may cancel their own pending order; admin cannot. |
| `DELETE` | `/items/:id` | Item owner or admin only. |

### Customer routes

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/customer/overview` | Total, pending, accepted and rejected orders for the signed-in customer. |
| `POST` | `/orders` | Body: `itemId`, `deliveryDate`, `deliveryAddress`, `message` (optional). Customer ID, vendor ID and item come from the database. Blocks duplicate active orders for the same item/date. |

### Vendor routes

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/vendor/overview` | Menu/order counts plus the vendor's plan. |
| `GET` | `/vendor/items` | All of the vendor's items. Optional `status` filter. |
| `POST` | `/items` | Creates a `pending` item. Free plan allows 3 active items; Premium is unlimited. |
| `PATCH` | `/items/:id` | Edit your own item. Status cannot be changed here. |
| `PATCH` | `/items/:id/availability` | Body: `isActive` boolean. Toggles `approved`/`inactive`. |
| `GET` | `/vendor/transactions` | The vendor's own transactions. Optional `status` filter. |
| `POST` | `/payments/checkout` | Creates a Stripe Checkout Session for the signed-in vendor. |
| `GET` | `/payments/session/:sessionId` | Result for the client's payment success page. |

### Admin routes

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/admin/overview` | User, vendor, customer, item, pending item and transaction totals. |
| `GET` | `/admin/items` | All items. Query: `status`, `category`, `q`. |
| `PATCH` | `/items/:id/status` | Body: `status` (`pending`, `approved`, `rejected`, `inactive`). |
| `GET` | `/users` | Safe user fields only. Query: `q` (name/email), `role`. |
| `GET` | `/admin/users/:id` | User details plus counts and recent orders. |
| `PATCH` | `/users/:id/block` | Body: `isBlocked` boolean. Admin accounts cannot be blocked here. |
| `GET` | `/transactions` | Read-only records. Query: `status`, `vendorId`, `q`, `from`, `to`. |

There is no route to edit or delete transactions.

## Database collections

The database name is `pizzaplaza`.

| Collection | Purpose |
| --- | --- |
| `user` | Better Auth users with `role`, `isBlocked`, `businessName`, `subscriptionPlan`, `subscriptionExpiresAt`. |
| `items` | Menu items with `vendorId`, status, price, image and timestamps. |
| `orders` | Customer orders with item/vendor/customer references and status. |
| `transactions` | Premium payment records. Stripe is the only writer of successful status. |

Startup creates indexes for the common vendor, status, customer and Stripe session queries.

## Test accounts and payments

- **Admin email:** `[ADD WORKING ADMIN EMAIL AFTER DEPLOYMENT]`
- **Admin password:** `[ADD WORKING ADMIN PASSWORD AFTER DEPLOYMENT]`
- **Stripe test card:** `4242 4242 4242 4242`
- Use any future expiry date and any CVC.

Admin accounts are not created through public registration. Assign `role: "admin"` securely in the database.

## Deployment notes

- Set `CLIENT_URL` and `BETTER_AUTH_URL` to the production client origin, with no trailing slash.
- CORS allows requests without an `Origin` (server-to-server/webhooks) or from exactly `CLIENT_URL`.
- Configure the Stripe webhook endpoint and copy its signing secret into `STRIPE_WEBHOOK_SECRET`.
- Keep `BASE_API_URL` on the client pointed at this deployed server to avoid `404`/`504` errors.
- `GET /` is a cheap health check.

## Challenge notes

### 1. Advanced search and sorting

`GET /items` builds the MongoDB query from validated query parameters: `q` searches name/description/category/location with an escaped regex, `category` and `location` filter exactly, `minPrice`/`maxPrice` bound the price, and `sort=price_asc|price_desc` controls ordering. `featured=1&limit=6` ranks active Premium vendors first for the homepage.

### 2. JWT / token verification

`requireAuth()` verifies each bearer token with `jose` against the Better Auth JWKS URL, checks `iss`, `aud` and `exp`, then loads the user from MongoDB. Roles are applied by `requireRole()`, and writes compare ownership IDs stored in the database. Invalid or expired tokens get `401`; forbidden roles get `403`.

### 3. Professional UI polish

This server supports the polished client by returning consistent JSON, clear error messages, safe public user fields, item snapshots on orders and vendor info on transactions. The client is responsible for the responsive theme, toasts, skeletons and animations.

## Security notes

- Secrets stay in `.env`, which is gitignored. `.env.example` contains only variable names.
- No route accepts a user ID or role from a request body for authorization.
- Premium is activated only by a signed Stripe webhook, and each Checkout Session can be claimed once.
- Failed or expired payment events cannot overwrite a payment that already succeeded.
