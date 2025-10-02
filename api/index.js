// api/index.js
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const prisma = require('./lib/prisma');

const app = express();

// ---- APP CONFIG - AUTH ----
app.set('trust proxy', 1);
app.use(cookieParser());
app.use(express.json());
// ---- BOOTSTRAP DB (tolerate missing columns/tables) ----
let __booted = false;
async function __bootstrapOnce() {
  if (__booted) return;
  __booted = true;
  try {
    // Ensure Product.stock exists
    await prisma.$executeRawUnsafe('ALTER TABLE "Product" ADD COLUMN IF NOT EXISTS stock integer NOT NULL DEFAULT 0');
  } catch (e) { console.error('BOOTSTRAP_ERR', e.message); }
}
app.use((req, _res, next) => { __bootstrapOnce().finally(() => next()); });

// ---- OBSERVABILITY: Request ID + Rate Limit ----
const { randomUUID } = require('crypto');

// Simple in-memory token bucket per IP+path (serverless instance-local)
const RATE = { windowMs: 60_000, limit: 60 }; // 60 req/min per endpoint
const __buckets = new Map();

app.use((req, res, next) => {
  // request id
  const rid = req.headers['x-request-id'] || randomUUID();
  req.rid = rid;
  res.setHeader('x-request-id', rid);

  // rate limit
  try {
    const ip = (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown').toString().split(',')[0].trim();
    const key = ip + '|' + req.method + '|' + req.path;
    const now = Date.now();
    let b = __buckets.get(key);
    if (!b || now - b.ts > RATE.windowMs) { b = { ts: now, count: 0 }; }
    b.count += 1;
    __buckets.set(key, b);
    if (b.count > RATE.limit) {
      return res.status(429).json({ ok: false, message: 'Rate limit exceeded' });
    }
  } catch (e) { /* ignore */ }
  next();
});


const ACCESS_TTL = process.env.ACCESS_TTL || '15m';
const REFRESH_TTL = process.env.REFRESH_TTL || '7d';
const ACCESS_SECRET = process.env.JWT_SECRET || 'dev_access_secret_change_me';
const REFRESH_SECRET = process.env.REFRESH_SECRET || (process.env.JWT_SECRET || 'dev_refresh_secret_change_me');

function signAccess(user) {
  const payload = { sub: String(user.id), role: user.role || 'ADMIN', email: user.email };
  return jwt.sign(payload, ACCESS_SECRET, { expiresIn: ACCESS_TTL });
}
function makeJti() { return crypto.randomBytes(16).toString('hex'); }
function hashToken(token) { return crypto.createHash('sha256').update(token).digest('hex'); }

function parseMsOrDays(ttl) {
  // accepts '15m','7d','6h' or milliseconds
  if (String(ttl).endsWith('d')) return parseInt(ttl) * 24 * 60 * 60 * 1000;
  if (String(ttl).endsWith('h')) return parseInt(ttl) * 60 * 60 * 1000;
  if (String(ttl).endsWith('m')) return parseInt(ttl) * 60 * 1000;
  const n = Number(ttl); return isNaN(n) ? 0 : n;
}
function setRtCookie(res, token) {
  res.cookie('rt', token, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    path: '/api/auth',
    maxAge: parseMsOrDays(REFRESH_TTL) || (7 * 24 * 60 * 60 * 1000),
  });
}

async function requireAuth(req, res, next) {
  try {
    const h = req.headers['authorization'] || '';
    const m = /^Bearer\s+(.+)$/.exec(h);
    if (!m) return res.status(401).json({ ok: false, message: 'Missing bearer token' });
    const decoded = jwt.verify(m[1], ACCESS_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ ok: false, message: 'Invalid token' });
  }
}

function requireRole(...roles) {
  const allow = new Set(roles.map(r => String(r).toUpperCase()));
  return (req, res, next) => {
    try {
      const role = String((req.user && (req.user.role || req.user.r)) || '').toUpperCase();
      if (!role) return res.status(401).json({ ok: false, message: 'Unauthorized' });
      if (!allow.has(role)) return res.status(403).json({ ok: false, message: 'Forbidden' });
      return next();
    } catch (e) {
      return res.status(500).json({ ok: false, message: e.message });
    }
  };
}


// ---- RAW QUERY HELPER (handles missing delegates) ----
async function rawQuery(sql, params = []) {
  try {
    if (Array.isArray(params) && params.length) {
      const esc = (v) => {
        if (v === null || v === undefined) return 'NULL';
        if (typeof v === 'number' || typeof v === 'bigint') return String(v);
        if (typeof v === 'boolean') return v ? 'TRUE' : 'FALSE';
        return '\'' + String(v).replace(/'/g, "''") + '\'';
      };
      const final = sql.replace(/\$(\d+)/g, (_, i) => esc(params[Number(i) - 1]));
      return prisma.$queryRawUnsafe(final);
    }
    return prisma.$queryRawUnsafe(sql);
  } catch (e) {
    console.error('RAW_QUERY_ERR', e);
    return null;
  }
}

/**
 * Prisma sometimes throws conversion errors for column 'role' (enum/text drift).
 * Fallback to raw SELECT with explicit CAST role::text.
 */
async function getUserByEmailSafe(email) {
  try {
    return await prisma.adminUser.findUnique({ where: { email } });
  } catch (e) {
    const msg = String(e && (e.message || e.code || e.name) || '');
    if (msg.includes('Error converting field') || msg.includes('Invalid `prisma.adminUser.findUnique()`')) {
      const rows = await rawQuery(
        'SELECT id, email, password, COALESCE(role::text, \'USER\') AS role FROM "AdminUser" WHERE email = $1 LIMIT 1',
        [email]
      );
      return rows && rows[0] ? rows[0] : null;
    }
    throw e;
  }
}

async function getUserByIdSafe(id) {
  try {
    return await prisma.adminUser.findUnique({ where: { id: Number(id) } });
  } catch (e) {
    const msg = String(e && (e.message || e.code || e.name) || '');
    if (msg.includes('Error converting field') || msg.includes('Invalid `prisma.adminUser.findUnique()`')) {
      const rows = await rawQuery(
        'SELECT id, email, password, COALESCE(role::text, \'USER\') AS role FROM "AdminUser" WHERE id = $1 LIMIT 1',
        [Number(id)]
      );
      return rows && rows[0] ? rows[0] : null;
    }
    throw e;
  }
}


// ---- CORS ----
// CHỈNH domain nếu khác
const ALLOWED_ORIGINS = [
  'https://tmdt-mini.pages.dev',
  'https://tmdt-admin.pages.dev',
];

app.use(
  cors({
    origin(origin, cb) {
      // Cho phép request không có origin (Postman, curl)
      if (!origin) return cb(null, true);
      if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
      return cb(new Error('CORS: Origin not allowed'), false);
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
  })
);

// ---- HOME ----
app.get('/', (_req, res) => {
  res.json({
    ok: true,
    service: 'tmdt-api',
    routes: [
      '/api/health',
      '/api/products',
      '/api/auth/login',
      '/api/cart',
      '/api/checkout',
    ],
  });
});

// ---- HEALTH ----
app.get('/api/health', async (_req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    res.json({ ok: true });
  } catch (e) {
    console.error('HEALTH_ERR', e);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ---- HEALTHZ (alias) ----
app.get('/api/healthz', async (_req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    res.json({ ok: true, ts: Date.now() });
  } catch (e) {
    console.error('[healthz]', e);
    res.status(500).json({ ok: false, error: e.message });
  }
});
app.head('/api/healthz', async (_req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    res.status(204).end();
  } catch (e) {
    console.error('[healthz:head]', e);
    res.status(500).end();
  }
});

// ---- INTROSPECT (debug) ----
app.get('/__introspect', (_req, res) => {
  const hasUser = prisma && prisma.adminUser && typeof prisma.adminUser.findUnique === 'function';
  const models = Object.keys(prisma || {}).filter(k => typeof prisma[k] === 'object' && !k.startsWith('_'));
  res.json({ clientCreated: !!prisma, hasUser, models });
});


// ---- AUTH ----

// Register (basic, default role USER)
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ ok: false, message: 'Missing payload' });
    const existed = await getUserByEmailSafe(email);
    if (existed) return res.status(409).json({ ok: false, message: 'Email exists' });
    const hashed = await bcrypt.hash(password, 10);
    await prisma.adminUser.create({ data: { email, password: hashed, role: 'USER' } });
    return res.status(201).json({ ok: true });
  } catch (e) {
    console.error('REGISTER_ERR', e);
    res.status(500).json({ ok: false, message: e.message });
  }
});

// Request OTP (forgot password)
app.post('/api/auth/forgot', async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ ok: false, message: 'Missing email' });
    const user = await getUserByEmailSafe(email);
    if (!user) return res.json({ ok: true });

    await prisma.passwordReset.deleteMany({ where: { userId: user.id } }).catch(() => {});
    const code = String(Math.floor(100000 + Math.random() * 900000));
    const codeHash = hashToken(code);
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
    await prisma.passwordReset.create({ data: { userId: user.id, codeHash, expiresAt } });

    // Send via Resend if key present; otherwise log
    try {
      const key = process.env.RESEND_API_KEY || '';
      if (key) {
        const resp = await fetch('https://api.resend.com/emails', {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${key}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({
            from: process.env.RESEND_FROM || 'no-reply@tmdt.local',
            to: [email],
            subject: 'Your OTP code',
            text: `Your verification code is: ${code} (valid 10 minutes)`
          }),
        });
        if (!resp.ok) {
          const t = await resp.text().catch(()=>'');
          console.error('RESEND_ERR', resp.status, t);
        }
      } else {
        console.log('OTP(for dev):', email, code);
      }
    } catch (e) {
      console.error('RESEND_SEND_ERR', e);
      console.log('OTP(for dev):', email, code);
    }

    return res.json({ ok: true });
  } catch (e) {
    console.error('FORGOT_ERR', e);
    res.status(500).json({ ok: false, message: e.message });
  }
});

// Verify OTP (no mutation)
app.post('/api/auth/password/verify', async (req, res) => {
  try {
    const { email, code } = req.body || {};
    if (!email || !code) return res.status(400).json({ ok: false, message: 'Missing payload' });
    const user = await getUserByEmailSafe(email);
    if (!user) return res.status(400).json({ ok: false, message: 'Invalid' });
    const rec = await prisma.passwordReset.findFirst({
      where: { userId: user.id, consumedAt: null },
      orderBy: { createdAt: 'desc' },
    });
    if (!rec) return res.status(400).json({ ok: false, message: 'Invalid code' });
    if (new Date(rec.expiresAt) < new Date()) return res.status(400).json({ ok: false, message: 'Code expired' });
    if (rec.codeHash !== hashToken(code)) return res.status(400).json({ ok: false, message: 'Invalid code' });
    return res.json({ ok: true });
  } catch (e) {
    console.error('VERIFY_CODE_ERR', e);
    res.status(500).json({ ok: false, message: e.message });
  }
});

// Set new password
app.post('/api/auth/password/set', async (req, res) => {
  try {
    const { email, code, newPassword } = req.body || {};
    if (!email || !code || !newPassword) return res.status(400).json({ ok: false, message: 'Missing payload' });
    const user = await getUserByEmailSafe(email);
    if (!user) return res.status(400).json({ ok: false, message: 'Invalid' });
    const rec = await prisma.passwordReset.findFirst({
      where: { userId: user.id, consumedAt: null },
      orderBy: { createdAt: 'desc' },
    });
    if (!rec) return res.status(400).json({ ok: false, message: 'Invalid code' });
    if (new Date(rec.expiresAt) < new Date()) return res.status(400).json({ ok: false, message: 'Code expired' });
    if (rec.codeHash !== hashToken(code)) return res.status(400).json({ ok: false, message: 'Invalid code' });

    const hashed = await bcrypt.hash(newPassword, 10);
    await prisma.$transaction([
      prisma.adminUser.update({ where: { id: user.id }, data: { password: hashed } }),
      prisma.passwordReset.update({ where: { id: rec.id }, data: { consumedAt: new Date() } }),
      prisma.refreshToken.updateMany({ where: { userId: user.id, revokedAt: null }, data: { revokedAt: new Date() } }),
    ]);
    res.clearCookie('rt', { path: '/api/auth' });
    return res.json({ ok: true });
  } catch (e) {
    console.error('SET_PW_ERR', e);
    res.status(500).json({ ok: false, message: e.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ ok: false, message: 'Missing payload' });

    let user = await getUserByEmailSafe(email);
    if (!user) return res.status(401).json({ ok: false, message: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.password || '');
    if (!ok) return res.status(401).json({ ok: false, message: 'Invalid credentials' });

    // issue tokens
    const accessToken = signAccess(user);
    const jti = makeJti();
    const refreshToken = jwt.sign({ sub: String(user.id), jti }, REFRESH_SECRET, { expiresIn: REFRESH_TTL });
    await prisma.refreshToken.create({
      data: {
        jti,
        userId: user.id,
        tokenHash: hashToken(refreshToken),
        userAgent: req.headers['user-agent'] || null,
        ip: (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '').toString(),
        expiresAt: new Date(Date.now() + (parseMsOrDays(REFRESH_TTL) || 7 * 24 * 60 * 60 * 1000)),
      },
    });
    setRtCookie(res, refreshToken);
    return res.json({ ok: true, accessToken, user: { id: user.id, email: user.email, role: user.role || 'ADMIN' } });
  } catch (e) {
    console.error('LOGIN_ERR', e);
    return res.status(500).json({ ok: false, message: e.message });
  }
});

// Refresh (rotation)
app.post('/api/auth/refresh', async (req, res) => {
  try {
    const rt = req.cookies?.rt;
    if (!rt) return res.status(401).json({ ok: false, message: 'No refresh cookie' });
    let decoded;
    try { decoded = jwt.verify(rt, REFRESH_SECRET); }
    catch { return res.status(401).json({ ok: false, message: 'Invalid refresh' }); }
    const userId = parseInt(decoded.sub || decoded.userId || decoded.id);
    const jti = decoded.jti;
    const rec = await prisma.refreshToken.findUnique({ where: { jti } }).catch(() => null);
    if (!rec || rec.revokedAt || hashToken(rt) !== rec.tokenHash) return res.status(401).json({ ok: false, message: 'Invalid refresh' });

    await prisma.refreshToken.update({ where: { jti }, data: { revokedAt: new Date() } });

    const newJti = makeJti();
    const refreshToken = jwt.sign({ sub: String(userId), jti: newJti }, REFRESH_SECRET, { expiresIn: REFRESH_TTL });
    await prisma.refreshToken.create({
      data: {
        jti: newJti,
        userId,
        tokenHash: hashToken(refreshToken),
        userAgent: req.headers['user-agent'] || null,
        ip: (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '').toString(),
        expiresAt: new Date(Date.now() + (parseMsOrDays(REFRESH_TTL) || 7 * 24 * 60 * 60 * 1000)),
      },
    });
    const user = await getUserByIdSafe(userId);
    setRtCookie(res, refreshToken);
    const accessToken = signAccess(user);
    return res.json({ ok: true, accessToken, user: { id: user.id, email: user.email, role: user.role || 'ADMIN' } });
  } catch (e) {
    console.error('REFRESH_ERR', e);
    res.status(500).json({ ok: false, message: e.message });
  }
});

// Me
app.get('/api/auth/me', requireAuth, async (req, res) => {
  try {
    const id = parseInt(req.user.sub || req.user.id);
    const user = await getUserByIdSafe(id);
    return res.json({ ok: true, user: { id: user.id, email: user.email, role: user.role } });
  } catch (e) {
    res.status(500).json({ ok: false, message: e.message });
  }
});

// Change password (authorized)
app.post('/api/auth/change-password', requireAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body || {};
    if (!currentPassword || !newPassword) return res.status(400).json({ ok: false, message: 'Missing payload' });
    const id = parseInt(req.user.sub || req.user.id);
    const user = await getUserByIdSafe(id);
    const ok = await bcrypt.compare(currentPassword, user.password || '');
    if (!ok) return res.status(401).json({ ok: false, message: 'Current password invalid' });
    const hashed = await bcrypt.hash(newPassword, 10);
    await prisma.adminUser.update({ where: { id }, data: { password: hashed } });
    await prisma.refreshToken.updateMany({ where: { userId: id, revokedAt: null }, data: { revokedAt: new Date() } });
    res.clearCookie('rt', { path: '/api/auth' });
    return res.json({ ok: true });
  } catch (e) {
    console.error('CHANGE_PW_ERR', e);
    res.status(500).json({ ok: false, message: e.message });
  }
});

// Admin-only: list users (RBAC demo)
app.get('/api/admin/users', requireAuth, requireRole('ADMIN','STAFF'), async (_req, res) => {
  try {
    let rows;
    try {
      rows = await prisma.adminUser.findMany({ select: { id: true, email: true, role: true, createdAt: true }, orderBy: { id: 'asc' } });
    } catch (e) {
      rows = await rawQuery(`SELECT id, email, COALESCE(role::text, 'USER') AS role, \"createdAt\" FROM \"AdminUser\" ORDER BY id ASC`);
    }
    res.json({ ok: true, users: rows });
  } catch (e) {
    console.error('ADMIN_USERS_ERR', e);
    res.status(500).json({ ok: false, message: e.message });
  }
});


// Admin-only: CRUD products
app.post('/api/admin/products', requireAuth, requireRole('ADMIN','STAFF'), async (req, res) => {
  try {
    const { name, price, description, imageUrl } = req.body || {};
    if (!name) return res.status(400).json({ ok: false, message: 'Missing name' });
    const data = { name, price: Number(price)||0, description: description||null, imageUrl: imageUrl||null };
    const created = await prisma.product.create({ data });
    res.status(201).json({ ok: true, product: created });
  } catch (e) {
    console.error('ADMIN_PRODUCT_CREATE_ERR', e);
    res.status(500).json({ ok: false, message: e.message });
  }
});

app.put('/api/admin/products/:id', requireAuth, requireRole('ADMIN','STAFF'), async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { name, price, description, imageUrl } = req.body || {};
    const data = {};
    if (name !== undefined) data.name = name;
    if (price !== undefined) data.price = Number(price);
    if (description !== undefined) data.description = description;
    if (imageUrl !== undefined) data.imageUrl = imageUrl;
    const updated = await prisma.product.update({ where: { id }, data });
    res.json({ ok: true, product: updated });
  } catch (e) {
    console.error('ADMIN_PRODUCT_UPDATE_ERR', e);
    res.status(500).json({ ok: false, message: e.message });
  }
});

app.delete('/api/admin/products/:id', requireAuth, requireRole('ADMIN'), async (req, res) => {
  try {
    const id = Number(req.params.id);
    await prisma.product.delete({ where: { id } });
    res.json({ ok: true });
  } catch (e) {
    console.error('ADMIN_PRODUCT_DELETE_ERR', e);
    res.status(500).json({ ok: false, message: e.message });
  }
});


// ---- PRODUCTS (with short cache) ----
const __productsCache = { data: null, ts: 0, ttl: 15_000 };

app.get('/api/products', async (_req, res) => {
  try {
    const now = Date.now();
    if (__productsCache.data && now - __productsCache.ts < __productsCache.ttl) {
      res.setHeader('Cache-Control', 'public, max-age=15');
      return res.json({ ok: true, data: __productsCache.data, cached: true });
    }
    const rows = await prisma.product.findMany({ orderBy: { id: 'asc' } });
    __productsCache.data = rows; __productsCache.ts = now;
    res.setHeader('Cache-Control', 'public, max-age=15');
    return res.json({ ok: true, data: rows });
  } catch (e) {
    console.error('PRODUCTS_ERR', e);
    res.status(500).json({ ok: false, message: e.message });
  }
});
// ---- EXPORT FOR VERCEL ----
module.exports = app;
exports.default = app;
