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
    if (typeof prisma.$queryRawUnsafe === 'function') {
      // support placeholders $1, $2 ... (Neon/PG)
      if (Array.isArray(params) && params.length) {
        // prisma.$queryRawUnsafe(sql, ...params) (Prisma >=5) – fallback: manual replace
        return await prisma.$queryRawUnsafe(
          sql.replace(/\$(\d+)/g, (_, i) => params[Number(i) - 1])
        );
      }
      return await prisma.$queryRawUnsafe(sql);
    }
  } catch (e) {
    console.error('RAW_QUERY_ERR', e);
  }
  return null;
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
// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ ok: false, message: 'Missing payload' });
    const existed = await prisma.adminUser.findUnique({ where: { email } });
    if (existed) return res.status(409).json({ ok: false, message: 'Email exists' });
    const hashed = await bcrypt.hash(password, 10);
    await prisma.adminUser.create({ data: { email, password: hashed, role: 'USER' } });
    return res.status(201).json({ ok: true });
  } catch (e) {
    console.error('REGISTER_ERR', e);
    res.status(500).json({ ok: false, message: e.message });
  }
});

// Refresh (rotate)
app.post('/api/auth/refresh', async (req, res) => {
  try {
    const rt = req.cookies?.rt;
    if (!rt) return res.status(401).json({ ok: false, message: 'No refresh cookie' });

    let decoded;
    try {
      decoded = jwt.verify(rt, REFRESH_SECRET);
    } catch {
      return res.status(401).json({ ok: false, message: 'Invalid refresh' });
    }

    const userId = parseInt(decoded.sub || decoded.userId || decoded.id);
    const jti = decoded.jti;
    const rec = await prisma.refreshToken.findUnique({ where: { jti } }).catch(() => null);
    if (!rec || rec.revokedAt) return res.status(401).json({ ok: false, message: 'Refresh revoked' });
    if (rec.expiresAt && new Date(rec.expiresAt) < new Date())
      return res.status(401).json({ ok: false, message: 'Refresh expired' });
    if (rec.tokenHash !== hashToken(rt)) return res.status(401).json({ ok: false, message: 'Refresh mismatch' });

    // rotate
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

    setRtCookie(res, refreshToken);
    const user = await prisma.adminUser.findUnique({ where: { id: userId } });
    const accessToken = signAccess(user);
    return res.json({ ok: true, accessToken });
  } catch (e) {
    console.error('REFRESH_ERR', e);
    res.status(500).json({ ok: false, message: e.message });
  }
});

// Logout
app.post('/api/auth/logout', async (req, res) => {
  try {
    const rt = req.cookies?.rt;
    if (rt) {
      try {
        const decoded = jwt.verify(rt, REFRESH_SECRET);
        await prisma.refreshToken
          .update({ where: { jti: decoded.jti }, data: { revokedAt: new Date() } })
          .catch(() => {});
      } catch {}
    }
    res.clearCookie('rt', { path: '/api/auth' });
    return res.json({ ok: true });
  } catch (e) {
    console.error('LOGOUT_ERR', e);
    res.status(500).json({ ok: false, message: e.message });
  }
});

// Me
app.get('/api/auth/me', requireAuth, async (req, res) => {
  try {
    const id = parseInt(req.user.sub || req.user.id);
    const user = await prisma.adminUser.findUnique({
      where: { id },
      select: { id: true, email: true, role: true },
    });
    return res.json({ ok: true, user });
  } catch (e) {
    res.status(500).json({ ok: false, message: e.message });
  }
});

// Change password
app.post('/api/auth/change-password', requireAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body || {};
    if (!currentPassword || !newPassword) return res.status(400).json({ ok: false, message: 'Missing payload' });

    const id = parseInt(req.user.sub || req.user.id);
    const user = await prisma.adminUser.findUnique({ where: { id } });
    const ok = await bcrypt.compare(currentPassword, user.password);
    if (!ok) return res.status(401).json({ ok: false, message: 'Current password invalid' });

    const hashed = await bcrypt.hash(newPassword, 10);
    await prisma.adminUser.update({ where: { id }, data: { password: hashed } });
    // revoke all refresh
    await prisma.refreshToken.updateMany({ where: { userId: id, revokedAt: null }, data: { revokedAt: new Date() } });
    res.clearCookie('rt', { path: '/api/auth' });
    return res.json({ ok: true });
  } catch (e) {
    console.error('CHANGE_PW_ERR', e);
    res.status(500).json({ ok: false, message: e.message });
  }
});

// Forgot -> send OTP (log if no provider configured)
app.post('/api/auth/forgot', async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ ok: false, message: 'Missing email' });

// Verify OTP (no mutation)
app.post('/api/auth/password/verify', async (req, res) => {
  try {
    const { email, code } = req.body || {};
    if (!email || !code) return res.status(400).json({ ok: false, message: 'Missing payload' });

// Set password with verified OTP
app.post('/api/auth/password/set', async (req, res) => {
  try {
    const { email, code, newPassword } = req.body || {};
    if (!email || !code || !newPassword) return res.status(400).json({ ok: false, message: 'Missing payload' });

    const user = await prisma.adminUser.findUnique({ where: { email } });
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

    const user = await prisma.adminUser.findUnique({ where: { email } });
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

    const user = await prisma.adminUser.findUnique({ where: { email } });
    if (!user) return res.json({ ok: true }); // tránh lộ thông tin

    await prisma.passwordReset.deleteMany({ where: { userId: user.id } }).catch(() => {});
    const code = String(Math.floor(100000 + Math.random() * 900000));
    const codeHash = hashToken(code);
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
    await prisma.passwordReset.create({ data: { userId: user.id, codeHash, expiresAt } });
    console.log('OTP(for dev):', email, code);
    // TODO: send via Resend/Sendgrid if key present
    return res.json({ ok: true });
  } catch (e) {
    console.error('FORGOT_ERR', e);
    res.status(500).json({ ok: false, message: e.message });
  }
});

// Reset with OTP
app.post('/api/auth/reset', async (req, res) => {
  try {
    const { email, code, newPassword } = req.body || {};
    if (!email || !code || !newPassword) return res.status(400).json({ ok: false, message: 'Missing payload' });

    const user = await prisma.adminUser.findUnique({ where: { email } });
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
    console.error('RESET_ERR', e);
    res.status(500).json({ ok: false, message: e.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ ok: false, message: 'Missing payload' });

    let user = null;
    try {
      user = await prisma.adminUser.findUnique({ where: { email } });
    } catch (e) {
      // schema drift: column not exist
      if (String(e.message || '').includes('does not exist')) {
        const rows = await rawQuery(
          'SELECT id, email, password FROM "AdminUser" WHERE email = $1 LIMIT 1',
          [email]
        );
        user = rows && rows[0] ? rows[0] : null;
      } else {
        throw e;
      }
    }

    if (!user) return res.status(401).json({ ok: false, message: 'Invalid email or password' });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ ok: false, message: 'Invalid email or password' });

    const accessToken = signAccess(user);
    const jti = makeJti();
    const refreshToken = jwt.sign({ sub: String(user.id), jti }, REFRESH_SECRET, { expiresIn: REFRESH_TTL });

    try {
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
    } catch (_) {}

    setRtCookie(res, refreshToken);
    return res.json({
      ok: true,
      accessToken,
      user: { id: user.id, email: user.email, role: user.role || 'ADMIN' },
    });
  } catch (e) {
    console.error('LOGIN_ERR', e);
    return res.status(500).json({ ok: false, message: e.message });
  }
});



// Admin-only: list users (RBAC demo)
app.get('/api/admin/users', requireAuth, requireRole('ADMIN','STAFF'), async (_req, res) => {
  try {
    const rows = await prisma.adminUser.findMany({ select: { id: true, email: true, role: true, createdAt: true }, orderBy: { id: 'asc' } });
    res.json({ ok: true, users: rows });
  } catch (e) {
    console.error('ADMIN_USERS_ERR', e);
    res.status(500).json({ ok: false, message: e.message });
  }
});
// ---- PRODUCTS ----
app.get('/api/products', async (_req, res) => {
  try {
    if (prisma.product && typeof prisma.product.findMany === 'function') {
      const items = await prisma.product.findMany({ orderBy: { createdAt: 'desc' } });
      return res.json({ ok: true, items });
    }
    const rows = await rawQuery(
      `SELECT id, name, description, price, "imageUrl", "createdAt"
       FROM "Product" ORDER BY "createdAt" DESC LIMIT 100`
    );
    if (rows) return res.json({ ok: true, items: rows });
    return res.json({ ok: true, items: [] });
  } catch (e) {
    console.error('PRODUCTS_ERR', e);
    res.status(500).json({ ok: false, message: e.message });
  }
});

// (tùy chọn) stub để tránh 404 khi client gọi checkout
app.post('/api/checkout', (_req, res) => res.status(501).json({ ok: false, message: 'Not implemented' }));


// ---- ERROR HANDLER (last) ----
app.use((err, req, res, _next) => {
  const status = err.status || err.statusCode || 500;
  const msg = err.message || 'Internal Server Error';
  if (status >= 500) {
    console.error('[error]', { url: req.url, method: req.method, status, msg });
  }
  res.status(status).json({ ok: false, error: msg });
});
// ---- EXPORT ----
module.exports = (req, res) => app(req, res);

// global error logs to help debugging on serverless
process.on('unhandledRejection', err => console.error('UNHANDLED_REJECTION', err));
process.on('uncaughtException', err => console.error('UNCAUGHT_EXCEPTION', err));
