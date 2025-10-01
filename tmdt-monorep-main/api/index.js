// api/index.js
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const prisma = require('./lib/prisma');

const app = express();
app.use(express.json());
// ---- RAW QUERY HELPER (handles missing delegates) ----
async function rawQuery(sql, params=[]) {
  try {
    if (typeof prisma.$queryRaw === 'function') {
      // Prefer parameterized query
      return await prisma.$queryRaw`${sql}`;
    }
    if (typeof prisma.$queryRawUnsafe === 'function') {
      return await prisma.$queryRawUnsafe(
        Array.isArray(params) && params.length ? 
          sql.replace(/\$(\d+)/g, (_,i)=>params[Number(i)-1]) : sql
      );
    }
  } catch (e) {
    console.error('RAW_QUERY_ERR', e);
  }
  return null;
}

// CHỈNH domain theo của bạn nếu khác
const ALLOWED_ORIGINS = [
  'https://tmdt-mini.pages.dev',
  'https://tmdt-admin.pages.dev',
];

app.use(
  cors({
    origin(origin, cb) {
      // Cho phép cả request không có origin (Postman, curl)
      if (!origin) return cb(null, true);
      if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
      return cb(new Error('CORS: Origin not allowed'), false);
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: false,
  })
);

// Trang chủ – liệt kê route
app.get('/', (req, res) => {
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

// Health check DB
app.get('/api/health', async (_req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    res.json({ ok: true });
  } catch (e) {
    console.error('HEALTH_ERR', e);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// DEBUG: xem Prisma có model user chưa
app.get('/__introspect', (_req, res) => {
  const hasUser =
    prisma && prisma.adminUser && typeof prisma.adminUser.findUnique === 'function';
  const models = Object.keys(prisma || {}).filter(
    (k) => typeof prisma[k] === 'object' && !k.startsWith('_')
  );
  res.json({ clientCreated: !!prisma, hasUser, models });
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ ok: false, message: 'Missing payload' });
    }

    let user = null;
    if (prisma.adminUser && typeof prisma.adminUser.findUnique === 'function') {
      user = await prisma.adminUser.findUnique({ where: { email } });
    } else {
      const rows = await rawQuery(`SELECT id, email, password FROM "AdminUser" WHERE email = '${email}' LIMIT 1`);
      user = rows && rows[0] ? rows[0] : null;
    }

    if (!user) return res.status(401).json({ ok: false, message: 'Email/password invalid' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ ok: false, message: 'Email/password invalid' });

    const token = jwt.sign(
      { sub: user.id, role: 'ADMIN' },
      process.env.JWT_SECRET || 'dev',
      { expiresIn: '1d' }
    );
    return res.json({ ok: true, token });
  } catch (e) {
    console.error('LOGIN_ERR', e);
    return res.status(500).json({ ok: false, message: e.message });
  }
});

// Products mẫu – nếu bạn đã có rồi thì giữ code của bạn
app.get('/api/products', async (_req, res) => {
  try {
    if (prisma.product && typeof prisma.product.findMany === 'function') {
      const items = await prisma.product.findMany({ orderBy: { createdAt: 'desc' } });
      return res.json({ ok: true, items });
    }
    // fallback: raw query
    const rows = await rawQuery(
      `SELECT id, name, description, price, "imageUrl", "createdAt" FROM "Product" ORDER BY "createdAt" DESC LIMIT 100`
    );
    if (rows) return res.json({ ok: true, items: rows });
    // ultimate fallback: static sample to avoid 500
    return res.json({ ok: true, items: [] });
  } catch (e) {
    console.error('PRODUCTS_ERR', e);
    res.status(500).json({ ok: false, message: e.message });
  }
});

module.exports = (req, res) => app(req, res);