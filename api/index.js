// api/index.js
// Express API chạy trên Vercel (@vercel/node). KHÔNG dùng serverless-http.

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');

const app = express();

// ====== CORS ======
const allowOrigin = process.env.CORS_ORIGIN || '*';
app.use(
  cors({
    origin: allowOrigin === '*' ? true : allowOrigin.split(',').map(s => s.trim()),
    credentials: false,
  })
);
app.use(express.json());

// ====== Prisma (cache trong dev để tránh tạo nhiều connection) ======
const g = globalThis;
const prisma = g.__prisma__ || new PrismaClient();
if (process.env.NODE_ENV !== 'production') g.__prisma__ = prisma;

// ====== Helpers ======
const JWT_SECRET = process.env.JWT_SECRET || 'devsecret';

function createToken(user) {
  return jwt.sign({ uid: user.id, email: user.email, role: user.role || 'user' }, JWT_SECRET, {
    expiresIn: '7d',
  });
}

function auth(req, res, next) {
  try {
    const h = req.headers.authorization || '';
    const token = h.startsWith('Bearer ') ? h.slice(7) : null;
    if (!token) return res.status(401).json({ ok: false, error: 'NO_TOKEN' });
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ ok: false, error: 'INVALID_TOKEN' });
  }
}

function safeInt(v, def = 0) {
  const n = parseInt(v, 10);
  return Number.isFinite(n) ? n : def;
}

// ====== Routes ======

// Health
app.get('/api/health', (req, res) => {
  res.json({ ok: true, env: process.env.NODE_ENV || 'development' });
});

// Auth: demo login (admin@demo.com / admin123) hoặc user trong DB
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ ok: false, error: 'MISSING_CREDENTIALS' });

    // Tìm trong DB
    let user = await prisma.user.findUnique({ where: { email } }).catch(() => null);

    // Fallback demo
    if (!user && email === 'admin@demo.com') {
      // tạo user demo nếu chưa có
      const hash = await bcrypt.hash('admin123', 10);
      user = await prisma.user.upsert({
        where: { email },
        create: { email, password: hash, name: 'Admin', role: 'admin' },
        update: {},
      });
    }

    if (!user) return res.status(401).json({ ok: false, error: 'USER_NOT_FOUND' });

    const ok = await bcrypt.compare(password, user.password || '');
    if (!ok) return res.status(401).json({ ok: false, error: 'WRONG_PASSWORD' });

    const token = createToken(user);
    res.json({ ok: true, token, user: { id: user.id, email: user.email, name: user.name, role: user.role } });
  } catch (e) {
    console.error('LOGIN_ERR', e);
    res.status(500).json({ ok: false, error: 'LOGIN_FAILED' });
  }
});

// Products
app.get('/api/products', async (req, res) => {
  try {
    const list = await prisma.product.findMany({
      orderBy: { createdAt: 'desc' },
    });
    res.json({ ok: true, items: list });
  } catch (e) {
    console.error('PRODUCTS_ERR', e);
    res.status(500).json({ ok: false, error: 'LOAD_PRODUCTS_FAILED' });
  }
});

// Create cart
app.post('/api/cart', async (req, res) => {
  try {
    const cart = await prisma.cart.create({ data: {} });
    res.json({ ok: true, cartId: cart.id });
  } catch (e) {
    console.error('CART_CREATE_ERR', e);
    res.status(500).json({ ok: false, error: 'CREATE_CART_FAILED' });
  }
});

// Get cart detail
app.get('/api/cart/:cid', async (req, res) => {
  try {
    const cartId = req.params.cid;
    const cart = await prisma.cart.findUnique({
      where: { id: cartId },
      include: { items: { include: { product: true } } },
    });
    if (!cart) return res.status(404).json({ ok: false, error: 'CART_NOT_FOUND' });
    res.json({ ok: true, cart });
  } catch (e) {
    console.error('CART_GET_ERR', e);
    res.status(500).json({ ok: false, error: 'GET_CART_FAILED' });
  }
});

// Add item to cart
app.post('/api/cart/:cid/items', async (req, res) => {
  try {
    const cartId = req.params.cid;
    const { productId, qty } = req.body || {};
    const quantity = Math.max(1, safeInt(qty, 1));

    // ensure cart exists
    const cart = await prisma.cart.findUnique({ where: { id: cartId } });
    if (!cart) return res.status(404).json({ ok: false, error: 'CART_NOT_FOUND' });

    // upsert item
    const existing = await prisma.cartItem.findFirst({ where: { cartId, productId } });

    if (existing) {
      await prisma.cartItem.update({
        where: { id: existing.id },
        data: { qty: existing.qty + quantity },
      });
    } else {
      await prisma.cartItem.create({
        data: { cartId, productId, qty: quantity },
      });
    }

    const updated = await prisma.cart.findUnique({
      where: { id: cartId },
      include: { items: { include: { product: true } } },
    });

    res.json({ ok: true, cart: updated });
  } catch (e) {
    console.error('CART_ADD_ERR', e);
    res.status(500).json({ ok: false, error: 'ADD_ITEM_FAILED' });
  }
});

// Checkout (mock)
app.post('/api/checkout', async (req, res) => {
  try {
    const { cartId, name, phone, address } = req.body || {};
    if (!cartId) return res.status(400).json({ ok: false, error: 'MISSING_CART_ID' });

    const cart = await prisma.cart.findUnique({
      where: { id: cartId },
      include: { items: { include: { product: true } } },
    });
    if (!cart) return res.status(404).json({ ok: false, error: 'CART_NOT_FOUND' });

    // tạo order đơn giản
    const order = await prisma.order.create({
      data: {
        name: name || 'Khách',
        phone: phone || '',
        address: address || '',
        items: {
          create: cart.items.map(it => ({
            productId: it.productId,
            qty: it.qty,
            price: it.product.price || 0,
          })),
        },
        cartId,
        status: 'PENDING',
      },
      include: { items: true },
    });

    // mock payment url
    const payment_url = `https://example.com/pay?order=${order.id}`;
    res.json({ ok: true, orderId: order.id, payment_url });
  } catch (e) {
    console.error('CHECKOUT_ERR', e);
    res.status(500).json({ ok: false, error: 'CHECKOUT_FAILED' });
  }
});

// ====== Export cho Vercel và chạy local ======
module.exports = app;

if (require.main === module) {
  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log(`API listening on http://localhost:${port}`));
}
