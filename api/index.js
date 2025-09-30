
const serverless = require('serverless-http');
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { PrismaClient } = require('@prisma/client');
const AWS = require('aws-sdk');
const { v4: uuidv4 } = require('uuid');

require('dotenv').config();

const app = express();
app.use(express.json());

const corsOrigin = process.env.CORS_ORIGIN || '*';
app.use(cors({ origin: corsOrigin }));

const prisma = new PrismaClient();

// R2 (S3 API)
let s3 = null;
if (process.env.R2_ACCOUNT_ID && process.env.R2_ACCESS_KEY_ID && process.env.R2_SECRET_ACCESS_KEY) {
  s3 = new AWS.S3({
    endpoint: `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
    accessKeyId: process.env.R2_ACCESS_KEY_ID,
    secretAccessKey: process.env.R2_SECRET_ACCESS_KEY,
    signatureVersion: 'v4',
  });
}
const R2_BUCKET = process.env.R2_BUCKET || 'uploads';
const R2_PUBLIC_BASE = process.env.R2_PUBLIC_BASE || '';

const JWT_SECRET = process.env.JWT_SECRET || 'changeme-supersecret';

// -------- Helpers --------
function auth(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token = header.split(' ')[1];
  if (!token) return res.status(401).json({ ok: false, error: 'NO_TOKEN' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ ok: false, error: 'INVALID_TOKEN' });
  }
}

app.get('/api/health', (req, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});

// ---- Auth ----
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ ok: false, error: 'MISSING_CREDENTIALS' });
  const user = await prisma.adminUser.findUnique({ where: { email } });
  if (!user) return res.status(401).json({ ok: false, error: 'INVALID_LOGIN' });
  const match = bcrypt.compareSync(password, user.password);
  if (!match) return res.status(401).json({ ok: false, error: 'INVALID_LOGIN' });
  const token = jwt.sign({ uid: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ ok: true, token });
});

// ---- Products (public) ----
app.get('/api/products', async (req, res) => {
  const items = await prisma.product.findMany({ orderBy: { id: 'desc' } });
  res.json({ ok: true, items });
});

app.get('/api/products/:id', async (req, res) => {
  const id = Number(req.params.id);
  const item = await prisma.product.findUnique({ where: { id } });
  if (!item) return res.status(404).json({ ok: false, error: 'NOT_FOUND' });
  res.json({ ok: true, item });
});

// ---- Admin Products (protected) ----
app.post('/api/admin/products', auth, async (req, res) => {
  const { name, description = '', price, imageUrl } = req.body || {};
  if (!name || !price) return res.status(400).json({ ok: false, error: 'MISSING_FIELDS' });
  const item = await prisma.product.create({ data: { name, description, price: Number(price), imageUrl } });
  res.json({ ok: true, item });
});

app.put('/api/admin/products/:id', auth, async (req, res) => {
  const id = Number(req.params.id);
  const { name, description, price, imageUrl } = req.body || {};
  const item = await prisma.product.update({ where: { id }, data: { name, description, price: Number(price), imageUrl } });
  res.json({ ok: true, item });
});

app.delete('/api/admin/products/:id', auth, async (req, res) => {
  const id = Number(req.params.id);
  await prisma.product.delete({ where: { id } });
  res.json({ ok: true });
});

// ---- Cart ----
app.post('/api/cart', async (req, res) => {
  const id = uuidv4();
  await prisma.cart.create({ data: { id } });
  res.json({ ok: true, cartId: id });
});

app.get('/api/cart/:cartId', async (req, res) => {
  const { cartId } = req.params;
  const cart = await prisma.cart.findUnique({
    where: { id: cartId },
    include: { items: { include: { product: true } } }
  });
  if (!cart) return res.status(404).json({ ok: false, error: 'NOT_FOUND' });
  res.json({ ok: true, cart });
});

app.post('/api/cart/:cartId/items', async (req, res) => {
  const { cartId } = req.params;
  const { productId, qty } = req.body || {};
  if (!productId || !qty) return res.status(400).json({ ok: false, error: 'MISSING_FIELDS' });
  const cart = await prisma.cart.findUnique({ where: { id: cartId } });
  if (!cart) return res.status(404).json({ ok: false, error: 'CART_NOT_FOUND' });
  const product = await prisma.product.findUnique({ where: { id: Number(productId) } });
  if (!product) return res.status(404).json({ ok: false, error: 'PRODUCT_NOT_FOUND' });
  const item = await prisma.cartItem.create({ data: { cartId, productId: Number(productId), qty: Number(qty) } });
  res.json({ ok: true, item });
});

// ---- Checkout ----
app.post('/api/checkout', async (req, res) => {
  const { cartId, name, phone, address } = req.body || {};
  if (!cartId || !name || !phone || !address) return res.status(400).json({ ok: false, error: 'MISSING_FIELDS' });
  const cart = await prisma.cart.findUnique({ where: { id: cartId }, include: { items: true } });
  if (!cart || cart.items.length === 0) return res.status(400).json({ ok: false, error: 'EMPTY_CART' });

  // Create order + items
  const order = await prisma.order.create({ data: { cartId, name, phone, address, status: 'PENDING' } });
  for (const ci of cart.items) {
    const prod = await prisma.product.findUnique({ where: { id: ci.productId } });
    await prisma.orderItem.create({
      data: { orderId: order.id, productId: ci.productId, qty: ci.qty, price: prod.price }
    });
  }
  // Mock payment url
  const payment_url = `https://example.com/pay?order=${order.id}`;
  res.json({ ok: true, order, payment_url });
});

// ---- Webhooks (mock) ----
app.post('/api/webhooks/zalopay', async (req, res) => {
  console.log('ZaloPay webhook:', req.body);
  res.json({ ok: true, received: req.body });
});

app.post('/api/webhooks/shipping', async (req, res) => {
  console.log('Shipping webhook:', req.body);
  res.json({ ok: true, received: req.body });
});

// ---- Upload to R2 ----
const upload = multer({ storage: multer.memoryStorage() });
app.post('/api/upload', auth, upload.single('file'), async (req, res) => {
  if (!s3) return res.status(500).json({ ok: false, error: 'R2_NOT_CONFIGURED' });
  if (!req.file) return res.status(400).json({ ok: false, error: 'NO_FILE' });
  const ext = req.file.originalname.split('.').pop();
  const key = `${new Date().toISOString().slice(0,10)}/${uuidv4()}.${ext}`;
  try {
    await s3
      .putObject({
        Bucket: R2_BUCKET,
        Key: key,
        Body: req.file.buffer,
        ContentType: req.file.mimetype,
        ACL: 'public-read', // requires public bucket policy
      })
      .promise();
    const url = R2_PUBLIC_BASE ? `${R2_PUBLIC_BASE}/${key}` : key;
    res.json({ ok: true, key, url });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: 'UPLOAD_FAILED', detail: e.message });
  }
});

module.exports = serverless(app);
if (require.main === module) {
  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log(`API listening on http://localhost:${port}`));
}

module.exports = app;
