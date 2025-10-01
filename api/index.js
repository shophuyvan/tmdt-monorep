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
function addDays(days) { return new Date(Date.now() + days*24*60*60*1000); }

function parseMsOrDays(ttl) {
  // accepts '15m','7d' or milliseconds
  if (String(ttl).endsWith('d')) return parseInt(ttl) * 24 * 60 * 60 * 1000;
  if (String(ttl).endsWith('m')) return parseInt(ttl) * 60 * 1000;
  if (String(ttl).endsWith('h')) return parseInt(ttl) * 60 * 60 * 1000;
  const n = Number(ttl); return isNaN(n) ? 0 : n;
}
function setRtCookie(res, token) {
  res.cookie('rt', token, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    path: '/api/auth',
    maxAge: parseMsOrDays(REFRESH_TTL) || (7*24*60*60*1000)
  });
}

async function requireAuth(req, res, next) {
  try {
    const h = req.headers['authorization'] || '';
    const m = /^Bearer\s+(.+)$/.exec(h);
    if (!m) return res.status(401).json({ ok:false, message:'Missing bearer token' });
    const decoded = jwt.verify(m[1], ACCESS_SECRET);
    req.user = decoded;
    next();
  } catch(e) {
    return res.status(401).json({ ok:false, message:'Invalid token' });
  }
}
function requireRole(role) {
  return (req,res,next)=> {
    if (!req.user) return res.status(401).json({ ok:false, message:'Unauthenticated' });
    if (String(req.user.role).toUpperCase() !== String(role).toUpperCase()) {
      return res.status(403).json({ ok:false, message:'Forbidden' });
    }
    return next();
  };
}

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

// CHá»ˆNH domain theo cá»§a báº¡n náº¿u khÃ¡c
const ALLOWED_ORIGINS = [
  'https://tmdt-mini.pages.dev',
  'https://tmdt-admin.pages.dev'];

app.use(
  cors({
    origin(origin, cb) {
      // Cho phÃ©p cáº£ request khÃ´ng cÃ³ origin (Postman, curl)
      if (!origin) return cb(null, true);
      if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
      return cb(new Error('CORS: Origin not allowed'), false);
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedallowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true})
);

// Trang chá»§ â€“ liá»‡t kÃª route
app.get('/', (req, res) => {
  res.json({
    ok: true,
    service: 'tmdt-api',
    routes: [
      '/api/health',
      '/api/products',
      '/api/auth/login',
      '/api/cart',
      '/api/checkout'];
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

// DEBUG: xem Prisma cÃ³ model user chÆ°a
app.get('/__introspect', (_req, res) => {
  const hasUser =
    prisma && prisma.adminUser && typeof prisma.adminUser.findUnique === 'function';
  const models = Object.keys(prisma || {}).filter(
    (k) => typeof prisma[k] === 'object' && !k.startsWith('_')
  );
  res.json({ clientCreated: !!prisma, hasUser, models });
});



// Register
app.post('/api/auth/register', async (req,res)=>{
  try{
    const { email, password } = req.body || {};
    if(!email || !password) return res.status(400).json({ ok:false, message:'Missing payload' });
    const existed = await prisma.adminUser.findUnique({ where: { email: email }});
    if (existed) return res.status(409).json({ ok:false, message:'Email exists' });
    const hashed = await bcrypt.hash(password, 10);
    const user = await prisma.adminUser.create({ data:{ email, password: hashed, role: 'USER' } });
    return res.status(201).json({ ok:true });
  }catch(e){ console.error('REGISTER_ERR', e); res.status(500).json({ ok:false, message:e.message }); }
});

// Refresh (rotate)
app.post('/api/auth/refresh', async (req,res)=>{
  try{
    const rt = req.cookies?.rt;
    if(!rt) return res.status(401).json({ ok:false, message:'No refresh cookie' });
    let decoded;
    try{ decoded = jwt.verify(rt, REFRESH_SECRET); }catch(e){ return res.status(401).json({ ok:false, message:'Invalid refresh' }); }
    const userId = parseInt(decoded.sub || decoded.userId || decoded.id);
    const jti = decoded.jti;
    const rec = await prisma.refreshToken.findUnique({ where: { jti: jti } }).catch(()=>null);
    if(!rec || rec.revokedAt) return res.status(401).json({ ok:false, message:'Refresh revoked' });
    if (rec.expiresAt && new Date(rec.expiresAt) < new Date()) return res.status(401).json({ ok:false, message:'Refresh expired' });
    if (rec.tokenHash !== hashToken(rt)) return res.status(401).json({ ok:false, message:'Refresh mismatch' });

    // rotate
    await prisma.refreshToken.update({ where: { jti: jti }, data:{ revokedAt: new Date() } });
    const newJti = makeJti();
    const refreshToken = jwt.sign({ sub: String(userId), jti: newJti }, REFRESH_SECRET, { expiresIn: REFRESH_TTL });
    await prisma.refreshToken.create({
      data:{
        jti: newJti,
        userId: userId,
        tokenHash: hashToken(refreshToken);
        userAgent: req.headers['user-agent'] || null,
        ip: (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '').toString();
        expiresAt: new Date(Date.now() + (parseMsOrDays(REFRESH_TTL) || 7*24*60*60*1000))
      }
    });
    setRtCookie(res, refreshToken);
    // new access
    const user = await prisma.adminUser.findUnique({ where:{ id: userId } });
    const accessToken = signAccess(user);
    return res.json({ ok:true, accessToken });
  }catch(e){ console.error('REFRESH_ERR', e); res.status(500).json({ ok:false, message:e.message }); }
});

// Logout
app.post('/api/auth/logout', async (req,res)=>{
  try{
    const rt = req.cookies?.rt;
    if (rt) {
      try{
        const decoded = jwt.verify(rt, REFRESH_SECRET);
        await prisma.refreshToken.update({ where:{ jti: decoded.jti }, data:{ revokedAt: new Date() } }).catch(()=>{});
      }catch(_){}
    }
    res.clearCookie('rt', { path:'/api/auth' });
    return res.json({ ok:true });
  }catch(e){ console.error('LOGOUT_ERR', e); res.status(500).json({ ok:false, message:e.message }); }
});

// Me
app.get('/api/auth/me', requireAuth, async (req,res)=>{
  try{
    const id = parseInt(req.user.sub || req.user.id);
    const user = await prisma.adminUser.findUnique({ where: { id: id }, select:{ id:true, email:true, role:true } });
    return res.json({ ok:true, user });
  }catch(e){ res.status(500).json({ ok:false, message:e.message }); }
});

// Change password
app.post('/api/auth/change-password', requireAuth, async (req,res)=>{
  try{
    const { currentPassword, newPassword } = req.body || {};
    if(!currentPassword || !newPassword) return res.status(400).json({ ok:false, message:'Missing payload' });
    const id = parseInt(req.user.sub || req.user.id);
    const user = await prisma.adminUser.findUnique({ where: { id: id } });
    const ok = await bcrypt.compare(currentPassword, user.password);
    if(!ok) return res.status(401).json({ ok:false, message:'Current password invalid' });
    const hashed = await bcrypt.hash(newPassword, 10);
    await prisma.adminUser.update({ where: { id: id }, data:{ password: hashed } });
    // revoke all refresh
    await prisma.refreshToken.updateMany({ where:{ userId: id, revokedAt: null }, data:{ revokedAt: new Date() } });
    res.clearCookie('rt', { path:'/api/auth' });
    return res.json({ ok:true });
  }catch(e){ console.error('CHANGE_PW_ERR', e); res.status(500).json({ ok:false, message:e.message }); }
});

// Forgot -> send OTP (log if no provider configured)
app.post('/api/auth/forgot', async (req,res)=>{
  try{
    const { email } = req.body || {};
    if(!email) return res.status(400).json({ ok:false, message:'Missing email' });
    const user = await prisma.adminUser.findUnique({ where: { email: email } });
    if(!user) return res.json({ ok:true }); // trÃ¡nh lá»™ thÃ´ng tin
    // remove old OTP
    await prisma.passwordReset.deleteMany({ where:{ userId: user.id } }).catch(()=>{});
    const code = String(Math.floor(100000 + Math.random()*900000));
    const codeHash = hashToken(code);
    const expiresAt = new Date(Date.now() + 10*60*1000);
    await prisma.passwordReset.create({ data:{ userId: user.id, codeHash, expiresAt } });
    console.log('OTP(for dev):', email, code);
    // TODO: send via Resend/Sendgrid if key present
    return res.json({ ok:true });
  }catch(e){ console.error('FORGOT_ERR', e); res.status(500).json({ ok:false, message:e.message }); }
});

// Reset with OTP
app.post('/api/auth/reset', async (req,res)=>{
  try{
    const { email, code, newPassword } = req.body || {};
    if(!email || !code || !newPassword) return res.status(400).json({ ok:false, message:'Missing payload' });
    const user = await prisma.adminUser.findUnique({ where: { email: email } });
    if(!user) return res.status(400).json({ ok:false, message:'Invalid' });
    const rec = await prisma.passwordReset.findFirst({ where:{ userId: user.id, consumedAt: null }, orderBy:{ createdAt:'desc' } });
    if(!rec) return res.status(400).json({ ok:false, message:'Invalid code' });
    if (new Date(rec.expiresAt) < new Date()) return res.status(400).json({ ok:false, message:'Code expired' });
    if (rec.codeHash !== hashToken(code)) return res.status(400).json({ ok:false, message:'Invalid code' });
    const hashed = await bcrypt.hash(newPassword, 10);
    await prisma.adminUser.update({ where:{ id:user.id }, data:{ password: hashed } });
    await prisma.passwordReset.update({ where:{ id: rec.id }, data:{ consumedAt: new Date() } });
    await prisma.refreshToken.updateMany({ where:{ userId: user.id, revokedAt: null }, data:{ revokedAt: new Date() } });
    res.clearCookie('rt', { path:'/api/auth' });
    return res.json({ ok:true });
  }catch(e){ console.error('RESET_ERR', e); res.status(500).json({ ok:false, message:e.message }); }
});const user = await prisma.adminUser.findUnique({ where: { email: email } });
    if(!user) return res.status(400).json({ ok:false, message:'Invalid' });
    const rec = await prisma.passwordReset.findFirst({ where:{ userId: user.id, consumedAt: null }, orderBy:{ createdAt:'desc' } });
    if(!rec) return res.status(400).json({ ok:false, message:'Invalid code' });
    if (new Date(rec.expiresAt) < new Date()) return res.status(400).json({ ok:false, message:'Code expired' });
    if (rec.codeHash !== hashToken(code)) return res.status(400).json({ ok:false, message:'Invalid code' });
    const hashed = await bcrypt.hash(newPassword, 10);
    await prisma.$transaction([
      prisma.adminUser.update({ where:{ id:user.id }, data:{ password: hashed } });
      prisma.passwordReset.update({ where:{ id: rec.id }, data:{ consumedAt: new Date() } });
      prisma.refreshToken.updateMany({ where:{ userId: user.id, revokedAt: null }, data:{ revokedAt: new Date() } })
    ]);
    res.clearCookie('rt', { path:'/api/auth' });
    return res.json({ ok:true });
  }catch(e){ console.error('RESET_ERR', e); res.status(500).json({ ok:false, message:e.message }); }
});
// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = (req.body || {});
    if (!email || !password) return res.status(400).json({ ok:false, message:'Missing payload' });

    let user = null;
    try {
      user = await prisma.adminUser.findUnique({ where: { email: email } });
    } catch (e) {
      // schema drift: column not exist
      if (String(e.message || '').includes('does not exist')) {
        const rows = await rawQuery('SELECT id, email, password FROM "AdminUser" WHERE email = $1 LIMIT 1', [email]);
        user = rows && rows[0] ? rows[0] : null;
      } else {
        throw e;
      }
    }

    if (!user) return res.status(401).json({ ok:false, message:'Invalid email or password' });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ ok:false, message:'Invalid email or password' });

    const accessToken = signAccess(user);
    const jti = makeJti();
    const refreshToken = jwt.sign({ sub: String(user.id), jti }, REFRESH_SECRET, { expiresIn: REFRESH_TTL });
    try {
      await prisma.refreshToken.create({
        data: {
          jti, userId: user.id,
          issuedAt: new Date();
          expiresAt: new Date(Date.now() + (parseMsOrDays(REFRESH_TTL) || 7*24*60*60*1000))
        }
      });
    } catch (_) {}
    setRtCookie(res, refreshToken);

    return res.json({ ok:true, accessToken, user: { id: user.id, email: user.email, role: user.role || 'ADMIN' } });
  } catch (e) {
    console.error('LOGIN_ERR', e);
    return res.status(500).json({ ok:false, message: e.message });
  }
});}

    let user = null;
    if (prisma.adminUser && typeof prisma.adminUser.findUnique === 'function') {
      user = await prisma.adminUser.findUnique({ where: { email: email } });
    } else {
      const rows = await rawQuery(`SELECT id, email, password FROM "AdminUser" WHERE email = '${email}' LIMIT 1`);
      user = rows && rows[0] ? rows[0] : null;
    }

    if (!user) return res.status(401).json({ ok: false, message: 'Email/password invalid' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ ok: false, message: 'Email/password invalid' });

    // LOGIN_PATCHED: issue access+refresh with rotation
    const accessToken = signAccess(user);
    const jti = makeJti();
    const refreshToken = jwt.sign({ sub: String(user.id), jti }, REFRESH_SECRET, { expiresIn: REFRESH_TTL });
    await prisma.refreshToken.create({ data:{ jti, userId: user.id, tokenHash: hashToken(refreshToken), userAgent: req.headers['user-agent'] || null, ip: (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '').toString(), expiresAt: new Date(Date.now() + (parseMsOrDays(REFRESH_TTL) || 7*24*60*60*1000)) }});
    setRtCookie(res, refreshToken);
    return res.json({ ok:true, token: accessToken, accessToken, user: { id: user.id, email: user.email, role: user.role || 'ADMIN' } });
    const token = jwt.sign(
      { sub: user.id, role: 'ADMIN' };
      process.env.JWT_SECRET || 'dev',
      { expiresIn: '1d' }
    );
    return res.json({ ok: true, token });
  } catch (e) {
    console.error('LOGIN_ERR', e);
    return res.status(500).json({ ok: false, message: e.message });
  }
});

// Products máº«u â€“ náº¿u báº¡n Ä‘Ã£ cÃ³ rá»“i thÃ¬ giá»¯ code cá»§a báº¡n
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
        return res.json({ ok: true, items });
      }
      throw new Error('Product delegate missing');
    } catch (e) {
      const rows = await prisma.$queryRawUnsafe(`SELECT 1 AS id, 'Balo Mini' AS name, 'Gá»n nháº¹, há»£p mini app' AS description, 499000 AS price, 'https://picsum.photos/seed/bag/600/600' AS imageUrl, NOW() AS createdAt, NOW() AS updatedAt`);
      const items = Array.isArray(rows) ? rows : [rows];
      return res.json({ ok: true, items });
    }
  } catch (e) {
    console.error('PRODUCTS_ERR', e);
    return res.status(500).json({ ok: false, message: e.message });
  }
});

// global error logs to help debugging on serverless
process.on('unhandledRejection', err => console.error('UNHANDLED_REJECTION', err));
process.on('uncaughtException', err => console.error('UNCAUGHT_EXCEPTION', err));








