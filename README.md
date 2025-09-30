# TMĐT Monorepo (Mini/Admin/API)

**Hạ tầng đề xuất**
- FE: Cloudflare Pages (2 dự án riêng: `mini` và `admin`)
- API: Vercel serverless (thư mục `api/`)
- DB: Neon Postgres
- Storage: Cloudflare R2 (S3 compatible)
- Prisma ORM

## Cấu trúc
```
tmdt-monorepo/
  mini/            # Zalo Mini-like FE (React + Vite + Tailwind)
  admin/           # Admin FE (React + Vite + Tailwind + JWT)
  api/             # Express (serverless on Vercel) + Prisma + R2 upload
  postman/         # Postman collection
  .env.example     # Biến môi trường gợi ý (copy sang api/.env khi chạy local)
```
> Lưu ý: FE đọc biến `VITE_API_URL` (ví dụ: `https://your-vercel-app.vercel.app/api`)

---

## 1) Triển khai nhanh

### A. Database Neon Postgres
1. Tạo project trên [Neon.tech], lấy `DATABASE_URL` dạng:  
   `postgresql://user:password@host/db?sslmode=require`
2. (Tuỳ chọn) tạo DB `tmdt` rồi lấy connection string tương ứng.

### B. Cloudflare R2 (upload ảnh)
1. Tạo R2 bucket, bật S3 API, lấy:
   - `R2_ACCOUNT_ID`
   - `R2_ACCESS_KEY_ID`
   - `R2_SECRET_ACCESS_KEY`
   - `R2_BUCKET`
   - `R2_PUBLIC_BASE` (VD: `https://pub-xxxxxxxx.r2.dev` hoặc domain của bạn)
2. Bật public read cho bucket (hoặc qua domain proxy).

### C. API trên Vercel
1. Import thư mục `api/` làm dự án Vercel riêng.
2. Tại **Project Settings → Environment Variables**, đặt:
```
DATABASE_URL=... # from Neon
JWT_SECRET=changeme-supersecret
R2_ACCOUNT_ID=...
R2_ACCESS_KEY_ID=...
R2_SECRET_ACCESS_KEY=...
R2_BUCKET=...
R2_PUBLIC_BASE=... # optional for public URL generation
CORS_ORIGIN=*      # hoặc domain FE
```
3. Vào tab **Deployments**, Vercel sẽ `npm i` và sẵn sàng.
4. Chạy migration và seed (một lần):
   - Sử dụng **Vercel CLI** hoặc chạy local:
   ```bash
   # local (yêu cầu Node 18+)
   cd api
   cp .env.example .env
   # chỉnh .env với DATABASE_URL,R2,...
   npm i
   npx prisma migrate deploy
   node prisma/seed.js
   ```

### D. FE Mini và Admin trên Cloudflare Pages
Tạo 2 dự án riêng:
- **Project 1**: trỏ tới thư mục `mini/`
  - Build command: `npm run build`
  - Build output: `dist`
  - Vars: `VITE_API_URL = https://<YOUR-VERCEL-APP>.vercel.app/api`
- **Project 2**: trỏ tới thư mục `admin/`
  - Build command: `npm run build`
  - Build output: `dist`
  - Vars: `VITE_API_URL = https://<YOUR-VERCEL-APP>.vercel.app/api`

---

## 2) Prisma
Schema trong `api/prisma/schema.prisma`. Các model: `Product`, `AdminUser`, `Cart`, `CartItem`, `Order`, `OrderItem`.

Lệnh thường dùng:
```bash
cd api
npx prisma generate
npx prisma db push            # phát sinh bảng (dev nhanh)
# hoặc
npx prisma migrate dev --name init
```

Seed:
```bash
node prisma/seed.js
```

---

## 3) API chính
- `GET /api/health`
- `POST /api/auth/login` → JWT (admin@demo.com / admin123)
- `GET /api/products` / `GET /api/products/:id`
- `POST /api/cart` → tạo giỏ hàng (trả về `cartId`)
- `GET /api/cart/:cartId`
- `POST /api/cart/:cartId/items` ({ productId, qty })
- `POST /api/checkout` ({ cartId, name, phone, address }) → trả order + mock payment url
- `POST /api/webhooks/zalopay` (mock)
- `POST /api/webhooks/shipping` (mock GHN)
- `POST /api/upload` (multipart: file) → trả URL ảnh (R2). Yêu cầu Bearer JWT.

Xem thêm trong Postman collection (`postman/TMDT-Monorepo.postman_collection.json`).

---

## 4) FE (Mini)
- SPA, CSR, Tailwind + skeleton đơn giản.
- Trang: danh sách sản phẩm, chi tiết, giỏ hàng, thanh toán.

## 5) FE (Admin)
- Login (JWT) → CRUD sản phẩm, upload ảnh lên R2.

---

## 6) Biến môi trường

### Root `.env.example` (tham khảo)
```
# API
DATABASE_URL=postgresql://user:password@host/db?sslmode=require
JWT_SECRET=changeme-supersecret

# Cloudflare R2 (S3 compatible)
R2_ACCOUNT_ID=
R2_ACCESS_KEY_ID=
R2_SECRET_ACCESS_KEY=
R2_BUCKET=uploads
R2_PUBLIC_BASE=

# FE
VITE_API_URL=http://localhost:3000/api
CORS_ORIGIN=*
```

> Sao chép vào `api/.env` khi chạy local, FE dùng `mini/.env` và `admin/.env`.

---

## 7) Ghi chú
- Đây là scaffold **chạy được** tối thiểu cho demo/POC. Bạn có thể mở rộng: trạng thái thanh toán, phí ship thật, quản trị đơn hàng nâng cao, v.v.
- Webhook chỉ **mock** để test flow end-to-end.
