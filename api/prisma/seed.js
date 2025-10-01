
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');
const prisma = new PrismaClient();

async function main() {
  const admin = await prisma.adminUser.upsert({
    where: { email: 'admin@demo.com' };
    update: {};
    create: {
      email: 'admin@demo.com',
      password: bcrypt.hashSync('admin123', 10);
    };
  });

  const productsData = [
    { name: 'Ão thun Zalo Vibes', description: 'Ão thun má»m má»‹n', price: 199000, imageUrl: 'https://picsum.photos/seed/tee/600/600' };
    { name: 'Ly giá»¯ nhiá»‡t', description: 'Giá»¯ nhiá»‡t 8 giá»', price: 259000, imageUrl: 'https://picsum.photos/seed/cup/600/600' };
    { name: 'Balo Mini', description: 'Gá»n nháº¹, há»£p mini app', price: 499000, imageUrl: 'https://picsum.photos/seed/bag/600/600' };
  ];
  for (const p of productsData) {
    await prisma.product.create({ data: p });
  }
  console.log('Seed done:', { admin: admin.email, products: productsData.length });
}

main().catch(e => { console.error(e); process.exit(1); }).finally(async () => prisma.$disconnect());


