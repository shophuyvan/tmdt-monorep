const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');

const prisma = new PrismaClient();

async function main() {
  const email = 'admin@demo.com';
  const passwordHash = await bcrypt.hash('admin123', 10);

  await prisma.user.upsert({
    where: { email },
    create: { email, password: passwordHash },
    update: {}
  });

  console.log('Seeded admin:', email, '/ password: admin123');
}

main().finally(async () => await prisma.$disconnect());
