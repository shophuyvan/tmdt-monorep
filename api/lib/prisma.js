// api/lib/prisma.js
const { PrismaClient } = require('@prisma/client');

let prisma;
if (!global._prisma) {
  prisma = new PrismaClient({
    log: ['warn', 'error'],
  });
  if (process.env.NODE_ENV !== 'production') {
    global._prisma = prisma;
  }
} else {
  prisma = global._prisma;
}

module.exports = prisma;


