// api/lib/prisma.js
const { PrismaClient } = require('@prisma/client');

let prisma;

if (!global._prisma) {
  prisma = new PrismaClient({
    // Only log warnings and errors to avoid noisy output in production logs
    log: ['warn', 'error'],
  });
  // Cache the client in dev to prevent exhausting database connections
  if (process.env.NODE_ENV !== 'production') {
    global._prisma = prisma;
  }
} else {
  prisma = global._prisma;
}

module.exports = prisma;
