-- Create Role enum if not exists
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'Role') THEN
        CREATE TYPE "Role" AS ENUM ('ADMIN', 'USER');
    END IF;
END $$;

-- Add role column if not exists
DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'AdminUser' AND column_name = 'role'
    ) THEN
        ALTER TABLE "AdminUser" ADD COLUMN "role" "Role" NOT NULL DEFAULT 'USER';
    END IF;
END $$;

-- Optional: set admin user role to ADMIN by email (adjust if needed)
UPDATE "AdminUser" SET "role" = 'ADMIN' WHERE email = 'admin@demo.com';