require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function initDB() {
  console.log('[DB INIT] Starting database table initialization...');

  try {
    // 1. Users Table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(20) DEFAULT 'user',
        status VARCHAR(20) DEFAULT 'trialing',
        owner_phone VARCHAR(20),
        trial_ends_at TIMESTAMP DEFAULT (CURRENT_TIMESTAMP + INTERVAL '14 days'),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log('  ✔ Created table: users');

    // 2. Phone Numbers Table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS phone_numbers (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        shield_number VARCHAR(20) UNIQUE NOT NULL,
        status VARCHAR(20) DEFAULT 'unassigned',
        user_id UUID REFERENCES users(id) ON DELETE SET NULL,
        assigned_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log('  ✔ Created table: phone_numbers');

    // 3. Contacts Table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS contacts (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        caller_number VARCHAR(20) NOT NULL,
        pin_code VARCHAR(10) NOT NULL,
        is_allowed BOOLEAN DEFAULT TRUE,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, caller_number)
      );
    `);
    console.log('  ✔ Created table: contacts');

    // 4. Subscriptions Table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS subscriptions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        stripe_customer_id VARCHAR(255),
        stripe_subscription_id VARCHAR(255),
        plan_tier VARCHAR(50) DEFAULT 'starter',
        status VARCHAR(50) DEFAULT 'trialing',
        current_period_end TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log('  ✔ Created table: subscriptions');

    console.log('[DB INIT] Database initialization complete!');
  } catch (err) {
    console.error('[DB INIT ERROR]', err.message);
  } finally {
    await pool.end();
  }
}

initDB();
