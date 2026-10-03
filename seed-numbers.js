require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const numbersToSeed = [
  '+18005550199',
  '+18005550198',
  '+18005550197'
];

async function seedNumbers() {
  console.log('[SEED] Adding Telnyx numbers to inventory pool...');
  try {
    for (const number of numbersToSeed) {
      await pool.query(
        `INSERT INTO phone_numbers (shield_number, status)
         VALUES ($1, 'unassigned')
         ON CONFLICT (shield_number) DO NOTHING;`,
        [number]
      );
      console.log(`  ✔ Seeded number: ${number}`);
    }
    console.log('[SEED] Phone number pool ready!');
  } catch (err) {
    console.error('[FULL ERROR DETAILS]:\n', err);
  } finally {
    await pool.end();
  }
}

seedNumbers();
