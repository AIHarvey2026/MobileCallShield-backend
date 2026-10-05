const { Pool } = require('pg');
const pool = new Pool({ 
  connectionString: "postgresql://shield_admin:4lzJQvoJ9Uw744Zz2sBFVDD0iprX4wgX@dpg-db0dfr6gekts73978prg-a.ohio-postgres.render.com/mobile_call_shield", 
  ssl: { rejectUnauthorized: false } 
});

async function run() {
  try {
    await pool.query("INSERT INTO phone_numbers (shield_number, status) VALUES ('+13466036303', 'unassigned') ON CONFLICT (shield_number) DO UPDATE SET status = 'unassigned', user_id = NULL;");
    console.log("SUCCESS: Shield number inserted into pool!");
  } catch (err) {
    console.error("ERROR:", err.message);
  } finally {
    process.exit(0);
  }
}
run();
