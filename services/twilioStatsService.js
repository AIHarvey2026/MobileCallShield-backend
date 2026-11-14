const twilio = require('twilio');
const { Pool } = require('pg');

const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function fetchAndStoreTwilioCalls(limit = 100) {
  try {
    const calls = await client.calls.list({ limit });

    for (const call of calls) {
      const cost = Math.abs(parseFloat(call.price || 0));
      const duration = parseInt(call.duration || 0, 10);

      const query = `
        INSERT INTO twilio_call_stats (call_sid, from_number, to_number, direction, duration_seconds, cost_usd, status)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (call_sid) DO UPDATE SET
          duration_seconds = EXCLUDED.duration_seconds,
          cost_usd = EXCLUDED.cost_usd,
          status = EXCLUDED.status;
      `;

      await pool.query(query, [
        call.sid,
        call.from,
        call.to,
        call.direction,
        duration,
        cost,
        call.status
      ]);
    }
    console.log(`✅ Synced ${calls.length} Twilio call logs to database.`);
  } catch (error) {
    console.error('❌ Error syncing Twilio call stats:', error);
  }
}

async function getWeeklyStatsPerNumber(phoneNumber) {
  const query = `
    SELECT 
      DATE_TRUNC('week', created_at) AS week_start,
      COUNT(*) AS total_calls,
      SUM(CEIL(duration_seconds / 60.0)) AS total_billed_minutes,
      SUM(cost_usd) AS total_weekly_cost,
      ROUND(AVG(cost_usd), 4) AS avg_cost_per_call
    FROM twilio_call_stats
    WHERE from_number = $1 OR to_number = $1
    GROUP BY week_start
    ORDER BY week_start DESC;
  `;

  try {
    const { rows } = await pool.query(query, [phoneNumber]);
    return rows;
  } catch (error) {
    console.error('❌ Error fetching weekly stats:', error);
    throw error;
  }
}

module.exports = {
  fetchAndStoreTwilioCalls,
  getWeeklyStatsPerNumber
};
