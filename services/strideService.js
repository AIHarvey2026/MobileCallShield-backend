const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function fetchAndStoreStrideStats() {
  const STRIDE_API_URL = process.env.STRIDE_API_URL || 'https://api.stride.is/v1/endpoint';
  const STRIDE_API_TOKEN = process.env.STRIDE_API_TOKEN;

  try {
    const response = await fetch(STRIDE_API_URL, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${STRIDE_API_TOKEN}`,
        'Content-Type': 'application/json'
      }
    });

    if (!response.ok) {
      throw new Error(`Stride API error: ${response.statusText}`);
    }

    const data = await response.json();
    const records = Array.isArray(data) ? data : (data.items || [data]);

    for (const record of records) {
      const recordId = record.id || record.record_id;
      if (!recordId) continue;

      const query = `
        INSERT INTO stride_stat_data (record_id, payload_data, status, updated_at)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (record_id) DO UPDATE SET
          payload_data = EXCLUDED.payload_data,
          status = EXCLUDED.status,
          updated_at = NOW();
      `;

      await pool.query(query, [
        String(recordId),
        JSON.stringify(record),
        record.status || 'active'
      ]);
    }

    console.log(`✅ Synced ${records.length} records to stride_stat_data table.`);
  } catch (error) {
    console.error('❌ Error syncing Stride stats data:', error);
  }
}

async function getStrideStatsSummary() {
  const query = `
    SELECT 
      DATE_TRUNC('week', created_at) AS week_start,
      COUNT(*) AS total_records,
      status
    FROM stride_stat_data
    GROUP BY week_start, status
    ORDER BY week_start DESC;
  `;

  try {
    const { rows } = await pool.query(query);
    return rows;
  } catch (error) {
    console.error('❌ Error fetching stride_stat_data summary:', error);
    throw error;
  }
}

module.exports = {
  fetchAndStoreStrideStats,
  getStrideStatsSummary
};
