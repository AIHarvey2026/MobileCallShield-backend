require('dotenv').config();
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const Telnyx = require('telnyx');
const { Pool } = require('pg');
const Stripe = require('stripe');

const stripeSecret = process.env.STRIPE_SECRET_KEY || '';
const telnyxApiKey = process.env.TELNYX_API_KEY || '';
const twilio = require('twilio');

const stripe = stripeSecret ? Stripe(stripeSecret) : null;

let telnyxClient = null;
try {
  if (telnyxApiKey) {
    telnyxClient = new Telnyx(telnyxApiKey);
  }
} catch (e) {
  console.error('[TELNYX INIT ERROR]', e.message);
}

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// -------------------------------------------------------------
// 1. CENTRALIZED ERROR CLASSES & HELPERS
// -------------------------------------------------------------
class AppError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = true;
  }
}

const catchAsync = fn => {
  return (req, res, next) => {
    fn(req, res, next).catch(next);
  };
};

// -------------------------------------------------------------
// 2. DETAILED ULTRA-VERBOSE REQUEST & RESPONSE LOGGER
// -------------------------------------------------------------
app.use((req, res, next) => {
  const start = Date.now();

  let responseBody = '';
  const originalJson = res.json;
  res.json = function (body) {
    responseBody = body;
    return originalJson.apply(this, arguments);
  };

  res.on('finish', () => {
    const duration = Date.now() - start;

    const detailedLog = {
      timestamp: new Date().toISOString(),
      type: 'HTTP_TRANSACTION',
      method: req.method,
      path: req.path,
      status: res.statusCode,
      durationMs: duration,
      headers: {
        contentType: req.headers['content-type'],
        userAgent: req.headers['user-agent'],
        authorization: req.headers['authorization'] ? '[PRESENT]' : '[NONE]'
      },
      query: req.query,
      params: req.params,
      requestBody: req.body,
      responseSummary: responseBody
    };

    console.log(JSON.stringify(detailedLog, null, 2));
  });

  next();
});

// -------------------------------------------------------------
// 3. DATABASE CONNECTION & QUERY LOGGER
// -------------------------------------------------------------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const originalPoolQuery = pool.query;
pool.query = async (text, params) => {
  console.log(JSON.stringify({
    timestamp: new Date().toISOString(),
    type: 'DB_QUERY',
    query: typeof text === 'string' ? text.trim().replace(/\s+/g, ' ') : text,
    parameters: params || []
  }, null, 2));

  return originalPoolQuery.apply(pool, [text, params]);
};

// Verify/Add columns to users table
pool.query(`
  ALTER TABLE users
  ADD COLUMN IF NOT EXISTS guardian_code VARCHAR(10) DEFAULT '1234',
  ADD COLUMN IF NOT EXISTS is_allowed BOOLEAN DEFAULT FALSE;
`).then(() => {
  console.log('  [DB CHECK] guardian_code and is_allowed columns verified/added');
}).catch(err => {
  console.error('  [DB ERROR] Column update failed:', err.message);
});

// Create contacts table if it doesn't exist (Global Startup)
pool.query(`
  CREATE TABLE IF NOT EXISTS contacts (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    caller_number VARCHAR(50) NOT NULL,
    pin_code VARCHAR(20),
    is_allowed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
`).then(() => {
  console.log('  [DB CHECK] contacts table verified/created');
}).catch(err => {
  console.error('  [DB ERROR] Contacts table creation failed:', err.message);
});

const OWNER_PHONE_NUMBER = process.env.OWNER_PHONE_NUMBER || '+18324254469';
const SHIELD_PHONE_NUMBER = process.env.SHIELD_PHONE_NUMBER || '+13466036303';
const BASE_URL = process.env.RENDER_EXTERNAL_URL || 'https://mobilecallshield-backend.onrender.com';

app.use(express.urlencoded({ extended: true }));

// Stripe Webhook (Raw body)
app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  res.json({ received: true });
});

app.use(express.json());

// -------------------------------------------------------------
// 4. API ENDPOINTS WITH CENTRALIZED ERROR CATCHING
// -------------------------------------------------------------

app.get('/', (req, res) => {
  res.send('Mobile Call Shield Backend Active');
});

// Login Endpoint
app.post('/api/auth/login', catchAsync(async (req, res, next) => {
  console.log('--------------------------------------------------');
  console.log('🚨 [INCOMING LOGIN REQUEST RAW HEADERS]:', JSON.stringify(req.headers, null, 2));
  console.log('🚨 [INCOMING LOGIN REQUEST RAW BODY]:', JSON.stringify(req.body, null, 2));
  console.log('--------------------------------------------------');

  const { email, password } = req.body || {};
  if (!email || !password) {
    return next(new AppError('Email and password are required', 400));
  }

  console.log(`[AUTH LOGIN ATTEMPT] Extracted email: "${email}" | Password Length: ${password.length}`);

  const userResult = await pool.query(
    'SELECT id, email, password, role, status FROM users WHERE email = $1',
    [email.trim()]
  );

  if (userResult.rows.length === 0) {
    console.log(`[AUTH LOGIN FAILED] Email not found in database: "${email}"`);
    return next(new AppError('Invalid email or password', 401));
  }

  const user = userResult.rows[0];
  const storedPassword = user.password || '';
  const inputPassword = password.trim();

  if (storedPassword !== inputPassword) {
    console.log(`[AUTH LOGIN FAILED] Password mismatch for user: "${email}"`);
    return next(new AppError('Invalid email or password', 401));
  }

  console.log(`[AUTH LOGIN SUCCESS] User logged in: "${email}"`);
  res.status(200).json({
    message: 'Login successful',
    user: { id: user.id, email: user.email, role: user.role || 'user' }
  });
}));

// -------------------------------------------------------------
// Save / Update Identity Contacts Endpoint (POST)
// -------------------------------------------------------------
app.post('/api/contacts', catchAsync(async (req, res, next) => {
  const bodyUserId = req.body?.userId || req.body?.user_id;
  const { caller_number, pin_code, is_allowed } = req.body || {};

  if (!bodyUserId) {
    return next(new AppError('User ID is required', 400));
  }

  // Insert contact into PostgreSQL
  await pool.query(
    `INSERT INTO contacts (user_id, caller_number, pin_code, is_allowed) 
     VALUES ($1, $2, $3, $4)`,
    [bodyUserId, caller_number, pin_code, is_allowed || false]
  );

  console.log(`[CONTACTS SAVE] Saved contact ${caller_number} for user: ${bodyUserId}`);

  res.status(200).json({
    message: 'Contact saved successfully',
    status: 'success'
  });
}));

// -------------------------------------------------------------
// Get Contacts Endpoint (GET) - Fetches real contacts from DB
// -------------------------------------------------------------
app.get('/api/contacts/:userId', catchAsync(async (req, res, next) => {
  const { userId } = req.params;

  if (!userId) {
    return next(new AppError('User ID is required', 400));
  }

  const result = await pool.query(
    'SELECT caller_number, pin_code, is_allowed FROM contacts WHERE user_id = $1 ORDER BY id DESC',
    [userId]
  );

  console.log(`[CONTACTS FETCH] Found ${result.rows.length} contacts for user: ${userId}`);

  res.status(200).json({
    status: 'success',
    contacts: result.rows
  });
}));

// -------------------------------------------------------------
// 5. GLOBAL CENTRALIZED ERROR-HANDLING MIDDLEWARE (Must be last)
// -------------------------------------------------------------
app.use((err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || 'error';

  console.log(JSON.stringify({
    timestamp: new Date().toISOString(),
    level: 'FATAL_OR_OPERATIONAL_ERROR',
    path: req.path,
    method: req.method,
    statusCode: err.statusCode,
    message: err.message,
    stack: err.stack
  }, null, 2));

  res.status(err.statusCode).json({
    status: err.status,
    error: err.message,
    ...(process.env.NODE_ENV !== 'production' && { stack: err.stack })
  });
});

const PORT = process.env.PORT || 10000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});