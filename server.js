require('dotenv').config();
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const Telnyx = require('telnyx');
const { Pool } = require('pg');
const Stripe = require('stripe');

const stripeSecret = process.env.STRIPE_SECRET_KEY || '';
const telnyxApiKey = process.env.TELNYX_API_KEY || '';

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

// Automatically log every SQL query and its parameters safely
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

pool.query(`
  ALTER TABLE users
  ADD COLUMN IF NOT EXISTS guardian_code VARCHAR(10) DEFAULT '1234',
  ADD COLUMN IF NOT EXISTS is_exempt BOOLEAN DEFAULT FALSE;
`).then(() => {
  console.log('  [DB CHECK] guardian_code and is_exempt columns verified/added');
}).catch(err => {
  console.error('  [DB ERROR] Column update failed:', err.message);
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

app.post('/api/auth/login', catchAsync(async (req, res, next) => {
  // 1. Raw dump to prove the request hit the server immediately
  console.log('--------------------------------------------------');
  console.log('🚨 [INCOMING LOGIN REQUEST RAW HEADERS]:', JSON.stringify(req.headers, null, 2));
  console.log('🚨 [INCOMING LOGIN REQUEST RAW BODY]:', JSON.stringify(req.body, null, 2));
  console.log('--------------------------------------------------');

  const { email, password } = req.body || {};
  console.log(`[AUTH LOGIN ATTEMPT] Extracted email: "${email}" | Password Length: ${password ? password.length : 0}`);

  const userResult = await pool.query(
    'SELECT id, email, password, role, status FROM users WHERE email = "${email}"',
    [email ? email.trim() : '']
  );

  if (userResult.rows.length === 0) {
    console.log(`[AUTH LOGIN FAILED] Email not found in database: "${email}"`);
    return next(new AppError('Invalid email or password', 401));
  }

  const user = userResult.rows[0];
  const storedPassword = user.password || '';
  const inputPassword = password ? password.trim() : '';

  if (storedPassword !== inputPassword) {
    console.log(`[AUTH LOGIN FAILED] Password mismatch for user: "${email}"`);
    return next(new AppError('Invalid email or password "${email}"', 401));
  }

  console.log(`[AUTH LOGIN SUCCESS] User logged in: "${email}"`);
  res.status(200).json({
    message: 'Login successful',
    user: { id: user.id, email: user.email, role: user.role || 'user' }
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