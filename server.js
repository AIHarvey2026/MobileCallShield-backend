require('dotenv').config();
// Automatically check and create tables when the server starts up
require('./init-db.js');
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const Telnyx = require('telnyx');
const { Pool } = require('pg');
const Stripe = require('stripe');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

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

// Verify contacts table with UUID user_id
pool.query(`
  CREATE TABLE IF NOT EXISTS contacts (
    id SERIAL PRIMARY KEY,
    user_id UUID NOT NULL,
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

// Get App Configuration & Branding Endpoint (GET)
app.get('/api/config', catchAsync(async (req, res, next) => {
    const result = await pool.query('SELECT app_name, support_email, support_phone, logo_url FROM app_settings LIMIT 1');
   
    res.status(200).json({
        success: true,
        config: result.rows[0] || {}
    });
}));

// Save / Update Identity Contacts Endpoint (POST)
app.post('/api/contacts', catchAsync(async (req, res, next) => {
  const bodyUserId = req.body?.userId || req.body?.user_id;
  const { caller_number, pin_code, is_allowed } = req.body || {};

  if (!bodyUserId) {
    return next(new AppError('User ID is required', 400));
  }

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

// Get Contacts Endpoint (GET)
app.get('/api/contacts', catchAsync(async (req, res, next) => {
    const userId = req.query.userId;
    
    if (!userId) {
        return next(new AppError('Missing userId parameter', 400));
    }

    const result = await pool.query(
        "SELECT * FROM contacts WHERE user_id = $1",
        [userId]
    );

    res.status(200).json({
        contacts: result.rows || []
    });
}));

// Get signed phone number

app.post('/api/preferences', async (req, res) => {
  const { userId, forwardingNumber } = req.body;

  if (!userId || !forwardingNumber) {
    return res.status(400).json({ error: 'User ID and forwarding number are required' });
  }

  try {
    // 1. Update the user's personal forwarding number in the users table
    await pool.query(
      'UPDATE users SET owner_phone = $1 WHERE id = $2',
      [forwardingNumber, userId]
    );

    // 2. Check if this user already has an assigned shield number
    let phoneResult = await pool.query(
      'SELECT shield_number FROM phone_numbers WHERE user_id = $1 LIMIT 1',
      [userId]
    );

    let assignedShieldNumber = phoneResult.rows[0]?.shield_number;

    // 3. If they don't have one yet, grab an unassigned number from the pool
    if (!assignedShieldNumber) {
      const poolResult = await pool.query(
        `SELECT id, shield_number FROM phone_numbers 
         WHERE status = 'unassigned' AND user_id IS NULL 
         LIMIT 1 FOR UPDATE`
      );

      if (poolResult.rows.length === 0) {
        return res.status(400).json({ error: 'No available phone numbers left in the pool.' });
      }

      assignedShieldNumber = poolResult.rows[0].shield_number;

      // Assign it to this user
      await pool.query(
        `UPDATE phone_numbers 
         SET status = 'assigned', user_id = $1, assigned_at = CURRENT_TIMESTAMP 
         WHERE shield_number = $2`,
        [userId, assignedShieldNumber]
      );
      
      console.log(`[POOL] Assigned ${assignedShieldNumber} to user ${userId}`);
    }

    res.status(200).json({
      success: true,
      message: 'Preferences saved and shield number assigned successfully',
      shield_number: assignedShieldNumber
    });

  } catch (err) {
    console.error('[PREFERENCES ERROR]', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});


// 1. Initial Voice Webhook when someone calls a user's assigned Shield number
app.post('/api/twilio/voice', async (req, res) => {
  const twml = new twilio.twiml.VoiceResponse();
  const callerNumber = req.body.From;
  const calledNumber = req.body.To; // This is the user's assigned shield_number

  console.log(`[TWILIO VOICE] Incoming call from ${callerNumber} to Shield number ${calledNumber}`);

  try {
    // 1. Find which user owns this shield number and get their forwarding number (owner_phone)
    const userResult = await pool.query(
      `SELECT u.id as user_id, u.owner_phone 
       FROM phone_numbers p
       JOIN users u ON p.user_id = u.id
       WHERE p.shield_number = $1 AND p.status = 'assigned'
       LIMIT 1`,
      [calledNumber]
    );

    if (userResult.rows.length === 0) {
      console.log(`[TWILIO VOICE ERROR] Shield number ${calledNumber} not found or unassigned.`);
      twml.say('This number is not active. Goodbye.');
      twml.hangup();
      res.type('text/xml');
      return res.send(twml.toString());
    }

    const { user_id, owner_phone } = userResult.rows[0];

    if (!owner_phone) {
      console.log(`[TWILIO VOICE ERROR] User ${user_id} has no forwarding number set.`);
      twml.say('The owner of this line has not configured their forwarding number yet. Please try again later.');
      twml.hangup();
      res.type('text/xml');
      return res.send(twml.toString());
    }

    // 2. Check if this caller is allowed for this specific user
    const contactResult = await pool.query(
      'SELECT * FROM contacts WHERE user_id = $1 AND caller_number = $2 AND is_allowed = TRUE LIMIT 1',
      [user_id, callerNumber]
    );

    if (contactResult.rows.length > 0) {
      console.log(`[TWILIO VOICE] Trusted caller ${callerNumber} for user ${user_id}. Forwarding to ${owner_phone}.`);
      twml.dial(owner_phone);
    } else {
      console.log(`[TWILIO VOICE] Unknown caller ${callerNumber} for user ${user_id}. Prompting for PIN.`);
      const gather = twml.gather({
        numDigits: 4,
        action: `/api/twilio/verify-pin?userId=${user_id}&ownerPhone=${encodeURIComponent(owner_phone)}`,
        method: 'POST',
        timeout: 10
      });
      gather.say('Please enter your secret 4-digit PIN code to connect to this line.');

      twml.say('We did not receive any input. Please leave a message after the tone.');
      twml.record({
        action: '/api/twilio/handle-voicemail',
        method: 'POST',
        transcribe: true,
        maxLength: 120
      });
    }
  } catch (err) {
    console.error('[TWILIO VOICE ERROR]', err.message);
    twml.say('An error occurred. Please try again later.');
  }

  res.type('text/xml');
  res.send(twml.toString());
});

// 2. PIN Verification Route
app.post('/api/twilio/verify-pin', async (req, res) => {
  const twml = new twilio.twiml.VoiceResponse();
  const enteredPin = req.body.Digits;
  const callerNumber = req.body.From;
  const userId = req.query.userId;
  const ownerPhone = req.query.ownerPhone;

  console.log(`[TWILIO PIN] Caller ${callerNumber} entered PIN: ${enteredPin} for user ${userId}`);

  try {
    const matchResult = await pool.query(
      'SELECT * FROM contacts WHERE user_id = $1 AND caller_number = $2 AND pin_code = $3 LIMIT 1',
      [userId, callerNumber, enteredPin]
    );

    if (matchResult.rows.length > 0) {
      const contact = matchResult.rows[0];
      await pool.query('UPDATE contacts SET is_allowed = TRUE WHERE id = $1', [contact.id]);

      console.log(`[TWILIO PIN SUCCESS] Valid PIN for ${callerNumber}. Connecting call to ${ownerPhone}.`);
      twml.say('PIN verified successfully. Connecting your call now.');
      twml.dial(ownerPhone);
    } else {
      console.log(`[TWILIO PIN FAILED] Invalid PIN entered by ${callerNumber}. Redirecting to voicemail.`);
      twml.say('Incorrect PIN code. Please leave a message after the tone.');
      twml.record({
        action: '/api/twilio/handle-voicemail',
        method: 'POST',
        transcribe: true,
        maxLength: 120
      });
    }
  } catch (err) {
    console.error('[TWILIO PIN ERROR]', err.message);
    twml.say('An error occurred processing your code.');
  }

  res.type('text/xml');
  res.send(twml.toString());
});

// 3. Voicemail Handler Route
app.post('/api/twilio/handle-voicemail', async (req, res) => {
  const twml = new twilio.twiml.VoiceResponse();
  const recordingUrl = req.body.RecordingUrl;
  const transcription = req.body.TranscriptionText || 'No transcription available';
  const callerNumber = req.body.From;

  console.log(`[TWILIO VOICEMAIL] Received from ${callerNumber}. Recording URL: ${recordingUrl}`);
  console.log(`[TWILIO VOICEMAIL TRANSCRIPT] ${transcription}`);

  twml.say('Thank you. Your message has been recorded. Goodbye.');
  twml.hangup();

  res.type('text/xml');
  res.send(twml.toString());
});

//UptimeRobot Health check
app.get('/api/health', (req, res) => {
    res.status(200).json({ status: 'healthy', timestamp: new Date() });
});


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