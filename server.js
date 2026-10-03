require('dotenv').config();
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const Telnyx = require('telnyx');
const { Pool } = require('pg');
const Stripe = require('stripe');

const stripeSecret = process.env.STRIPE_SECRET_KEY || '';
const telnyxApiKey = process.env.TELNYX_API_KEY || '';

const stripe = Stripe(stripeSecret);
const telnyxClient = new Telnyx({ apiKey: telnyxApiKey });

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Initialize PostgreSQL Connection Pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Configuration Defaults
const OWNER_PHONE_NUMBER = process.env.OWNER_PHONE_NUMBER || '+18324254469';
const SHIELD_PHONE_NUMBER = process.env.SHIELD_PHONE_NUMBER || '+13466036303';
const BASE_URL = process.env.RENDER_EXTERNAL_URL || 'https://mobile-call-shield.onrender.com';

// -------------------------------------------------------------
// GLOBAL MIDDLEWARE (Must be placed before routes to parse Telnyx form data)
// -------------------------------------------------------------
app.use(express.urlencoded({ extended: true }));

// -------------------------------------------------------------
// 1. STRIPE WEBHOOK ROUTE (Uses raw body)
// -------------------------------------------------------------
app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  // ... (stripe logic remains identical)
});

// JSON parser for rest of JSON endpoints
app.use(express.json());

// -------------------------------------------------------------
// 2. TELNYX INBOUND VOICE ROUTES (TeXML Flow)
// -------------------------------------------------------------
app.post('/voice', async (req, res) => {
  // Ensure we capture parameters regardless of casing or request content-type
  const calledNumber = req.body?.To || req.body?.to || req.body?.data?.payload?.to || SHIELD_PHONE_NUMBER;
  const callerNumber = req.body?.From || req.body?.from || req.body?.data?.payload?.from || 'Unknown';

  console.log(`[VOICE] Incoming call To: ${calledNumber} | From: ${callerNumber}`);
  res.type('text/xml');

  try {
    const userResult = await pool.query(
      `SELECT user_id FROM phone_numbers WHERE shield_number = $1 AND status = 'assigned'`,
      [calledNumber]
    );

    if (userResult.rows.length === 0) {
      console.log(`[UNASSIGNED NUMBER] No active account for ${calledNumber}`);
      const xmlResponse = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Say voice="Polly.Joanna-Neural">This shield number is currently unassigned. Goodbye.</Say>
    <Hangup/>
</Response>`;
      return res.send(xmlResponse);
    }

    const userId = userResult.rows[0].user_id;

    const contactResult = await pool.query(
      `SELECT pin_code, is_allowed FROM contacts WHERE user_id = $1 AND caller_number = $2`,
      [userId, callerNumber]
    );

    if (contactResult.rows.length === 0) {
      console.log(`[VOICE] New caller ${callerNumber} -> Routing to /voice/setup`);
      const xmlResponse = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Gather input="dtmf" action="${BASE_URL}/voice/setup" method="POST" timeout="5" numDigits="4" finishOnKey="#">
        <Say voice="Polly.Joanna-Neural">
            Welcome to Mobile Call Shield. Please enter a 4-digit code on your keypad, followed by the pound key.
        </Say>
    </Gather>
    <Redirect method="POST">${BASE_URL}/voice/voicemail</Redirect>
</Response>`;
      return res.send(xmlResponse);
    }

    console.log(`[VOICE] Returning caller ${callerNumber} -> Routing to /voice/process`);
    const xmlResponse = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Gather input="dtmf" action="${BASE_URL}/voice/process" method="POST" timeout="5" numDigits="4" finishOnKey="#">
        <Say voice="Polly.Joanna-Neural">
            Thank you for calling Mobile Call Shield. Please enter your 4-digit code on your keypad now.
        </Say>
    </Gather>
    <Redirect method="POST">${BASE_URL}/voice/voicemail</Redirect>
</Response>`;
    return res.send(xmlResponse);

  } catch (err) {
    console.error('[VOICE DB ERROR]', err);
    const xmlResponse = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Say voice="Polly.Joanna-Neural">An error occurred while processing your call. Goodbye.</Say>
    <Hangup/>
</Response>`;
    return res.send(xmlResponse);
  }
});
