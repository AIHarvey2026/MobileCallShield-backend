require('dotenv').config();
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const Telnyx = require('telnyx');
const { Pool } = require('pg');
const Stripe = require('stripe');

const stripeSecret = process.env.STRIPE_SECRET_KEY || '';
const telnyxApiKey = process.env.TELNYX_API_KEY || '';

// Safely initialize Stripe
const stripe = stripeSecret ? Stripe(stripeSecret) : null;

// Safely initialize Telnyx SDK
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

// Initialize PostgreSQL Connection Pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Ensure database columns are set up on server startup
pool.query(`
  ALTER TABLE users 
  ADD COLUMN IF NOT EXISTS guardian_code VARCHAR(10) DEFAULT '1234',
  ADD COLUMN IF NOT EXISTS is_exempt BOOLEAN DEFAULT FALSE;
`).then(() => {
  console.log('✅ [DB CHECK] guardian_code and is_exempt columns verified/added');
}).catch(err => {
  console.error('❌ [DB ERROR] Column update failed:', err.message);
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
  if (!stripe) {
    return res.status(500).send('Stripe is not configured.');
  }

  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    console.error('[STRIPE WEBHOOK ERROR] Signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  const client = await pool.connect();

  try {
    switch (event.type) {
      case 'checkout.session.completed':
      case 'customer.subscription.created': {
        const sessionOrSub = event.data.object;
        const customerEmail = sessionOrSub.customer_email || sessionOrSub.email;
        const stripeCustomerId = sessionOrSub.customer;
        const stripeSubId = sessionOrSub.subscription || sessionOrSub.id;

        console.log(`[STRIPE] New active subscription for: ${customerEmail}`);

        await client.query('BEGIN');

        const userRes = await client.query(
          `SELECT id FROM users WHERE email = $1;`,
          [customerEmail]
        );

        if (userRes.rows.length > 0) {
          const userId = userRes.rows[0].id;

          await client.query(
            `UPDATE users SET status = 'active' WHERE id = $1;`,
            [userId]
          );

          await client.query(
            `INSERT INTO subscriptions (user_id, stripe_customer_id, stripe_subscription_id, plan_tier, status)
             VALUES ($1, $2, $3, 'starter', 'active')
             ON CONFLICT (user_id) DO UPDATE 
             SET status = 'active', stripe_subscription_id = $3;`,
            [userId, stripeCustomerId, stripeSubId]
          );

          const existingNum = await client.query(
            `SELECT id FROM phone_numbers WHERE user_id = $1 AND status = 'assigned';`,
            [userId]
          );

          if (existingNum.rows.length === 0) {
            const numRes = await client.query(
              `SELECT id, shield_number FROM phone_numbers 
               WHERE status = 'unassigned' LIMIT 1 FOR UPDATE;`
            );

            if (numRes.rows.length > 0) {
              await client.query(
                `UPDATE phone_numbers 
                 SET status = 'assigned', user_id = $1, assigned_at = CURRENT_TIMESTAMP 
                 WHERE id = $2;`,
                [userId, numRes.rows[0].id]
              );
              console.log(`[PROVISION] Assigned ${numRes.rows[0].shield_number} to user ${userId}`);
            } else {
              console.warn(`[PROVISION WARNING] No unassigned numbers available in pool!`);
            }
          }
        }

        await client.query('COMMIT');
        break;
      }

      case 'customer.subscription.deleted': {
        const subscription = event.data.object;
        const stripeCustomerId = subscription.customer;

        console.log(`[STRIPE] Subscription canceled for customer: ${stripeCustomerId}`);

        await client.query('BEGIN');

        const subRes = await client.query(
          `SELECT user_id FROM subscriptions WHERE stripe_customer_id = $1;`,
          [stripeCustomerId]
        );

        if (subRes.rows.length > 0) {
          const userId = subRes.rows[0].user_id;

          const userCheck = await client.query(
            `SELECT is_exempt FROM users WHERE id = $1;`,
            [userId]
          );

          if (userCheck.rows.length > 0 && userCheck.rows[0].is_exempt) {
            console.log(`[STRIPE] User ${userId} is marked as exempt. Skipping status revocation.`);
          } else {
            await client.query(
              `UPDATE users SET status = 'canceled' WHERE id = $1;`,
              [userId]
            );

            await client.query(
              `UPDATE phone_numbers 
               SET status = 'unassigned', user_id = NULL, assigned_at = NULL 
               WHERE user_id = $1;`,
              [userId]
            );

            console.log(`[RECLAIM] Returned shield number for user ${userId} back to unassigned pool.`);
          }
        }

        await client.query('COMMIT');
        break;
      }

      default:
        console.log(`[STRIPE] Unhandled event type: ${event.type}`);
    }
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('[STRIPE WEBHOOK PROCESSING ERROR]', err.message);
  } finally {
    client.release();
  }

  res.json({ received: true });
});

// JSON parser for remaining API endpoints
app.use(express.json());

// -------------------------------------------------------------
// 2. Health Check & Config Endpoints
// -------------------------------------------------------------
app.get('/', (req, res) => {
  res.send('Mobile Call Shield Backend Active');
});

app.get('/api/shield-number', (req, res) => {
  res.json({ shieldNumber: SHIELD_PHONE_NUMBER });
});

// -------------------------------------------------------------
// 3. REST API ENDPOINTS FOR ANDROID APP & ADMIN
// -------------------------------------------------------------

app.post('/api/auth/register', async (req, res) => {
  const { email, password, owner_phone } = req.body;

  if (!email || !password || !owner_phone) {
    return res.status(400).json({ error: 'Email, password, and owner_phone are required.' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const userRes = await client.query(
      `INSERT INTO users (email, password_hash, owner_phone, status)
       VALUES ($1, $2, $3, 'trialing')
       RETURNING id, email, owner_phone, status, created_at;`,
      [email, password, owner_phone]
    );
    const user = userRes.rows[0];

    const numRes = await client.query(
      `SELECT id, shield_number FROM phone_numbers 
       WHERE status = 'unassigned' LIMIT 1 FOR UPDATE;`
    );

    let assignedNumber = null;
    if (numRes.rows.length > 0) {
      assignedNumber = numRes.rows[0].shield_number;
      await client.query(
        `UPDATE phone_numbers 
         SET status = 'assigned', user_id = $1, assigned_at = CURRENT_TIMESTAMP 
         WHERE id = $2;`,
        [user.id, numRes.rows[0].id]
      );
    }

    await client.query('COMMIT');

    res.status(201).json({
      message: 'User registered successfully',
      user: {
        id: user.id,
        email: user.email,
        ownerPhone: user.owner_phone,
        shieldNumber: assignedNumber
      }
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('[AUTH REGISTER ERROR]', err.message);
    if (err.code === '23505') {
      return res.status(400).json({ error: 'Email address is already registered.' });
    }
    res.status(500).json({ error: 'Internal server error during registration.' });
  } finally {
    client.release();
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};

  try {
    console.log(`[AUTH] Login attempt for: ${email}`);

    // Fetch user and check both password_hash and password columns for maximum database compatibility
    const userResult = await pool.query(
      'SELECT id, email, password_hash, password, role, status FROM users WHERE email = $1',
      [email ? email.trim() : '']
    );

    if (userResult.rows.length === 0) {
      console.log(`[AUTH] User not found: ${email}`);
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const user = userResult.rows[0];
    const storedPassword = user.password_hash || user.password || '';

    if (storedPassword !== (password ? password.trim() : '')) {
      console.log(`[AUTH] Invalid password attempt for: ${email}`);
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    console.log(`[AUTH] Login successful for: ${email}`);
    res.status(200).json({
      message: 'Login successful',
      user: { id: user.id, email: user.email, role: user.role || 'user' }
    });

  } catch (err) {
    console.error('❌ [AUTH LOGIN ERROR]:', err.message);
    console.error(err.stack);
    res.status(500).json({ 
      error: 'Internal Server Error', 
      details: err.message 
    });
  }
});

// Verify Guardian Unlock Code Endpoint
app.post('/api/verify-guardian-code', async (req, res) => {
  const { user_id, guardian_code } = req.body;

  if (!user_id || !guardian_code) {
    return res.status(400).json({ error: 'user_id and guardian_code are required' });
  }

  try {
    const result = await pool.query(
      'SELECT guardian_code FROM users WHERE id = $1',
      [user_id]
    );

    if (result.rows.length > 0 && result.rows[0].guardian_code === guardian_code) {
      res.status(200).json({ success: true, message: 'Unlocked successfully' });
    } else {
      res.status(401).json({ success: false, error: 'Invalid Guardian Code' });
    }
  } catch (err) {
    console.error('❌ [GUARDIAN CODE ERROR]:', err.message);
    res.status(500).json({ error: 'Server error', details: err.message });
  }
});

// Admin Toggle Family Exemption Endpoint
app.post('/api/admin/toggle-exempt', async (req, res) => {
  const { user_id, is_exempt } = req.body;

  if (!user_id || typeof is_exempt !== 'boolean') {
    return res.status(400).json({ error: 'user_id and is_exempt boolean are required' });
  }

  try {
    const newStatus = is_exempt ? 'active' : 'trialing';

    await pool.query(
      `UPDATE users 
       SET is_exempt = $1, status = $2 
       WHERE id = $3;`,
      [is_exempt, newStatus, user_id]
    );

    console.log(`[ADMIN] Set user ${user_id} exemption status to: ${is_exempt}`);
    res.status(200).json({ 
      success: true, 
      message: `User family exemption set to ${is_exempt}` 
    });
  } catch (err) {
    console.error('❌ [ADMIN EXEMPT ERROR]:', err.message);
    res.status(500).json({ error: 'Failed to update user exemption status.' });
  }
});

app.get('/api/contacts/:userId', async (req, res) => {
  const { userId } = req.params;

  try {
    const contactsRes = await pool.query(
      `SELECT id, caller_number, pin_code, is_allowed, updated_at 
       FROM contacts WHERE user_id = $1 
       ORDER BY updated_at DESC;`,
      [userId]
    );

    res.json({ contacts: contactsRes.rows });
  } catch (err) {
    console.error('[GET CONTACTS ERROR]', err.message);
    res.status(500).json({ error: 'Failed to fetch contacts.' });
  }
});

app.post('/api/contacts', async (req, res) => {
  let { user_id, caller_number, pin_code, is_allowed } = req.body;

  if (!user_id || !caller_number || !pin_code) {
    return res.status(400).json({ error: 'user_id, caller_number, and pin_code are required.' });
  }

  let cleanedNumber = caller_number.replace(/\D/g, '');
  if (cleanedNumber.length === 10) {
    cleanedNumber = `+1${cleanedNumber}`;
  } else if (!cleanedNumber.startsWith('+')) {
    cleanedNumber = `+${cleanedNumber}`;
  }

  try {
    const contactRes = await pool.query(
      `INSERT INTO contacts (user_id, caller_number, pin_code, is_allowed)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (user_id, caller_number)
       DO UPDATE SET pin_code = EXCLUDED.pin_code, 
                     is_allowed = EXCLUDED.is_allowed, 
                     updated_at = CURRENT_TIMESTAMP
       RETURNING *;`,
      [user_id, cleanedNumber, pin_code, is_allowed ?? true]
    );

    res.status(200).json({
      message: 'Contact updated successfully',
      contact: contactRes.rows[0]
    });
  } catch (err) {
    console.error('[SAVE CONTACT ERROR]', err.message);
    res.status(500).json({ error: 'Failed to save contact.', details: err.message });
  }
});

app.delete('/api/contacts/:contactId', async (req, res) => {
  const { contactId } = req.params;

  try {
    await pool.query(`DELETE FROM contacts WHERE id = $1;`, [contactId]);
    res.json({ message: 'Contact removed successfully.' });
  } catch (err) {
    console.error('[DELETE CONTACT ERROR]', err.message);
    res.status(500).json({ error: 'Failed to delete contact.' });
  }
});

// -------------------------------------------------------------
// 4. TELNYX INBOUND VOICE ROUTES (TeXML Flow)
// -------------------------------------------------------------

app.post('/voice', async (req, res) => {
  const calledNumber = req.body?.To || req.body?.to || SHIELD_PHONE_NUMBER;
  const callerNumber = req.body?.From || req.body?.from || 'Unknown';
  res.type('text/xml');

  try {
    await pool.query(
      `INSERT INTO call_logs (call_uuid, from_number, origin_city, origin_state, to_number)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (call_uuid) DO NOTHING`,
      [req.body?.CallSid || `call-${Date.now()}`, callerNumber, 'Unknown', 'Unknown', calledNumber]
    ).catch(e => console.error('Call log error:', e.message));

    const userResult = await pool.query(
      `SELECT u.id FROM users u 
       JOIN phone_numbers p ON u.id = p.user_id 
       WHERE p.shield_number = $1`,
      [calledNumber]
    );

    if (userResult.rows.length === 0) {
      console.log(`[VOICE] Unassigned shield number: ${calledNumber}`);
      const xmlResponse = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Say voice="Polly.Joanna-Neural">This number is not yet configured. Goodbye.</Say>
    <Hangup/>
</Response>`;
      return res.send(xmlResponse);
    }

    const userId = userResult.rows[0].id;

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
    console.error('[VOICE DB ERROR]', err.message);
    const xmlResponse = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Say voice="Polly.Joanna-Neural">An error occurred while processing your call. Goodbye.</Say>
    <Hangup/>
</Response>`;
    return res.send(xmlResponse);
  }
});

// Added missing /voice/process route for returning callers
app.post('/voice/process', async (req, res) => {
  const calledNumber = req.body?.To || req.body?.to || SHIELD_PHONE_NUMBER;
  const callerNumber = req.body?.From || req.body?.from || 'Unknown';
  const digits = (req.body?.Digits || req.body?.digits || '').trim();

  console.log(`[VOICE PROCESS] Returning caller ${callerNumber} entered PIN: "${digits}"`);
  res.type('text/xml');

  try {
    if (digits.length === 4) {
      const userResult = await pool.query(
        `SELECT u.id, u.owner_phone FROM users u 
         JOIN phone_numbers p ON u.id = p.user_id 
         WHERE p.shield_number = $1`,
        [calledNumber]
      );

      if (userResult.rows.length > 0) {
        const user = userResult.rows[0];

        const contactResult = await pool.query(
          `SELECT pin_code FROM contacts WHERE user_id = $1 AND caller_number = $2`,
          [user.id, callerNumber]
        );

        if (contactResult.rows.length > 0 && contactResult.rows[0].pin_code === digits) {
          const targetPhone = user.owner_phone || OWNER_PHONE_NUMBER;
          const xmlResponse = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Say voice="Polly.Joanna-Neural">Pin accepted. Connecting your call now.</Say>
    <Dial timeout="20" callerId="${callerNumber}">${targetPhone}</Dial>
</Response>`;
          return res.send(xmlResponse);
        }
      }
    }
  } catch (err) {
    console.error('[PROCESS DB ERROR]', err.message);
  }

  const xmlResponse = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Say voice="Polly.Joanna-Neural">Incorrect pin code.</Say>
    <Redirect method="POST">${BASE_URL}/voice/voicemail</Redirect>
</Response>`;
  res.send(xmlResponse);
});

app.post('/voice/setup', async (req, res) => {
  const calledNumber = req.body?.To || req.body?.to || SHIELD_PHONE_NUMBER;
  const callerNumber = req.body?.From || req.body?.from || 'Unknown';
  const digits = (req.body?.Digits || req.body?.digits || '').trim();

  console.log(`[VOICE SETUP] ${callerNumber} entering PIN: "${digits}"`);
  res.type('text/xml');

  try {
    if (digits.length === 4) {
      const userResult = await pool.query(
        `SELECT u.id, u.owner_phone FROM users u 
         JOIN phone_numbers p ON u.id = p.user_id 
         WHERE p.shield_number = $1`,
        [calledNumber]
      );

      if (userResult.rows.length > 0) {
        const user = userResult.rows[0];

        await pool.query(
          `INSERT INTO contacts (user_id, caller_number, pin_code, is_allowed)
           VALUES ($1, $2, $3, TRUE)
           ON CONFLICT (user_id, caller_number) 
           DO UPDATE SET pin_code = EXCLUDED.pin_code, updated_at = CURRENT_TIMESTAMP;`,
          [user.id, callerNumber, digits]
        );

        const targetPhone = user.owner_phone || OWNER_PHONE_NUMBER;

        const xmlResponse = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Say voice="Polly.Joanna-Neural">Your code has been saved. Connecting your call now.</Say>
    <Dial timeout="20" callerId="${callerNumber}">${targetPhone}</Dial>
</Response>`;
        return res.send(xmlResponse);
      }
    }
  } catch (err) {
    console.error('[SETUP DB ERROR]', err.message);
  }

  const xmlResponse = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Redirect method="POST">${BASE_URL}/voice/voicemail</Redirect>
</Response>`;
  res.send(xmlResponse);
});

app.post('/voice/voicemail', (req, res) => {
  res.type('text/xml');
  const xmlResponse = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Say voice="Polly.Joanna-Neural">
        Please leave a message after the tone. Press pound when finished.
    </Say>
    <Record
        action="${BASE_URL}/voice/voicemail-complete"
        method="POST"
        maxLength="60"
        finishOnKey="#"
        playBeep="true"
    />
    <Say voice="Polly.Joanna-Neural">Thank you. Your message has been saved. Goodbye.</Say>
    <Hangup/>
</Response>`;
  res.send(xmlResponse);
});

app.post('/voice/voicemail-complete', (req, res) => {
  console.log('[VOICEMAIL RECORDED]', req.body);
  res.type('text/xml');
  res.send(`<?xml version="1.0" encoding="UTF-8"?><Response><Hangup/></Response>`);
});

// -------------------------------------------------------------
// 5. Telnyx Inbound SMS Webhook
// -------------------------------------------------------------
app.post('/sms', async (req, res) => {
  try {
    const data = req.body?.data || req.body;
    const eventType = data.event_type || req.body?.event_type;

    if (eventType && eventType !== 'message.received') {
      return res.status(200).send('Event ignored');
    }

    const payload = data.payload || data;
    const fromNumber = payload.from?.phone_number || payload.from || payload.From;
    const toNumber = payload.to?.[0]?.phone_number || payload.to || SHIELD_PHONE_NUMBER;
    const messageText = (payload.text || payload.Body || '').trim();

    console.log(`[SMS] Incoming text from ${fromNumber}: "${messageText}"`);

    if (fromNumber === toNumber) {
      return res.status(200).send('Loop prevented');
    }

    let replyText = 'Command not recognized. Valid commands: ALERTS ON/OFF, SET GUARDIAN [number].';
    const textUpper = messageText.toUpperCase();

    if (textUpper === 'ALERTS ON') {
      replyText = 'Shield Alerts enabled. You will receive SMS alerts for unverified calls.';
    } else if (textUpper === 'ALERTS OFF') {
      replyText = 'Shield Alerts disabled.';
    } else if (textUpper.startsWith('SET GUARDIAN ')) {
      const guardianNum = messageText.substring(13).trim();
      replyText = `Guardian notification number set to: ${guardianNum}.`;
    }

    if (telnyxClient) {
      await telnyxClient.messages.create({
        from: toNumber,
        to: fromNumber,
        text: replyText
      });
      console.log(`[SMS] Reply sent to ${fromNumber}`);
    }

    res.status(200).send('OK');
  } catch (err) {
    console.error('[SMS ERROR]', err.message);
    res.status(200).send('Error processed');
  }
});

// -------------------------------------------------------------
// 6. Global Error Handling Middleware
// -------------------------------------------------------------
app.use((err, req, res, next) => {
  const timestamp = new Date().toISOString();
  console.error(`[${timestamp}] ❌ UNHANDLED SERVER ERROR:`, err.message);
  console.error(err.stack);
  res.status(500).json({ error: 'Internal Server Error', message: err.message });
});

// -------------------------------------------------------------
// 7. WebSocket Server for Live Audio Screening
// -------------------------------------------------------------
wss.on('connection', (ws) => {
  console.log('[Media Stream] WebSocket client connected');

  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);
      if (data.event === 'start') {
        console.log(`[Media Stream] Started: ${data.start.call_session_id || data.start.call_control_id}`);
      } else if (data.event === 'stop') {
        console.log('[Media Stream] Stopped');
      }
    } catch (e) {
      console.error('[Media Stream] Parse error:', e.message);
    }
  });

  ws.on('close', () => console.log('[Media Stream] Disconnected'));
});

// -------------------------------------------------------------
// 8. Start Unified HTTP & WebSocket Server
// -------------------------------------------------------------
const PORT = process.env.PORT || 10000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
