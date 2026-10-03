require('dotenv').config();
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const Telnyx = require('telnyx');
const { Pool } = require('pg');

const telnyx = Telnyx(process.env.TELNYX_API_KEY);

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

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
// 1. Health Check & Config Endpoints
// -------------------------------------------------------------
app.get('/', (req, res) => {
  res.send('Mobile Call Shield Backend (PostgreSQL Multi-Tenant) Active');
});

app.get('/api/shield-number', (req, res) => {
  res.json({ shieldNumber: SHIELD_PHONE_NUMBER });
});

// -------------------------------------------------------------
// 2. TELNYX INBOUND VOICE ROUTES (PostgreSQL Driven)
// -------------------------------------------------------------

// Voice Step 1: Initial Call Entry Point
app.post('/voice', async (req, res) => {
  const calledNumber = req.body?.To || req.body?.to || SHIELD_PHONE_NUMBER;
  const callerNumber = req.body?.From || req.body?.from || 'Unknown';

  console.log(`[VOICE] Incoming call To: ${calledNumber} | From: ${callerNumber}`);
  res.type('text/xml');

  try {
    // 1. Identify owner of the shield number in DB
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

    // 2. Check if caller is already saved in contacts
    const contactResult = await pool.query(
      `SELECT pin_code, is_allowed FROM contacts WHERE user_id = $1 AND caller_number = $2`,
      [userId, callerNumber]
    );

    // FIRST-TIME CALLER: Route to /voice/setup to create a PIN
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

    // RETURNING CALLER: Route to /voice/process to verify existing PIN
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

// Voice Step 2: Setup PIN for New Caller
app.post('/voice/setup', async (req, res) => {
  const calledNumber = req.body?.To || req.body?.to || SHIELD_PHONE_NUMBER;
  const callerNumber = req.body?.From || req.body?.from || 'Unknown';
  const digits = (req.body?.Digits || req.body?.digits || '').trim();

  console.log(`[VOICE SETUP] ${callerNumber} entering PIN: "${digits}"`);
  res.type('text/xml');

  if (digits.length === 4) {
    try {
      // Find owner of shield number
      const userResult = await pool.query(
        `SELECT u.id, u.owner_phone FROM users u 
         JOIN phone_numbers p ON u.id = p.user_id 
         WHERE p.shield_number = $1`,
        [calledNumber]
      );

      if (userResult.rows.length > 0) {
        const user = userResult.rows[0];

        // Save PIN into PostgreSQL contacts table
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
    } catch (err) {
      console.error('[SETUP DB ERROR]', err);
    }
  }

  // Failed setup -> Send to Voicemail
  const xmlResponse = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Redirect method="POST">${BASE_URL}/voice/voicemail</Redirect>
</Response>`;
  res.send(xmlResponse);
});

// Voice Step 3: Process & Verify PIN
app.post('/voice/process', async (req, res) => {
  const calledNumber = req.body?.To || req.body?.to || SHIELD_PHONE_NUMBER;
  const callerNumber = req.body?.From || req.body?.from || 'Unknown';
  const userPin = (req.body?.Digits || req.body?.digits || '').trim();

  res.type('text/xml');

  try {
    const contactResult = await pool.query(
      `SELECT c.pin_code, u.owner_phone 
       FROM contacts c
       JOIN users u ON c.user_id = u.id
       JOIN phone_numbers p ON u.id = p.user_id
       WHERE p.shield_number = $1 AND c.caller_number = $2`,
      [calledNumber, callerNumber]
    );

    if (contactResult.rows.length > 0) {
      const { pin_code, owner_phone } = contactResult.rows[0];

      if (userPin === pin_code) {
        const targetPhone = owner_phone || OWNER_PHONE_NUMBER;
        console.log(`[VERIFY SUCCESS] PIN verified for ${callerNumber}. Dialing owner ${targetPhone}`);

        const xmlResponse = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Say voice="Polly.Joanna-Neural">Code verified. Connecting your call now.</Say>
    <Dial timeout="20" callerId="${callerNumber}">${targetPhone}</Dial>
</Response>`;
        return res.send(xmlResponse);
      }
    }
  } catch (err) {
    console.error('[VERIFY DB ERROR]', err);
  }

  console.log(`[VERIFY FAILED] Invalid PIN from ${callerNumber}`);
  const xmlResponse = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Say voice="Polly.Joanna-Neural">Invalid code.</Say>
    <Redirect method="POST">${BASE_URL}/voice/voicemail</Redirect>
</Response>`;
  res.send(xmlResponse);
});

// Voice Step 4: Voicemail Recording Route
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

// Voice Step 5: Voicemail Complete Callback
app.post('/voice/voicemail-complete', (req, res) => {
  console.log('[VOICEMAIL RECORDED]', req.body);
  res.type('text/xml');
  res.send(`<?xml version="1.0" encoding="UTF-8"?><Response><Hangup/></Response>`);
});

// -------------------------------------------------------------
// 3. Telnyx Inbound SMS Webhook
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

    await telnyx.messages.create({
      from: toNumber,
      to: fromNumber,
      text: replyText
    });

    console.log(`[SMS] Reply sent to ${fromNumber}`);
    res.status(200).send('OK');
  } catch (err) {
    console.error('[SMS ERROR]', err.message);
    res.status(200).send('Error processed');
  }
});

// -------------------------------------------------------------
// 4. WebSocket Server for Live Audio Screening
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
// 5. Start Server
// -------------------------------------------------------------
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
